"""Two fake model agents exchanging encrypted greeting messages over a stream.

The embedding vectors are static test metadata, not a language-model or
cryptographic primitive. The transport deliberately fragments each envelope
and yields frames asynchronously to exercise the real PQC-A2A API.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from typing import Any

from pqc_a2a import AgentCard, AgentIdentity, ReplayCache, fragment, open_envelope, reassemble, seal


STATIC_EMBEDDINGS: dict[str, tuple[float, ...]] = {
    "hello from gpt-sim": (0.10, -0.20, 0.30, 0.40),
    "hello from gemma-sim": (-0.10, 0.20, 0.30, -0.40),
}


class FakeEmbeddingModel:
    """Deterministic stand-in for an embedding endpoint."""

    def embed(self, text: str) -> list[float]:
        try:
            return list(STATIC_EMBEDDINGS[text])
        except KeyError as exc:
            raise ValueError(f"no static embedding fixture for {text!r}") from exc


class FragmentStream:
    """An in-memory asynchronous byte stream with deterministic frame delay."""

    def __init__(self, frame_delay_ms: float = 1.0, mtu: int = 180) -> None:
        if frame_delay_ms < 0:
            raise ValueError("frame_delay_ms cannot be negative")
        self.frame_delay = frame_delay_ms / 1000
        self.mtu = mtu
        self._frames: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def write_envelope(self, envelope: dict[str, Any]) -> int:
        raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        frames = fragment(raw, mtu=self.mtu, message_id=envelope["message_id"])
        for frame in frames:
            await self._frames.put(frame)
            if self.frame_delay:
                await asyncio.sleep(self.frame_delay)
        await self._frames.put(None)
        return len(frames)

    async def read_envelope(self) -> tuple[dict[str, Any], int]:
        frames: list[bytes] = []
        while True:
            frame = await self._frames.get()
            if frame is None:
                break
            frames.append(frame)
        raw = reassemble(frames)
        return json.loads(raw), len(frames)


@dataclass
class FakeModelAgent:
    name: str
    model: str
    identity: AgentIdentity
    card: AgentCard
    embedder: FakeEmbeddingModel

    @classmethod
    def create(cls, name: str, model: str) -> "FakeModelAgent":
        identity = AgentIdentity(name)
        return cls(name, model, identity, AgentCard(name), FakeEmbeddingModel())

    def signed_card(self) -> dict[str, Any]:
        return self.card.sign(self.identity)

    def greeting(self) -> dict[str, Any]:
        text = f"hello from {self.model}"
        return {"type": "greeting", "agent": self.name, "model": self.model, "text": text, "fake_embedding": self.embedder.embed(text)}

    async def send(self, stream: FragmentStream, recipient: "FakeModelAgent") -> int:
        return await stream.write_envelope(seal(self.identity, recipient.identity, self.greeting()))

    async def receive(self, stream: FragmentStream, sender: "FakeModelAgent") -> tuple[dict[str, Any], int]:
        envelope, frame_count = await stream.read_envelope()
        payload = open_envelope(self.identity, sender.identity, envelope, ReplayCache())
        return payload, frame_count


async def run_demo(frame_delay_ms: float = 1.0, mtu: int = 180) -> dict[str, Any]:
    gpt = FakeModelAgent.create("agent-gpt", "gpt-sim")
    gemma = FakeModelAgent.create("agent-gemma", "gemma-sim")

    # The demo uses each generated identity as the local trust anchor. A real
    # deployment would load these trust anchors from a certificate/KMS system.
    AgentCard.verify_signed(gpt.signed_card(), gpt.identity)
    AgentCard.verify_signed(gemma.signed_card(), gemma.identity)
    gpt.card.negotiate(gemma.card)

    gpt_to_gemma = FragmentStream(frame_delay_ms, mtu)
    gemma_to_gpt = FragmentStream(frame_delay_ms, mtu)
    _, _, received_by_gemma, received_by_gpt = await asyncio.gather(
        gpt.send(gpt_to_gemma, gemma),
        gemma.send(gemma_to_gpt, gpt),
        gemma.receive(gpt_to_gemma, gpt),
        gpt.receive(gemma_to_gpt, gemma),
    )
    # The first two gather entries are frame counts; the last two are payloads.
    gemma_payload, gemma_frames = received_by_gemma
    gpt_payload, gpt_frames = received_by_gpt
    return {"status": "ok", "transport": {"mtu": mtu, "frame_delay_ms": frame_delay_ms}, "gpt_received": gpt_payload, "gemma_received": gemma_payload, "frames": {"gpt_to_gemma": gemma_frames, "gemma_to_gpt": gpt_frames}}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run two fake GPT/Gemma agents over encrypted PQC-A2A streaming")
    parser.add_argument("--frame-delay-ms", type=float, default=1.0)
    parser.add_argument("--mtu", type=int, default=180)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run_demo(args.frame_delay_ms, args.mtu)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
