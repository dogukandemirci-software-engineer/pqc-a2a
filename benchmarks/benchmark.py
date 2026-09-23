from __future__ import annotations

import csv
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqc_a2a import AgentIdentity, ReplayCache, open_envelope, seal


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    lower, upper = int(position), min(int(position) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def stats(values: list[float]) -> dict[str, float]:
    return {
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "stdev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def classical_roundtrip(sender_x: X25519PrivateKey, receiver_x: X25519PrivateKey, signer: Ed25519PrivateKey, payload: bytes) -> tuple[float, int]:
    receiver_public = receiver_x.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = sender_x.exchange(X25519PublicKey.from_public_bytes(receiver_public))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqc-a2a/benchmark/classical").derive(shared)
    nonce = hashlib.sha256(payload).digest()[:12]
    aad = b"classical-baseline-v1"
    start = time.perf_counter_ns()
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
    signature = signer.sign(ciphertext + aad)
    signer.public_key().verify(signature, ciphertext + aad)
    AESGCM(key).decrypt(nonce, ciphertext, aad)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return elapsed, len(ciphertext) + len(signature) + len(nonce)


def run(n: int = 50):
    pqc_sender, pqc_receiver = AgentIdentity("agent-a"), AgentIdentity("agent-b")
    classical_sender_x, classical_receiver_x = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    classical_signer = Ed25519PrivateKey.generate()
    rows = []
    for payload_size in (256, 4096, 16384):
        payload = b"x" * payload_size
        pqc_seal, pqc_open, pqc_sizes, classical_times, classical_sizes = [], [], [], [], []
        for i in range(n):
            body = {"type": "task.result", "seq": i, "payload": payload.decode("ascii")}
            start = time.perf_counter_ns(); envelope = seal(pqc_sender, pqc_receiver, body); pqc_seal.append((time.perf_counter_ns() - start) / 1e6)
            pqc_sizes.append(len(json.dumps(envelope, separators=(",", ":"))))
            start = time.perf_counter_ns(); assert open_envelope(pqc_receiver, pqc_sender, envelope, ReplayCache()) == body; pqc_open.append((time.perf_counter_ns() - start) / 1e6)
            classical_elapsed, classical_size = classical_roundtrip(classical_sender_x, classical_receiver_x, classical_signer, payload)
            classical_times.append(classical_elapsed); classical_sizes.append(classical_size)
        seal_s, open_s = stats(pqc_seal), stats(pqc_open)
        classical_s = stats(classical_times)
        pqc_roundtrips = [a + b for a, b in zip(pqc_seal, pqc_open)]
        rows.append({
            "samples": n,
            "payload_bytes": payload_size,
            "pqc_envelope_bytes": statistics.median(pqc_sizes),
            "classical_envelope_bytes": statistics.median(classical_sizes),
            "pqc_seal_median_ms": seal_s["median_ms"], "pqc_seal_p95_ms": seal_s["p95_ms"], "pqc_seal_stdev_ms": seal_s["stdev_ms"],
            "pqc_open_median_ms": open_s["median_ms"], "pqc_open_p95_ms": open_s["p95_ms"], "pqc_open_stdev_ms": open_s["stdev_ms"],
            "pqc_roundtrip_median_ms": statistics.median(pqc_roundtrips),
            "pqc_roundtrip_stdev_ms": statistics.stdev(pqc_roundtrips) if len(pqc_roundtrips) > 1 else 0.0,
            "classical_roundtrip_median_ms": classical_s["median_ms"], "classical_roundtrip_p95_ms": classical_s["p95_ms"], "classical_roundtrip_stdev_ms": classical_s["stdev_ms"],
        })
    out = Path(__file__).parent / "results.csv"
    with out.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    print(json.dumps({"samples": n, "rows": rows}, indent=2))


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 50)


def _unused_plot_placeholder() -> None:
    """Plots are produced by analyze_results.py from raw CSV data."""
    return None
