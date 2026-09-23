"""In-process reference rendezvous/relay primitives.

A production deployment can implement the same interfaces over HTTPS/QUIC.
The relay never receives stable AgentIdentity values or plaintext records.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from .operations import DurableReplayCache
from .protocol import AgentIdentity, canonical, b64, unb64, _sign
from .secure_channel import opaque_handle
import oqs


@dataclass(frozen=True)
class CapabilityToken:
    subject_handle: str
    audience: str
    scopes: tuple[str, ...]
    expires_at: int
    nonce: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"format": "pqc-a2a-capability/1", "subject_handle": self.subject_handle, "audience": self.audience, "scopes": list(self.scopes), "expires_at": self.expires_at, "nonce": self.nonce, "signature": self.signature}


def issue_capability(identity: AgentIdentity, *, audience: str, scopes: tuple[str, ...], ttl_seconds: int = 300, epoch: int | None = None) -> dict[str, Any]:
    if not audience or not scopes or ttl_seconds < 1 or ttl_seconds > 3600: raise ValueError("invalid capability")
    body = {"format": "pqc-a2a-capability/1", "subject_handle": opaque_handle(identity, epoch=epoch), "audience": audience, "scopes": list(scopes), "expires_at": int(time.time()) + ttl_seconds, "nonce": hashlib.sha3_256(b64(identity.sig_public).encode() + str(time.time_ns()).encode()).hexdigest()}
    return {**body, "signature": b64(_sign(identity, canonical(body)))}


def verify_capability(token: dict[str, Any], identity: AgentIdentity, *, audience: str, required_scope: str, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    subject = token.get("subject_handle")
    valid_handles = {opaque_handle(identity, epoch=now // 3600), opaque_handle(identity, epoch=(now // 3600) - 1)}
    if token.get("format") != "pqc-a2a-capability/1" or subject not in valid_handles:
        raise ValueError("capability subject mismatch")
    scopes = token.get("scopes")
    expires_at = token.get("expires_at")
    if token.get("audience") != audience or not isinstance(scopes, list) or required_scope not in scopes or not isinstance(expires_at, int) or now > expires_at:
        raise ValueError("capability expired or scope denied")
    unsigned = {k: v for k, v in token.items() if k != "signature"}
    with oqs.Signature(identity.sig_name) as verifier:
        if not verifier.verify(canonical(unsigned), unb64(token.get("signature", "")), identity.sig_public): raise ValueError("capability signature failed")


class Rendezvous:
    def __init__(self, *, replay_cache: Any | None = None, max_records: int = 10_000):
        self.records: dict[str, tuple[dict[str, Any], int]] = {}
        self.replay = replay_cache or DurableReplayCache(":memory:")
        self.max_records = max_records

    def register(self, handle: str, endpoint: str, capability: dict[str, Any], identity: AgentIdentity, *, ttl_seconds: int = 300, now: int | None = None) -> None:
        if not isinstance(handle, str) or not handle or not isinstance(endpoint, str) or not endpoint or ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("invalid rendezvous registration")
        if len(self.records) >= self.max_records and handle not in self.records: raise RuntimeError("rendezvous capacity exceeded")
        now = int(time.time()) if now is None else now
        verify_capability(capability, identity, audience="rendezvous", required_scope="register", now=now)
        if handle != capability.get("subject_handle"):
            raise ValueError("capability subject does not own handle")
        self.records[handle] = ({"endpoint": endpoint, "handle": handle}, now + ttl_seconds)

    def lookup(self, handle: str, capability: dict[str, Any], identity: AgentIdentity, *, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        verify_capability(capability, identity, audience="rendezvous", required_scope="lookup", now=now)
        value = self.records.get(handle)
        if value is None or value[1] < now: raise ValueError("rendezvous handle unavailable")
        return dict(value[0])


class OpaqueRelay:
    def __init__(self, *, max_queue_per_handle: int = 128):
        if max_queue_per_handle < 1: raise ValueError("invalid relay queue limit")
        self.max_queue = max_queue_per_handle; self._queues: dict[str, list[dict[str, Any]]] = {}

    def forward(self, record: dict[str, Any]) -> None:
        handle = record.get("handle")
        if not isinstance(handle, str) or not handle or record.get("format") != "pqc-a2a-secure-record/1": raise ValueError("invalid opaque relay record")
        queue = self._queues.setdefault(handle, [])
        if len(queue) >= self.max_queue: raise RuntimeError("relay queue capacity exceeded")
        queue.append(dict(record))

    def receive(self, handle: str) -> dict[str, Any]:
        queue = self._queues.get(handle, [])
        if not queue: raise LookupError("no relayed record")
        return queue.pop(0)


__all__ = ["CapabilityToken", "issue_capability", "verify_capability", "Rendezvous", "OpaqueRelay"]
