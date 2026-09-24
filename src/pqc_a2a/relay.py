"""In-process reference rendezvous/relay primitives with bounded state."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .operations import DurableReplayCache
from .protocol import AgentIdentity, canonical, b64, unb64, _sign
from .secure_channel import opaque_handle
import oqs

MAX_HANDLE_BYTES = 256
MAX_ENDPOINT_BYTES = 2048
MAX_RELAY_RECORD_BYTES = 16 * 1024 * 1024

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
    if not audience or not scopes or ttl_seconds < 1 or ttl_seconds > 3600:
        raise ValueError("invalid capability")
    body = {"format": "pqc-a2a-capability/1", "subject_handle": opaque_handle(identity, epoch=epoch), "audience": audience, "scopes": list(scopes), "expires_at": int(time.time()) + ttl_seconds, "nonce": hashlib.sha3_256(b64(identity.sig_public).encode() + str(time.time_ns()).encode()).hexdigest()}
    return {**body, "signature": b64(_sign(identity, canonical(body)))}


def verify_capability(token: dict[str, Any], identity: AgentIdentity, *, audience: str, required_scope: str, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    subject = token.get("subject_handle")
    valid_handles = {opaque_handle(identity, epoch=now // 3600), opaque_handle(identity, epoch=(now // 3600) - 1)}
    scopes = token.get("scopes")
    expires_at = token.get("expires_at")
    if token.get("format") != "pqc-a2a-capability/1" or not isinstance(subject, str) or len(subject.encode()) > MAX_HANDLE_BYTES or subject not in valid_handles:
        raise ValueError("capability subject mismatch")
    if token.get("audience") != audience or not isinstance(scopes, list) or required_scope not in scopes or not isinstance(expires_at, int) or isinstance(expires_at, bool) or now >= expires_at:
        raise ValueError("capability expired or scope denied")
    unsigned = {k: v for k, v in token.items() if k != "signature"}
    with oqs.Signature(identity.sig_name) as verifier:
        if not verifier.verify(canonical(unsigned), unb64(token.get("signature", "")), identity.sig_public):
            raise ValueError("capability signature failed")


class Rendezvous:
    def __init__(self, *, replay_cache: Any | None = None, max_records: int = 10_000):
        if max_records < 1:
            raise ValueError("invalid rendezvous limit")
        self.records: dict[str, tuple[dict[str, Any], int]] = {}
        self.replay = replay_cache or DurableReplayCache(":memory:")
        self.max_records = max_records
        self._lock = threading.RLock()

    def _purge(self, now: int) -> None:
        for key, (_, expires_at) in list(self.records.items()):
            if expires_at <= now:
                del self.records[key]

    def register(self, handle: str, endpoint: str, capability: dict[str, Any], identity: AgentIdentity, *, ttl_seconds: int = 300, now: int | None = None) -> None:
        if not isinstance(handle, str) or not handle or len(handle.encode()) > MAX_HANDLE_BYTES or not isinstance(endpoint, str) or not endpoint or len(endpoint.encode()) > MAX_ENDPOINT_BYTES or ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("invalid rendezvous registration")
        now = int(time.time()) if now is None else now
        with self._lock:
            self._purge(now)
            verify_capability(capability, identity, audience="rendezvous", required_scope="register", now=now)
            if handle != capability.get("subject_handle"):
                raise ValueError("capability subject does not own handle")
            expires_at = min(now + ttl_seconds, int(capability["expires_at"]))
            self.records[handle] = ({"endpoint": endpoint, "handle": handle}, expires_at)
            if len(self.records) > self.max_records:
                del self.records[handle]
                raise RuntimeError("rendezvous capacity exceeded")

    def lookup(self, handle: str, capability: dict[str, Any], identity: AgentIdentity, *, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        if not isinstance(handle, str) or not handle or len(handle.encode()) > MAX_HANDLE_BYTES:
            raise ValueError("invalid rendezvous handle")
        with self._lock:
            verify_capability(capability, identity, audience="rendezvous", required_scope="lookup", now=now)
            if handle != capability.get("subject_handle"):
                raise ValueError("capability subject does not own handle")
            self._purge(now)
            value = self.records.get(handle)
            if value is None:
                raise ValueError("rendezvous handle unavailable")
            return dict(value[0])


class OpaqueRelay:
    def __init__(self, *, max_queue_per_handle: int = 128, max_handles: int = 10_000, max_total_records: int = 100_000, max_total_bytes: int = 256 * 1024 * 1024):
        if min(max_queue_per_handle, max_handles, max_total_records, max_total_bytes) < 1:
            raise ValueError("invalid relay queue limit")
        self.max_queue, self.max_handles, self.max_total_records, self.max_total_bytes = max_queue_per_handle, max_handles, max_total_records, max_total_bytes
        self._queues: dict[str, deque[dict[str, Any]]] = {}
        self._bytes = 0
        self._lock = threading.RLock()

    def forward(self, record: dict[str, Any]) -> None:
        handle = record.get("handle") if isinstance(record, dict) else None
        if not isinstance(handle, str) or not handle or len(handle.encode()) > MAX_HANDLE_BYTES or record.get("format") not in {"pqc-a2a-secure-record/1", "pqc-a2a-secure-record/2"}:
            raise ValueError("invalid opaque relay record")
        size = len(canonical(record))
        if size > MAX_RELAY_RECORD_BYTES:
            raise ValueError("relay record exceeds limit")
        with self._lock:
            queue = self._queues.get(handle)
            if queue is None:
                if len(self._queues) >= self.max_handles:
                    raise RuntimeError("relay handle capacity exceeded")
                queue = self._queues.setdefault(handle, deque())
            if len(queue) >= self.max_queue or sum(len(items) for items in self._queues.values()) >= self.max_total_records or self._bytes + size > self.max_total_bytes:
                raise RuntimeError("relay queue capacity exceeded")
            queue.append(dict(record)); self._bytes += size

    def receive(self, handle: str) -> dict[str, Any]:
        with self._lock:
            queue = self._queues.get(handle)
            if not queue:
                raise LookupError("no relayed record")
            record = queue.popleft(); self._bytes -= len(canonical(record))
            if not queue:
                del self._queues[handle]
            return record


__all__ = ["CapabilityToken", "issue_capability", "verify_capability", "Rendezvous", "OpaqueRelay"]
