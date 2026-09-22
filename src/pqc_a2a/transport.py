"""QUIC/TLS 1.3 transport profile and application-level MTU fragmentation."""
from __future__ import annotations

import hashlib, math
from dataclasses import dataclass
from typing import Iterable

from aioquic.quic.configuration import QuicConfiguration

ALPN = "pqc-a2a/1"
TLS_VERSION = "TLSv1.3"

@dataclass(frozen=True)
class TransportProfile:
    alpn: str = ALPN
    mtu: int = 1200
    tcp_fallback: bool = True
    max_fragments: int = 4096

    def client_configuration(self, certificate: str | None = None, private_key: str | None = None) -> QuicConfiguration:
        config = QuicConfiguration(is_client=True, alpn_protocols=[self.alpn], max_datagram_frame_size=self.mtu)
        if certificate and private_key: config.load_cert_chain(certificate, private_key)
        return config

    def server_configuration(self, certificate: str, private_key: str) -> QuicConfiguration:
        config = QuicConfiguration(is_client=False, alpn_protocols=[self.alpn], max_datagram_frame_size=self.mtu)
        config.load_cert_chain(certificate, private_key)
        return config


def fragment(payload: bytes, mtu: int = 1200, message_id: str = "") -> list[bytes]:
    """Split an envelope after serialization; every fragment carries a compact header."""
    if mtu < 64: raise ValueError("MTU must leave room for the fragment header")
    chunk_size = mtu - 48
    count = max(1, math.ceil(len(payload) / chunk_size))
    digest = hashlib.sha256(payload).hexdigest()[:16]
    if count > 4096: raise ValueError("message exceeds fragment limit")
    return [f"PQA1|{message_id}|{i}|{count}|{digest}|".encode() + payload[i * chunk_size:(i + 1) * chunk_size] for i in range(count)]


def reassemble(fragments: Iterable[bytes], max_fragments: int = 4096) -> bytes:
    parts = list(fragments)
    if not parts or len(parts) > max_fragments: raise ValueError("invalid fragment set")
    parsed = []
    for raw in parts:
        head, body = raw.split(b"|", 5)[:5], raw.split(b"|", 5)[-1]
        if head[0] != b"PQA1": raise ValueError("unknown fragment version")
        _, mid, idx, total, digest = head
        parsed.append((mid, int(idx), int(total), digest, body))
    mids = {x[0] for x in parsed}; totals = {x[2] for x in parsed}; digests = {x[3] for x in parsed}
    if len(mids) != 1 or len(totals) != 1 or len(digests) != 1 or next(iter(totals)) != len(parsed): raise ValueError("incomplete fragment set")
    data = b"".join(x[4] for x in sorted(parsed, key=lambda x: x[1]))
    if hashlib.sha256(data).hexdigest().encode()[:16] != next(iter(digests)): raise ValueError("fragment digest mismatch")
    return data

__all__ = ["ALPN", "TLS_VERSION", "TransportProfile", "fragment", "reassemble"]
