"""QUIC/TLS 1.3 transport profile and authenticated application framing."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import ssl
from dataclasses import dataclass
from typing import Iterable

from aioquic.quic.configuration import QuicConfiguration

ALPN = "pqc-a2a/1"
TLS_VERSION = "TLSv1.3"
_PREFIX = b"PQA1\n"


@dataclass(frozen=True)
class TransportProfile:
    alpn: str = ALPN
    mtu: int = 1200
    tcp_fallback: bool = True
    max_fragments: int = 4096

    def __post_init__(self) -> None:
        if self.mtu < 128 or self.max_fragments < 1:
            raise ValueError("invalid transport limits")

    def client_configuration(self, certificate: str | None = None, private_key: str | None = None, *, cafile: str | None = None, server_name: str | None = None) -> QuicConfiguration:
        """Create a TLS 1.3 QUIC client config with certificate verification enabled.

        ``cafile`` must point to the trust store for the deployment. Passing no
        CA intentionally makes a real connection fail rather than silently
        accepting an unauthenticated peer.
        """
        config = QuicConfiguration(is_client=True, alpn_protocols=[self.alpn], max_datagram_frame_size=self.mtu, cafile=cafile, server_name=server_name, verify_mode=ssl.CERT_REQUIRED)
        if certificate and private_key:
            config.load_cert_chain(certificate, private_key)
        return config

    def server_configuration(self, certificate: str, private_key: str, *, cafile: str | None = None, require_client_certificate: bool = False) -> QuicConfiguration:
        config = QuicConfiguration(is_client=False, alpn_protocols=[self.alpn], max_datagram_frame_size=self.mtu, cafile=cafile, verify_mode=ssl.CERT_REQUIRED if require_client_certificate else ssl.CERT_NONE)
        config.load_cert_chain(certificate, private_key)
        return config


def _header(message_id: str, index: int, total: int, digest: str) -> bytes:
    if not isinstance(message_id, str) or "\n" in message_id:
        raise ValueError("message_id must be a single-line string")
    return _PREFIX + json.dumps({"id": message_id, "i": index, "n": total, "h": digest}, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def fragment(payload: bytes, mtu: int = 1200, message_id: str = "", max_fragments: int = 4096) -> list[bytes]:
    """Split bytes into self-describing frames whose complete size is <= mtu."""
    if mtu < 128 or max_fragments < 1:
        raise ValueError("invalid fragmentation limits")
    digest = hashlib.sha256(payload).hexdigest()
    total = max(1, math.ceil(len(payload) / max(1, mtu - len(_header(message_id, 0, 1, digest)))))
    while True:
        overhead = max(len(_header(message_id, i, total, digest)) for i in range(total))
        new_total = max(1, math.ceil(len(payload) / max(1, mtu - overhead)))
        if new_total == total:
            break
        total = new_total
    if total > max_fragments:
        raise ValueError("message exceeds fragment limit")
    frames = []
    offset = 0
    for index in range(total):
        header = _header(message_id, index, total, digest)
        chunk_size = mtu - len(header)
        body = payload[offset:offset + chunk_size]
        offset += len(body)
        frame = header + body
        if len(frame) > mtu:
            raise ValueError("fragment exceeds MTU")
        frames.append(frame)
    return frames


def reassemble(fragments: Iterable[bytes], max_fragments: int = 4096) -> bytes:
    parts = list(fragments)
    if not parts or len(parts) > max_fragments:
        raise ValueError("invalid fragment set")
    parsed = []
    for raw in parts:
        try:
            prefix, rest = raw.split(b"\n", 1)
            header_raw, body = rest.split(b"\n", 1)
            if prefix != _PREFIX[:-1]:
                raise ValueError("unknown fragment version")
            header = json.loads(header_raw)
            mid, index, total, digest = header["id"], header["i"], header["n"], header["h"]
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("malformed fragment") from exc
        if not isinstance(mid, str) or not isinstance(index, int) or isinstance(index, bool) or not isinstance(total, int) or isinstance(total, bool) or not isinstance(digest, str):
            raise ValueError("invalid fragment header")
        if total < 1 or total > max_fragments or index < 0 or index >= total or len(digest) != 64:
            raise ValueError("invalid fragment range")
        parsed.append((mid, index, total, digest, body))
    mids, totals, digests = {x[0] for x in parsed}, {x[2] for x in parsed}, {x[3] for x in parsed}
    if len(mids) != 1 or len(totals) != 1 or len(digests) != 1:
        raise ValueError("inconsistent fragment set")
    total = next(iter(totals))
    if total != len(parsed) or {x[1] for x in parsed} != set(range(total)):
        raise ValueError("incomplete or duplicate fragment set")
    data = b"".join(x[4] for x in sorted(parsed, key=lambda x: x[1]))
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), next(iter(digests))):
        raise ValueError("fragment digest mismatch")
    return data


__all__ = ["ALPN", "TLS_VERSION", "TransportProfile", "fragment", "reassemble"]
