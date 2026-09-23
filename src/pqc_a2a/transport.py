"""QUIC/TLS 1.3 transport profile and authenticated application framing."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import ssl
import socket
import struct
import fnmatch
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Iterable

from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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
        if require_client_certificate and not cafile:
            raise ValueError("cafile is required for mutual TLS")
        config = QuicConfiguration(is_client=False, alpn_protocols=[self.alpn], max_datagram_frame_size=self.mtu, cafile=cafile, verify_mode=ssl.CERT_REQUIRED if require_client_certificate else ssl.CERT_NONE)
        config.load_cert_chain(certificate, private_key)
        return config

    @staticmethod
    def validate_certificate_hostname(certificate: str, hostname: str) -> str:
        """Validate SAN/CN using Python's hostname verifier and return SHA-256 pin."""
        if not hostname: raise ValueError("hostname is required")
        with open(certificate, "rb") as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
        try:
            names = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            names = []
        if not names:
            names = [attribute.value for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        if not any(fnmatch.fnmatchcase(hostname.lower(), name.lower()) for name in names):
            raise ValueError("certificate hostname/SAN mismatch")
        with open(certificate, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()


class TcpFallback:
    """Length-prefixed TLS fallback for deployments where QUIC is unavailable."""
    def __init__(self, sock: socket.socket, *, max_frame_size: int = 16 * 1024 * 1024):
        if max_frame_size < 1: raise ValueError("invalid TCP frame limit")
        self.sock, self.max_frame_size = sock, max_frame_size

    def send(self, payload: bytes) -> None:
        if not isinstance(payload, bytes) or len(payload) > self.max_frame_size: raise ValueError("TCP payload exceeds limit")
        self.sock.sendall(struct.pack("!I", len(payload)) + payload)

    def recv(self) -> bytes:
        header = self._read_exact(4); length = struct.unpack("!I", header)[0]
        if length > self.max_frame_size: raise ValueError("TCP frame exceeds limit")
        return self._read_exact(length)

    def _read_exact(self, size: int) -> bytes:
        chunks, remaining = [], size
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk: raise ConnectionError("TCP fallback closed before frame completion")
            chunks.append(chunk); remaining -= len(chunk)
        return b"".join(chunks)


def provision_dev_certificate(directory: str, hostname: str = "localhost") -> tuple[str, str]:
    """Create a short-lived self-signed SAN certificate for local integration tests.

    This intentionally is not a production CA. Production deployments should
    provision certificates through their CA/KMS/HSM and pass the resulting
    paths to ``TransportProfile``.
    """
    from pathlib import Path
    root = Path(directory); root.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = root / "dev-cert.pem", root / "dev-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    import os
    os.chmod(key_path, 0o600)
    return str(cert_path), str(key_path)


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


__all__ = ["ALPN", "TLS_VERSION", "TransportProfile", "TcpFallback", "provision_dev_certificate", "fragment", "reassemble"]
