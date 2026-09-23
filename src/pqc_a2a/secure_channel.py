"""End-to-end session channel with opaque peer handles.

This is transport-neutral: relay/gateway code sees only handles and encrypted
records. Stable AgentIdentity values remain inside the authenticated handshake.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs

from .protocol import AgentIdentity, canonical, b64, unb64, _sign


def opaque_handle(identity: AgentIdentity, *, audience: str = "pqc-a2a", epoch: int | None = None) -> str:
    """Return a rotating, non-reversible identifier for discovery/routing."""
    epoch = int(time.time() // 3600) if epoch is None else epoch
    raw = canonical({"audience": audience, "epoch": epoch, "agent": identity.public_record()})
    return b64(hashlib.sha3_256(raw).digest()[:18])


def _derive(shared: bytes, transcript: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"pqc-a2a/session/1/" + hashlib.sha3_256(transcript).digest()).derive(shared)


@dataclass(frozen=True)
class SessionHello:
    handle: str
    session_id: str
    ephemeral_x25519: str
    issued_at: int
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"format": "pqc-a2a-session-hello/1", "handle": self.handle, "session_id": self.session_id, "ephemeral_x25519": self.ephemeral_x25519, "issued_at": self.issued_at, "signature": self.signature}


@dataclass(frozen=True)
class SecureRecord:
    handle: str
    session_id: str
    sequence: int
    ciphertext: str
    nonce: str
    padding_bucket: int

    def to_dict(self) -> dict[str, Any]:
        return {"format": "pqc-a2a-secure-record/1", "handle": self.handle, "session_id": self.session_id, "sequence": self.sequence, "ciphertext": self.ciphertext, "nonce": self.nonce, "padding_bucket": self.padding_bucket}


class ReplayWindow:
    def __init__(self, *, window: int = 128):
        if window < 1: raise ValueError("replay window must be positive")
        self.window, self.highest, self._seen = window, -1, set()

    def accept(self, sequence: int) -> bool:
        if not isinstance(sequence, int) or sequence < 0: return False
        if sequence <= self.highest - self.window: return False
        if sequence in self._seen: return False
        self._seen.add(sequence)
        if sequence > self.highest: self.highest = sequence
        self._seen = {item for item in self._seen if item > self.highest - self.window}
        return True


class SessionInitiator:
    def __init__(self, identity: AgentIdentity, peer: AgentIdentity, *, handle_epoch: int | None = None, replay_window: int = 128):
        self.identity, self.peer = identity, peer
        self.handle = opaque_handle(identity, epoch=handle_epoch)
        self.peer_handle = opaque_handle(peer, epoch=handle_epoch)
        self.session_id = str(uuid.uuid4())
        self._ephemeral = X25519PrivateKey.generate()
        self._key: bytes | None = None
        self._hello: dict[str, Any] | None = None
        self.send_sequence = 0
        self.receive_window = ReplayWindow(window=replay_window)

    def hello(self, *, issued_at: int | None = None) -> dict[str, Any]:
        issued_at = int(time.time()) if issued_at is None else issued_at
        public = self._ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        body = {"format": "pqc-a2a-session-hello/1", "handle": self.handle, "session_id": self.session_id, "ephemeral_x25519": b64(public), "issued_at": issued_at, "peer_handle": self.peer_handle}
        self._hello = body
        return {**body, "signature": b64(_sign(self.identity, canonical(body)))}

    def accept_ack(self, ack: dict[str, Any]) -> None:
        if ack.get("session_id") != self.session_id or ack.get("peer_handle") != self.handle: raise ValueError("session acknowledgement binding failed")
        self._verify_peer(ack, self.peer)
        peer_ephemeral = X25519PublicKey.from_public_bytes(unb64(ack["ephemeral_x25519"]))
        if self._hello is None: raise ValueError("session hello was not sent")
        self._key = _derive(self._ephemeral.exchange(peer_ephemeral), canonical({"hello": self._hello, "ack": {k: v for k, v in ack.items() if k != "signature"}}))

    def _verify_peer(self, value: dict[str, Any], identity: AgentIdentity) -> None:
        unsigned = {k: v for k, v in value.items() if k != "signature"}
        with oqs.Signature(identity.sig_name) as verifier:
            if not verifier.verify(canonical(unsigned), unb64(value.get("signature", "")), identity.sig_public): raise ValueError("session signature verification failed")

    def encrypt(self, payload: dict[str, Any], *, padding_bucket: int = 0) -> dict[str, Any]:
        if self._key is None: raise ValueError("session is not established")
        if padding_bucket < 0 or padding_bucket > 1 << 20: raise ValueError("invalid padding bucket")
        raw_payload = canonical(payload)
        padding = b64(secrets.token_bytes(max(0, padding_bucket - len(raw_payload)))) if padding_bucket > len(raw_payload) else ""
        raw = canonical({"payload": payload, "padding": padding})
        sequence = self.send_sequence; self.send_sequence += 1
        aad = canonical({"session_id": self.session_id, "handle": self.peer_handle, "sequence": sequence, "padding_bucket": padding_bucket})
        nonce = secrets.token_bytes(12)
        return SecureRecord(self.peer_handle, self.session_id, sequence, b64(AESGCM(self._key).encrypt(nonce, raw, aad)), b64(nonce), padding_bucket).to_dict()

    def decrypt(self, record: dict[str, Any]) -> dict[str, Any]:
        if self._key is None: raise ValueError("session is not established")
        if record.get("session_id") != self.session_id or record.get("handle") != self.handle or not self.receive_window.accept(record.get("sequence")): raise ValueError("invalid or replayed session record")
        aad = canonical({"session_id": self.session_id, "handle": self.handle, "sequence": record["sequence"], "padding_bucket": record["padding_bucket"]})
        plaintext = AESGCM(self._key).decrypt(unb64(record["nonce"]), unb64(record["ciphertext"]), aad)
        decoded = __import__("json").loads(plaintext)
        if not isinstance(decoded, dict) or not isinstance(decoded.get("payload"), dict): raise ValueError("malformed secure session payload")
        return decoded["payload"]

    def respond(self, hello: dict[str, Any], *, issued_at: int | None = None) -> dict[str, Any]:
        if hello.get("peer_handle") != self.handle: raise ValueError("session hello handle mismatch")
        unsigned = {k: v for k, v in hello.items() if k != "signature"}
        with oqs.Signature(self.peer.sig_name) as verifier:
            if not verifier.verify(canonical(unsigned), unb64(hello.get("signature", "")), self.peer.sig_public): raise ValueError("session hello signature failed")
        self.session_id = hello["session_id"]
        self._ephemeral = X25519PrivateKey.generate()
        peer_public = X25519PublicKey.from_public_bytes(unb64(hello["ephemeral_x25519"]))
        issued_at = int(time.time()) if issued_at is None else issued_at
        body = {"format": "pqc-a2a-session-ack/1", "session_id": self.session_id, "peer_handle": hello["handle"], "handle": self.handle, "ephemeral_x25519": b64(self._ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "issued_at": issued_at}
        self._key = _derive(self._ephemeral.exchange(peer_public), canonical({"hello": {k: v for k, v in hello.items() if k != "signature"}, "ack": body}))
        return {**body, "signature": b64(_sign(self.identity, canonical(body)))}


__all__ = ["opaque_handle", "SessionHello", "SecureRecord", "ReplayWindow", "SessionInitiator"]
