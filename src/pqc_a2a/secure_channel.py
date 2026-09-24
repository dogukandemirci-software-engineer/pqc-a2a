"""Hybrid post-quantum end-to-end session channel with opaque handles."""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
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

SESSION_SUITE = "ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM"
MAX_SEQUENCE = (1 << 64) - 1
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024


def opaque_handle(identity: AgentIdentity, *, audience: str = "pqc-a2a", epoch: int | None = None) -> str:
    epoch = int(time.time() // 3600) if epoch is None else epoch
    raw = canonical({"audience": audience, "epoch": epoch, "agent": identity.public_record()})
    return b64(hashlib.sha3_256(raw).digest()[:18])


def _derive(shared: bytes, transcript: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"pqc-a2a/session/2/" + label + hashlib.sha3_256(transcript).digest()).derive(shared)


def _nonce(salt: bytes, sequence: int) -> bytes:
    if len(salt) != 4 or not 0 <= sequence <= MAX_SEQUENCE:
        raise ValueError("invalid session nonce input")
    return salt + sequence.to_bytes(8, "big")


@dataclass(frozen=True)
class SessionHello:
    handle: str
    session_id: str
    ephemeral_x25519: str
    kem_ciphertext: str
    nonce_salt: str
    issued_at: int
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"format": "pqc-a2a-session-hello/2", "handle": self.handle, "session_id": self.session_id, "ephemeral_x25519": self.ephemeral_x25519, "kem_ciphertext": self.kem_ciphertext, "nonce_salt": self.nonce_salt, "issued_at": self.issued_at, "signature": self.signature}


@dataclass(frozen=True)
class SecureRecord:
    handle: str
    session_id: str
    sequence: int
    ciphertext: str
    nonce: str
    padding_bucket: int

    def to_dict(self) -> dict[str, Any]:
        return {"format": "pqc-a2a-secure-record/2", "handle": self.handle, "session_id": self.session_id, "sequence": self.sequence, "ciphertext": self.ciphertext, "nonce": self.nonce, "padding_bucket": self.padding_bucket}


class ReplayWindow:
    def __init__(self, *, window: int = 128):
        if window < 1:
            raise ValueError("replay window must be positive")
        self.window, self.highest, self._seen = window, -1, set()

    def accept(self, sequence: int) -> bool:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= MAX_SEQUENCE:
            return False
        if sequence <= self.highest - self.window or sequence in self._seen:
            return False
        self._seen.add(sequence)
        if sequence > self.highest:
            self.highest = sequence
        self._seen = {item for item in self._seen if item > self.highest - self.window}
        return True

    def can_accept(self, sequence: int) -> bool:
        return isinstance(sequence, int) and not isinstance(sequence, bool) and 0 <= sequence <= MAX_SEQUENCE and sequence > self.highest - self.window and sequence not in self._seen


class SessionInitiator:
    """One authenticated hybrid session; each instance has one active generation."""

    def __init__(self, identity: AgentIdentity, peer: AgentIdentity, *, handle_epoch: int | None = None, replay_window: int = 128, clock_skew: int = 30, max_age_seconds: int = 300):
        if clock_skew < 0 or max_age_seconds < 1:
            raise ValueError("invalid session time policy")
        self.identity, self.peer = identity, peer
        self.handle = opaque_handle(identity, epoch=handle_epoch)
        self.peer_handle = opaque_handle(peer, epoch=handle_epoch)
        self.session_id = str(uuid.uuid4())
        self._ephemeral = X25519PrivateKey.generate()
        self._key: bytes | None = None
        self._send_key: bytes | None = None
        self._recv_key: bytes | None = None
        self._pqc_secret: bytes | None = None
        self._hello: dict[str, Any] | None = None
        self._nonce_salt = secrets.token_bytes(4)
        self.send_sequence = 0
        self.receive_window = ReplayWindow(window=replay_window)
        self.clock_skew, self.max_age_seconds = clock_skew, max_age_seconds
        self._accepted_hello_ids: set[str] = set()
        self._lock = threading.RLock()
        self._role = "initiator"

    def _fresh(self, timestamp: Any, now: int) -> bool:
        return isinstance(timestamp, int) and not isinstance(timestamp, bool) and abs(now - timestamp) <= self.max_age_seconds + self.clock_skew

    def _derive_directional(self, x_secret: bytes, pqc_secret: bytes, transcript: bytes) -> None:
        master = _derive(len(pqc_secret).to_bytes(2, "big") + pqc_secret + len(x_secret).to_bytes(2, "big") + x_secret, transcript, b"hybrid")
        self._key = master
        if self._role == "responder":
            self._send_key = _derive(master, transcript, b"r2i")
            self._recv_key = _derive(master, transcript, b"i2r")
        else:
            self._send_key = _derive(master, transcript, b"i2r")
            self._recv_key = _derive(master, transcript, b"r2i")

    def hello(self, *, issued_at: int | None = None) -> dict[str, Any]:
        with self._lock:
            issued_at = int(time.time()) if issued_at is None else issued_at
            if not isinstance(issued_at, int) or isinstance(issued_at, bool):
                raise ValueError("invalid hello timestamp")
            public = self._ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            with oqs.KeyEncapsulation(self.peer.kem_name) as kem:
                kem_ct, self._pqc_secret = kem.encap_secret(self.peer.kem_public)
            body = {"format": "pqc-a2a-session-hello/2", "suite": SESSION_SUITE, "handle": self.handle, "peer_handle": self.peer_handle, "session_id": self.session_id, "ephemeral_x25519": b64(public), "kem_ciphertext": b64(kem_ct), "nonce_salt": b64(self._nonce_salt), "issued_at": issued_at}
            self._hello = body
            return {**body, "signature": b64(_sign(self.identity, canonical(body)))}

    def accept_ack(self, ack: dict[str, Any], *, now: int | None = None) -> None:
        with self._lock:
            now = int(time.time()) if now is None else now
            if self._hello is None or ack.get("format") != "pqc-a2a-session-ack/2" or ack.get("suite") != SESSION_SUITE or ack.get("session_id") != self.session_id or ack.get("peer_handle") != self.handle or ack.get("handle") != self.peer_handle or ack.get("nonce_salt") != self._hello.get("nonce_salt"):
                raise ValueError("session acknowledgement binding failed")
            if not self._fresh(ack.get("issued_at"), now) or not self._fresh(self._hello.get("issued_at"), now):
                raise ValueError("session acknowledgement is stale")
            self._verify_peer(ack, self.peer)
            peer_ephemeral = X25519PublicKey.from_public_bytes(unb64(ack["ephemeral_x25519"]))
            transcript = canonical({"hello": self._hello, "ack": {k: v for k, v in ack.items() if k != "signature"}})
            self._derive_directional(self._ephemeral.exchange(peer_ephemeral), self._pqc_secret or b"", transcript)

    def _verify_peer(self, value: dict[str, Any], identity: AgentIdentity) -> None:
        unsigned = {k: v for k, v in value.items() if k != "signature"}
        with oqs.Signature(identity.sig_name) as verifier:
            if not verifier.verify(canonical(unsigned), unb64(value.get("signature", "")), identity.sig_public):
                raise ValueError("session signature verification failed")

    def encrypt(self, payload: dict[str, Any], *, padding_bucket: int = 0) -> dict[str, Any]:
        with self._lock:
            if self._send_key is None:
                raise ValueError("session is not established")
            if not isinstance(payload, dict) or len(canonical(payload)) > MAX_PAYLOAD_BYTES or padding_bucket < 0 or padding_bucket > 1 << 20:
                raise ValueError("invalid or oversized session payload")
            if self.send_sequence > MAX_SEQUENCE:
                raise ValueError("session sequence exhausted")
            raw_payload = canonical(payload)
            padding = b64(secrets.token_bytes(max(0, padding_bucket - len(raw_payload)))) if padding_bucket > len(raw_payload) else ""
            raw = canonical({"payload": payload, "padding": padding})
            sequence = self.send_sequence
            self.send_sequence += 1
            aad = canonical({"format": "pqc-a2a-secure-record/2", "suite": SESSION_SUITE, "direction": "i2r" if self._role == "initiator" else "r2i", "session_id": self.session_id, "handle": self.peer_handle, "sequence": sequence, "padding_bucket": padding_bucket})
            nonce = _nonce(self._nonce_salt, sequence)
            ciphertext = AESGCM(self._send_key).encrypt(nonce, raw, aad)
            record = SecureRecord(self.peer_handle, self.session_id, sequence, b64(ciphertext), b64(nonce), padding_bucket).to_dict()
            if len(canonical(record)) > MAX_RECORD_BYTES:
                raise ValueError("secure session record exceeds limit")
            return record

    def decrypt(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._recv_key is None or not isinstance(record, dict) or record.get("format") != "pqc-a2a-secure-record/2":
                raise ValueError("invalid session record")
            if len(canonical(record)) > MAX_RECORD_BYTES:
                raise ValueError("secure session record exceeds limit")
            sequence = record.get("sequence")
            if record.get("session_id") != self.session_id or record.get("handle") != self.handle or not self.receive_window.can_accept(sequence):
                raise ValueError("invalid or replayed session record")
            try:
                padding_bucket = record["padding_bucket"]
                if not isinstance(padding_bucket, int) or isinstance(padding_bucket, bool) or not 0 <= padding_bucket <= 1 << 20:
                    raise ValueError("invalid padding bucket")
                nonce = unb64(record["nonce"])
                if nonce != _nonce(self._nonce_salt, sequence):
                    raise ValueError("invalid session nonce")
                direction = "r2i" if self._role == "initiator" else "i2r"
                aad = canonical({"format": "pqc-a2a-secure-record/2", "suite": SESSION_SUITE, "direction": direction, "session_id": self.session_id, "handle": self.handle, "sequence": sequence, "padding_bucket": padding_bucket})
                plaintext = AESGCM(self._recv_key).decrypt(nonce, unb64(record["ciphertext"]), aad)
                if len(plaintext) > MAX_PAYLOAD_BYTES + (1 << 20):
                    raise ValueError("session plaintext exceeds limit")
                decoded = json.loads(plaintext)
            except Exception as exc:
                raise ValueError("secure session record authentication failed") from exc
            if not isinstance(decoded, dict) or not isinstance(decoded.get("payload"), dict) or not isinstance(decoded.get("padding"), str):
                raise ValueError("malformed secure session payload")
            if not self.receive_window.accept(sequence):
                raise ValueError("invalid or replayed session record")
            return decoded["payload"]

    def respond(self, hello: dict[str, Any], *, issued_at: int | None = None, now: int | None = None) -> dict[str, Any]:
        with self._lock:
            now = int(time.time()) if now is None else now
            if hello.get("format") != "pqc-a2a-session-hello/2" or hello.get("suite") != SESSION_SUITE or hello.get("peer_handle") != self.handle or hello.get("session_id") in self._accepted_hello_ids:
                raise ValueError("session hello binding or replay failed")
            if not self._fresh(hello.get("issued_at"), now):
                raise ValueError("session hello is stale")
            unsigned = {k: v for k, v in hello.items() if k != "signature"}
            with oqs.Signature(self.peer.sig_name) as verifier:
                if not verifier.verify(canonical(unsigned), unb64(hello.get("signature", "")), self.peer.sig_public):
                    raise ValueError("session hello signature failed")
            peer_public = X25519PublicKey.from_public_bytes(unb64(hello["ephemeral_x25519"]))
            with oqs.KeyEncapsulation(self.identity.kem_name, secret_key=self.identity.kem_secret) as kem:
                pqc_secret = kem.decap_secret(unb64(hello["kem_ciphertext"]))
            nonce_salt = unb64(hello["nonce_salt"])
            if len(nonce_salt) != 4:
                raise ValueError("invalid session nonce salt")
            candidate_ephemeral = X25519PrivateKey.generate()
            response_time = int(time.time()) if issued_at is None else issued_at
            if not self._fresh(response_time, now):
                raise ValueError("invalid session acknowledgement time")
            body = {"format": "pqc-a2a-session-ack/2", "suite": SESSION_SUITE, "session_id": hello["session_id"], "peer_handle": hello["handle"], "handle": self.handle, "ephemeral_x25519": b64(candidate_ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "nonce_salt": hello["nonce_salt"], "issued_at": response_time}
            transcript = canonical({"hello": unsigned, "ack": body})
            old_state = (self.session_id, self._ephemeral, self._key, self._send_key, self._recv_key, self._nonce_salt, self._role, self.receive_window)
            self.session_id, self._ephemeral, self._nonce_salt, self._role = hello["session_id"], candidate_ephemeral, nonce_salt, "responder"
            self._derive_directional(candidate_ephemeral.exchange(peer_public), pqc_secret, transcript)
            try:
                signed = {**body, "signature": b64(_sign(self.identity, canonical(body)))}
            except Exception:
                self.session_id, self._ephemeral, self._key, self._send_key, self._recv_key, self._nonce_salt, self._role, self.receive_window = old_state
                raise
            self.receive_window = ReplayWindow(window=old_state[-1].window)
            self.send_sequence = 0
            self._accepted_hello_ids.add(hello["session_id"])
            return signed


__all__ = ["SESSION_SUITE", "opaque_handle", "SessionHello", "SecureRecord", "ReplayWindow", "SessionInitiator"]
