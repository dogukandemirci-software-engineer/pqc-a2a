"""Crypto-agile hybrid PQC A2A message exchange PoC.

This is a research replica of the paper's integration ideas, not a production
PKI or an implementation of the A2A transport specification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip("=")


def unb64(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class AgentIdentity:
    agent_id: str
    kem_name: str = "ML-KEM-768"
    sig_name: str = "ML-DSA-65"
    kem_public: bytes = field(init=False)
    kem_secret: bytes = field(init=False)
    sig_public: bytes = field(init=False)
    sig_secret: bytes = field(init=False)
    x_private: X25519PrivateKey = field(init=False, repr=False)
    x_public: bytes = field(init=False)

    def __post_init__(self) -> None:
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            self.kem_public = kem.generate_keypair()
            self.kem_secret = kem.export_secret_key()
        with oqs.Signature(self.sig_name) as sig:
            self.sig_public = sig.generate_keypair()
            self.sig_secret = sig.export_secret_key()
        self.x_private = X25519PrivateKey.generate()
        self.x_public = self.x_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.sig_name) as sig:
            return bool(sig.verify(message, signature, self.sig_public))


class ReplayCache:
    def __init__(self, ttl_seconds: float = 300.0):
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def accept(self, message_id: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        self._seen = {k: t for k, t in self._seen.items() if now - t <= self.ttl_seconds}
        if message_id in self._seen:
            return False
        self._seen[message_id] = now
        return True


def _derive_secret(pqc_secret: bytes, classical_secret: bytes, context: bytes) -> bytes:
    # Robust combiner: both components are required to derive the AEAD key.
    return HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"pqc-a2a/v1/" + context).derive(
        pqc_secret + classical_secret
    )


def seal(sender: AgentIdentity, recipient: AgentIdentity, payload: dict[str, Any], *, conversation_id: str | None = None) -> dict[str, Any]:
    """Create an authenticated-encrypted envelope for recipient."""
    message_id = str(uuid.uuid4())
    conversation_id = conversation_id or str(uuid.uuid4())
    aad_obj = {
        "version": 1, "message_id": message_id, "conversation_id": conversation_id,
        "sender": sender.agent_id, "recipient": recipient.agent_id,
        "kem": sender.kem_name, "sig": sender.sig_name,
    }
    aad = canonical(aad_obj)
    with oqs.KeyEncapsulation(recipient.kem_name) as kem:
        kem_ct, pqc_secret = kem.encap_secret(recipient.kem_public)
    x_eph = X25519PrivateKey.generate()
    classical_secret = x_eph.exchange(X25519PublicKey.from_public_bytes(recipient.x_public))
    key = _derive_secret(pqc_secret, classical_secret, conversation_id.encode())
    nonce = AESGCM.generate_key(bit_length=96) if False else __import__("secrets").token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, canonical(payload), aad)
    envelope = {**aad_obj, "ephemeral_x25519": b64(x_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                "kem_ciphertext": b64(kem_ct), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
    to_sign = canonical(envelope)
    with oqs.Signature(sender.sig_name, secret_key=sender.sig_secret) as sig:
        envelope["signature"] = b64(sig.sign(to_sign))
    return envelope


def open_envelope(recipient: AgentIdentity, sender: AgentIdentity, envelope: dict[str, Any], replay: ReplayCache | None = None) -> dict[str, Any]:
    required = {"message_id", "conversation_id", "sender", "recipient", "kem", "sig", "ephemeral_x25519", "kem_ciphertext", "nonce", "ciphertext", "signature"}
    if set(envelope) < required:
        raise ValueError("malformed envelope")
    if envelope["recipient"] != recipient.agent_id or envelope["sender"] != sender.agent_id:
        raise ValueError("identity binding failed")
    signature = unb64(envelope["signature"])
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    with oqs.Signature(sender.sig_name) as sig:
        if not sig.verify(canonical(unsigned), signature, sender.sig_public):
            raise ValueError("signature verification failed")
    if replay is not None and not replay.accept(envelope["message_id"]):
        raise ValueError("replay detected")
    with oqs.KeyEncapsulation(recipient.kem_name, secret_key=recipient.kem_secret) as kem:
        pqc_secret = kem.decap_secret(unb64(envelope["kem_ciphertext"]))
    classical_secret = recipient.x_private.exchange(X25519PublicKey.from_public_bytes(unb64(envelope["ephemeral_x25519"])))
    key = _derive_secret(pqc_secret, classical_secret, envelope["conversation_id"].encode())
    aad = canonical({k: envelope[k] for k in ("version", "message_id", "conversation_id", "sender", "recipient", "kem", "sig")})
    plaintext = AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad)
    return json.loads(plaintext)


def tamper(envelope: dict[str, Any]) -> dict[str, Any]:
    x = dict(envelope)
    raw = bytearray(unb64(x["ciphertext"])); raw[0] ^= 1; x["ciphertext"] = b64(bytes(raw))
    return x


def available_algorithms() -> dict[str, list[str]]:
    return {"kem": list(oqs.get_enabled_kem_mechanisms()), "signature": list(oqs.get_enabled_sig_mechanisms())}


__all__ = ["AgentIdentity", "ReplayCache", "seal", "open_envelope", "tamper", "available_algorithms"]
