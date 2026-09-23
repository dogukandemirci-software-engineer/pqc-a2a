"""Hybrid PQC A2A messaging primitives.

This module is a research prototype. It uses liboqs for ML-KEM/ML-DSA and
cryptography for X25519, HKDF and AES-GCM. Protocol state is advanced only
after authentication and decryption succeed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode("ascii").rstrip("=")


def unb64(x: str) -> bytes:
    if not isinstance(x, str):
        raise ValueError("base64 field must be a string")
    try:
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except Exception as exc:
        raise ValueError("invalid base64 field") from exc


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding; non-standard NaN/Infinity are forbidden."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("object is not canonical JSON") from exc


def _hkdf(secret: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=None, info=info).derive(secret)


def _derive_secret(pqc_secret: bytes, classical_secret: bytes, context: bytes) -> bytes:
    # Length-prefixing prevents ambiguity if an implementation ever changes
    # one of the component secret lengths.
    ikm = len(pqc_secret).to_bytes(2, "big") + pqc_secret + len(classical_secret).to_bytes(2, "big") + classical_secret
    return _hkdf(ikm, b"pqc-a2a/v1/hybrid/" + context)


@dataclass
class AgentIdentity:
    agent_id: str
    kem_name: str = "ML-KEM-768"
    sig_name: str = "ML-DSA-65"
    kem_public: bytes = field(init=False)
    kem_secret: bytes = field(init=False, repr=False)
    sig_public: bytes = field(init=False)
    sig_secret: bytes = field(init=False, repr=False)
    x_private: X25519PrivateKey = field(init=False, repr=False)
    x_public: bytes = field(init=False)

    def __post_init__(self) -> None:
        if not self.agent_id or not isinstance(self.agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            self.kem_public = kem.generate_keypair()
            self.kem_secret = kem.export_secret_key()
        with oqs.Signature(self.sig_name) as sig:
            self.sig_public = sig.generate_keypair()
            self.sig_secret = sig.export_secret_key()
        self.x_private = X25519PrivateKey.generate()
        self.x_public = self.x_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public_record(self) -> dict[str, str]:
        return {"agent_id": self.agent_id, "kem_name": self.kem_name, "sig_name": self.sig_name, "kem_public": b64(self.kem_public), "sig_public": b64(self.sig_public), "x_public": b64(self.x_public)}

    def _record(self) -> dict[str, str]:
        raw_x = self.x_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return {**self.public_record(), "kem_secret": b64(self.kem_secret), "sig_secret": b64(self.sig_secret), "x_private": b64(raw_x)}

    def save(self, path: str | os.PathLike[str], password: str) -> None:
        """Save private material encrypted with scrypt and AES-256-GCM."""
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("identity password must contain at least 12 characters")
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
        public = self.public_record()
        ciphertext = AESGCM(key).encrypt(nonce, canonical(self._record()), canonical(public))
        envelope = {"format": "pqc-a2a-identity/1", "public": public, "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        target = Path(path)
        target.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: str | os.PathLike[str], password: str) -> "AgentIdentity":
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("identity password must contain at least 12 characters")
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        if envelope.get("format") != "pqc-a2a-identity/1":
            raise ValueError("unsupported identity format")
        key = Scrypt(salt=unb64(envelope["salt"]), length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
        try:
            record = json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), canonical(envelope["public"])))
        except InvalidTag as exc:
            raise ValueError("identity password or ciphertext is invalid") from exc
        obj = object.__new__(cls)
        obj.agent_id, obj.kem_name, obj.sig_name = record["agent_id"], record["kem_name"], record["sig_name"]
        obj.kem_public, obj.kem_secret = unb64(record["kem_public"]), unb64(record["kem_secret"])
        obj.sig_public, obj.sig_secret = unb64(record["sig_public"]), unb64(record["sig_secret"])
        obj.x_private = X25519PrivateKey.from_private_bytes(unb64(record["x_private"]))
        obj.x_public = obj.x_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if obj.public_record() != envelope["public"]:
            raise ValueError("identity public/private key mismatch")
        return obj


@dataclass(frozen=True)
class AgentCard:
    """Capability card. In a deployment it must itself be authenticated."""
    agent_id: str
    kem_profiles: tuple[str, ...] = ("ML-KEM-768",)
    signature_profiles: tuple[str, ...] = ("ML-DSA-65", "SLH_DSA_PURE_SHA2_128S")
    alpn_protocols: tuple[str, ...] = ("pqc-a2a/1",)
    max_fragment_size: int = 1200
    version: str = "1.0"

    def __post_init__(self) -> None:
        if self.max_fragment_size < 64:
            raise ValueError("max_fragment_size is too small")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.agent_id, "version": self.version, "capabilities": {"kem": list(self.kem_profiles), "signatures": list(self.signature_profiles), "alpn": list(self.alpn_protocols), "max_fragment_size": self.max_fragment_size}}

    def negotiate(self, remote: "AgentCard") -> dict[str, Any]:
        kem = next((x for x in self.kem_profiles if x in remote.kem_profiles), None)
        sig = next((x for x in self.signature_profiles if x in remote.signature_profiles), None)
        alpn = next((x for x in self.alpn_protocols if x in remote.alpn_protocols), None)
        if not (kem and sig and alpn):
            raise ValueError("no compatible crypto profile")
        return {"kem": kem, "signature": sig, "alpn": alpn, "fragment_size": min(self.max_fragment_size, remote.max_fragment_size)}

    def sign(self, identity: AgentIdentity) -> dict[str, Any]:
        if identity.agent_id != self.agent_id:
            raise ValueError("card and signing identity do not match")
        card = self.to_dict()
        public = identity.public_record()
        signed_body = {"card": card, "issuer": identity.agent_id, "public": public}
        return {"format": "pqc-a2a-card/1", **signed_body, "signature": b64(_sign(identity, canonical(signed_body)))}

    @staticmethod
    def verify_signed(signed: dict[str, Any], trusted_identity: AgentIdentity) -> "AgentCard":
        if signed.get("format") != "pqc-a2a-card/1" or signed.get("issuer") != trusted_identity.agent_id:
            raise ValueError("untrusted capability card")
        card = signed.get("card")
        if signed.get("public") != trusted_identity.public_record():
            raise ValueError("capability card public-key binding failed")
        signed_body = {"card": card, "issuer": signed["issuer"], "public": signed["public"]}
        with oqs.Signature(trusted_identity.sig_name) as sig:
            if not sig.verify(canonical(signed_body), unb64(signed["signature"]), trusted_identity.sig_public):
                raise ValueError("capability card signature verification failed")
        capabilities = card.get("capabilities", {})
        return AgentCard(card["name"], tuple(capabilities["kem"]), tuple(capabilities["signatures"]), tuple(capabilities["alpn"]), int(capabilities["max_fragment_size"]), card["version"])


class ReplayCache:
    def __init__(self, ttl_seconds: float = 300.0):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds, self._seen, self._lock = ttl_seconds, {}, threading.Lock()

    def accept(self, message_id: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if now - t <= self.ttl_seconds}
            if message_id in self._seen:
                return False
            self._seen[message_id] = now
            return True


def _sign(identity: AgentIdentity, data: bytes) -> bytes:
    with oqs.Signature(identity.sig_name, secret_key=identity.sig_secret) as sig:
        return sig.sign(data)


def _check_envelope(envelope: dict[str, Any], required: set[str], version: int) -> None:
    if not isinstance(envelope, dict) or not required.issubset(envelope):
        raise ValueError("malformed envelope")
    if envelope.get("version") != version:
        raise ValueError("unsupported envelope version")
    for name in ("message_id", "sender", "recipient", "kem", "sig"):
        if not isinstance(envelope.get(name), str) or not envelope[name]:
            raise ValueError("invalid envelope identity field")


def seal(sender: AgentIdentity, recipient: AgentIdentity, payload: dict[str, Any], *, conversation_id: str | None = None) -> dict[str, Any]:
    message_id, conversation_id = str(uuid.uuid4()), conversation_id or str(uuid.uuid4())
    aad_obj = {"version": 1, "message_id": message_id, "conversation_id": conversation_id, "sender": sender.agent_id, "recipient": recipient.agent_id, "kem": sender.kem_name, "sig": sender.sig_name}
    with oqs.KeyEncapsulation(recipient.kem_name) as kem:
        kem_ct, pqc_secret = kem.encap_secret(recipient.kem_public)
    x_eph = X25519PrivateKey.generate()
    classical_secret = x_eph.exchange(X25519PublicKey.from_public_bytes(recipient.x_public))
    key = _derive_secret(pqc_secret, classical_secret, conversation_id.encode())
    unsigned = {**aad_obj, "ephemeral_x25519": b64(x_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "kem_ciphertext": b64(kem_ct), "nonce": b64(secrets.token_bytes(12))}
    unsigned["ciphertext"] = b64(AESGCM(key).encrypt(unb64(unsigned["nonce"]), canonical(payload), canonical(aad_obj)))
    unsigned["signature"] = b64(_sign(sender, canonical(unsigned)))
    return unsigned


def open_envelope(recipient: AgentIdentity, sender: AgentIdentity, envelope: dict[str, Any], replay: ReplayCache | None = None) -> dict[str, Any]:
    required = {"version", "message_id", "conversation_id", "sender", "recipient", "kem", "sig", "ephemeral_x25519", "kem_ciphertext", "nonce", "ciphertext", "signature"}
    _check_envelope(envelope, required, 1)
    if envelope["recipient"] != recipient.agent_id or envelope["sender"] != sender.agent_id:
        raise ValueError("identity binding failed")
    if envelope["kem"] != recipient.kem_name or envelope["sig"] != sender.sig_name:
        raise ValueError("algorithm binding failed")
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    with oqs.Signature(sender.sig_name) as sig:
        if not sig.verify(canonical(unsigned), unb64(envelope["signature"]), sender.sig_public):
            raise ValueError("signature verification failed")
    with oqs.KeyEncapsulation(recipient.kem_name, secret_key=recipient.kem_secret) as kem:
        pqc_secret = kem.decap_secret(unb64(envelope["kem_ciphertext"]))
    classical_secret = recipient.x_private.exchange(X25519PublicKey.from_public_bytes(unb64(envelope["ephemeral_x25519"])))
    key = _derive_secret(pqc_secret, classical_secret, envelope["conversation_id"].encode())
    aad = canonical({k: envelope[k] for k in ("version", "message_id", "conversation_id", "sender", "recipient", "kem", "sig")})
    payload = json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad))
    if replay is not None and not replay.accept(envelope["message_id"]):
        raise ValueError("replay detected")
    return payload


@dataclass
class EphemeralKEMToken:
    token_id: str
    public_key: bytes
    secret_key: bytes = field(repr=False)
    owner_id: str | None = None


class AsyncKEMRatchet:
    def __init__(self, identity: AgentIdentity, peer: AgentIdentity, root_key: bytes, queue_size: int = 8):
        if queue_size < 0:
            raise ValueError("queue_size cannot be negative")
        self.identity, self.peer, self.chain_key, self.queue = identity, peer, root_key, []
        self.used: set[str] = set()
        self.refill(queue_size)

    def refill(self, count: int = 1) -> list[EphemeralKEMToken]:
        if count < 0:
            raise ValueError("count cannot be negative")
        for _ in range(count):
            with oqs.KeyEncapsulation(self.identity.kem_name) as kem:
                public = kem.generate_keypair(); secret = kem.export_secret_key()
            self.queue.append(EphemeralKEMToken(str(uuid.uuid4()), public, secret, self.identity.agent_id))
        return self.queue[-count:] if count else []

    def _next(self, extra: bytes) -> tuple[bytes, bytes]:
        next_chain = _hkdf(self.chain_key + extra, b"pqc-a2a/ratchet/chain")
        return next_chain, _hkdf(next_chain, b"pqc-a2a/ratchet/message")

    def seal(self, payload: dict[str, Any], token: EphemeralKEMToken) -> dict[str, Any]:
        if token.token_id in self.used or token.owner_id not in (None, self.peer.agent_id):
            raise ValueError("ephemeral token is not available to this peer")
        with oqs.KeyEncapsulation(self.peer.kem_name) as kem:
            ct, shared = kem.encap_secret(token.public_key)
        next_chain, key = self._next(shared)
        mid = str(uuid.uuid4())
        aad = {"version": 2, "message_id": mid, "ratchet": True, "token_id": token.token_id, "sender": self.identity.agent_id, "recipient": self.peer.agent_id, "kem": self.peer.kem_name, "sig": self.identity.sig_name}
        out = {**aad, "kem_ciphertext": b64(ct), "nonce": b64(secrets.token_bytes(12))}
        out["ciphertext"] = b64(AESGCM(key).encrypt(unb64(out["nonce"]), canonical(payload), canonical(aad)))
        out["signature"] = b64(_sign(self.identity, canonical(out)))
        self.chain_key, self.used = next_chain, self.used | {token.token_id}
        return out

    def open(self, envelope: dict[str, Any], replay: ReplayCache | None = None) -> dict[str, Any]:
        required = {"version", "message_id", "ratchet", "token_id", "sender", "recipient", "kem", "sig", "kem_ciphertext", "nonce", "ciphertext", "signature"}
        _check_envelope(envelope, required, 2)
        if envelope["sender"] != self.peer.agent_id or envelope["recipient"] != self.identity.agent_id or envelope["kem"] != self.identity.kem_name or envelope["sig"] != self.peer.sig_name or envelope["ratchet"] is not True:
            raise ValueError("ratchet identity or algorithm binding failed")
        token = next((x for x in self.queue if x.token_id == envelope["token_id"]), None)
        if token is None:
            raise ValueError("unknown or consumed ephemeral token")
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        with oqs.Signature(self.peer.sig_name) as sig:
            if not sig.verify(canonical(unsigned), unb64(envelope["signature"]), self.peer.sig_public):
                raise ValueError("signature verification failed")
        with oqs.KeyEncapsulation(self.identity.kem_name, secret_key=token.secret_key) as kem:
            shared = kem.decap_secret(unb64(envelope["kem_ciphertext"]))
        next_chain, key = self._next(shared)
        aad = canonical({k: envelope[k] for k in ("version", "message_id", "ratchet", "token_id", "sender", "recipient", "kem", "sig")})
        payload = json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad))
        if replay is not None and not replay.accept(envelope["message_id"]):
            raise ValueError("replay detected")
        self.chain_key = next_chain
        self.queue.remove(token)
        token.secret_key = b"\x00" * len(token.secret_key)
        return payload

    def save_state(self, path: str | os.PathLike[str], password: str) -> None:
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("ratchet password must contain at least 12 characters")
        record = {"format": "pqc-a2a-ratchet/1", "identity": self.identity.agent_id, "peer": self.peer.agent_id, "chain_key": b64(self.chain_key), "used": sorted(self.used), "queue": [{"token_id": t.token_id, "public_key": b64(t.public_key), "secret_key": b64(t.secret_key), "owner_id": t.owner_id} for t in self.queue]}
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
        ciphertext = AESGCM(key).encrypt(nonce, canonical(record), b"pqc-a2a-ratchet/1")
        Path(path).write_text(json.dumps({"format": "pqc-a2a-ratchet/1", "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        try:
            Path(path).chmod(0o600)
        except OSError:
            pass

    @classmethod
    def load_state(cls, identity: AgentIdentity, peer: AgentIdentity, path: str | os.PathLike[str], password: str) -> "AsyncKEMRatchet":
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("ratchet password must contain at least 12 characters")
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        if envelope.get("format") != "pqc-a2a-ratchet/1":
            raise ValueError("unsupported ratchet state format")
        key = Scrypt(salt=unb64(envelope["salt"]), length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
        try:
            record = json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), b"pqc-a2a-ratchet/1"))
        except InvalidTag as exc:
            raise ValueError("ratchet password or ciphertext is invalid") from exc
        if record["identity"] != identity.agent_id or record["peer"] != peer.agent_id:
            raise ValueError("ratchet identity binding failed")
        obj = cls.__new__(cls)
        obj.identity, obj.peer = identity, peer
        obj.chain_key, obj.used = unb64(record["chain_key"]), set(record["used"])
        obj.queue = [EphemeralKEMToken(t["token_id"], unb64(t["public_key"]), unb64(t["secret_key"]), t.get("owner_id")) for t in record["queue"]]
        return obj


def establish_ratchet(sender: AgentIdentity, recipient: AgentIdentity, queue_size: int = 8) -> tuple[AsyncKEMRatchet, AsyncKEMRatchet]:
    with oqs.KeyEncapsulation(recipient.kem_name) as kem:
        ct, pqc = kem.encap_secret(recipient.kem_public)
    with oqs.KeyEncapsulation(recipient.kem_name, secret_key=recipient.kem_secret) as kem:
        pqc2 = kem.decap_secret(ct)
    classical = sender.x_private.exchange(X25519PublicKey.from_public_bytes(recipient.x_public))
    root = _derive_secret(pqc, classical, b"ratchet-bootstrap")
    if not hmac.compare_digest(pqc, pqc2):
        raise ValueError("bootstrap KEM self-check failed")
    return AsyncKEMRatchet(sender, recipient, root, 0), AsyncKEMRatchet(recipient, sender, root, queue_size)


class ArchiveSigner:
    algorithm = "SLH_DSA_PURE_SHA2_128S"

    def __init__(self):
        with oqs.Signature(self.algorithm) as sig:
            self.public_key = sig.generate_keypair(); self.secret_key = sig.export_secret_key()

    def sign_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        data = canonical(manifest)
        with oqs.Signature(self.algorithm, secret_key=self.secret_key) as sig:
            signature = sig.sign(data)
        return {"manifest": manifest, "algorithm": self.algorithm, "signature": b64(signature), "digest": hashlib.sha3_256(data).hexdigest()}

    def verify(self, archive: dict[str, Any]) -> bool:
        try:
            if archive.get("algorithm") != self.algorithm:
                return False
            data = canonical(archive["manifest"])
            expected_digest = hashlib.sha3_256(data).hexdigest()
            if not hmac.compare_digest(archive.get("digest", ""), expected_digest):
                return False
            with oqs.Signature(self.algorithm) as sig:
                return bool(sig.verify(data, unb64(archive["signature"]), self.public_key))
        except (KeyError, TypeError, ValueError):
            return False


def tamper(envelope: dict[str, Any]) -> dict[str, Any]:
    x = dict(envelope); raw = bytearray(unb64(x["ciphertext"])); raw[0] ^= 1; x["ciphertext"] = b64(bytes(raw)); return x


def available_algorithms() -> dict[str, list[str]]:
    return {"kem": list(oqs.get_enabled_kem_mechanisms()), "signature": list(oqs.get_enabled_sig_mechanisms())}


__all__ = ["AgentIdentity", "AgentCard", "ReplayCache", "AsyncKEMRatchet", "EphemeralKEMToken", "establish_ratchet", "ArchiveSigner", "seal", "open_envelope", "tamper", "available_algorithms"]
