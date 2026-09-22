"""Crypto-agile hybrid PQC A2A message exchange and asynchronous ratchet PoC."""
from __future__ import annotations

import base64, hashlib, json, secrets, time, uuid
from dataclasses import dataclass, field
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64(x: bytes) -> str: return base64.urlsafe_b64encode(x).decode().rstrip("=")
def unb64(x: str) -> bytes: return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def canonical(obj: Any) -> bytes: return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _hkdf(secret: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=None, info=info).derive(secret)


def _derive_secret(pqc_secret: bytes, classical_secret: bytes, context: bytes) -> bytes:
    return _hkdf(pqc_secret + classical_secret, b"pqc-a2a/v1/" + context)


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
            self.kem_public = kem.generate_keypair(); self.kem_secret = kem.export_secret_key()
        with oqs.Signature(self.sig_name) as sig:
            self.sig_public = sig.generate_keypair(); self.sig_secret = sig.export_secret_key()
        self.x_private = X25519PrivateKey.generate()
        self.x_public = self.x_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class AgentCard:
    """A signed-discovery-compatible capability card for crypto-profile negotiation."""
    agent_id: str
    kem_profiles: tuple[str, ...] = ("ML-KEM-768",)
    signature_profiles: tuple[str, ...] = ("ML-DSA-65", "SLH_DSA_PURE_SHA2_128S")
    alpn_protocols: tuple[str, ...] = ("pqc-a2a/1",)
    max_fragment_size: int = 1200
    version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.agent_id, "version": self.version, "capabilities": {"kem": list(self.kem_profiles), "signatures": list(self.signature_profiles), "alpn": list(self.alpn_protocols), "max_fragment_size": self.max_fragment_size}}

    def negotiate(self, remote: "AgentCard") -> dict[str, Any]:
        kem = next((x for x in self.kem_profiles if x in remote.kem_profiles), None)
        sig = next((x for x in self.signature_profiles if x in remote.signature_profiles), None)
        alpn = next((x for x in self.alpn_protocols if x in remote.alpn_protocols), None)
        if not (kem and sig and alpn): raise ValueError("no compatible crypto profile")
        return {"kem": kem, "signature": sig, "alpn": alpn, "fragment_size": min(self.max_fragment_size, remote.max_fragment_size)}


class ReplayCache:
    def __init__(self, ttl_seconds: float = 300.0): self.ttl_seconds, self._seen = ttl_seconds, {}
    def accept(self, message_id: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        self._seen = {k: t for k, t in self._seen.items() if now - t <= self.ttl_seconds}
        if message_id in self._seen: return False
        self._seen[message_id] = now; return True


def _sign(identity: AgentIdentity, data: bytes, algorithm: str | None = None) -> bytes:
    algorithm = algorithm or identity.sig_name
    with oqs.Signature(algorithm, secret_key=identity.sig_secret if algorithm == identity.sig_name else None) as sig:
        return sig.sign(data)


def seal(sender: AgentIdentity, recipient: AgentIdentity, payload: dict[str, Any], *, conversation_id: str | None = None) -> dict[str, Any]:
    message_id, conversation_id = str(uuid.uuid4()), conversation_id or str(uuid.uuid4())
    aad_obj = {"version": 1, "message_id": message_id, "conversation_id": conversation_id, "sender": sender.agent_id, "recipient": recipient.agent_id, "kem": sender.kem_name, "sig": sender.sig_name}
    with oqs.KeyEncapsulation(recipient.kem_name) as kem: kem_ct, pqc_secret = kem.encap_secret(recipient.kem_public)
    x_eph = X25519PrivateKey.generate(); classical_secret = x_eph.exchange(X25519PublicKey.from_public_bytes(recipient.x_public))
    key = _derive_secret(pqc_secret, classical_secret, conversation_id.encode())
    unsigned = {**aad_obj, "ephemeral_x25519": b64(x_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "kem_ciphertext": b64(kem_ct), "nonce": b64(secrets.token_bytes(12))}
    unsigned["ciphertext"] = b64(AESGCM(key).encrypt(unb64(unsigned["nonce"]), canonical(payload), canonical(aad_obj)))
    unsigned["signature"] = b64(_sign(sender, canonical(unsigned)))
    return unsigned


def open_envelope(recipient: AgentIdentity, sender: AgentIdentity, envelope: dict[str, Any], replay: ReplayCache | None = None) -> dict[str, Any]:
    required = {"message_id", "conversation_id", "sender", "recipient", "kem", "sig", "ephemeral_x25519", "kem_ciphertext", "nonce", "ciphertext", "signature"}
    if set(envelope) < required: raise ValueError("malformed envelope")
    if envelope["recipient"] != recipient.agent_id or envelope["sender"] != sender.agent_id: raise ValueError("identity binding failed")
    signature = unb64(envelope["signature"]); unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    with oqs.Signature(sender.sig_name) as sig:
        if not sig.verify(canonical(unsigned), signature, sender.sig_public): raise ValueError("signature verification failed")
    if replay is not None and not replay.accept(envelope["message_id"]): raise ValueError("replay detected")
    with oqs.KeyEncapsulation(recipient.kem_name, secret_key=recipient.kem_secret) as kem: pqc_secret = kem.decap_secret(unb64(envelope["kem_ciphertext"]))
    classical_secret = recipient.x_private.exchange(X25519PublicKey.from_public_bytes(unb64(envelope["ephemeral_x25519"])))
    key = _derive_secret(pqc_secret, classical_secret, envelope["conversation_id"].encode())
    aad = canonical({k: envelope[k] for k in ("version", "message_id", "conversation_id", "sender", "recipient", "kem", "sig")})
    return json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad))


@dataclass
class EphemeralKEMToken:
    token_id: str
    public_key: bytes
    secret_key: bytes = field(repr=False)


class AsyncKEMRatchet:
    """Asynchronous one-time KEM queue plus symmetric chain-key ratchet.

    The receiver precomputes one-time ML-KEM keypairs. The sender consumes a
    public token per message. After opening, the receiver deletes that token;
    the chain key also advances, providing per-message key separation.
    """
    def __init__(self, identity: AgentIdentity, peer: AgentIdentity, root_key: bytes, queue_size: int = 8):
        self.identity, self.peer, self.chain_key, self.queue = identity, peer, root_key, []
        self.used: set[str] = set(); self.refill(queue_size)

    def refill(self, count: int = 1) -> list[EphemeralKEMToken]:
        for _ in range(count):
            with oqs.KeyEncapsulation(self.identity.kem_name) as kem:
                public = kem.generate_keypair(); secret = kem.export_secret_key()
            self.queue.append(EphemeralKEMToken(str(uuid.uuid4()), public, secret))
        return self.queue[-count:]

    def _step(self, extra: bytes) -> bytes:
        self.chain_key = _hkdf(self.chain_key + extra, b"pqc-a2a/ratchet/chain")
        return _hkdf(self.chain_key, b"pqc-a2a/ratchet/message")

    def seal(self, payload: dict[str, Any], token: EphemeralKEMToken) -> dict[str, Any]:
        if token.token_id in self.used: raise ValueError("ephemeral token already used")
        with oqs.KeyEncapsulation(self.peer.kem_name) as kem: ct, shared = kem.encap_secret(token.public_key)
        key = self._step(shared); mid = str(uuid.uuid4()); aad = {"version": 2, "message_id": mid, "ratchet": True, "token_id": token.token_id, "sender": self.identity.agent_id, "recipient": self.peer.agent_id, "kem": self.peer.kem_name}
        out = {**aad, "kem_ciphertext": b64(ct), "nonce": b64(secrets.token_bytes(12))}
        out["ciphertext"] = b64(AESGCM(key).encrypt(unb64(out["nonce"]), canonical(payload), canonical(aad)))
        out["signature"] = b64(_sign(self.identity, canonical(out))); self.used.add(token.token_id)
        return out

    def open(self, envelope: dict[str, Any], replay: ReplayCache | None = None) -> dict[str, Any]:
        tid = envelope["token_id"]
        token = next((x for x in self.queue if x.token_id == tid), None)
        if token is None: raise ValueError("unknown or consumed ephemeral token")
        if not replay or replay.accept(envelope["message_id"]):
            with oqs.KeyEncapsulation(self.identity.kem_name, secret_key=token.secret_key) as kem: shared = kem.decap_secret(unb64(envelope["kem_ciphertext"]))
            key = self._step(shared); aad = {k: envelope[k] for k in ("version", "message_id", "ratchet", "token_id", "sender", "recipient", "kem")}
            with oqs.Signature(self.peer.sig_name) as sig:
                unsigned = {k: v for k, v in envelope.items() if k != "signature"}
                if not sig.verify(canonical(unsigned), unb64(envelope["signature"]), self.peer.sig_public): raise ValueError("signature verification failed")
            self.queue.remove(token); token.secret_key = b"\x00" * len(token.secret_key)
            return json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), canonical(aad)))
        raise ValueError("replay detected")


def establish_ratchet(sender: AgentIdentity, recipient: AgentIdentity, queue_size: int = 8) -> tuple[AsyncKEMRatchet, AsyncKEMRatchet]:
    with oqs.KeyEncapsulation(recipient.kem_name) as kem: ct, pqc = kem.encap_secret(recipient.kem_public)
    with oqs.KeyEncapsulation(recipient.kem_name, secret_key=recipient.kem_secret) as kem: pqc2 = kem.decap_secret(ct)
    classical = sender.x_private.exchange(X25519PublicKey.from_public_bytes(recipient.x_public))
    root = _derive_secret(pqc, classical, b"ratchet-bootstrap")
    assert pqc == pqc2
    return AsyncKEMRatchet(sender, recipient, root, 0), AsyncKEMRatchet(recipient, sender, root, queue_size)


class ArchiveSigner:
    """Long-lived, slower SLH-DSA-128s signer for archive manifests."""
    # liboqs 0.16 exposes the FIPS SLH-DSA-SHA2-128s parameter set as this
    # canonical mechanism identifier.
    algorithm = "SLH_DSA_PURE_SHA2_128S"
    def __init__(self):
        with oqs.Signature(self.algorithm) as sig: self.public_key = sig.generate_keypair(); self.secret_key = sig.export_secret_key()
    def sign_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        data = canonical(manifest)
        with oqs.Signature(self.algorithm, secret_key=self.secret_key) as sig: signature = sig.sign(data)
        return {"manifest": manifest, "algorithm": self.algorithm, "signature": b64(signature), "digest": hashlib.sha3_256(data).hexdigest()}
    def verify(self, archive: dict[str, Any]) -> bool:
        data = canonical(archive["manifest"])
        with oqs.Signature(self.algorithm) as sig: return bool(sig.verify(data, unb64(archive["signature"]), self.public_key))


def tamper(envelope: dict[str, Any]) -> dict[str, Any]:
    x = dict(envelope); raw = bytearray(unb64(x["ciphertext"])); raw[0] ^= 1; x["ciphertext"] = b64(bytes(raw)); return x

def available_algorithms() -> dict[str, list[str]]:
    return {"kem": list(oqs.get_enabled_kem_mechanisms()), "signature": list(oqs.get_enabled_sig_mechanisms())}

__all__ = ["AgentIdentity", "AgentCard", "ReplayCache", "AsyncKEMRatchet", "EphemeralKEMToken", "establish_ratchet", "ArchiveSigner", "seal", "open_envelope", "tamper", "available_algorithms"]
