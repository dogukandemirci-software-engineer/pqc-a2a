"""Authenticated, replay-resistant Agent Card discovery helpers."""
from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

from .a2a import agent_card_document, verify_agent_card
from .protocol import AgentCard, AgentIdentity, TrustStore, canonical, b64, unb64, _sign
import oqs


def make_discovery_record(card: AgentCard, identity: AgentIdentity, *, challenge: str, issued_at: int | None = None, ttl_seconds: int = 300, url: str | None = None) -> dict[str, Any]:
    if not challenge or ttl_seconds <= 0 or ttl_seconds > 3600: raise ValueError("invalid discovery parameters")
    issued_at = int(time.time()) if issued_at is None else int(issued_at)
    body = {"format": "pqc-a2a-discovery/1", "challenge": challenge, "issued_at": issued_at, "expires_at": issued_at + ttl_seconds, "agent_card": agent_card_document(card, identity, url=url)}
    return {**body, "signature": b64(_sign(identity, canonical(body)))}


def verify_discovery_record(record: dict[str, Any], *, trusted_identity: AgentIdentity, replay: Any, now: int | None = None, clock_skew: int = 30) -> AgentCard:
    if record.get("format") != "pqc-a2a-discovery/1": raise ValueError("unsupported discovery format")
    if not isinstance(record.get("challenge"), str) or not record["challenge"]: raise ValueError("invalid discovery challenge")
    if not isinstance(record.get("issued_at"), int) or not isinstance(record.get("expires_at"), int) or record["expires_at"] <= record["issued_at"]: raise ValueError("invalid discovery validity")
    now = int(time.time()) if now is None else int(now)
    if now < record["issued_at"] - clock_skew or now > record["expires_at"] + clock_skew: raise ValueError("discovery record expired")
    body = {k: record[k] for k in ("format", "challenge", "issued_at", "expires_at", "agent_card")}
    with oqs.Signature(trusted_identity.sig_name) as verifier:
        if not verifier.verify(canonical(body), unb64(record.get("signature", "")), trusted_identity.sig_public): raise ValueError("discovery signature verification failed")
    if not replay.accept(record["challenge"]): raise ValueError("discovery replay detected")
    return verify_agent_card(record["agent_card"], trusted_identity)


def provision_trust_store_from_discovery(record: dict[str, Any], *, anchor: AgentIdentity, store: TrustStore, replay: Any, now: int | None = None) -> str:
    """Provision only after an already trusted anchor authenticates discovery.

    This is not PKI: callers must establish the anchor out of band and retain
    the store as protected configuration.
    """
    card = verify_discovery_record(record, trusted_identity=anchor, replay=replay, now=now)
    public = record["agent_card"]["card"]["issuerPublicKey"]
    if public["agent_id"] != card.agent_id: raise ValueError("discovery identity mismatch")
    with store._lock:
        existing = store.trusted.get(card.agent_id)
        if existing is not None and existing != public: raise ValueError("discovery would replace an existing pin")
        store.trusted[card.agent_id] = public
    return hashlib.sha3_256(canonical(public)).hexdigest()


def new_challenge() -> str: return str(uuid.uuid4())


__all__ = ["make_discovery_record", "verify_discovery_record", "provision_trust_store_from_discovery", "new_challenge"]
