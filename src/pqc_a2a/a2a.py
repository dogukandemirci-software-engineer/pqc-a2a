"""Small protocol adapter for A2A-style Agent Card and JSON-RPC messages.

This module deliberately stays transport-neutral: HTTP/QUIC servers can use the
same validation functions while choosing their own framework and discovery policy.
"""
from __future__ import annotations

from typing import Any

from .protocol import AgentCard, AgentIdentity, canonical, b64, unb64, _sign
import oqs


def agent_card_document(card: AgentCard, identity: AgentIdentity, *, url: str | None = None, skills: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return an A2A-compatible public Agent Card with a PQC signature."""
    if identity.agent_id != card.agent_id:
        raise ValueError("card and signing identity do not match")
    document = {
        "name": card.agent_id,
        "description": "PQC-A2A agent",
        "url": url,
        "version": card.version,
        "capabilities": card.to_dict()["capabilities"],
        "skills": skills or [],
        "securitySchemes": {"pqc_a2a": {"type": "apiKey", "in": "header", "name": "PQC-A2A-Signature"}},
        "issuer": identity.agent_id,
        "issuerPublicKey": identity.public_record(),
    }
    return {"format": "pqc-a2a-agent-card/1", "card": document, "signature": b64(_sign(identity, canonical(document)))}


def verify_agent_card(document: dict[str, Any], trusted_identity: AgentIdentity) -> AgentCard:
    """Verify an Agent Card before capability negotiation or task dispatch."""
    if document.get("format") != "pqc-a2a-agent-card/1":
        raise ValueError("unsupported Agent Card format")
    card = document.get("card")
    if not isinstance(card, dict) or card.get("issuer") != trusted_identity.agent_id or card.get("issuerPublicKey") != trusted_identity.public_record():
        raise ValueError("Agent Card issuer binding failed")
    with oqs.Signature(trusted_identity.sig_name) as verifier:
        if not verifier.verify(canonical(card), unb64(document.get("signature", "")), trusted_identity.sig_public):
            raise ValueError("Agent Card signature verification failed")
    capabilities = card.get("capabilities", {})
    return AgentCard(card["name"], tuple(capabilities["kem"]), tuple(capabilities["signatures"]), tuple(capabilities["alpn"]), int(capabilities["max_fragment_size"]), card["version"])


def make_jsonrpc_request(method: str, params: dict[str, Any], request_id: str | int = 1) -> dict[str, Any]:
    if not method or not isinstance(params, dict):
        raise ValueError("JSON-RPC method and object params are required")
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def validate_jsonrpc_request(request: dict[str, Any], *, allowed_methods: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or "id" not in request or not isinstance(request.get("method"), str) or not isinstance(request.get("params"), dict):
        raise ValueError("invalid JSON-RPC 2.0 request")
    if allowed_methods is not None and request["method"] not in allowed_methods:
        raise ValueError("unsupported JSON-RPC method")
    return request


def make_jsonrpc_result(request_id: str | int, result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ValueError("JSON-RPC result must be an object")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


__all__ = ["agent_card_document", "verify_agent_card", "make_jsonrpc_request", "validate_jsonrpc_request", "make_jsonrpc_result"]
