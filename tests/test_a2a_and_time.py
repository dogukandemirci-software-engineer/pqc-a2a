import pytest

from pqc_a2a import (
    AgentCard,
    AgentIdentity,
    ReplayCache,
    agent_card_document,
    make_jsonrpc_request,
    make_jsonrpc_result,
    open_envelope,
    seal,
    validate_jsonrpc_request,
    verify_agent_card,
)


def test_message_validity_window_is_signed_and_enforced():
    sender, receiver = AgentIdentity("sender"), AgentIdentity("receiver")
    envelope = seal(sender, receiver, {"ok": True}, issued_at=1000, ttl_seconds=10)
    assert open_envelope(receiver, sender, envelope, ReplayCache(), now=1005) == {"ok": True}
    with pytest.raises(ValueError, match="expired"):
        open_envelope(receiver, sender, envelope, ReplayCache(), now=1011, clock_skew=0)
    envelope["expires_at"] = 9999
    with pytest.raises(ValueError):
        open_envelope(receiver, sender, envelope, ReplayCache(), now=1005)


def test_agent_card_and_jsonrpc_adapter():
    identity = AgentIdentity("agent")
    signed = agent_card_document(AgentCard("agent"), identity, url="https://agent.example/a2a")
    assert verify_agent_card(signed, identity).agent_id == "agent"
    request = make_jsonrpc_request("tasks/send", {"message": {"role": "user"}}, request_id="r1")
    assert validate_jsonrpc_request(request, allowed_methods={"tasks/send"}) == request
    assert make_jsonrpc_result("r1", {"status": "working"})["jsonrpc"] == "2.0"
    signed["card"]["name"] = "attacker"
    with pytest.raises(ValueError):
        verify_agent_card(signed, identity)
