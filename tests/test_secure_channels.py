import asyncio
import time

import pytest

from pqc_a2a import (
    AgentIdentity, OpaqueRelay, ReplayWindow, Rendezvous, SessionInitiator,
    issue_capability, opaque_handle, padding_bucket, redact_metadata,
)


def test_session_handshake_hides_stable_ids_and_rejects_replay():
    a, b = AgentIdentity("agent-a-real"), AgentIdentity("agent-b-real")
    client, server = SessionInitiator(a, b, handle_epoch=7), SessionInitiator(b, a, handle_epoch=7)
    hello = client.hello(issued_at=int(time.time()))
    assert "agent-a-real" not in str(hello) and "agent-b-real" not in str(hello)
    ack = server.respond(hello, issued_at=int(time.time())); client.accept_ack(ack)
    record = client.encrypt({"task": "secret"}, padding_bucket=256)
    assert server.decrypt(record) == {"task": "secret"}
    with pytest.raises(ValueError, match="replayed"):
        server.decrypt(record)


def test_replay_window_allows_bounded_out_of_order():
    window = ReplayWindow(window=3)
    assert window.accept(2) and window.accept(0) and window.accept(1)
    assert not window.accept(0)
    assert not window.accept(-1)


def test_opaque_relay_and_rendezvous_capability():
    identity = AgentIdentity("real-agent")
    handle = opaque_handle(identity, epoch=0)
    assert "real-agent" not in handle
    register = issue_capability(identity, audience="rendezvous", scopes=("register", "lookup"), ttl_seconds=300, epoch=0)
    rendezvous = Rendezvous(replay_cache=__import__("pqc_a2a").DurableReplayCache(":memory:"))
    rendezvous.register(handle, "https://private.invalid", register, identity, now=100)
    assert rendezvous.lookup(handle, register, identity, now=100)["handle"] == handle
    relay = OpaqueRelay(max_queue_per_handle=1)
    record = {"format": "pqc-a2a-secure-record/2", "handle": handle, "session_id": "s", "sequence": 0}
    relay.forward(record); assert relay.receive(handle) == record


def test_p2_privacy_helpers():
    assert padding_bucket(200) == 256
    assert redact_metadata({"sender": "secret", "nested": {"ip": "10.0.0.1"}}) == {"sender": "[redacted]", "nested": {"ip": "[redacted]"}}
