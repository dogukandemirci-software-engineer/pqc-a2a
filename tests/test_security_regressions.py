import json
import ssl
import time

import pytest

from pqc_a2a import AgentIdentity, DurableReplayCache, ReplayCache, Rendezvous, TransportProfile, fragment, reassemble, open_envelope, seal


def test_failed_decryption_does_not_advance_ratchet_or_consume_token():
    a, b = AgentIdentity("a"), AgentIdentity("b")
    sender, receiver = __import__("pqc_a2a").establish_ratchet(a, b, queue_size=1)
    token = receiver.queue[0]
    env = sender.seal({"ok": True}, token)
    before = receiver.chain_key
    tampered = dict(env)
    tampered["ciphertext"] = tampered["ciphertext"][:-1] + ("A" if tampered["ciphertext"][-1] != "A" else "B")
    with pytest.raises(ValueError):
        receiver.open(tampered)
    assert receiver.chain_key == before
    assert receiver.queue[0].token_id == token.token_id
    assert receiver.open(env) == {"ok": True}


def test_failed_regular_decryption_does_not_poison_replay_cache():
    a, b = AgentIdentity("a"), AgentIdentity("b")
    env = seal(a, b, {"x": 1})
    cache = ReplayCache()
    tampered = dict(env)
    tampered["ciphertext"] = tampered["ciphertext"][:-1] + ("A" if tampered["ciphertext"][-1] != "A" else "B")
    with pytest.raises(ValueError):
        open_envelope(b, a, tampered, cache)
    assert open_envelope(b, a, env, cache) == {"x": 1}


def test_fragment_rejects_duplicate_and_out_of_range_indices():
    parts = fragment(b"payload" * 100, mtu=160, message_id="m")
    with pytest.raises(ValueError, match="duplicate|incomplete"):
        reassemble(parts[:-1] + [parts[0]])
    raw = bytearray(parts[0])
    header_end = raw.index(b"\n", raw.index(b"\n") + 1)
    header = json.loads(raw[len(b"PQA1\n"):header_end])
    header["i"] = header["n"]
    raw = b"PQA1\n" + json.dumps(header, sort_keys=True, separators=(",", ":")).encode() + raw[header_end:]
    with pytest.raises(ValueError, match="range"):
        reassemble([bytes(raw)] + parts[1:])


def test_fragment_handles_delimiter_bytes_and_mtu():
    payload = b"|\n\x00" * 1000
    parts = fragment(payload, mtu=180, message_id="safe|id")
    assert all(len(part) <= 180 for part in parts)
    assert reassemble(reversed(parts)) == payload


def test_archive_digest_and_algorithm_are_verified():
    from pqc_a2a import ArchiveSigner
    signer = ArchiveSigner()
    archive = signer.sign_manifest({"n": 1})
    archive["digest"] = "0" * 64
    assert not signer.verify(archive)
    archive = signer.sign_manifest({"n": 1})
    archive["algorithm"] = "ML-DSA-65"
    assert not signer.verify(archive)


def test_tls_client_does_not_default_to_insecure_peer_acceptance():
    with pytest.raises(ValueError, match="cafile"):
        TransportProfile().client_configuration()


def test_durable_memory_replay_cache_persists_between_operations():
    cache = DurableReplayCache(":memory:")
    assert cache.accept("first")
    assert not cache.accept("first")


def test_rendezvous_rejects_capability_for_different_handle():
    identity = AgentIdentity("rendezvous-owner")
    capability = __import__("pqc_a2a").issue_capability(identity, audience="rendezvous", scopes=("register",), ttl_seconds=300, epoch=0)
    rendezvous = Rendezvous(replay_cache=DurableReplayCache(":memory:"))
    with pytest.raises(ValueError, match="subject"):
        rendezvous.register("not-the-token-subject", "https://private.invalid", capability, identity, now=100)


def test_secure_channel_failed_authentication_does_not_advance_window():
    from pqc_a2a import SessionInitiator
    sender, receiver = AgentIdentity("window-a"), AgentIdentity("window-b")
    client = SessionInitiator(sender, receiver, handle_epoch=0)
    server = SessionInitiator(receiver, sender, handle_epoch=0)
    hello = client.hello(issued_at=int(time.time()))
    client.accept_ack(server.respond(hello, issued_at=int(time.time())))
    record = client.encrypt({"ok": True})
    forged = dict(record)
    forged["sequence"] = 100000
    with pytest.raises(ValueError):
        server.decrypt(forged)
    assert server.decrypt(record) == {"ok": True}


def test_session_hello_replay_and_stale_handshake_are_rejected():
    from pqc_a2a import SessionInitiator
    sender, receiver = AgentIdentity("fresh-a"), AgentIdentity("fresh-b")
    client = SessionInitiator(sender, receiver)
    server = SessionInitiator(receiver, sender)
    hello = client.hello(issued_at=100)
    with pytest.raises(ValueError, match="stale"):
        server.respond(hello, now=1000)
    fresh = client.hello(issued_at=int(time.time()))
    ack = server.respond(fresh, issued_at=int(time.time()))
    client.accept_ack(ack)
    with pytest.raises(ValueError, match="replay"):
        server.respond(fresh, now=int(time.time()))


def test_replay_cache_is_bounded_and_rejects_invalid_identifiers():
    cache = ReplayCache(ttl_seconds=60, max_entries=1, max_id_bytes=8)
    assert cache.accept("one")
    with pytest.raises(RuntimeError):
        cache.accept("two")
    with pytest.raises(ValueError):
        cache.accept("too-long-id")


def test_session_nonce_and_format_are_authenticated():
    from pqc_a2a import SessionInitiator
    sender, receiver = AgentIdentity("nonce-a"), AgentIdentity("nonce-b")
    client, server = SessionInitiator(sender, receiver), SessionInitiator(receiver, sender)
    hello = client.hello(issued_at=int(time.time()))
    client.accept_ack(server.respond(hello, issued_at=int(time.time())))
    record = client.encrypt({"ok": True})
    mutated = dict(record)
    mutated["format"] = "pqc-a2a-secure-record/1"
    with pytest.raises(ValueError):
        server.decrypt(mutated)


def test_discovery_requires_the_outstanding_challenge():
    identity = AgentIdentity("challenge-agent")
    cache = ReplayCache()
    record = __import__("pqc_a2a").make_discovery_record(__import__("pqc_a2a").AgentCard(identity.agent_id), identity, challenge="expected")
    with pytest.raises(ValueError, match="challenge"):
        __import__("pqc_a2a").verify_discovery_record(record, trusted_identity=identity, replay=cache, expected_challenge="different")
