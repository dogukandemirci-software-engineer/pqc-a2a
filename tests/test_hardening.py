import socket

import pytest

from pqc_a2a import (
    AgentCard, AgentIdentity, AuditLogger, DurableReplayCache, FileSecretProvider, Metrics, ReplayCache,
    SkippedKeyStore, TcpFallback, TrustStore, make_discovery_record,
    new_challenge, open_envelope, provision_trust_store_from_discovery,
    provision_dev_certificate, seal, verify_discovery_record,
)


def test_discovery_is_signed_time_bound_and_replay_protected(tmp_path):
    identity = AgentIdentity("discovery-agent")
    cache = DurableReplayCache(tmp_path / "replay.db", ttl_seconds=60)
    challenge = new_challenge(); record = make_discovery_record(AgentCard(identity.agent_id), identity, challenge=challenge)
    assert verify_discovery_record(record, trusted_identity=identity, replay=cache, expected_challenge=challenge).agent_id == identity.agent_id
    with pytest.raises(ValueError, match="replay"):
        verify_discovery_record(record, trusted_identity=identity, replay=cache, expected_challenge=challenge)
    expired = make_discovery_record(AgentCard(identity.agent_id), identity, challenge=new_challenge(), issued_at=1000, ttl_seconds=5)
    with pytest.raises(ValueError, match="expired"):
        verify_discovery_record(expired, trusted_identity=identity, replay=cache, expected_challenge=expired['challenge'], now=1006, clock_skew=0)


def test_discovery_can_provision_only_from_anchor(tmp_path):
    identity = AgentIdentity("provisioned")
    cache = DurableReplayCache(tmp_path / "replay.db")
    record = make_discovery_record(AgentCard(identity.agent_id), identity, challenge="one")
    store = TrustStore()
    assert provision_trust_store_from_discovery(record, anchor=identity, store=store, replay=cache, expected_challenge="one")
    assert store.is_trusted(identity)


def test_bounded_skipped_keys_and_durable_replay(tmp_path):
    keys = SkippedKeyStore(max_keys=1, max_bytes=32)
    keys.put("a", b"12345678901234567890123456789012")
    assert keys.pop("a") == b"12345678901234567890123456789012"
    keys.put("a", b"key")
    with pytest.raises(RuntimeError): keys.put("b", b"key")
    cache = DurableReplayCache(tmp_path / "replay.db", max_entries=1)
    assert cache.accept("m") and not cache.accept("m")
    with pytest.raises(RuntimeError): cache.accept("n")


def test_secret_lifecycle_and_tcp_fallback():
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        provider = FileSecretProvider(root)
        provider.put("identity", b"secret")
        assert provider.get("identity") == b"secret"
        provider.destroy("identity")
        with pytest.raises(FileNotFoundError): provider.get("identity")
    left, right = socket.socketpair()
    try:
        TcpFallback(left).send(b"hello")
        assert TcpFallback(right).recv() == b"hello"
    finally:
        left.close(); right.close()
    metrics = Metrics(); metrics.inc("envelope.open"); assert metrics.snapshot() == {"envelope.open": 1}


def test_certificate_san_and_envelope_observability(tmp_path):
    cert, key = provision_dev_certificate(str(tmp_path), "localhost")
    from pqc_a2a import TransportProfile
    assert len(TransportProfile.validate_certificate_hostname(cert, "localhost")) == 64
    sender, receiver = AgentIdentity("obs-a"), AgentIdentity("obs-b")
    metrics = Metrics(); audit = AuditLogger()
    assert open_envelope(receiver, sender, seal(sender, receiver, {"ok": 1}), ReplayCache(), metrics=metrics, audit=audit) == {"ok": 1}
    assert metrics.snapshot()["envelope.open.success"] == 1


def test_transport_and_envelope_fuzz_like_mutations_are_rejected():
    sender, receiver = AgentIdentity("a"), AgentIdentity("b")
    envelope = seal(sender, receiver, {"v": 1})
    for field in ("nonce", "kem_ciphertext", "ephemeral_x25519", "signature"):
        mutated = dict(envelope); mutated[field] = "!"
        with pytest.raises((ValueError, Exception)):
            open_envelope(receiver, sender, mutated, ReplayCache())
