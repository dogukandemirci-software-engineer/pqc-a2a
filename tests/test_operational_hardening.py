import os

import pytest

from pqc_a2a import AgentIdentity, TrustStore, open_envelope, seal


PASSWORD = "correct horse battery staple"


def test_identity_save_is_atomic_and_private(tmp_path):
    identity = AgentIdentity("atomic")
    path = tmp_path / "identity.json"
    identity.save(path, PASSWORD)
    assert path.exists()
    assert path.stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob(".identity.json.*"))
    assert (tmp_path / "identity.json.lock").exists()


def test_trust_store_enforces_pin_revocation_and_reload(tmp_path):
    sender = AgentIdentity("sender")
    recipient = AgentIdentity("recipient")
    store = TrustStore()
    store.add(sender)
    envelope = seal(sender, recipient, {"hello": True})
    assert open_envelope(recipient, sender, envelope, trust_store=store) == {"hello": True}

    store.revoke(sender, "compromised")
    with pytest.raises(ValueError, match="trusted|revoked"):
        open_envelope(recipient, sender, envelope, trust_store=store)

    path = tmp_path / "trust.json"
    store.save(path)
    loaded = TrustStore.load(path)
    assert not loaded.is_trusted(sender)
    assert path.stat().st_mode & 0o077 == 0


def test_rotation_requires_old_trust_and_revokes_old_key(tmp_path):
    old = AgentIdentity("rotating")
    new = AgentIdentity("rotating")
    recipient = AgentIdentity("recipient")
    store = TrustStore()
    store.add(old)
    rotation = store.rotate(old, new)
    assert rotation["format"] == "pqc-a2a-rotation/1"
    assert not store.is_trusted(old)
    assert store.is_trusted(new)
    current = seal(new, recipient, {"key": "new"})
    assert open_envelope(recipient, new, current, trust_store=store) == {"key": "new"}
    old_message = seal(old, recipient, {"key": "old"})
    with pytest.raises(ValueError, match="trusted|revoked"):
        open_envelope(recipient, old, old_message, trust_store=store)
    path = tmp_path / "rotated-trust.json"
    store.save(path)
    assert TrustStore.load(path).is_trusted(new)
