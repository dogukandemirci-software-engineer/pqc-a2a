import json

import pytest

from pqc_a2a import AgentCard, AgentIdentity, establish_ratchet


PASSWORD = "correct horse battery staple"


def test_identity_roundtrip_is_encrypted(tmp_path):
    identity = AgentIdentity("persisted")
    path = tmp_path / "identity.json"
    identity.save(path, PASSWORD)
    data = json.loads(path.read_text())
    assert data["format"] == "pqc-a2a-identity/1"
    assert identity.public_record() == data["public"]
    assert AgentIdentity.load(path, PASSWORD).public_record() == identity.public_record()
    with pytest.raises(Exception):
        AgentIdentity.load(path, "wrong password")
    assert "kem_secret" not in path.read_text()


def test_signed_card_roundtrip_and_tamper_rejection():
    identity = AgentIdentity("card-agent")
    card = AgentCard("card-agent")
    signed = card.sign(identity)
    assert AgentCard.verify_signed(signed, identity).to_dict() == card.to_dict()
    signed["card"]["name"] = "attacker"
    with pytest.raises(ValueError):
        AgentCard.verify_signed(signed, identity)


def test_ratchet_state_can_resume_after_restart(tmp_path):
    a, b = AgentIdentity("a"), AgentIdentity("b")
    sender, receiver = establish_ratchet(a, b, queue_size=2)
    token = receiver.queue[0]
    envelope = sender.seal({"seq": 1}, token)
    assert receiver.open(envelope) == {"seq": 1}
    sender_path, receiver_path = tmp_path / "sender.state", tmp_path / "receiver.state"
    sender.save_state(sender_path, PASSWORD)
    receiver.save_state(receiver_path, PASSWORD)
    sender2 = type(sender).load_state(a, b, sender_path, PASSWORD)
    receiver2 = type(receiver).load_state(b, a, receiver_path, PASSWORD)
    next_token = receiver2.queue[0]
    envelope2 = sender2.seal({"seq": 2}, next_token)
    assert receiver2.open(envelope2) == {"seq": 2}
    with pytest.raises(ValueError):
        type(receiver).load_state(b, a, receiver_path, "wrong password")
