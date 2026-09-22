import json
import pytest
from pqc_a2a import AgentCard, AgentIdentity, ArchiveSigner, ReplayCache, establish_ratchet, fragment, reassemble


def test_agent_card_negotiation():
    a = AgentCard('a', signature_profiles=('SLH_DSA_PURE_SHA2_128S', 'ML-DSA-65'), max_fragment_size=1200)
    b = AgentCard('b', signature_profiles=('ML-DSA-65',), max_fragment_size=1000)
    selected = a.negotiate(b)
    assert selected == {'kem': 'ML-KEM-768', 'signature': 'ML-DSA-65', 'alpn': 'pqc-a2a/1', 'fragment_size': 1000}


def test_ratchet_queue_forward_secrecy_and_replay():
    a, b = AgentIdentity('a'), AgentIdentity('b')
    sender, receiver = establish_ratchet(a, b, queue_size=2)
    token = receiver.queue[0]
    env = sender.seal({'seq': 1}, token)
    assert receiver.open(env, ReplayCache()) == {'seq': 1}
    assert len(receiver.queue) == 1
    token2 = receiver.queue[0]
    env2 = sender.seal({'seq': 2}, token2)
    assert env['ciphertext'] != env2['ciphertext']
    assert receiver.open(env2, ReplayCache()) == {'seq': 2}
    assert len(receiver.queue) == 0
    with pytest.raises(ValueError): receiver.open(env, ReplayCache())


def test_archive_slh_dsa():
    signer = ArchiveSigner()
    archived = signer.sign_manifest({'messages': 3, 'digest': 'abc'})
    assert signer.verify(archived)
    archived['manifest']['messages'] = 4
    assert not signer.verify(archived)


def test_fragmentation_roundtrip_and_tamper():
    payload = b'agent-envelope:' + b'x' * 5000
    parts = fragment(payload, mtu=256, message_id='m1')
    assert len(parts) > 1 and reassemble(parts) == payload
    parts[0] = parts[0][:-1] + b'Y'
    with pytest.raises(ValueError, match='digest'): reassemble(parts)


def test_transport_configuration():
    from pqc_a2a import TransportProfile, ALPN, TLS_VERSION
    p = TransportProfile(mtu=1200)
    c = p.client_configuration()
    assert c.alpn_protocols == [ALPN] and TLS_VERSION == 'TLSv1.3'
