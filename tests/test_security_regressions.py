import json
import ssl

import pytest

from pqc_a2a import AgentIdentity, ReplayCache, TransportProfile, fragment, reassemble, open_envelope, seal


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
    config = TransportProfile().client_configuration()
    assert config.verify_mode == ssl.CERT_REQUIRED
