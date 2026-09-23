import json
import random

import pytest

from pqc_a2a import AgentIdentity, fragment, open_envelope, reassemble, seal


def test_fragment_reassemble_property_for_many_payload_shapes():
    rng = random.Random(0xA2A)
    for size in [0, 1, 2, 127, 128, 129, 1024, 4096, 8191]:
        payload = bytes(rng.randrange(256) for _ in range(size))
        parts = fragment(payload, mtu=256, message_id=f"m-{size}")
        assert reassemble(parts) == payload


def test_malformed_fragment_fuzz_inputs_are_rejected():
    rng = random.Random(0xF00D)
    for _ in range(100):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        with pytest.raises(ValueError):
            reassemble([raw])


def test_envelope_mutation_fuzz_never_returns_plaintext():
    sender, receiver = AgentIdentity("fuzz-a"), AgentIdentity("fuzz-b")
    envelope = seal(sender, receiver, {"secret": "value"})
    keys = list(envelope)
    for index in range(30):
        mutated = dict(envelope)
        key = keys[index % len(keys)]
        if isinstance(mutated[key], str):
            mutated[key] = mutated[key][::-1]
        else:
            mutated[key] = None
        try:
            result = open_envelope(receiver, sender, mutated)
        except Exception:
            continue
        assert result != {"secret": "value"}
