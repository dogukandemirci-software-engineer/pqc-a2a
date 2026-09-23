# PQC-A2A

PQC-A2A is a research prototype for hybrid post-quantum agent-to-agent messaging. It combines ML-KEM-768 with X25519 for key establishment, ML-DSA-65 for message authentication, and AES-256-GCM for payload encryption.

## Scope

The library provides authenticated envelopes, one-time KEM ratchets, encrypted identity and ratchet state persistence, signed Agent Cards, trust-store pinning, QUIC/TLS profile helpers, and strict fragmentation/reassembly. The A2A adapter adds a transport-neutral signed Agent Card document and JSON-RPC 2.0 request/response validation helpers.

Every regular envelope includes a signed `issued_at`/`expires_at` validity window. The HKDF input is transcript-bound to the negotiated algorithms, message context, recipient public keys, ephemeral X25519 key, and ML-KEM ciphertext. This prevents a ciphertext or public-key substitution from reusing a derived message key. The default identity model does not claim message-level forward secrecy if a long-lived recipient private key is later compromised; use the one-time KEM ratchet for the stronger session property.

## Quickstart

```bash
python -m pip install -e '.[dev]'
pytest -q
python benchmarks/benchmark.py 50
python benchmarks/analyze_results.py
```

The benchmark reports median, p95, sample standard deviation, and a 95% confidence interval. It compares the hybrid construction with an X25519 + Ed25519 + AES-GCM classical baseline. Results are environment-specific and are not a hardware ranking.

## Security limitations

This is not a production-ready protocol or a formal security proof. PKI, discovery replay/expiry policy, certificate provisioning, side-channel resistance, memory zeroization guarantees, and durable distributed replay storage remain deployment responsibilities. The cryptographic implementation depends on liboqs and should receive an independent review before production use.

See the Turkish README for the complete project history and examples. The project is released under the MIT License; citation metadata is in `CITATION.cff`.
