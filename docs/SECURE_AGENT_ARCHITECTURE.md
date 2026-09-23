# Secure Agent Communication Architecture

## P0: end-to-end session

`SessionInitiator` creates a rotating `opaque_handle`, signs a short-lived X25519 session hello with the long-term ML-DSA identity, and derives a bidirectional AES-GCM session key from the authenticated transcript. Secure records contain only the recipient handle, session ID, sequence, nonce, ciphertext, and padding bucket. The stable `agent_id` is not present in session records. `ReplayWindow` rejects duplicates and records outside the bounded reordering window.

`TcpFallback.client()` and `TcpFallback.server()` wrap the length-prefixed fallback in TLS 1.3. The client requires a CA file and hostname; mutual TLS requires a CA file on the server. QUIC configuration remains available through `TransportProfile`.

## P1: rendezvous, relay, and orchestration

`issue_capability()` creates a short-lived, scoped token bound to a rotating handle and audience. `Rendezvous` stores only an opaque handle and endpoint with a TTL. `OpaqueRelay` forwards only records marked as secure session records and enforces a bounded per-handle queue. A production implementation can replace these in-process classes with HTTPS/QUIC services without changing the session record format.

`SecureAgentTransport` is a LangGraph-compatible adapter without a hard dependency on LangGraph. A graph node can use `make_node()` to send a dict state fragment over the encrypted session while keeping graph state and transport identifiers separate.

## P2: metadata reduction

`padding_bucket()` and the session `padding_bucket` option reduce payload-size leakage. `dummy_payload()` can support an application-managed cover-traffic schedule. `redact_metadata()` is intended for logs and audit events. These controls reduce leakage but do not provide strong anonymity against a global traffic observer. Hiding peer IP addresses requires a relay, VPN, onion route, or mixnet; application encryption alone cannot do that.

## Honest security boundary

The relay can hide the peer's direct IP address only when the network topology actually routes traffic through it. A relay operator can still observe timing, volume, connection duration, and the relay-side endpoint. Strong traffic-analysis resistance requires padding schedules, batching, cover traffic, and usually multiple independently operated relays. The project does not claim anonymity, unlinkability, or protection against a global passive observer.

For deployment, use a real CA or SPIFFE/SPIRE identity plane, KMS/HSM-backed key storage, certificate rotation, durable HA replay storage, rate limiting, and an independent protocol review.
