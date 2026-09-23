# Operational Threat Model

This project is a research prototype. The following controls are explicit deployment obligations rather than claims made by the library.

| Asset | Threat | Control implemented here | Operational validation still required |
|---|---|---|---|
| Agent Card identity | forged or replayed discovery | signed card, challenge, validity window, replay cache | anchor distribution, revocation and monitoring |
| Message confidentiality | KEM/ciphertext substitution | transcript-bound HKDF and AEAD | independent protocol review |
| Ratchet state | loss, reordering, resource exhaustion | bounded token queue and `SkippedKeyStore` limits | delivery policy, persistence and incident recovery |
| Private keys | disk theft or process compromise | encrypted persistence and secret-provider boundary | KMS/HSM, rotation, access policy and memory inspection |
| Transport peer | MITM or wrong hostname | TLS 1.3, required client verification, SAN helper, explicit mTLS | certificate issuance, renewal, SAN inventory and TCP policy |
| Replay and audit | restart replay or missing evidence | durable SQLite replay cache, audit and metric hooks | HA storage, retention, alert thresholds and log integrity |

No implementation can guarantee zeroization of immutable Python `bytes`, prevent all side channels, or replace an independent cryptographic review. Before production, run certificate/rotation drills, restore the replay database from backup, exercise queue exhaustion, and validate alerts from invalid signatures, expired cards, replay attempts, and mTLS failures.
