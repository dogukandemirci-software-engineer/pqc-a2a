# PQC-A2A

**PQC-A2A**, AI ajanları arasında kimlik doğrulamalı ve hibrit post-quantum güvenlikli mesajlaşma için Python kütüphanesidir. Proje; **ML-KEM-768 + X25519** ile anahtar anlaşması, **ML-DSA-65** ile imza, **AES-256-GCM** ile veri gizliliği ve replay/state kontrolleri etrafında yapılandırılmıştır.

> **Durum:** Güvenlik hardening ve regression testleri uygulanmış production adayı bir temel. PKI/CA, KMS/HSM, dağıtık replay storage, sertifika rotasyonu ve bağımsız kriptografik protokol incelemesi hâlâ deployment sorumluluğudur. Bu proje formal güvenlik ispatı veya anonimlik çözümü iddiasında değildir.

[English README](README.en.md) · [Threat model](docs/THREAT_MODEL.md) · [Secure architecture](docs/SECURE_AGENT_ARCHITECTURE.md) · [Protocol architecture source](docs/protocol_architecture.mmd)

## Öne çıkan özellikler

| Katman | Sağlanan kontrol |
| --- | --- |
| Hibrit anahtar anlaşması | ML-KEM-768 ile X25519 ortak secret’ının transcript-bound HKDF ile türetilmesi |
| Mesaj kimlik doğrulaması | ML-DSA-65 imzası, canonical JSON ve algorithm binding |
| Veri gizliliği | AES-256-GCM; metadata AAD içinde doğrulanır |
| Mesaj yaşam döngüsü | `issued_at`, `expires_at`, clock-skew politikası ve replay cache |
| Session kanalı | İmzalı X25519 hello/ack, opaque handle, sequence ve bounded replay window |
| Ratchet | One-time ephemeral KEM token’ları, bounded queue, state persistence ve başarısız decrypt sonrası state koruması |
| Kimlik ve güven | Signed Agent Card, discovery challenge/TTL, trust-store pinning ve key rotation yapı taşları |
| Transport | QUIC/TLS 1.3 profili, TLS TCP fallback ve MTU-aware fragmentation |
| Relay | Opaque handle routing, scoped capability token, TTL-bound rendezvous ve bounded queue |
| Operasyon | Durable SQLite replay cache, audit event hook, metrics hook, skipped-key limitleri |
| A2A uyumluluğu | Transport-neutral Agent Card ve JSON-RPC 2.0 request/result yardımcıları |

## Protokol mimarisi

Aşağıdaki şema discovery’den session handshake’e, şifreli envelope’dan transport/relay katmanına kadar ana veri akışını gösterir. Kesikli oklar ratchet ve formal modelin secure channel ile ilişkisini gösterir.

![PQC-A2A protokol mimarisi](docs/protocol_architecture.png)

Şemanın kaynak dosyası [`docs/protocol_architecture.mmd`](docs/protocol_architecture.mmd) içindedir.

### Mesaj akışı

1. **Identity ve Agent Card:** Ajan ML-KEM, ML-DSA ve X25519 public material’ı üretir. Agent Card signing identity ile imzalanır.
2. **Trust ve discovery:** Discovery kaydı challenge, geçerlilik aralığı ve imza ile doğrulanır. Trust store deployment tarafından sabitlenen anchor/pin politikasını taşır.
3. **Session handshake:** Taraflar kısa ömürlü X25519 anahtarlarıyla signed hello/ack değiştirir. Session key handshake transcript’ine bağlanır.
4. **Secure record:** Payload AES-256-GCM ile korunur. `session_id`, recipient handle, sequence ve padding bucket AAD olarak bağlanır.
5. **Protocol envelope:** Tekil mesajlarda ML-KEM ciphertext, ephemeral X25519 public key, nonce, ciphertext ve ML-DSA signature birlikte taşınır.
6. **Transport ve relay:** QUIC veya TLS 1.3 TCP fallback kullanılabilir. Relay yalnızca opaque handle ve secure record görmelidir.
7. **Receiver commit:** Receiver signature ve AEAD doğrulamasını tamamlamadan replay window state’ini ilerletmez.

## Kurulum

Python 3.10 veya üzeri ve native `liboqs` build ortamı gerekir. Ubuntu için:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends cmake ninja-build libssl-dev
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Native backend’i doğrulayın:

```bash
python -c "from pqc_a2a import available_algorithms; print(available_algorithms())"
```

Beklenen katalogda en az `ML-KEM-768` ve `ML-DSA-65` bulunmalıdır. `liboqs-python`, Python wrapper’a ek olarak native shared library gerektirir; yalnızca `pip install` ile tamamlanan ortamlarda testler başlamayabilir.

## Hızlı başlangıç

```python
from pqc_a2a import AgentIdentity, ReplayCache, open_envelope, seal

sender = AgentIdentity("agent-a")
receiver = AgentIdentity("agent-b")
replay = ReplayCache(ttl_seconds=300)

envelope = seal(
    sender,
    receiver,
    {"method": "summarize", "input": "post-quantum message"},
    ttl_seconds=300,
)

payload = open_envelope(receiver, sender, envelope, replay=replay)
assert payload["method"] == "summarize"
```

Identity ve ratchet state dosyaları scrypt + AES-GCM ile password-protected saklanabilir:

```python
identity.save("agent.identity.json", password="a-long-development-password")
restored = AgentIdentity.load("agent.identity.json", password="a-long-development-password")
```

Bu dosya tabanlı şifreleme KMS/HSM yerine geçmez. Production deployment’ta password’lerin kaynak kodda veya düz environment variable içinde tutulmaması gerekir.

## Production güvenlik modeli

| Korunan varlık | Kütüphane kontrolü | Deployment sorumluluğu |
| --- | --- | --- |
| Mesaj gizliliği | ML-KEM/X25519 hybrid derivation + AES-GCM | Anahtarların KMS/HSM’de tutulması ve rotation |
| Mesaj bütünlüğü | ML-DSA signature + AES-GCM authentication tag | Trusted identity/public-key dağıtımı |
| Replay | In-memory veya durable replay backend | HA storage, backup/restore ve retention |
| Session replay | Bounded replay window; authentication sonrası commit | Session persistence ve failover politikası |
| Agent Card sahteciliği | Signed card + trust-store pinning | Root anchor, revocation ve monitoring |
| Transport peer | TLS 1.3, CA verification, opsiyonel mTLS | CA issuance, renewal, SAN/EKU ve network policy |
| Metadata | Opaque handle ve padding bucket yardımcıları | Relay/VPN/mixnet topolojisi ve traffic shaping |
| Secret storage | Password-protected identity/ratchet formats | KMS/HSM, access control, memory/process isolation |

> **Önemli sınır:** Şifreleme tek başına IP adresini, timing’i, bağlantı süresini veya trafik hacmini gizlemez. Global passive observer’a karşı anonymity, unlinkability veya güçlü traffic-analysis resistance iddiası yoktur.

## Hardening durumu

Son hardening commit’inde (`fcb6c17`) aşağıdaki production riskleri kapatıldı veya sınırlandırıldı:

- Failed secure-channel ciphertext’inin replay window’u ilerletmesi engellendi.
- `DurableReplayCache(":memory:")` bağlantılar arasında state kaybetmeyecek şekilde düzeltildi.
- Rendezvous registration, capability token subject handle’ına bağlandı.
- Capability expiry ve scope tip kontrolleri sıkılaştırıldı.
- Fragment reassembly için fragment count, total byte, message-id ve digest format limitleri eklendi.
- Dosya secret provider’ın plaintext-at-rest semantiği açık hale getirildi; atomic write ve `fsync` eklendi.
- Replay, capability ownership ve forged-high-sequence senaryoları için regression testleri eklendi.

Bu hardening bağımsız bir kriptografik incelemenin yerini tutmaz.

## Benchmark ve ölçümler

Sonuçlar repository içindeki `benchmarks/results.csv` ve `benchmarks/analysis_summary.json` dosyalarından üretilmiştir. Her veri noktası **20 örneğe** dayanır. Sonuçlar belirli bir ortamın ölçümüdür; donanım sıralaması veya genel throughput garantisi değildir.

![PQC-A2A benchmark ve formal doğrulama dashboard'u](benchmarks/readme_metrics.png)

### Temel ölçümler

| Payload | PQC envelope | Klasik envelope | PQC round-trip median | PQC seal p95 | PQC open p95 | Klasik round-trip median | PQC/klasik latency |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 256 B | 6,674 B | 348 B | 0.985 ms | 0.835 ms | 0.517 ms | 0.220 ms | 4.48× |
| 4 KiB | 11,794 B | 4,188 B | 1.272 ms | 0.939 ms | 0.594 ms | 0.247 ms | 5.15× |
| 16 KiB | 28,178 B | 16,476 B | 2.131 ms | 1.461 ms | 1.033 ms | 0.332 ms | 6.41× |

| Payload | PQC absolute overhead | Klasik absolute overhead | PQC expansion | Klasik expansion | PQC round-trip CI95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 256 B | 6,418 B | 92 B | 26.07× | 1.36× | ±0.101 ms |
| 4 KiB | 7,698 B | 92 B | 2.88× | 1.02× | ±0.047 ms |
| 16 KiB | 11,794 B | 92 B | 1.72× | 1.01× | ±0.069 ms |

### Ölçümlerin yorumu

PQC envelope boyutu özellikle küçük payload’larda sabit kriptografik metadata nedeniyle büyüktür. 256 B payload için envelope expansion factor **26.07×**, 4 KiB için **2.88×**, 16 KiB için **1.72×** ölçülmüştür. Klasik baseline expansion factor aynı sırayla **1.36×**, **1.02×** ve **1.01×** seviyesindedir.

Hybrid PQC round-trip median değeri payload büyüdükçe **0.985 ms’den 2.131 ms’ye** çıkmıştır. Bu ölçüm, ML-KEM/ML-DSA implementation’ının ve serialization maliyetinin küçük mesajlarda baskın olabileceğini gösterir. Production kapasite planı için hedef CPU mimarisinde yeni benchmark alınmalıdır.

95% confidence interval half-width değerleri PQC için sırasıyla **0.101 ms**, **0.047 ms** ve **0.069 ms**; klasik baseline için **0.020 ms**, **0.007 ms** ve **0.015 ms** olarak raporlanmıştır. Bu aralıklar ölçüm belirsizliğini gösterir; protokolün güvenlik olasılığı değildir.

Benchmark’ı yeniden üretmek için:

```bash
python benchmarks/benchmark.py 50
python benchmarks/analyze_results.py
python benchmarks/generate_readme_assets.py
```

`benchmarks/benchmark.png` temel seal/open latency ve wire overhead’i, `benchmarks/analysis.png` baseline karşılaştırmasını, `benchmarks/readme_metrics.png` ise genişletilmiş dashboard’u gösterir.

## Formal model kapsamı

Ratchet state machine’i `formal/Ratchet.tla` ve `formal/Ratchet.cfg` ile TLC 2.19 üzerinde finite-state olarak kontrol edilmiştir.

| TLC metriği | Değer |
| --- | ---: |
| Üretilen state | 35 |
| Distinct state | 32 |
| Queue’da kalan state | 0 |
| Complete graph depth | 7 |
| Invariant violation | 0 |
| Kontrol edilen invariant | 5 |

Kontrol edilen invariant’lar: `TypeOK`, `NoConsumeOnBad`, `SingleUse`, `ReceiverNeverAhead` ve `TokenConsistency`.

![TLA+ / TLC finite-state verification](formal/verification.png)

Bu sonuç yalnızca belirtilen finite-state model için geçerlidir. ML-KEM, ML-DSA, AES-GCM, liboqs veya Python runtime’ın matematiksel güvenliğini kanıtlamaz. `0 invariant violations` gerçek dünyada sıfır güvenlik açığı anlamına gelmez.

## Test ve kalite kontrolleri

Yerel validation sonucunda:

```text
39 passed
Ruff F/E9 source checks: passed
Bandit source scan: passed
pip-audit: no known vulnerabilities
compileall: passed
git diff --check: passed
```

Test suite envelope, replay, ratchet, signed Agent Card, discovery, trust-store, TLS/TCP framing, fragmentation, session handshake, opaque relay, capability ve operational hardening senaryolarını kapsar.

## Dizin yapısı

```text
src/pqc_a2a/
├── protocol.py          # Identity, envelopes, trust, replay, ratchet
├── secure_channel.py    # Session hello/ack, secure records, replay window
├── transport.py         # QUIC/TLS, TCP fallback, fragmentation
├── discovery.py         # Signed discovery records
├── relay.py             # Capabilities, rendezvous, opaque relay
├── operations.py        # Persistence, audit, metrics, limits
├── a2a.py               # Agent Card ve JSON-RPC adapter
└── langgraph_adapter.py # Optional LangGraph-compatible transport

tests/                   # Protocol, fuzz-like ve regression testleri
benchmarks/              # Benchmark, analysis ve README dashboard scriptleri
formal/                  # TLA+ model, TLC config ve verification output
docs/                    # Threat model, architecture ve diagram source
```

## Release öncesi checklist

- KMS/HSM-backed secret provider ve key rotation runbook’u.
- Gerçek CA/SPIFFE/SPIRE trust plane, certificate renewal ve revocation.
- Durable replay DB backup/restore, crash recovery ve multi-process testleri.
- Rate limiting, connection timeout, queue backpressure ve telemetry.
- Adversarial fuzzing; özellikle handshake replay, fragment memory pressure ve malformed schema input’ları.
- Hedef CPU/OS/Python matrisi üzerinde native liboqs build ve benchmark.
- Bağımsız cryptographic protocol review ve security disclosure süreci.

## Lisans ve referanslar

Proje MIT License ile yayımlanır. Citation metadata [`CITATION.cff`](CITATION.cff) içindedir.

[1]: https://csrc.nist.gov/pubs/fips/203/final "NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard"
[2]: https://csrc.nist.gov/pubs/fips/204/final "NIST FIPS 204: Module-Lattice-Based Digital Signature Standard"
[3]: https://cryptography.io/en/latest/hazmat/primitives/aead/ "cryptography AEAD primitives"
[4]: https://github.com/open-quantum-safe/liboqs "Open Quantum Safe liboqs"
[5]: https://github.com/aiortc/aioquic "aioquic QUIC and HTTP/3 implementation"
[6]: https://lamport.azurewebsites.net/tla/tla.html "The TLA+ Specification Language and Tools"

## On bağımsız threat modeling sonucu

Bu bölüm, 24 Eylül 2026 tarihinde repository’nin mevcut kaynak kodu, testleri, TLA+ modeli ve deployment belgeleri üzerinde yürütülen **10 bağımsız tehdit modelini** özetler. Her model farklı bir saldırı yüzeyine odaklandı. “Düzeltildi” ifadesi ilgili kod ve regression testinin repository’ye işlendiğini; “deployment sınırı” ifadesi kütüphane dışında kalan bir kontrolü belirtir.

| # | Model | İlk sonuç | Durum |
| ---: | --- | --- | --- |
| 1 | Kriptografik primitive ve transcript binding | P1: session kanalı X25519-only idi | **Düzeltildi: hybrid ML-KEM session** |
| 2 | KEM ratchet ve forward-security state machine | P1: durable rollback/concurrency sınırı | **Kısmen düzeltildi: state rollback için deployment fence gerekir** |
| 3 | Envelope signature ve message validation | P1: replay cache opsiyoneldi | **Düzeltildi: replay cache fail-closed ve bounded** |
| 4 | Replay, sequence ve secure-session saldırıları | P1: hello replay ile state reset | **Düzeltildi: freshness, one-shot generation ve deterministic nonce** |
| 5 | Discovery ve trust lifecycle | P1: challenge verifier’a bağlı değildi | **Düzeltildi: expected challenge ve TTL policy** |
| 6 | TLS/QUIC transport peer authentication | P1: QUIC endpoint identity opsiyoneldi | **Düzeltildi: explicit CA/server name; mTLS unsupported ise fail-closed** |
| 7 | Fragmentation/parser/resource exhaustion | P1: relay ve record limitleri yetersizdi | **Kısmen düzeltildi: global relay limits; ingress quotas deployment’a ait** |
| 8 | Relay/rendezvous/capability authorization | P1: cross-subject lookup mümkündü | **Düzeltildi: capability subject binding ve expiry purge** |
| 9 | Persistence/secrets/crash consistency | P1: SQLite connection leak ve rollback sınırı | **Düzeltildi: explicit connection close; rollback anchor deployment’a ait** |
| 10 | Operations/metadata/supply chain | P1: unbounded replay/relay ve optional padding | **Kısmen düzeltildi: bounds; supply-chain pinning release sürecine ait** |

### 1. Kriptografik primitive ve transcript binding

**Tehdit aktörü:** Kaydedilmiş handshake trafiğini daha sonra quantum-capable bir adversary olarak analiz eden saldırgan.

**İncelenen alan:** ML-KEM/X25519 hibrit türetme, ML-DSA authentication, algorithm binding ve HKDF transcript.

**Bulgular:** Regular `seal()`/`open_envelope()` yolu ML-KEM-768 ve X25519 secret’larını transcript-bound HKDF ile birleştiriyordu. Ancak eski `SessionInitiator` handshake’i yalnızca X25519’dan session key türetiyordu. ML-DSA imzası kimlik doğrular fakat X25519 secret’ını quantum adversary’ye karşı korumaz. Bu, kaydedilmiş session trafiği için gerçek bir post-quantum confidentiality açığıydı.

**Uygulanan düzeltme:** Session protocol v2 artık `ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM` suite identifier’ını imzalı hello/ack içine alıyor. Initiator ML-KEM ciphertext üretir; responder kendi ML-KEM secret’ı ile decapsulation yapar. X25519 ve ML-KEM secret’ları length-prefixed, role-labelled HKDF ile birleştirilir. Suite, handle, session ID, ephemeral key, nonce salt ve transcript birlikte bağlanır. Suite veya KEM alanı değiştirilirse handshake başarısız olur.

**Kalan sınır:** ML-KEM/ML-DSA implementation güvenliği liboqs sürümüne ve bağımsız cryptographic review’a bağlıdır. Bu değişiklik quantum güvenlik iddiasını protocol key establishment seviyesinde düzeltir; global anonymity sağlamaz.

### 2. KEM ratchet ve forward-security state machine

**Tehdit aktörü:** Stale backup restore eden operator, crash sonrası eski state’i yükleyen worker veya aynı state dosyasına paralel yazan worker.

**İncelenen alan:** `AsyncKEMRatchet`, one-time token tüketimi, chain advancement, persistence ve out-of-order delivery.

**Bulgular:** In-memory transition başarısız decrypt sonrasında doğru biçimde değişmiyordu. Buna karşılık eski bir encrypted snapshot geri yüklenirse consumed token ve eski chain state yeniden canlanabiliyordu. Per-object lock da multi-process compare-and-swap sağlamıyordu. Ayrıca `SkippedKeyStore` ayrı bir utility olsa da ratchet global chain advancement içinde kullanılmıyordu; token2’nin token1’den önce gelmesi availability sorunu oluşturabiliyordu.

**Uygulanan düzeltme:** Regression kapsamına forged sequence ve failed-authentication state invariants eklendi. Ratchet state limitlerinin load sırasında doğrulanması ve monotonic generation/CAS ile korunması release checklist’e açıkça alındı. Production deployment’ta ratchet state ile replay ledger aynı transactional owner veya rollback-protected store altında tutulmalıdır.

**Kalan sınır:** Bu repository’de tam multi-process transactional ratchet store veya persisted skipped-key protocol henüz bulunmaz. Strict FIFO deployment policy kullanılmalı ya da bounded skipped-key state makinesi ayrıca uygulanmalıdır; bu sınır artık güvenlik iddiası olarak gizlenmemektedir.

### 3. Envelope signature ve message validation

**Tehdit aktörü:** Geçerli imzalı mesajı tekrar gönderen saldırgan, malformed envelope gönderen servis veya cache vermeden `open_envelope()` çağıran entegrasyon.

**İncelenen alan:** ML-DSA signature coverage, AES-GCM AAD, payload schema, validity window ve replay retention.

**Bulgular:** Signature/AAD/transcript binding doğrudan kırılabilir görünmüyordu. Ancak replay cache opsiyoneldi; 300 saniyelik default retention, 86.400 saniyeye kadar izin verilen envelope TTL’sinden kısa olabiliyordu. `dict` contract’ına rağmen list/scalar payload kabul edilebiliyordu. Boolean timestamp’ler Python’da integer gibi davranabiliyordu.

**Uygulanan düzeltme:** `open_envelope()` artık replay cache olmadan fail-closed olur. `ReplayCache` bounded `max_entries` ve `max_id_bytes` uygular. `DurableReplayCache` de aynı identifier limitlerini uygular ve explicit `close()`/context-manager ile SQLite bağlantılarını kapatır. Envelope payload’ı seal ve open aşamasında object olmak zorundadır. Timestamp bool değerlerini ve 24 saat üzerindeki validity window’larını reddeder. Base64 alanları canonical URL-safe biçimde doğrulanır. Regular envelope KEM alanı artık gerçek recipient KEM profiline bağlanır.

**Kalan sınır:** Replay cache’in kapasite dolumunda fail-closed davranışı uygulama backpressure ve idempotency transaction’ı ile birleştirilmelidir.

### 4. Replay, sequence ve secure-session saldırıları

**Tehdit aktörü:** Signed hello/ack kaydedip tekrar sunan ağ saldırganı veya session nesnesini eşzamanlı kullanan uygulama.

**İncelenen alan:** `SessionInitiator`, `ReplayWindow`, session generation, nonce uniqueness ve handshake state commit.

**Bulgular:** Signed hello freshness kontrol edilmeden responder state’ini değiştirebiliyordu. Eski session replay edilerek responder ile initiator desynchronize edilebiliyordu. Random nonce’lar aynı session key altında yön ayrımı olmadan kullanılıyordu; uzun session’larda nonce collision riski oluşuyordu. Handshake başarısızken live state’in kısmen değişebilmesi de DoS oluşturabiliyordu.

**Uygulanan düzeltme:** Session v2’de issued-at freshness window, one-shot accepted session IDs, explicit suite/format validation ve atomic candidate-state commit bulunur. Her direction için ayrı HKDF key kullanılır. Nonce artık 4-byte session salt + 8-byte unsigned sequence olarak deterministic türetilir; sequence wrap reddedilir. Secure record format, suite, direction, handle ve sequence AAD içine alınır. Payload ve complete record boyutları bounded’dir.

**Kalan sınır:** Session nesnesi tek aktif generation için tasarlanmıştır. Rekeying gerekiyorsa yeni `SessionInitiator` oluşturulmalı veya ayrıca authenticated generation rollover protokolü uygulanmalıdır.

### 5. Discovery ve trust lifecycle

**Tehdit aktörü:** Başka bir request için üretilmiş signed discovery response’u kullanan replay saldırganı veya revocation sonrası eski identity kullanan servis.

**İncelenen alan:** Discovery challenge, TTL, replay cache, signed Agent Card, issuer/subject binding ve trust lifecycle.

**Bulgular:** Verifier kendi outstanding challenge’ını record ile karşılaştırmıyordu. Discovery TTL verifier tarafında enforcement edilmediğinde uzun süreli valid record kabul edilebiliyordu. Agent Card `name` alanı issuer ile zorunlu biçimde bağlanmıyordu.

**Uygulanan düzeltme:** `verify_discovery_record()` artık `expected_challenge` ister ve exact challenge binding yapar. Discovery validity window verifier tarafında maksimum 3600 saniye ile sınırlandırılır; replay acceptance aynı injected `now` değerini kullanır. Agent Card verifier `name == issuer == trusted_identity.agent_id` şartını uygular. Provisioning API challenge’ı açıkça alır.

**Kalan sınır:** TrustStore revocation/rotation persistence’ı operator-controlled durable policy olarak kalır. İlk trust anchor out-of-band pin veya CA/SPIFFE root ile kurulmalıdır; self-authorizing bootstrap güvenli değildir.

### 6. TLS/QUIC transport peer authentication

**Tehdit aktörü:** Yanlış public CA certificate’i sunan MITM, etkisiz mTLS bayrağına güvenen servis veya TCP fallback üzerinde slowloris yapan peer.

**İncelenen alan:** QUIC client CA/hostname, QUIC mTLS, TCP TLS 1.3, ALPN, hostname matching ve read lifecycle.

**Bulgular:** QUIC client `cafile` ve `server_name` olmadan oluşturulabiliyor, bu da endpoint identity’yi chain-only bırakabiliyordu. `aioquic==1.3.0` ile `require_client_certificate=True` flag’i gerçek CertificateRequest enforcement’ı garanti etmiyordu. TCP fallback ALPN, timeout ve context lifecycle eksiklerine sahipti. Hostname helper shell-glob semantiği kullanıyordu.

**Uygulanan düzeltme:** QUIC client configuration explicit `cafile` ve `server_name` olmadan fail eder. Aioquic sürümü client-certificate enforcement sağlayamıyorsa QUIC mTLS configuration artık sessizce devam etmek yerine fail-closed olur. TCP fallback timeout, `close()`, context manager, ALPN ve optional client certificate yükleme desteğine sahiptir. Hostname helper RFC-style `ssl._dnsname_match` semantics kullanır; multi-label wildcard genişlemesi kabul edilmez.

**Kalan sınır:** `ssl._dnsname_match` runtime compatibility için kullanılan düşük seviyeli stdlib helper’dır; gerçek TLS chain, EKU, revocation ve CA policy yine TLS context/deployment tarafından doğrulanmalıdır. QUIC mTLS için CertificateRequest destekleyen uyumlu aioquic adapter veya upstream sürümü kullanılmalıdır.

### 7. Fragmentation, parser ve resource exhaustion

**Tehdit aktörü:** Untrusted fragment, oversized secure record, unique relay handle veya yarım TCP frame gönderen DoS saldırganı.

**İncelenen alan:** Fragment header parsing, reassembly memory, secure record decoding, relay queue ve TCP framing.

**Bulgular:** Fragment aggregate limitleri olmasına rağmen header JSON parse edilmeden önce ayrı header budget’i yoktu. Secure record ciphertext ve JSON payload boyutları doğrudan API seviyesinde sınırsızdı. Relay yalnızca handle başına queue limitliyordu; unique handle ve total byte büyümesi mümkündü. TCP frame reads deadline olmadan blocking idi.

**Uygulanan düzeltme:** Session secure records için 16 MiB complete-record ve 8 MiB payload sınırı eklendi. Replay identifiers ve relay handle/endpoint/record alanları bounded oldu. `OpaqueRelay` global handle, record ve byte quota uygular; queue drain sonrası empty handle silinir ve FIFO için `deque` kullanılır. Rendezvous expired entries register/lookup sırasında purge edilir ve endpoint/handle uzunlukları sınırlanır. TCP fallback finite timeout ve context lifecycle uygular.

**Kalan sınır:** HTTP/QUIC listener connection limits, concurrency budgets, rate limiting ve outer JSON body limits kütüphane dışındaki network adapter tarafından uygulanmalıdır.

### 8. Relay, rendezvous ve capability authorization

**Tehdit aktörü:** Geçerli kendi capability’siyle başka handle lookup etmeye çalışan tenant veya handle bilen yetkisiz relay client.

**İncelenen alan:** Capability subject/audience/scope, rendezvous register/lookup ve opaque relay ingress/egress.

**Bulgular:** Rendezvous lookup token subject ile istenen handle’ı karşılaştırmıyordu; capability sahibi başka handle endpoint’i okuyabiliyordu. Opaque relay forward/receive operations capability veya principal context almıyordu. Capability nonce replay semantiği de açık değildi.

**Uygulanan düzeltme:** `Rendezvous.lookup()` artık requested handle ile capability subject handle’ın eşit olmasını ister. Capability expiry exact boundary’de fail-closed kontrol edilir. Registration lease capability expiry ile sınırlandırılır. Expired records capacity kontrolünden önce purge edilir. Opaque relay global resource bounds ve strict handle/record size checks uygular.

**Kalan sınır:** Opaque relay authorization’ın network-facing bir adapter’da authenticated principal/capability ile çağrılması gerekir. In-process `forward()`/`receive()` API’si ciphertext routing sağlar; tek başına tenant authentication değildir. Bu sınır README’de açıkça belirtilmelidir.

### 9. Persistence, secrets ve crash consistency

**Tehdit aktörü:** Crash sonrası eski snapshot restore eden operator, shared parent directory’ye erişen local attacker veya uzun çalışan process.

**İncelenen alan:** SQLite replay store, FileSecretProvider, encrypted identity/ratchet state, file locks ve rollback.

**Bulgular:** Disk-backed `DurableReplayCache` her operation için SQLite connection açıyor fakat explicit close etmiyordu; uzun servislerde file descriptor sızıntısı oluşabiliyordu. FileSecretProvider deterministic temp file bırakabiliyor ve plaintext-at-rest semantiğine sahipti. Encrypted ratchet/trust snapshots atomic olsa da stale backup rollback’ına karşı generation anchor taşımıyordu.

**Uygulanan düzeltme:** Durable replay cache her disk operation sonrası connection’ı kapatır; in-memory cache için explicit `close()` ve context-manager eklenmiştir. Identifier limits SQLite replay storage’a da uygulanır. FileSecretProvider’ın plaintext sınırı dokümante edilir; production KMS/HSM kullanımı zorunlu release checklist maddesidir. Ratchet state size policy ve rollback riskleri açıkça test/checklist kapsamına alınmıştır.

**Kalan sınır:** Rollback protection için monotonic external generation, transactional state owner veya database-backed CAS gerekir. Atomic rename tek başına stale backup’ı reddetmez. Python immutable `bytes` için garantili zeroization yapılamaz.

### 10. Operational, metadata ve supply-chain modeli

**Tehdit aktörü:** Invalid-signature/replay flood gönderen saldırgan, logları okuyan operator veya farklı dependency çözümleyen build ortamı.

**İncelenen alan:** Failure telemetry, audit redaction, padding, metrics cardinality, dependency reproducibility ve deployment defaults.

**Bulgular:** Başarısız authentication sınıfları için built-in failure telemetry yoktu. Audit event stable sender/recipient ID’leri taşıyabiliyordu. Padding opt-in idi ve complete record’ı sabit boyuta getirmiyordu. Dependency çözümü hash-pinned lock/SBOM olmadan range-based kalıyordu.

**Uygulanan düzeltme:** Threat model ve release checklist’te log minimization, bounded telemetry, dependency lock/hashes ve SBOM gereklilikleri ayrı kontrol olarak tanımlandı. Session record’lar suite/direction/format bağlamıyla doğrulanır; payload/record boyutları sınırlıdır. Metrik ve audit kullanımının deployment tarafından redacted, bounded ve authenticated sink’e bağlanması gerektiği açıkça belirtilmiştir.

**Kalan sınır:** Repository’de henüz imzalı SBOM/provenance attestation veya tam failure-event exporter bulunmaz. Production release pipeline exact dependency hashes, trusted index, SBOM ve reproducible build kontrollerini eklemelidir. Padding traffic analysis’i azaltır; timing/volume/connection metadata’sını tek başına gizlemez.

### Threat modeling sonucu

10 modelde **P0 seviyesinde doğrudan primitive kırılması bulunmadı**. En ciddi gerçek bulgu, eski SessionInitiator’ın quantum-safe session olarak belgelenmesine rağmen yalnızca X25519 kullanmasıydı; session protocol v2 ile ML-KEM hibrit handshake’e geçirildi. Diğer P1/P2 bulguların çoğu replay, freshness, authorization, resource exhaustion ve state durability sınıfındaydı. Bunlar kriptografik algoritmayı kırmaz; fakat production sistemin güvenlik iddiasını pratikte geçersiz kılabilecek protokol ve operasyon açıklarıdır.

Son doğrulama:

```text
43 passed
Session hybrid handshake regression: passed
Stale/replayed hello rejection: passed
Strict replay-cache limits: passed
Discovery expected-challenge binding: passed
Secure-record format/nonce binding: passed
```

Bu modeller adversarial review kapsamını genişletir; bağımsız cryptographic audit, target-platform fuzzing, multi-process crash testing ve live CA/KMS drills yerine geçmez.
