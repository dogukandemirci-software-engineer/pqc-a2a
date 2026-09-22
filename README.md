# PQC-A2A: Post-Quantum Secure Agent-to-Agent PoC

Bu depo, Zenodo kaydında sunulan **Post-Quantum Cryptography Integration Framework for Autonomous Agent-to-Agent (A2A) Systems: Architecture, Threats, and Optimization Strategies** çalışmasının çalışan araştırma prototipidir. Uygulama; hibrit KEM, ajan kimliği, crypto-profile negotiation, asenkron KEM ratchet, QUIC/TLS 1.3 transport profili, MTU fragmentation ve uzun süreli arşiv imzasını tek bir PoC’de birleştirir.

> **Kapsam:** ML-KEM-768 ve X25519 ile hibrit anahtar kurma, ML-DSA-65 ile mesaj kimlik doğrulama, AES-256-GCM ile içerik gizliliği, ML-KEM tek-seferlik ephemeral token kuyruğu ile per-message forward secrecy, `aioquic` ile TLS 1.3/QUIC yapılandırması ve SLH-DSA-128s arşiv imzası.

![Hybrid PQC A2A benchmark](benchmarks/benchmark.png)

## Mimari

```text
Agent Card A  <---- capability negotiation: KEM / signature / ALPN / MTU ---->  Agent Card B
     |                                                                        |
     |  Receiver precomputes one-time ML-KEM ephemeral public-key queue        |
     |  Sender consumes one token per message                                  |
     |  ML-KEM shared secret + chain key -> HKDF ratchet message key            |
     |  AES-256-GCM payload + ML-DSA-65 signature                               |
     |                                                                        |
     +---------------------- QUIC / TLS 1.3 / ALPN pqc-a2a/1 -----------------+
                    application fragmentation for MTU <= 1200 bytes

Long-lived archive manifest --------------------------------------> SLH-DSA-PURE-SHA2-128S
```

## Hızlı başlangıç

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest -q
python benchmarks/benchmark.py 20
```

`liboqs-python` ilk kullanımda `liboqs` kütüphanesini yerel olarak derleyebilir. Ubuntu için `cmake`, `ninja-build`, `build-essential`, `libssl-dev` gereklidir. Üretimde derleme yerine güvenilir, sabitlenmiş bir liboqs paketi ve donanım/işletim sistemi matrisi kullanılmalıdır.

## Eklenen bileşenler

### Asenkron KEM ratchet

`AsyncKEMRatchet`, alıcı tarafında önceden üretilen tek kullanımlık ML-KEM public/secret-key çiftlerini kuyrukta tutar. Gönderici her mesaj için farklı bir public token tüketir. Alıcı mesajı açtıktan sonra corresponding secret key’i kuyruktan siler ve bellekte sıfırlar. Her mesajın ML-KEM shared secret’i chain key ile HKDF-SHA3-256 üzerinden birleştirilir; chain key de her adımda ilerler. Böylece her mesaj ayrı bir AEAD anahtarı kullanır ve eski token’ın silinmesi per-message forward secrecy hedefini destekler.

`establish_ratchet()` hibrit bootstrap yapar. `queue_size` alıcının önceden hesaplayacağı ephemeral token sayısını belirler. Kuyruk tükendiğinde `refill()` ile yeni tokenlar üretilmelidir. Bu PoC sıralı açmayı test eder; kayıp veya yeniden sıralanmış paketler için üretim seviyesinde skipped-message key store ayrıca gerekir.

### Agent Card ve crypto-profile negotiation

`AgentCard` aşağıdaki capability alanlarını JSON-compatible biçimde taşır:

| Alan | İçerik |
|---|---|
| `kem` | ML-KEM mekanizma listesi |
| `signatures` | ML-DSA-65 ve SLH-DSA profilleri |
| `alpn` | `pqc-a2a/1` gibi transport profilleri |
| `max_fragment_size` | İki tarafın ortak MTU sınırı |

`negotiate()` iki tarafın sıralı tercihlerinden ortak KEM, imza, ALPN ve minimum fragmentation boyutunu seçer. Ortak profil yoksa bağlantı güvenli biçimde reddedilir.

### QUIC/TLS 1.3 ve MTU fragmentation

`TransportProfile` `aioquic` için client/server `QuicConfiguration` üretir. ALPN `pqc-a2a/1` olarak sabitlenir; `aioquic` QUIC handshake’ini TLS 1.3 ile gerçekleştirir. Server tarafında sertifika ve private key verilmesi zorunludur. `fragment()` uygulama envelope’unu varsayılan 1200 byte MTU içine sığan parçalara böler. Her parça message ID, sıra numarası, toplam parça sayısı ve SHA-256 digest taşır. `reassemble()` sıra kontrolü, eksik parça kontrolü ve digest doğrulaması yapar.

Bu katman JSON mesajlaşmasını QUIC stream/datagram uygulamasına bağlamak için hazır bir yapılandırma ve güvenli framing sağlar. TCP fallback bayrağı profile eklenmiştir; tam TCP listener/HTTP gateway bu küçük PoC’ye dahil edilmemiştir.

### SLH-DSA-128s arşiv imzaları

`ArchiveSigner`, kısa ömürlü mesaj imzalarından ayrı bir uzun ömürlü manifest imzası üretir. `SLH_DSA_PURE_SHA2_128S`, liboqs 0.16.0 içindeki FIPS SLH-DSA-SHA2-128s parametre setinin etkin mekanizma adıdır. Manifest digest’i ve imzası birlikte saklanır. Mesaj içi düşük gecikmeli authentication için ML-DSA-65, arşiv bütünlüğü için daha yavaş hash-based SLH-DSA kullanılır.

## Benchmark

Benchmark üç gerçek payload boyutunda 20 round-trip örneği alır. Her örnekte yeni ajan kimlikleri bir kez oluşturulur; her mesaj için yeni ephemeral X25519 anahtarı, KEM ciphertext’i ve AES-GCM nonce üretilir. `results.csv` medyan `seal`, `open`, toplam round-trip gecikmesini ve envelope boyutunu kaydeder.

Ubuntu 24.04 üzerinde, 20 örnek ve `liboqs-python 0.16.0` ile alınan medyan sonuçlar:

| Payload | Seal (ms) | Open (ms) | Round-trip (ms) | Envelope (bytes) |
|---:|---:|---:|---:|---:|
| 256 B | 0.869 | 0.564 | 1.442 | 6,650 |
| 4 KiB | 0.990 | 0.708 | 1.696 | 11,770 |
| 16 KiB | 1.553 | 1.179 | 2.711 | 28,154 |

Bu değerler donanımlar arası performans iddiası değildir. Native liboqs derlemesi, CPU özellikleri ve Python sürümü sonucu etkiler; ham çıktı `benchmarks/results.csv` içindedir.

## Test kapsamı

Test paketi **8 test** içerir. Mesaj round-trip’i, replay reddi, ciphertext tamper reddi ve identity binding yanında Agent Card müzakeresini, iki adımlı ratchet zincir ilerlemesini, ephemeral token tüketimini, SLH-DSA manifest imza doğrulamasını, MTU fragmentation/reassembly ve QUIC ALPN configuration’ı test eder.

```text
8 passed
```

## Paper-to-PoC eşlemesi

| Çerçeve fikri | Replica karşılığı |
|---|---|
| Crypto agility | Agent Card negotiation ve envelope algoritma alanları |
| Quantum-safe key establishment | NIST standardize ML-KEM-768 |
| Agent authentication | ML-DSA-65 |
| Asynchronous forward secrecy | Ephemeral ML-KEM queue + HKDF chain-key ratchet |
| Confidentiality/integrity | AES-256-GCM ve imzalı canonical AAD |
| Transport hardening | QUIC/TLS 1.3, ALPN `pqc-a2a/1`, MTU fragmentation |
| Long-term authenticity | SLH-DSA-SHA2-128s archive manifest signer |
| Freshness | Conversation ID, random message ID ve TTL replay cache |
| Optimization measurement | Payload boyutlarına göre benchmark ve PNG grafik |

## Sınırlamalar ve güvenlik notu

Bu proje bir **PoC ve paper replica**dır. A2A servis discovery, sertifika otoritesi, sertifika iptali, anahtar rotasyonu, donanım güvenlik modülü ve üretim gözlemlenebilirliği eklenmeden gerçek ajan trafiğine açılmamalıdır. QUIC profile ve fragmentation yardımcıları gerçek `aioquic` yapılandırması oluşturur; uygulamanın tam socket lifecycle’ı, sertifika provisioning’i ve TCP fallback gateway’i kapsam dışıdır. Ratchet kayıp/out-of-order paketleri için skipped-key store ve güvenli kalıcı state gerektirir.

## Kaynaklar

[1]: https://zenodo.org/records/22898956 "Post-Quantum Cryptography Integration Framework for Autonomous Agent-to-Agent (A2A) Systems: Architecture, Threats, and Optimization Strategies"
[2]: https://github.com/open-quantum-safe/liboqs-python "liboqs-python bindings"
[3]: https://github.com/open-quantum-safe/liboqs "Open Quantum Safe liboqs"
[4]: https://csrc.nist.gov/pubs/fips/203/final "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard"
[5]: https://csrc.nist.gov/pubs/fips/204/final "FIPS 204: Module-Lattice-Based Digital Signature Standard"
[6]: https://github.com/aiortc/aioquic "aioquic QUIC and HTTP/3 implementation"
