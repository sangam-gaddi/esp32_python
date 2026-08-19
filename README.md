# Secure OTA Firmware Update with Lightweight Cryptography

A working proof-of-concept secure over-the-air firmware update system for the
ESP32, built on **Ascon** — the lightweight cryptography family standardised in
NIST SP 800-232 — with **Ed25519** signatures for authenticity.

An update provider builds an encrypted, signed package; the device downloads it,
verifies it, installs it to an inactive partition, and reboots into it. Anything
that fails verification is rejected and the running firmware is untouched.

```
firmware.bin
    │
    ├─► Ascon-Hash256 ──► digest ──► Ed25519 sign ──► signature
    │
    ├─► Ascon-AEAD128 encrypt (fresh nonce) ──────► ciphertext + tag
    ▼
firmware_v2.sota ──► OTA server ──► ESP32
                                     │
                          Ed25519 verify      → reject
                          version / rollback  → reject
                          Ascon decrypt       → reject (tag)
                          Ascon-Hash256       → reject (digest)
                                     │
                          write inactive partition, reboot
```

---

## Status

| | |
| --- | --- |
| Firmware build | **passes** — ESP-IDF 5.3.1, target `esp32`, 926,720-byte image, zero warnings |
| Host test suite | **130 passed** (Python) |
| C test suite | **16 groups / ~15,200 cases passed** (the same sources the firmware links) |
| Cryptography | validated against **1025** Ascon-Hash256 + **1089** Ascon-AEAD128 official KAT vectors, and RFC 8032 Ed25519 vectors |
| Attack scenarios | **9** tamper modes, all rejected; **7** scenario tests |
| Hardware validation | **not performed — no ESP32 was available.** Nothing on-device has been run. |

That last row is the honest caveat and it is repeated wherever it matters. The
cryptography, the package format, the parser and every rejection path are
genuinely tested on the host. Wi-Fi association, the on-device TLS handshake, the
partition write, the reboot and the rollback behaviour are **not**.

---

## 1. Objective

Build a demonstrable secure OTA system meeting these goals:

1. Firmware **confidentiality** in storage and transit — Ascon-AEAD128
2. Firmware **integrity** — Ascon-Hash256
3. Firmware **authenticity** — Ed25519
4. Protection against **unauthorised** firmware — embedded trusted public key
5. Protection against **rollback** — signed monotonic security version
6. **Safe installation** — ESP-IDF OTA partitions, boot switched only after all checks
7. **Lightweight** cryptography suited to the ESP32 — 1,982 bytes of flash for hash + AEAD
8. Clear demonstration of both **successful and rejected** updates

---

## 2. Architecture

Three parties, deliberately holding different secrets:

| Party | Ed25519 private | Ed25519 public | Ascon key |
| --- | --- | --- | --- |
| Build / signing host | **yes** | yes | yes |
| Update server | no | no | **no** |
| Device | **no** | yes (embedded) | yes (NVS) |

**The server holds no keys at all.** An attacker who fully owns it can delete
packages or lie in its metadata, but cannot produce a package the device accepts.

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — state machine, code
layout, memory behaviour, partition table.

### Layered verification, and why

| Check | Proves | Key |
| --- | --- | --- |
| Ascon-AEAD128 tag | ciphertext + metadata unmodified, from a holder of the shared key | symmetric, on every device |
| Ascon-Hash256 + Ed25519 | the **plaintext** is what the signer approved | asymmetric, private half never on a device |

The symmetric key is on every device and so is extractable. Because the Ed25519
signature covers the AEAD tag, an attacker who steals it can decrypt firmware but
**cannot forge** it. That is the point of the layering, and it is tested directly.

---

## 3. Requirements

### Hardware

* ESP32 development board (ESP32-WROOM-32 / DevKitC or similar)
* **4 MB flash** — required; three 1.25 MB app slots do not fit in 2 MB
* USB cable, and Wi-Fi that both the board and your PC can reach

### Software

| | |
| --- | --- |
| ESP-IDF | **5.3.1** (other 5.x releases will most likely work; 5.3.1 is what this was built with) |
| Python | 3.9 or newer |
| Python packages | `pip install -r server/requirements.txt` |
| Host C compiler | optional, for the C test suite — GCC, Clang, or MSVC Build Tools |

Install ESP-IDF via the [official installer](https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32/get-started/)
or:

```bash
git clone -b v5.3.1 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32          # Windows: .\install.ps1 esp32
. ./export.sh                             # Windows: .\export.ps1
```

---

## 4. Quick start

```bash
# 1. dependencies
pip install -r server/requirements.txt

# 2. keys (Ed25519 pair + Ascon key), and the device's trust anchors
python tools/generate_keys.py --write-device-config

# 3. Wi-Fi and server address
cp main/device_config.h.example main/device_config.h
#   edit WIFI_SSID, WIFI_PASSWORD, OTA_SERVER_URL (your PC's LAN IP)

# 4. build and flash V1
idf.py set-target esp32
idf.py build flash monitor
#   -> "Current Firmware Version: 1.0.0"

# 5. bump main/app_config.h to 2.0.0 / SECURITY_VERSION 2, rebuild (do not flash)
idf.py build

# 6. package it
python tools/create_ota_package.py --firmware build/secure_ota.bin \
    --version 2.0.0 --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota

# 7. serve it
python server/app.py

# -> within 60 s the device downloads, verifies, installs and reboots into 2.0.0
```

Full walkthrough with expected serial output:
**[`docs/DEMO.md`](docs/DEMO.md)**.

No board? Everything cryptographic runs on the host —
see [§8](#8-tests) and `docs/DEMO.md` Part 0.

---

## 5. Key generation

```bash
python tools/generate_keys.py --write-device-config
```

| File | Goes where | Secret? |
| --- | --- | --- |
| `keys/ed25519_private.pem` | signing host only | **yes** — never leaves the build machine |
| `keys/ed25519_public.pem` | embedded in the firmware | no — it is the trust anchor |
| `keys/ota_enc_key.hex` | packaging tool **and** device | **yes** — shared secret |
| `main/crypto_config.h` | generated for the firmware | contains the provisioning key |

`keys/`, `main/crypto_config.h`, `main/device_config.h` and `server/certs/` are all
git-ignored. See [`keys/README.md`](keys/README.md) for which key belongs where and
why, and `docs/SECURITY.md` §5.1 for the honest limitations of compiling a shared
key into a demonstration image.

---

## 6. Creating a package

```bash
python tools/create_ota_package.py \
    --firmware build/secure_ota.bin \
    --version 2.0.0 \
    --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota
```

Inspect or verify any package, stage by stage, exactly as the device does:

```bash
python tools/verify_package.py server/packages/firmware_v2.0.0.sota
```

```
  [1] structure                    PASS  format v1, header 160 B, payload 926720 B
  [2] Ed25519 signature            PASS  signed header[0:96] is authentic
  [3] Ascon-AEAD128 tag            PASS  decrypted 926720 bytes
  [4] Ascon-Hash256                PASS  matches the signed digest

RESULT: ACCEPTED -- this package would install on the device
```

Format specification: [`docs/PACKAGE_FORMAT.md`](docs/PACKAGE_FORMAT.md).

---

## 7. Running the server

```bash
python server/app.py                        # HTTP  on 0.0.0.0:8000
python server/app.py --https --port 8443    # HTTPS, needs tools/make_dev_certs.py
```

| Endpoint | Purpose |
| --- | --- |
| `GET /` | status page |
| `GET /health` | liveness |
| `GET /api/firmware/latest` | metadata for the newest package |
| `GET /api/firmware/list` | every package, plus any it rejected |
| `GET /api/firmware/<version>/package` | download |

The JSON metadata is **untrusted** — a hint so the device can skip a needless
download. Every value that matters is re-read from the signed package header.

For HTTPS:

```bash
python tools/make_dev_certs.py --ip 192.168.1.42
```

The device pins that single CA certificate. **Certificate verification is never
disabled** — there is no insecure option in the firmware. Plain HTTP is supported
for development, gated behind `OTA_ALLOW_INSECURE_HTTP`, and warned about loudly;
it is not secure, though every package-level check still applies.

See [`server/README.md`](server/README.md).

---

## 8. Tests

```bash
# Python: cryptography, format, signatures, attacks, server            (130 tests)
python -m pytest tests/ -v

# C: the same sources the firmware links, compiled and run on this machine
python tests/host/make_fixtures.py
python tests/host/build_and_run.py
```

What is covered:

| Suite | What it proves |
| --- | --- |
| `tests/test_ascon_kat.py` | Python Ascon matches **1025 + 1089** official SP 800-232 vectors, including streaming at awkward chunk sizes |
| `tests/host/test_ascon_kat.c` | the **C** Ascon matches the same vectors; both hash implementations agree; correct at all 8 byte alignments; every tampered input rejected |
| `tests/host/test_package_parser.c` | the **C parser** accepts/rejects **26 fixtures built by the Python packager** exactly as specified; Ed25519 against RFC 8032; no plaintext escapes on failure |
| `tests/test_package.py` | every field offset asserted literally; round-trip at awkward sizes; the encryption key never appears in a package |
| `tests/test_signature.py` | flipping **any** of the 96 signed bytes invalidates the signature; a stolen symmetric key does not permit forgery |
| `tests/test_negative.py` | the seven attack scenarios, through the real command-line tools |
| `tests/test_server.py` | server behaviour, and that it references no key material at all |

### The attack scenarios

| Test | Attack | Expected |
| --- | --- | --- |
| 1 | valid update | **accepted**, firmware byte-identical |
| 2 | modified firmware | rejected — `ASCON AUTHENTICATION FAILED` |
| 3 | invalid / foreign signature | rejected — `INVALID SIGNATURE` |
| 4 | wrong encryption key | rejected — `ASCON AUTHENTICATION FAILED` |
| 5 | rollback to an older security version | rejected — `ROLLBACK DETECTED` |
| 6 | corrupted or truncated package | rejected — structural |
| 7 | interrupted transfer | rejected; previous firmware keeps running |

Build the attack packages yourself:

```bash
python tools/tamper_package.py --mode rollback \
    --input server/packages/firmware_v2.0.0.sota \
    --output build/attacks/rollback.sota --security-version 1
python tools/verify_package.py build/attacks/rollback.sota \
    --current-security-version 2
#   [5] version / anti-rollback      FAIL  security 1 < 2: ROLLBACK
```

Nine modes are available: `flip-ciphertext`, `flip-metadata`, `bad-signature`,
`foreign-signer`, `wrong-key`, `hash-mismatch`, `rollback`, `truncate`,
`bad-magic`.

---

## 9. Measured sizes

From `idf.py size-components` — real build output, not estimates:

| Component | Flash | What it is |
| --- | --- | --- |
| `libascon.a` | **1,982 B** | Ascon-Hash256 **and** Ascon-AEAD128, one-shot and streaming, zero constant tables |
| `libed25519.a` | 5,991 B | Ed25519 verification (TweetNaCl) |
| `libota_package.a` | 1,096 B | package parsing and the verification sequence |
| `libmain.a` | 8,486 B | OTA state machine, Wi-Fi, keys, versions |
| Whole image (`secure_ota.bin`) | 926,720 B | 29% of the app partition free |

Peak additional RAM for an update is about **9.3 KB**, and it does not scale with
firmware size — the image is decrypted, hashed and written in 4 KB chunks and is
never held in memory.

Runtime timings are **not measured** — that needs hardware.
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) provides the harness and leaves every
timing field explicitly blank.

---

## 10. Limitations

The full treatment is in [`docs/SECURITY.md`](docs/SECURITY.md). The essentials:

**Protects against** firmware modification, unauthorised firmware, invalid
signatures, wrong encryption keys, package corruption, rollback attempts,
interrupted updates, and a fully compromised update server.

**Does not protect against:**

* **Physical extraction of the shared Ascon key.** It is in plain NVS and, in this
  demonstration build, compiled into the image. Anyone who can read the flash
  recovers it and can then decrypt packages — though still not forge them. A real
  product needs per-device keys in eFuse plus flash encryption.
* A device that is already fully compromised — code with full privileges can patch
  the verification out. That needs Secure Boot, which is chip-level and
  irreversible.
* A compromised signing host. The private key *is* the authority.
* Hardware fault injection, and physical side-channel analysis (the Ascon
  implementation is not masked, though tag and digest comparisons are
  constant-time).
* Denial of service — an attacker who controls the network can simply block
  updates.

Secure Boot and Flash Encryption are documented as optional hardening.
**Nothing in this project burns an eFuse**, and no irreversible operation is ever
performed automatically.

This is an academic proof of concept. It implements standard cryptography
correctly and proves it against official vectors. It is not audited, and it is not
"unbreakable".

---

## 11. Documentation

| Document | Contents |
| --- | --- |
| [`docs/IMPLEMENTATION_AUDIT.md`](docs/IMPLEMENTATION_AUDIT.md) | Phase 1 audit of the baseline repository: what worked, what was broken, what was missing |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | system and device design, state machine, memory behaviour, partitions |
| [`docs/PACKAGE_FORMAT.md`](docs/PACKAGE_FORMAT.md) | normative `.sota` wire format, byte by byte |
| [`docs/SECURITY.md`](docs/SECURITY.md) | threat model, what is and is not defended, honest limitations |
| [`docs/DEMO.md`](docs/DEMO.md) | step-by-step demonstration, successful update and five attacks |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | measured static sizes; runtime harness with figures left blank |
| [`components/ed25519/README.md`](components/ed25519/README.md) | TweetNaCl provenance and verification hashes |
| [`keys/README.md`](keys/README.md) | which key belongs where |

---

## 12. Cryptographic provenance

Nothing here was invented, and nothing is a "custom" scheme.

| Piece | Origin |
| --- | --- |
| Ascon-p permutation | inherited from the baseline repository; **unmodified**, because it passes all 1025 official hash vectors |
| Ascon mode logic | follows the upstream `ascon-c` reference implementation; restructured into an incremental API for streaming |
| Ed25519 | **TweetNaCl** (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers), public domain, unmodified, SHA-256 hashes recorded |
| KAT vectors | verbatim from `github.com/ascon/ascon-c` (the SP 800-232 drop) |
| Ed25519 vectors | RFC 8032 §7.1, cross-checked against OpenSSL |
| OTA installation | `esp_ota_*` exclusively — no raw flash writes anywhere |

ESP-IDF's mbedTLS does not provide Ed25519, which is why a vetted implementation
is bundled rather than written.

### What was fixed in the inherited code

The baseline's Ascon-Hash256 was algorithmically correct but not usable on the
target:

* it read its input through `((uint32_t*)in)[0]`, which **panics the ESP32** on
  any input that is not 4-byte aligned — the normal case for network buffers — and
  is undefined behaviour besides;
* it was one-shot only, forcing a whole firmware image into RAM;
* it narrowed a 64-bit length to `unsigned long`;
* its debug path printed the entire message — plaintext firmware — to the console.

All four are fixed; the algorithm is untouched, and both the original and the new
streaming implementation are held to the same 1025 vectors.
See `docs/IMPLEMENTATION_AUDIT.md`.

---

## 13. Repository layout

```
main/                   application: OTA state machine, Wi-Fi, keys, versions
components/ascon/       Ascon-Hash256 + Ascon-AEAD128     (no ESP-IDF deps)
components/ed25519/     Ed25519 verification, TweetNaCl   (no ESP-IDF deps)
components/ota_package/ package parsing + verification    (no ESP-IDF deps)
sotalib/                host implementation of the same primitives and format
tools/                  key generation, packaging, verification, tampering, certs
server/                 Flask OTA server (holds no keys)
tests/                  Python suites, C host suites, official KAT vectors
docs/                   audit, architecture, format, security, demo, benchmarks
partitions.csv          factory + ota_0 + ota_1 + otadata
sdkconfig.defaults      tracked build configuration (sdkconfig is generated)
```

The three `components/` directories contain **no ESP-IDF dependencies at all**, so
the exact code the device trusts is compiled and executed on the development
machine by `tests/host/build_and_run.py`. A parser that only ever runs on the
target is a parser nobody has really tested.
