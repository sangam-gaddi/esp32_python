# Security Model

This document states what the project protects against, what it does not, and
which claims have actually been tested. It is deliberately blunt about the gaps:
a prototype that oversells itself is less useful than one whose limits are known.

**This is an academic proof of concept.** It is not "military grade", not
"unbreakable", and not audited. It implements real, standard cryptography
correctly and validates it against official test vectors — that is the claim, and
it is the only claim.

---

## 1. Trust model

| Party | Ed25519 private key | Ed25519 public key | Ascon-AEAD128 key |
| --- | --- | --- | --- |
| Build / signing host | **yes** | yes | yes |
| Update server | no | no | **no** |
| Device | **no** | yes (embedded) | yes (in NVS) |
| Attacker on the network | no | yes (it is public) | no |

Two consequences follow directly from the table.

**The server is untrusted by construction.** It holds no key material at all —
`tests/test_server.py::test_server_module_holds_no_key_material` asserts that
`server/app.py` does not even reference a key-loading function. An attacker who
fully owns the server can delete packages, serve stale ones, or lie in the JSON
metadata. They cannot produce a package the device accepts, because that requires
a signature under a key the server has never held.

**The device cannot authorise its own updates.** It has no signing key. A
compromised device cannot manufacture firmware that other devices would accept.

---

## 2. Security goals and how each is met

| # | Goal | Mechanism | Where |
| --- | --- | --- | --- |
| 1 | Firmware confidentiality in storage and transit | Ascon-AEAD128 encryption, fresh 128-bit nonce per package | `ascon_aead128.c` |
| 2 | Firmware integrity | Ascon-Hash256 over the plaintext, compared after decryption | `ascon_hash256.c`, `ota_package.c` |
| 3 | Firmware authenticity | Ed25519 signature over `header[0:96]`, verified against an embedded trusted key | `ed25519_verify.c` |
| 4 | Protection against unauthorised firmware | The trusted public key is compiled in and never taken from the package | `device_keys.c` |
| 5 | Protection against rollback | Monotonic `security_version` in NVS, compared against the *signed* field | `version_manager.c` |
| 6 | Safe installation | `esp_ota_*` to the inactive partition; boot switched only after all checks | `ota_manager.c` |
| 7 | Lightweight cryptography suited to the ESP32 | Ascon: **1,982 bytes** of flash for hash + AEAD combined, ~130-byte streaming context | measured, see BENCHMARKS |
| 8 | Demonstrable acceptance *and* rejection | Nine attack packages, seven scenario tests | `tamper_package.py`, `test_negative.py` |

---

## 3. Why the design is layered this way

A reasonable question: if Ascon-AEAD128 already authenticates the ciphertext, why
also hash and sign?

Because they authenticate **different things under different keys**.

| Check | Proves | Under which key | Fails if… |
| --- | --- | --- | --- |
| Ascon-AEAD128 tag | the ciphertext and metadata came from someone holding the shared key, unmodified | symmetric, shared with the device | payload or metadata altered; wrong device key |
| Ascon-Hash256 + Ed25519 | the **plaintext** is what the signer approved | asymmetric, private half never on the device | signed by anyone else; digest does not describe the firmware |

The symmetric key is on every device. If a single device is opened and its key
extracted, the attacker can encrypt arbitrary firmware and compute a valid tag
for it. What they still cannot do is sign it — and the signature covers the tag,
so replaying a genuine signature fails because that signature commits to a
different tag.

**A leaked encryption key therefore costs confidentiality, not authenticity.**
That is the reason the signed region extends to offset 96 rather than stopping at
80, and it is tested directly:
`tests/test_signature.py::test_stealing_the_symmetric_key_does_not_allow_forgery`.

The hash comparison after decryption then catches the remaining case that neither
the tag nor the signature alone would: a build server that is compromised or
simply buggy, producing a package that is correctly encrypted *and* correctly
signed but whose declared digest does not match the firmware.
`tools/tamper_package.py --mode hash-mismatch` builds exactly that, and it is the
only tamper mode for which `OTA_PKG_ERR_HASH` is the first failure.

---

## 4. Attacks the prototype defeats

Each row has a corresponding automated test. "Tested" means an automated test
asserts the rejection, on the host, in both the Python and C implementations
where applicable.

| Attack | Result | Reported as | Tested |
| --- | --- | --- | --- |
| Modify one byte of encrypted firmware | rejected | `ASCON AUTHENTICATION FAILED` | `test_negative.py::test_2_*`, C fixtures |
| Modify any byte of the metadata | rejected | `INVALID SIGNATURE` | `test_signature.py::test_full_verify_rejects_any_signed_byte_change` — sweeps **all 96 signed bytes** |
| Replace the signature with random bytes | rejected | `INVALID SIGNATURE` | `test_3_*`, `bad_signature.sota` |
| Sign with an attacker's own key | rejected | `INVALID SIGNATURE` | `test_3_unauthorised_firmware_cannot_claim_a_high_version` |
| Graft a genuine signature onto a different header | rejected | `INVALID SIGNATURE` | `test_signature_from_a_different_package_is_not_transferable` |
| Encrypt under a different symmetric key | rejected | `ASCON AUTHENTICATION FAILED` | `test_4_*`, `wrong_key.sota` |
| Forge a package using a **stolen** symmetric key | rejected | `INVALID SIGNATURE` | `test_stealing_the_symmetric_key_does_not_allow_forgery` |
| Replay a genuinely-signed older release | rejected | `ROLLBACK DETECTED` | `test_5_*`, `rollback.sota` |
| Relabel an old package with a higher version | rejected | `INVALID SIGNATURE` | `test_version_fields_are_authenticated` |
| Truncate the package | rejected | `package truncated` | `test_6_*`, `test_7_*` (4 truncation points) |
| Corrupt the magic, format version or size fields | rejected | structural error | `test_6_*`, 9 C fixtures |
| Interrupt the transfer at any point | rejected, previous firmware keeps running | `package truncated` | `test_7_interrupted_download_is_never_accepted` |
| Substitute a package built for a different device fleet | rejected | tag or signature failure | implied by key separation |
| Serve a valid package with lying JSON metadata | metadata ignored; header decides | n/a | metadata is documented as untrusted |

### Cross-implementation coverage

The same rejections are verified twice, in independently written code:

* **Python** (`sotalib/`) — 130 tests
* **C** (the exact firmware sources) — 16 test groups over 26 fixture packages,
  compiled and executed on the host

Both are pinned to the official Ascon KAT vectors (1025 hash + 1089 AEAD) and to
the RFC 8032 Ed25519 vectors, so neither can drift into a private dialect.

---

## 5. What the prototype does **not** protect against

This section is the important one.

### 5.1 Physical extraction of the symmetric key

**The single largest weakness.** The Ascon key is stored in plain NVS, and in this
demonstration build it is also compiled into the firmware image
(`crypto_config.h`) so that a single `idf.py flash` produces a working device.

Anyone who can read the flash — a chip reader, or `esptool.py read_flash` over
USB — recovers it. With it they can decrypt any package, which ends
confidentiality for the whole fleet, since every device shares one key.

They still cannot **forge** firmware (§3), so authenticity survives. But
confidentiality does not.

What a real product does instead:

* a **unique per-device key**, provisioned at manufacture, so one extracted key
  compromises one device;
* the key in **eFuse** or NVS-encrypted storage, not in a build artefact;
* **flash encryption** enabled so the flash contents are useless when read out;
* the key never present in any image that is distributed.

The NVS-backed design in `main/device_keys.c` is the right shape for this — it
reads from NVS and only falls back to the compiled-in key on a virgin device,
logging a warning when it does — but the demonstration fallback is what makes it
extractable. Do not present this as production key management.

### 5.2 Other limitations

| Not protected against | Why |
| --- | --- |
| **A fully compromised device** | Code already running with full privileges can patch out the verification. Defeating this needs Secure Boot (§7), which is chip-level and irreversible. |
| **A compromised signing host** | The private key *is* the authority. Steal it and you can sign anything. Mitigation is organisational: an HSM, an air-gapped signer, key rotation, short-lived signing certificates. |
| **Hardware fault injection / glitching** | Voltage or clock glitching can skip a comparison. Requires physical access and hardened countermeasures the ESP32 does not offer. |
| **Side-channel analysis** | The Ascon implementation is not masked. Power or EM analysis with physical access could recover the key. Tag and digest comparisons *are* constant-time (`ascon_notzero`, `ascon_hash256_equal`), which addresses the easy remote timing oracle, not physical DPA. |
| **Denial of service** | An attacker who controls the network can simply block updates. Nothing here prevents that; the device stays on its current firmware, which is the safe failure mode but is still a failure. |
| **Traffic analysis over HTTP** | With the development HTTP transport, an observer sees that an update happened, its size, and the metadata. The firmware stays encrypted. |
| **Rollback across a factory reset** | The version floor lives in NVS. Erasing NVS (physical access, or `idf.py erase-flash`) resets it. eFuse-backed anti-rollback (§7) is the fix, at the cost of irreversibility. |
| **Malicious-but-signed firmware** | If the legitimate signer signs something harmful, every check passes by design. Signatures prove origin, never intent. |
| **Nonce reuse by a broken packager** | The packager draws a fresh nonce from `os.urandom()` per package and only accepts an explicit nonce behind a warned testing flag. A modified packager that reused one would break confidentiality; the device cannot detect this. |

---

## 6. Transport security

The application-level cryptography is what protects the firmware. The transport
is a second, independent layer.

**HTTPS** is supported and is what a deployment should use.
`tools/make_dev_certs.py` produces a development CA and a server certificate with
the correct `subjectAltName`; the device pins that single CA certificate rather
than trusting a bundle of public roots, which is both correct for a private server
and about 64 KB smaller.

**Certificate verification is never disabled.** There is no "insecure" or
"skip verification" option anywhere in the firmware. `skip_cert_common_name_check`
is explicitly `false`. If TLS fails, the update does not happen.

**Plain HTTP is supported for development only**, and is gated behind
`OTA_ALLOW_INSECURE_HTTP` in `device_config.h` so that shipping it has to be a
deliberate act. When it is in use the firmware prints a five-line warning on every
check, and the server prints one at start-up and on its status page.

To be precise about what HTTP costs and does not cost:

* **Still enforced:** the Ed25519 signature, the Ascon-AEAD128 tag, the
  Ascon-Hash256 digest, and anti-rollback. A tampered package delivered over a
  hostile link is still rejected — the negative tests do not depend on the
  transport at all.
* **Lost:** confidentiality of the metadata, concealment of the fact that an
  update is happening, and any protection against an attacker who blocks or
  redirects the request.

Plain HTTP is not secure. Do not describe an HTTP demonstration as a secure
transport.

---

## 7. Optional hardening: Secure Boot and Flash Encryption

**Neither is enabled, and nothing in this project burns an eFuse.** These are
described so the gap is understood, not as steps to run casually.

### Secure Boot v2

The bootloader verifies an RSA-3072 signature over the application before running
it, with the public key digest held in eFuse.

*What it adds:* protection against an attacker who can write flash directly —
exactly the gap in §5.1 and §5.2. Without it, physical flash access bypasses
every check in this project, because the attacker simply writes their own image
instead of going through the OTA path.

*What it costs:* **irreversible**. Burning the key digest eFuse is permanent. A
mistake bricks the board. Every future image must be signed with the matching
key; lose it and the device can never be updated again. It also cannot be tested
in this environment, since no ESP32 was available.

To enable deliberately: `idf.py menuconfig` → Security features → Enable hardware
Secure Boot in bootloader, then follow the ESP-IDF Secure Boot v2 documentation
in full before flashing anything.

### Flash Encryption

The flash controller transparently encrypts flash contents with a key in eFuse.

*What it adds:* an attacker reading the flash gets ciphertext, so the provisioned
Ascon key and the firmware stay confidential. This directly addresses §5.1.

*What it costs:* also **irreversible**, and it complicates development flashing
significantly (release mode disables the UART download path used to re-flash).

### `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`

ESP-IDF's own anti-rollback uses a monotonic secure-version eFuse, which the
bootloader refuses to boot below.

*What it adds:* the version floor survives an NVS erase (§5.2).

*What it costs:* eFuse writes are permanent and monotonic. Once the chip's secure
version is raised it can never run an older image again — including a known-good
one you might want for debugging.

**This project deliberately enforces anti-rollback in software instead**
(`main/version_manager.c`), because the software version is testable, reversible,
and appropriate for a demonstration. `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`
*is* enabled — that one is software-only, reversible, burns nothing, and is what
makes a bad update self-healing.

---

## 8. Cryptographic implementation notes

### Validation

| Primitive | Validated against | Result |
| --- | --- | --- |
| Ascon-Hash256 (C, both implementations) | 1025 official SP 800-232 vectors | pass |
| Ascon-AEAD128 (C) | 1089 official SP 800-232 vectors, encrypt and decrypt | pass |
| Ascon-Hash256 (Python) | the same 1025 vectors | pass |
| Ascon-AEAD128 (Python) | the same 1089 vectors | pass |
| Ed25519 (C, TweetNaCl) | RFC 8032 §7.1 vectors 1–3 | pass |
| Ed25519 (Python) | the same RFC 8032 vectors | pass |
| C parser ↔ Python packager | 26 cross-validation fixtures | pass |

Vector files are committed verbatim in `tests/vectors/` with their provenance
recorded, so the claims are re-checkable rather than asserted.

### Nothing was invented

* **Ascon-p** — the permutation inherited from the baseline repository, kept
  unmodified because it passes all 1025 hash vectors (see
  `IMPLEMENTATION_AUDIT.md` §2.2). The AEAD is layered on that same audited
  permutation rather than introducing a second copy of Ascon.
* **Ascon mode logic** — follows the upstream `ascon-c` reference
  implementation; the only change is restructuring into an incremental API for
  streaming.
* **Ed25519** — TweetNaCl, unmodified, with recorded SHA-256 hashes
  (`components/ed25519/README.md`). No elliptic-curve arithmetic was written for
  this project.
* **OTA installation** — `esp_ota_*` exclusively. No raw flash writes.

### Defects fixed in the inherited code

From the Phase 1 audit:

* **Unaligned 32-bit loads** (`((uint32_t*)in)[0]`) — would raise a
  `LoadStoreAlignment` panic on the ESP32 for any input not 4-byte aligned, which
  is the normal case for network buffers. Also undefined behaviour under strict
  aliasing. Replaced with memcpy-based helpers, verified at all eight alignments.
* **No streaming API** — forced buffering a whole image in RAM. Added.
* **`unsigned long` narrowing** of a 64-bit length. Fixed.
* **The debug path** printed the entire message — i.e. plaintext firmware — plus
  every intermediate permutation state. It was already compiled out by default;
  `printstate.h` now `#error`s if anyone tries to enable it in a device build.

### Deliberate hygiene

* Tag comparison uses `ascon_notzero()`, digest comparison uses
  `ascon_hash256_equal()` — both branch-free, so a rejection does not reveal how
  many bytes matched.
* Failed AEAD decryption zeroes its output buffer, so unauthenticated plaintext
  cannot be used by a caller that ignores the return value. Tested:
  `test_no_plaintext_on_failure`.
* Key buffers are wiped with a `volatile`-qualified loop after use.
* No key material is ever logged. The boot log prints an Ascon-Hash256
  *fingerprint* of the key, which lets host and device be compared without
  disclosing anything.
* The firmware detects an all-zero trusted public key (the untouched template)
  and says so loudly, rather than rejecting every update for a reason that looks
  cryptographic.

---

## 9. What has not been verified

Stated plainly, because it matters more than the list of things that were:

* **No ESP32 hardware was available.** The firmware compiles cleanly for
  `esp32` with ESP-IDF 5.3.1 and produces a 926 KB image, but it has never been
  flashed, booted, or run. Nothing in this repository claims otherwise.
* Consequently: Wi-Fi association, the TLS handshake on-device, the actual OTA
  partition write, the reboot into new firmware, and the rollback behaviour are
  **untested on hardware**. They follow standard ESP-IDF patterns, which is
  evidence of nothing.
* **No runtime performance figures exist.** `docs/BENCHMARKS.md` provides the
  measurement harness and the real static sizes from the build; every timing
  field is marked "not measured" rather than estimated.
* The cryptography, the package format, the parser, the verification order and
  every rejection path *are* tested — on the host, with the same C sources the
  firmware links, against official vectors.
