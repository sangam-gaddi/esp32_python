# Implementation Audit — Baseline Repository

**Audit date:** 2026-08-19
**Repository:** `sangam-gaddi/esp32_python` (branch `shubham`, commit `d0d6e61` "Initial commit")
**Method:** static code review plus host-side execution of the existing C code against official Ascon Known-Answer-Test (KAT) vectors.

This document records the state of the project **before** any implementation work. It is Phase 1 of the project plan and is deliberately factual: every claim below is either a direct quotation of the code or the result of a command that was actually executed.

---

## 1. Existing files

| File | Lines | Content |
| --- | --- | --- |
| `.gitignore` | 1 | `build/` only |
| `CMakeLists.txt` | 4 | project `secure_ota` |
| `sdkconfig` | 2008 | generated, ESP-IDF 5.3.1, target `esp32` |
| `main/CMakeLists.txt` | 2 | registers `main.c` |
| `main/main.c` | 11 | one `printf` plus an idle loop |
| `components/ascon/CMakeLists.txt` | 4 | registers 3 sources |
| `components/ascon/include/api.h` | 5 | variant selection defines |
| `components/ascon/include/ascon.h` | 20 | state union |
| `components/ascon/include/constants.h` | 93 | IVs, rates, round constants |
| `components/ascon/include/lendian.h` | 39 | endian macros |
| `components/ascon/include/printstate.h` | 33 | debug macros, compiled out by default |
| `components/ascon/src/hash.c` | 88 | `crypto_hash()` |
| `components/ascon/src/permutations.c` | 107 | `P()`, 32-bit half-word implementation |
| `components/ascon/src/printstate.c` | 50 | debug printers, fully `#ifdef`-ed out |

Total: 15 files, 2473 lines, of which 2008 are the generated `sdkconfig`.

---

## 2. What works

### 2.1 The Ascon hash is correct — verified, not assumed

`components/ascon/src/hash.c` and `permutations.c` were copied out of the repository, compiled on the host with MSVC 19.44 (x64, little-endian), and run against the **official Ascon KAT file** `crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt`, downloaded from the upstream reference repository `github.com/ascon/ascon-c` (branch `main`, the NIST SP 800-232 code drop).

Result:

```
KAT kat_hash256.txt: pass=1025 fail=0
```

**All 1025 official vectors pass.** This settles every question the project brief asked about the existing Ascon code:

| Question from the brief | Answer |
| --- | --- |
| What Ascon variant is implemented? | **Ascon-Hash256** as standardised in **NIST SP 800-232**. Not the older Ascon-Hash v1.2, which produces different digests. |
| Is the implementation correct? | Yes — bit-exact on all 1025 official vectors. |
| Compatible with the Ascon-Hash requirement? | Yes. 32-byte / 256-bit digest, `pa = pb = 12`. |
| Can it safely be reused? | **Yes, and it should be.** |
| Does it need fixes? | Yes — see section 3. The *algorithm* is right; the *plumbing* around it is not ESP32-safe. |
| Is Ascon-128 AEAD available? | **No.** Encryption is entirely absent. |

### 2.2 The permutation `P()` is correct and reusable

`P(ascon_state_t *p, uint8_t round_const)` implements Ascon-p on 32-bit halves (the `opt32` strategy: five 64-bit words held as `{lo, hi}` pairs, S-box applied to each half, linear layer via a 64-bit shift trick).

The round count is encoded in the *start constant*, and the loop `while (rnd >= 0x4b) { ...; rnd -= 15; }` yields:

| Call | Rounds | Ascon usage |
| --- | --- | --- |
| `P(&s, 0xf0)` | 12 | `p^12` (`pa`) |
| `P(&s, 0xb4)` | 8 | `p^8` |
| `P(&s, 0x96)` | 6 | `p^6` |

This matches upstream's `RC0 = 0xf0 … RCb = 0x4b`, constants already present in `constants.h`. Because the hash KAT passes, `P()` is transitively proven correct, so **the AEAD mode can be layered on this same permutation** instead of introducing a second, unaudited copy of Ascon.

### 2.3 The byte/word convention is upstream-compatible

`s.x[i]` holds a **little-endian load** of the corresponding 8 rate bytes, and partial-block padding puts the `0x01` byte at offset `len` (`bytes[len] ^= 0x01` in `hash.c`). That is byte-for-byte the convention of upstream `word.h` (`LOADBYTES` plus `PAD(i) = 0x01 << 8i`), so upstream's vetted AEAD mode logic can be ported without re-deriving byte order.

### 2.4 Debug output is already inert

The brief flagged `printbytes()` / `printstate()` as a possible leak of firmware material. In fact `include/printstate.h` compiles them to `do {} while (0)` unless `ASCON_PRINT_STATE` is defined, and `printstate.c` is entirely wrapped in `#ifdef ASCON_PRINT_STATE`. **No debug output is emitted in the default build.** The residual risk is that someone defines the macro; handled in 3.6.

### 2.5 ESP-IDF scaffolding is valid

The three `CMakeLists.txt` files are correct, minimal, idiomatic ESP-IDF component definitions, and `main.c` would boot. Nothing here needs to be discarded.

---

## 3. Defects found

### 3.1 Unaligned 32-bit access — will fault on ESP32 (severity: high)

`hash.c` reads the message and writes the digest through `uint32_t*` casts:

```c
tmp.l = ((uint32_t*)in)[0];      /* line 45 */
tmp.h = ((uint32_t*)in)[1];      /* line 46 */
...
((uint32_t*)out)[0] = tmp0.l;    /* line 72 */
((uint32_t*)out)[1] = tmp0.h;    /* line 73 */
```

Two distinct problems:

1. **Alignment.** The ESP32's Xtensa LX6 cannot perform unaligned 32-bit loads or stores against data memory; it raises a `LoadStoreAlignment` exception, which panics and reboots. This happens not to matter on x64, which is why the host KAT run passes. In this project the hashed bytes arrive in an HTTP receive buffer at an arbitrary payload offset, so **unaligned pointers are the normal case, not the exception.**
2. **Strict aliasing.** Reading a `const unsigned char*` through a `uint32_t*` lvalue is undefined behaviour. GCC at `-O2` is entitled to miscompile it.

Fix: `memcpy` into a local word, as upstream's `LOADBYTES` / `STOREBYTES` do. The compiler folds that back into a single load wherever it legally can.

### 3.2 No incremental hash API (severity: high — blocks the project)

The only entry point is one-shot:

```c
int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long inlen);
```

That requires the **whole message in RAM simultaneously**. The firmware image to hash is on the order of 1 MB; the ESP32 has roughly 300 KB of usable heap, and brief section 17 explicitly forbids buffering the whole image. An `init` / `update` / `final` API is mandatory and does not exist.

### 3.3 Ascon-128 AEAD is completely missing (severity: high — blocks the project)

There is no encryption, no decryption, and no tag verification anywhere in the repository. `constants.h` holds the constants an AEAD would need (`ASCON_128_IV`, `ASCON_128A_IV`, `ASCON_128_RATE`, `ASCON_128_PB_ROUNDS`, `ASCON_TAG_SIZE`) but no code uses them. Confidentiality — security goal 1 — is unimplemented.

### 3.4 `unsigned long` truncation (severity: low)

`hash.c:30`, `unsigned long len = inlen;` narrows an `unsigned long long`. `unsigned long` is 32-bit on both Windows and Xtensa, so messages of 4 GiB or more are silently truncated. MSVC reports it:

```
hash.c(30): warning C4244: 'initializing': conversion from 'unsigned __int64'
            to 'unsigned long', possible loss of data
```

Harmless for firmware images, but a real narrowing bug and trivially fixed.

### 3.5 Obscure aliasing in the squeeze tail (severity: low; behaviour is correct)

```c
uint8_t* bytes = (uint8_t*)&tmp;   /* line 57 */
...
tmp = s.w[0];
tmp.x = U64LE(tmp.x);
memcpy(out, bytes, len);           /* line 84 — reads back through the alias */
```

This is *correct* — it copies the freshly stored `tmp` — but only if the reader notices that `bytes` aliases `tmp` 27 lines earlier. A maintenance hazard rather than a bug.

### 3.6 The debug path is a latent leak (severity: low)

Built with `-DASCON_PRINT_STATE`, `crypto_hash()` prints the **entire message** (`printbytes("m", in, inlen)`) — that is, plaintext firmware — plus every intermediate permutation state. Fine for an offline KAT harness, never acceptable in firmware. Needs a hard guard so a device build cannot enable it.

### 3.7 `api.h` couples the component to a single variant (severity: low)

`ASCON_HASH_BYTES` and `ASCON_HASH_ROUNDS` live in `api.h` as bare `#define`s with no include guard and no namespace. Adding a second primitive to the same component collides with this. Needs restructuring, not deletion.

---

## 4. What is missing

Measured against the project's own acceptance criteria, the baseline satisfies **1 of 25** items (Ascon-Hash works). Missing:

**Device firmware**

- Wi-Fi station bring-up, retry, IP acquisition
- NVS initialisation and persistent device state
- An OTA partition table (see section 7) and any use of `esp_ota_ops`
- HTTP(S) client, update check, metadata fetch, chunked package download
- Package parser and format validation
- Streaming Ascon-AEAD128 decryption and tag verification
- Streaming Ascon-Hash256 computation and comparison against the signed digest
- Ed25519 signature verification. No Ed25519 implementation is present, and ESP-IDF's bundled mbedTLS does **not** provide EdDSA
- Trusted public-key configuration; provisioned symmetric-key storage
- Firmware-version and monotonic security-version anti-rollback logic
- An explicit OTA state machine and demo-grade logging
- Anything resembling `ota_manager.c`, `package_parser.c`, `version_manager.c`

**Host and server side** — everything. There is no `server/`, no `tools/`, no `tests/`, no `docs/`, no key generation, no package builder, no OTA server, no automated tests.

**Documentation** — there is no `README.md` at all.

---

## 5. Ascon implementation details

| Property | Value |
| --- | --- |
| Primitive | Ascon-Hash256 (NIST SP 800-232) |
| Digest length | 32 bytes (`ASCON_HASH_BYTES 32`, `CRYPTO_BYTES 32`) |
| Rounds | `pa = pb = 12` (`ASCON_HASH_ROUNDS 12`, start constant `0xf0`) |
| Rate | 8 bytes (`ASCON_HASH_RATE 8`) |
| IV | precomputed post-`p^12` words `ASCON_HASH_IV0..4` |
| Strategy | `opt32` — 64-bit words as `{lo,hi}` 32-bit halves |
| Word convention | little-endian byte load into `s.x[i]` |
| Padding | `0x01` at byte offset `len`, i.e. `PAD(i) = 0x01 << 8i` |
| Endianness | `lendian.h`; correct for LE and BE (`_MSC_VER`, `__BYTE_ORDER__`) |
| KAT status | **1025 / 1025 official vectors pass** |
| Verdict | **Reuse. Fix the plumbing, keep the algorithm.** |

Reviewed specifically for the defect classes the brief named:

| Checked for | Finding |
| --- | --- |
| Endian issues | None. `lendian.h` handles both orders; KAT confirms the LE path. |
| Incorrect padding | None. Matches upstream `PAD()`. |
| Incorrect IV | None. Matches SP 800-232 Ascon-Hash256. |
| Incorrect permutation rounds | None. 12 rounds confirmed from the constant decrement. |
| Incorrect finalisation | None. The squeeze loop emits exactly 32 bytes. |
| Incorrect output handling | Correct, but through an obscure alias (3.5). |
| Buffer overflows | None found. All writes bounded by `CRYPTO_BYTES`. |
| Alignment problems | **Yes — 3.1. Will fault on ESP32.** |
| Undefined behaviour | **Yes — 3.1 strict aliasing, 3.4 narrowing.** |
| Debugging prints | Compiled out by default; latent risk 3.6. |
| Memory safety | The one-shot API forces a full-image RAM buffer (3.2). |

---

## 6. ESP-IDF configuration

| Setting | Value | Comment |
| --- | --- | --- |
| ESP-IDF version | **5.3.1** | Recorded in the generated `sdkconfig` header. |
| `CONFIG_IDF_TARGET` | `esp32` | Xtensa LX6, dual core. |
| `CONFIG_ESPTOOLPY_FLASHSIZE` | **`2MB`** | The ESP-IDF *default*, not a detected value. Two OTA slots do not fit comfortably in 2 MB. Must be raised to 4 MB. |
| `CONFIG_ESPTOOLPY_FLASHMODE` | `dio` | Fine. |
| `CONFIG_COMPILER_OPTIMIZATION_DEBUG` | `y` (`-Og`) | Acceptable for a demo; relevant to benchmarking. |
| `CONFIG_ESP_MAIN_TASK_STACK_SIZE` | `3584` | Too small once TLS, OTA and crypto share the task. |
| `CONFIG_ESP_WIFI_ENABLED` | `y` | Available. |
| `CONFIG_ESP_HTTP_CLIENT_ENABLE_HTTPS` | `y` | HTTPS transport available. |
| `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE` | `y`, full, 200 certs | Server-certificate verification is possible. |
| `CONFIG_MBEDTLS_HARDWARE_{AES,SHA,MPI}` | `y` | Present, but irrelevant: there is no hardware acceleration for Ascon or Ed25519. |
| `CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP` | not set | `esp_https_ota` currently refuses plain HTTP. |
| `CONFIG_ESP_HTTPS_OTA_DECRYPT_CB` | not set | Pre-decryption callback not enabled. |

## 7. OTA partition configuration — absent

```
CONFIG_PARTITION_TABLE_SINGLE_APP=y
CONFIG_PARTITION_TABLE_FILENAME="partitions_singleapp.csv"
```

The project uses the **single-app** partition table. There is no `ota_0`, no `ota_1`, no `otadata`, and no `partitions.csv` in the repository. Therefore **OTA is physically impossible** in the baseline: `esp_ota_get_next_update_partition()` would fail. This is the largest structural gap on the device side.

## 8. Security configuration

| Setting | Value | Comment |
| --- | --- | --- |
| `CONFIG_SECURE_BOOT` | not set | Optional hardening; needs irreversible eFuse burns. Out of scope by default per brief section 25. |
| `CONFIG_SECURE_FLASH_ENC_ENABLED` | not set | Same. |
| `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` | not set | Needed for `esp_ota_mark_app_valid_cancel_rollback()`. |
| `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` | not set | Needed for the eFuse-backed monotonic security version. |
| `CONFIG_APP_PROJECT_VER_FROM_CONFIG` | not set | The version string comes from git; the project needs an explicit *signed* version instead. |
| Committed secrets | **none found** — a good starting point. |
| `.gitignore` coverage | `build/` only; would not protect a future `keys/` directory. |

## 9. Dependencies

- No `idf_component.yml` anywhere, no `dependencies.lock`, no managed components.
- No `sdkconfig.defaults`. The whole configuration lives in the generated, committed `sdkconfig`. That is tolerable, but `sdkconfig.defaults` is the reproducible way to pin project settings.
- **No Ed25519 implementation is available.** ESP-IDF 5.3's mbedTLS offers Curve25519 ECDH but not Ed25519 signatures, so a vetted implementation must be added as a component.
- Host side: nothing exists. Available on this machine: Python 3.11.0 with `cryptography` 43.0.3 (provides Ed25519), `Flask` 3.0.3, `requests` 2.32.3, `pytest` 8.3.2.

## 10. Build status of the baseline

**Not established — ESP-IDF is not installed on this machine.**

Verified absent: `IDF_PATH` unset, `idf.py` not on `PATH`, and no ESP-IDF installation under `C:\Espressif`, `D:\Espressif`, `C:\esp`, `D:\esp`, `%USERPROFILE%\esp`, or `%USERPROFILE%\.espressif`.

Also relevant to planning:

- **No ESP32 is connected.** Serial-port enumeration returns nothing, and no CP210x / CH340 / FTDI USB-UART device is present. `idf.py flash` and `idf.py monitor` cannot run, so no on-hardware result is claimed anywhere in this project.
- Disk: `C:` has **0.4 GB** free, `D:` has 19.6 GB free. An ESP-IDF install — roughly 1.5 GB of framework plus about 2 GB of toolchains, which default to `%USERPROFILE%\.espressif` on `C:` — does not fit on `C:` as-is and needs `IDF_TOOLS_PATH` redirected to `D:`.

What *can* be verified here, and will be:

- MSVC 19.44 (Visual Studio 2022 Build Tools) compiles and runs C on the host — already used for the KAT run in 2.1. All cryptography and all package parsing and verification logic will be written free of ESP-IDF dependencies, so the **same C sources the firmware uses** can be compiled and tested on the host and cross-checked against the Python packager.
- Python 3.11 for the server, the package generator, and the negative tests.

---

## 11. Conclusion and plan

The baseline holds one genuinely valuable asset — a **correct, standards-conformant Ascon-Hash256 implementation**, now proven against all 1025 official vectors — plus valid ESP-IDF scaffolding. Everything else in the security flow is missing.

The work is therefore *additive*, not a rewrite:

1. **Keep** `P()`, `constants.h`, `lendian.h`, `ascon.h` and the `crypto_hash()` entry point.
2. **Fix** the alignment, aliasing and narrowing defects (3.1, 3.4) and harden the debug path (3.6).
3. **Add** a streaming Ascon-Hash256 API and an Ascon-AEAD128 implementation, both built on the existing audited permutation, both KAT-validated.
4. **Add** a vetted Ed25519 verifier as a component.
5. **Add** the OTA partition table, package parser, version manager, OTA state machine, Wi-Fi and NVS-backed key and version storage.
6. **Add** host tooling: key generation, package builder, OTA server, and automated positive **and negative** tests.
7. **Document** the package format, architecture, threat model and demo script.

Hardware validation is out of reach in this environment and is reported as such throughout.
