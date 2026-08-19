# Benchmarks

## Reading this document

There are two kinds of number here, kept strictly apart:

* **Measured** — produced by a command that was actually run. Every such figure
  names the command.
* **Not measured** — requires an ESP32, and no ESP32 was available. These are left
  blank. They are **not** estimated, extrapolated, or filled in from published
  figures for other platforms.

A harness is provided so that anyone with a board can fill the blanks in.

---

## 1. Static footprint — measured

Source: `idf.py size` and `idf.py size-components`, ESP-IDF 5.3.1, target `esp32`,
`-Os` (`CONFIG_COMPILER_OPTIMIZATION_SIZE=y`).

### Whole image

Two size figures appear below and they measure different things, so both are
given rather than one being passed off as the other:

* **`secure_ota.bin` = 926,720 bytes (`0xe2400`)** -- the file on disk, which is
  what gets flashed and what the packager encrypts. This is the number to quote.
* **Total of all linked sections = 926,616 bytes** -- from `idf.py size`. Slightly
  smaller because the `.bin` is padded and carries an appended image hash.

| Metric | Value |
| --- | --- |
| `secure_ota.bin` on disk | **926,720 bytes** (`0xe2400`) |
| Total of linked sections | 926,616 bytes |
| Flash code (`.text`) | 650,994 bytes |
| Flash data (`.rodata`) | 171,488 bytes |
| IRAM used | 88,050 bytes (67.2% of 131,072) |
| DRAM used | 36,172 bytes (20.0% of 180,736) |
| App partition | 1,310,720 bytes (`0x140000`) |
| **Free in the partition** | **384,000 bytes (29%)** |

The image fits comfortably, and there is room for three such slots
(`factory` + `ota_0` + `ota_1`) in 4 MB of flash.

### This project's own code

| Component | Total | `.text` | `.rodata` | What it is |
| --- | --- | --- | --- | --- |
| `libascon.a` | **1,982 B** | 1,982 | 0 | Ascon-Hash256 **and** Ascon-AEAD128, both APIs |
| `libed25519.a` | 5,991 B | 4,199 | 1,792 | Ed25519 verification (TweetNaCl) |
| `libota_package.a` | 1,096 B | 1,096 | 0 | package parsing + verification sequence |
| `libmain.a` | 8,486 B | 7,662 | 783 | OTA state machine, Wi-Fi, keys, versions |
| **Total added** | **17,555 B** | | | ~1.9% of the image |

The Ascon figure is the headline result for a "lightweight cryptography" project:
**hash and authenticated encryption together, in under 2 KB of flash, with no
constant tables at all** (`.rodata` is zero — the round constants are immediates
and the IVs are five 64-bit words). For comparison, the rest of the image is
dominated by Wi-Fi and mbedTLS, which are needed for the *transport*, not for the
firmware verification.

### RAM per update

Struct sizes are `sizeof()` values from a compiled binary, not arithmetic:
`tests/host/` builds the same headers, and `uint64_t` alignment is 8 bytes on
Xtensa as on x86-64, so they carry over to the target. Buffer sizes come from
`OTA_DOWNLOAD_CHUNK_SIZE` in `main/app_config.h`.

| Allocation | Size | Where |
| --- | --- | --- |
| Ciphertext download buffer | 4,096 B | heap (`malloc`, checked) |
| Plaintext buffer | 4,111 B | heap (`malloc`, checked) |
| `ota_pkg_payload_ctx_t` | 200 B | stack |
| ├─ `ascon_aead128_ctx_t` | 80 B | state 40, key 16, buffer 16, + padding |
| └─ `ascon_hash256_ctx_t` | 56 B | state 40, buffer 8, + padding |
| Parsed header (`ota_pkg_header_t`) | 320 B | stack (160 raw + parsed fields) |
| Ed25519 verify scratch | 640 B | stack, bounded by `ED25519_MAX_MESSAGE_BYTES` |
| **Peak added for an update** | **9,367 B** | independent of firmware size |

Nothing scales with the image being installed — that is the point of the streaming
API. A 1 MB update and a 100 KB update cost the same RAM. Confirmed by streaming a
real 926,720-byte package through the device parser on the host with these exact
buffer sizes: 8,207 bytes of buffers, and it accepted the package and rejected a
single-bit-flipped copy of it.

---

## 2. Host-side cryptography — measured

Not representative of ESP32 performance (a desktop x86-64 versus a 240 MHz
Xtensa), but it does confirm both implementations are functional and gives a sense
of relative cost.

Source: `python -m pytest tests/test_ascon_kat.py` and
`python tests/host/build_and_run.py`, on the development machine.

| Suite | Cases | Wall clock |
| --- | --- | --- |
| Python Ascon KAT (1025 hash + 1089 AEAD, plus streaming and tamper tests) | 29 tests | ~14 s |
| C Ascon KAT (same vectors + streaming + alignment + tamper) | 11 groups, 15,092 cases | < 1 s |
| C package parser (26 fixtures + RFC 8032 + streaming) | 5 groups, 124 cases | < 1 s |

The pure-Python implementation is roughly three orders of magnitude slower than
the C one, which is expected and irrelevant — it only ever packages firmware on a
workstation.

---

## 3. Device runtime — NOT MEASURED

**No ESP32 hardware was available.** Every field below is blank because no
measurement was taken. Do not fill these in from other sources; measure them.

| Metric | Value |
| --- | --- |
| Ascon-Hash256 throughput (KB/s) | *not measured* |
| Ascon-AEAD128 decrypt throughput (KB/s) | *not measured* |
| Ed25519 verification time (ms) | *not measured* |
| Time to hash a 926 KB image (s) | *not measured* |
| Time to decrypt a 926 KB image (s) | *not measured* |
| OTA download time over HTTP (s) | *not measured* |
| OTA download time over HTTPS (s) | *not measured* |
| Total update time, check to reboot (s) | *not measured* |
| Flash write throughput (KB/s) | *not measured* |
| Free heap before an update (bytes) | *not measured* |
| Free heap at peak during an update (bytes) | *not measured* |
| Boot time to Wi-Fi connected (ms) | *not measured* |

### What the firmware already reports

Instrumentation is in place, so a board produces most of these figures with no
code changes. `main/ota_manager.c` logs:

* **Ed25519 verification time**, in microseconds, from `esp_timer_get_time()`:
  ```
  I (11102) OTA: Signature verification successful (nnnnn us)
  ```
* **Download + decrypt + hash + flash-write duration** for the whole payload:
  ```
  I (4xxxx) OTA: Package downloaded (926720 bytes in nnnnn ms)
  ```
* **Free heap** every 32 KB of progress, and in the 15-second heartbeat:
  ```
  I (12182) OTA:   32768 / 926720 bytes (3%), heap nnnnnn
  I (15312) BOOT: alive: firmware 2.0.0, OTA state IDLE, checks 1, rejections 0, heap nnnnnn
  ```

Dividing the payload duration by the size gives combined
decrypt + hash + flash throughput. Separating the three needs the microbenchmark
below.

---

## 4. Microbenchmark harness

To measure the primitives in isolation on hardware, add this to `app_main()`
after `device_keys_init()`. It is not compiled in by default — a benchmark loop
in a security demo is noise.

```c
#include "ascon_aead128.h"
#include "ascon_hash256.h"
#include "esp_timer.h"

static void benchmark_crypto(void) {
    const size_t N = 64 * 1024;               /* 64 KB per pass */
    uint8_t *buf = malloc(N);
    uint8_t *out = malloc(N);
    if (!buf || !out) { free(buf); free(out); return; }
    memset(buf, 0xA5, N);

    uint8_t digest[ASCON_HASH256_BYTES];
    uint8_t key[16] = {0}, nonce[16] = {0}, tag[16];

    /* Ascon-Hash256 */
    int64_t t = esp_timer_get_time();
    ascon_hash256(digest, buf, N);
    int64_t hash_us = esp_timer_get_time() - t;

    /* Ascon-AEAD128 encrypt */
    t = esp_timer_get_time();
    ascon_aead128_encrypt(out, tag, key, nonce, buf, N, NULL, 0);
    int64_t enc_us = esp_timer_get_time() - t;

    /* Ascon-AEAD128 decrypt + verify */
    t = esp_timer_get_time();
    int bad = ascon_aead128_decrypt(buf, key, nonce, out, N, tag, NULL, 0);
    int64_t dec_us = esp_timer_get_time() - t;

    ESP_LOGI("BENCH", "Ascon-Hash256   %6lld us for %u KB = %lld KB/s",
             hash_us, (unsigned)(N / 1024), (int64_t)N * 1000 / hash_us);
    ESP_LOGI("BENCH", "AEAD128 encrypt %6lld us for %u KB = %lld KB/s",
             enc_us, (unsigned)(N / 1024), (int64_t)N * 1000 / enc_us);
    ESP_LOGI("BENCH", "AEAD128 decrypt %6lld us for %u KB = %lld KB/s (tag ok=%d)",
             dec_us, (unsigned)(N / 1024), (int64_t)N * 1000 / dec_us, bad == 0);

    free(buf);
    free(out);
}
```

For Ed25519, the OTA log line already gives it. To measure it standalone, call
`ota_pkg_verify_signature()` in a loop of 20 and divide — one verification is
short enough that timer granularity matters.

### Method notes for whoever runs this

* Report the CPU frequency (`CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ`, default 160 MHz on
  ESP32 — bump to 240 for a fair figure) and the optimisation level. Both change
  the answer substantially.
* Run each measurement at least three times; Wi-Fi interrupts perturb single runs.
* Report heap with `esp_get_free_heap_size()` and
  `esp_get_minimum_free_heap_size()`, the latter being the more useful number.
* Measure download time over HTTP and HTTPS separately — the TLS handshake and
  record processing are a large part of an OTA on this class of device, and they
  belong to the transport, not to Ascon.
* State the flash mode and frequency; DIO at 40 MHz (this project's default) is
  meaningfully slower than QIO at 80 MHz.

---

## 5. Comparison notes

For context on why Ascon is a reasonable choice here, rather than as a performance
claim:

* mbedTLS provides SHA-256 and AES-GCM with **hardware acceleration** on the
  ESP32, so on this specific chip AES-GCM would very likely be faster than a
  software Ascon. The argument for Ascon is not speed on hardware that happens to
  accelerate AES — it is a **1,982-byte** software footprint with no tables, a
  ~120-byte streaming state, and one permutation serving both hashing and
  authenticated encryption. On a microcontroller without an AES peripheral, that
  matters a great deal.
* Ed25519 is used rather than the RSA-3072 of ESP-IDF Secure Boot because the
  public key is 32 bytes instead of 384 and the signature 64 instead of 384 —
  significant when the trust anchor is compiled into a constrained image and the
  signature travels in a 160-byte header.

Neither claim is backed by on-device timing here. They are design rationale, and
they are labelled as such.
