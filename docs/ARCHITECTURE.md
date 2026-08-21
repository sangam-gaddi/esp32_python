# Architecture

## 1. The whole system, end to end

```
        BUILD / SIGNING HOST                    UPDATE SERVER            ESP32 DEVICE
    (holds the private key)                  (holds no keys)      (holds public key + Ascon key)
    ───────────────────────────              ───────────────      ──────────────────────────────

    firmware.bin
        │
        ├─► Ascon-Hash256 ──► digest
        │
        ├─► Ed25519 sign
        │     (over header[0:96])
        │
        ├─► Ascon-AEAD128 encrypt
        │     fresh nonce, ad = header[0:80]
        │
        ▼
    firmware_v2.sota ───────────────────►  server/packages/
                                                  │
                                           GET /api/firmware/latest
                                                  │  ◄──────────────────  check for update
                                                  │  ──────────────────►  JSON hint (untrusted)
                                                  │
                                           GET .../package
                                                  │  ◄──────────────────  download
                                                  │  ──────────────────►  160-byte header
                                                                          │
                                                                    Ed25519 verify ─► reject
                                                                          │
                                                                    version check  ─► reject
                                                                          │
                                                  │  ──────────────────►  ciphertext, streamed
                                                                          │
                                                              Ascon-AEAD128 decrypt (chunked)
                                                              Ascon-Hash256 absorb  (chunked)
                                                              esp_ota_write → INACTIVE partition
                                                                          │
                                                                    AEAD tag       ─► reject
                                                                    hash compare   ─► reject
                                                                          │
                                                              esp_ota_set_boot_partition()
                                                                          │
                                                                       reboot
                                                                          │
                                                                    new firmware runs
```

The three parties hold deliberately different secrets:

| Party | Ed25519 private | Ed25519 public | Ascon key |
| --- | --- | --- | --- |
| Build / signing host | **yes** | yes | yes |
| Update server | no | no | **no** |
| Device | **no** | yes | yes |

The server holding nothing is the structural reason a compromised server cannot
push malicious firmware. It can delete packages, serve stale ones, or lie in its
JSON metadata — none of which lets it produce a package the device accepts.

---

## 2. Device state machine

Implemented in `main/ota_manager.c`; every transition logs a line.

```
   ┌──────────┐
   │ OTA_IDLE │◄──────────────────────────────────────────────┐
   └────┬─────┘                                              │
        │ interval expires, or ota_manager_trigger_now()      │
        ▼                                                    │
   ┌───────────┐   no newer version                           │
   │ OTA_CHECK ├─────────────────────────────────────────────►│
   └────┬──────┘   (or server unreachable)                    │
        │                                                     │
        ▼                                                     │
   ┌──────────────┐                                           │
   │ OTA_METADATA │  fetch + parse the 160-byte header         │
   └────┬─────────┘                                           │
        │                                                     │
        ▼                                                     │
   ┌───────────────────────┐   INVALID SIGNATURE               │
   │ OTA_SIGNATURE_VERIFY  ├──────────────────────────┐        │
   └────┬──────────────────┘                          │        │
        ▼                                             │        │
   ┌─────────────────────┐   ROLLBACK DETECTED        │        │
   │ OTA_VERSION_VERIFY  ├───────────────────────────►│        │
   └────┬────────────────┘                            │        │
        ▼                                             │        │
   ┌──────────────┐                                   │        │
   │ OTA_DOWNLOAD │  chunked read                     │        │
   └────┬─────────┘                                   │        │
        ▼                                             │        │
   ┌─────────────┐   network error                     │        │
   │ OTA_DECRYPT ├───────────────────────────────────►│        │
   └────┬────────┘   Ascon decrypt + hash + flash write│       │
        ▼                                             │        │
   ┌─────────────────┐   TAG or HASH MISMATCH          │        │
   │ OTA_HASH_VERIFY ├────────────────────────────────►│        │
   └────┬────────────┘                                │        │
        ▼                                             ▼        │
   ┌─────────────┐                            ┌────────────┐   │
   │ OTA_INSTALL │  esp_ota_end +             │ OTA_FAILED ├───┘
   │             │  set_boot_partition        └────────────┘
   └────┬────────┘                             running firmware
        ▼                                      untouched
   ┌────────────┐
   │ OTA_REBOOT │ esp_restart()
   └────────────┘
```

`OTA_FAILED` has exactly one arrival path in the code — a single `cleanup:`
label — so there is no way to leave a partially-committed update behind. The boot
partition is only ever changed on the success path.

### Why signature and version checks come before the download

The header is self-contained and arrives first. Rejecting there means:

* an unauthorised package costs 160 bytes of traffic, not 1 MB;
* a rollback attempt never touches flash;
* unauthenticated payload never reaches flash in these cases at all.

### What is unavoidably written before authentication

An AEAD tag and a hash can only be checked once the whole payload has been seen.
Streaming decryption therefore writes not-yet-authenticated plaintext to the
inactive OTA partition. This is safe because that partition is inert: nothing
executes from it unless `esp_ota_set_boot_partition()` is called, which happens
only after every check has passed. A failed update leaves flash holding bytes
that will never run, and the bootloader keeps starting the previous image.

The alternative — buffering the entire image in RAM to verify before writing — is
impossible on a device with ~300 KB of heap and a ~1 MB image.

---

## 3. Code layout

```
CMakeLists.txt              project definition
partitions.csv              factory + ota_0 + ota_1 + otadata (4 MB flash)
sdkconfig.defaults          tracked configuration (sdkconfig is generated)

main/                       application layer -- no cryptography implemented here
  main.c                    entry point: NVS, keys, versions, Wi-Fi, rollback confirm
  app_config.h              versions, intervals, buffer sizes, NVS names
  device_config.h(.example) Wi-Fi credentials, server URL      (git-ignored)
  crypto_config.h(.example) trusted public key, provisioning key (git-ignored)
  ota_manager.c/.h          the state machine, HTTP, streaming install
  wifi_manager.c/.h         station bring-up and retry
  device_keys.c/.h          NVS-backed key provisioning, fingerprint logging
  device_report.c/.h        dashboard heartbeat/events + 3-command allowlist
  version_manager.c/.h      monotonic version state for anti-rollback
  server_ca_cert.pem        embedded CA for HTTPS (placeholder until generated)

components/
  ascon/                    Ascon-Hash256 + Ascon-AEAD128   (NIST SP 800-232)
    src/permutations.c        Ascon-p  -- inherited, KAT-proven, unmodified
    src/hash.c                original one-shot hash -- kept, defects fixed
    src/ascon_hash256.c       incremental hash (streaming OTA needs it)
    src/ascon_aead128.c       AEAD, one-shot and incremental
    include/ascon_word.h      alignment-safe load/store helpers
  ed25519/                  signature verification
    src/tweetnacl.c           unmodified public-domain reference implementation
    src/ed25519_verify.c      detached-signature wrapper
  ota_package/              package parsing + the verification sequence
    src/ota_package.c

sotalib/                    host implementation of the same primitives + format
  ascon.py                  Ascon-Hash256 and Ascon-AEAD128 in pure Python
  package.py                the .sota format: build, parse, verify

tools/
  generate_keys.py          Ed25519 pair + Ascon key, and the device config
  create_ota_package.py     firmware.bin -> firmware_vX.sota
  verify_package.py         inspect and verify, stage by stage
  tamper_package.py         build the nine attack packages
  make_dev_certs.py         development CA + server certificate for HTTPS
  simulate_device.py        SIMULATED device for testing the dashboard UI

server/
  app.py                    Flask metadata + package server (holds no keys)
  dashboard/                management UI: blueprint, SQLite, templates, static
  packages/                 published .sota files (the device sees these)
  staging/                  built but unpublished packages       (git-ignored)
  certs/                    development TLS material              (git-ignored)

tests/
  test_ascon_kat.py         1025 + 1089 official KAT vectors, Python
  test_package.py           format offsets, round-trip, structural rejection
  test_signature.py         RFC 8032 vectors; signature binding; key hygiene
  test_negative.py          the seven attack scenarios, through the real CLI
  test_server.py            server behaviour and key hygiene
  test_dashboard.py         dashboard APIs, and that the OTA API is unchanged
  vectors/                  official Ascon KAT files
  host/
    build_and_run.py        compile + run the C tests on the development machine
    test_ascon_kat.c        the C Ascon code vs the same official vectors
    test_package_parser.c   the C parser vs packages built by Python
    make_fixtures.py        generates the 26 cross-validation fixtures

docs/
  IMPLEMENTATION_AUDIT.md   Phase 1 audit of the baseline repository
  ARCHITECTURE.md           this file
  PACKAGE_FORMAT.md         normative wire format
  SECURITY.md               threat model and honest limitations
  DEMO.md                   step-by-step demonstration script
  BENCHMARKS.md             measured static sizes; runtime figures not measured
```

### Separation of concerns

The brief asked for cryptography kept apart from networking, and the split is
enforced by dependency direction:

```
       main/ota_manager.c          knows about HTTP, flash, FreeRTOS
              │                   knows NOTHING about Ascon internals
              ▼
     components/ota_package       knows the wire format and the check order
              │                   knows NOTHING about HTTP or ESP-IDF
              ├────────────┐
              ▼            ▼
   components/ascon   components/ed25519
                             knows only mathematics
```

`components/ascon`, `components/ed25519` and `components/ota_package` contain
**no ESP-IDF dependencies whatsoever**. That is what makes them host-testable:
`tests/host/build_and_run.py` compiles the very same `.c` files with MSVC or GCC
and runs them against official test vectors and real packages. A parser that only
ever runs on the target is a parser nobody has really tested.

---

## 4. Memory behaviour

The device never holds a firmware image in RAM.

| Item | Size | Where |
| --- | --- | --- |
| Download buffer (ciphertext) | `OTA_DOWNLOAD_CHUNK_SIZE` = 4096 B | heap, checked |
| Plaintext buffer | 4096 + 15 B | heap, checked |
| `ota_pkg_payload_ctx_t` | 200 B | stack |
| ├─ `ascon_aead128_ctx_t` | 80 B | inside the above |
| └─ `ascon_hash256_ctx_t` | 56 B | inside the above |
| `ota_pkg_header_t` (raw + parsed) | 320 B | stack |
| Ed25519 verify scratch | 2 × (64 + 256) = 640 B | stack, bounded |
| **total** | **9,367 B** | independent of firmware size |

(Struct sizes are measured `sizeof()` values, not estimates.)

Both heap allocations are checked and freed on every path, including all failure
paths, via the single `cleanup:` label. Nothing scales with firmware size:

```c
while (received < hdr.ciphertext_size) {
    n = esp_http_client_read(client, inbuf, want);      /* ≤ 4 KB          */
    ota_pkg_payload_update(&payload, outbuf, &produced, inbuf, n);
                                                       /* decrypt + hash  */
    esp_ota_write(ota, outbuf, produced);              /* straight to flash */
}
```

Ascon's streaming API is what makes this possible: the AEAD keeps at most 15
buffered bytes and the hash at most 7, so arbitrary network chunk sizes are
handled without any alignment requirement on the caller. The host tests exercise
chunk sizes of 1, 7, 15, 16, 17, 63, 64, 100, 512, 1024 and 4096 bytes against
the same expected output.

### The alignment fix that made this work

The inherited hash read its input through `((uint32_t*)in)[0]`. The ESP32's
Xtensa LX6 cannot perform unaligned 32-bit data loads — it raises a
`LoadStoreAlignment` exception and panics — and bytes arriving from an HTTP
buffer are at an arbitrary offset, so unaligned input is the *normal* case here,
not an edge case. Every load and store now goes through the memcpy-based helpers
in `components/ascon/include/ascon_word.h`.
`tests/host/test_ascon_kat.c::test_hash_unaligned` hashes the same data at all
eight byte alignments and requires identical digests.

---

## 5. Partition layout and update safety

```
0x008000  partition table
0x009000  nvs        20 KB   keys, accepted version state
0x00e000  otadata     8 KB   which slot the bootloader starts
0x010000  phy_init    4 KB
0x020000  factory   1.25 MB  the USB-flashed image; OTA never overwrites it
0x160000  ota_0     1.25 MB  OTA target A
0x2a0000  ota_1     1.25 MB  OTA target B
0x3e0000  (128 KB spare)
```

`esp_ota_get_next_update_partition()` alternates between `ota_0` and `ota_1`, so
the running image is never the one being written. Nothing writes to raw flash
addresses; installation goes exclusively through `esp_ota_begin` /
`esp_ota_write` / `esp_ota_end` / `esp_ota_set_boot_partition`.

The built firmware is 926 KB, leaving 29% of a slot free.

### Two independent safety nets

**1. The boot partition is switched last.** A failure at any earlier point —
network drop, bad tag, hash mismatch, flash error — leaves `otadata` untouched
and the previous image selected.

**2. Rollback on a bad boot.** With `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` a
freshly installed image starts in `PENDING_VERIFY`. `main.c` calls
`esp_ota_mark_app_valid_cancel_rollback()` **only after** NVS, keys and Wi-Fi are
working. An image that installs but cannot function never marks itself valid, and
the bootloader reverts to the previous slot on the next restart. This costs no
eFuses and is fully reversible.

`main/version_manager.c` documents the subtlety these two combine to create: the
accepted-version state must be advanced *after* a successful boot, not before the
reboot. Recording it early would leave a rolled-back device claiming a version it
is not running, and it would then refuse to install the very update it needs.

---

## 6. Configuration and secrets

| File | Tracked? | Contents |
| --- | --- | --- |
| `sdkconfig.defaults` | yes | project build configuration |
| `sdkconfig` | **no** | generated |
| `main/app_config.h` | yes | versions, intervals, buffer sizes |
| `main/device_config.h.example` | yes | template |
| `main/device_config.h` | **no** | Wi-Fi password, server URL |
| `main/crypto_config.h.example` | yes | template with zeroed keys |
| `main/crypto_config.h` | **no** | trusted public key + provisioning key |
| `keys/ed25519_private.pem` | **no** | the signing key |
| `keys/ota_enc_key.hex` | **no** | the shared Ascon key |
| `server/certs/*` | **no** | development TLS keys |

The firmware refuses to hide a missing trust anchor: `device_keys_log_status()`
detects an all-zero public key (i.e. the untouched template) and says so loudly
at boot, because otherwise every update would be rejected for a reason that looks
like a cryptographic failure.
