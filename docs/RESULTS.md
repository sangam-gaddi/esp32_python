# Measured Results — ESP32 hardware

All figures were measured on a real ESP32 (rev 45 silicon, 4 MB flash, DIO @ 40 MHz,
CPU 160 MHz, `-Os`, ESP-IDF v5.3.1) over 2.4 GHz Wi-Fi (802.11n), with plain HTTP
transport, on 2026-10-11. Firmware image: 940,000 B. Values are mean ± SD (n = runs).
Raw logs: `build/measure/` · Scripts: `tools/measure_server.py`,
`tools/measure_campaign.py`, `tools/measure_report.py`, `main/crypto_bench.c`.

| No. | Parameter | Unit | Result |
| --- | --- | --- | --- |
| 1 | Firmware encryption time (Ascon-AEAD128) | ms | **468.2 ± 0.1** on ESP32 (938,688 B, n=5) · 4,695 ± 206 on the build host (pure-Python packager, n=3) |
| 2 | Firmware decryption time (Ascon-AEAD128, incl. tag check) | ms | **481.9 ± 19.2** (n=5) |
| 3 | Ascon-Hash256 computation time | ms | **1,159.2 ± 0.003** (938,688 B, n=5) |
| 4 | Ed25519 signature verification time | ms | **759.2 ± 3.8** (microbenchmark, n=10) · 763.7 ± 4.3 inside real OTA runs (n=10) |
| 5 | Total OTA update time | s | **11.81 ± 0.14** check → installed (n=10) · **18.33 ± 0.13** check → new firmware running and marked valid (n=10) |
| 6 | Peak RAM consumption | bytes | **25,656 ± 494** heap during an update (max 26,340; HTTP client + buffers + crypto), n=10 |
| 7 | Additional flash usage | bytes | **9,069** (Ascon 1,982 + Ed25519 5,991 + package parser 1,096) = 0.96 % of the 940,000 B image |
| 8 | Firmware package overhead | % | **0.017 %** (160 B header on 940,000 B) |
| 9 | Firmware download throughput | KB/s | **388.9 ± 7.0** network only · **125.8 ± 0.8** end-to-end (download + decrypt + hash + flash write) |
| 10 | Successful update rate | % | **100 %** (10 / 10) |
| 11 | Tampered / invalid firmware rejection rate | % | **100 %** (12 / 12 attacks, 12 / 12 left firmware unchanged) |
| 12 | Rollback prevention and recovery success | % | **100 %** rollback blocked (3 / 3) · **100 %** power-cut recovery (2 / 2) · **100 %** bad-image auto-rollback (2 / 2) |

**Energy consumption: not measured.** No power-measurement instrument was used. It
is not estimated here.

## Breakdown of a 940,000 B update (n = 10, ms)

| Stage | Time |
| --- | --- |
| Ed25519 verify | 764 ± 4 |
| Partition erase (`esp_ota_begin`) | 2,660 ± 52 |
| Network read | 2,361 ± 43 |
| Ascon decrypt + hash (streamed) | 1,774 ± 8 |
| Flash write | 3,125 ± 8 |
| Image validation (`esp_ota_end`) | 340 ± 3 |
| Whole cycle, check → ready to reboot | 11,843 ± 99 |

Flash erase and flash write account for about half the update time. Network and
cryptography each take roughly 15–20 %.

## Attacks delivered to the device over the network (row 11)

| Attack | Rejected at |
| --- | --- |
| Flipped ciphertext bit | DECRYPT (Ascon tag) |
| Flipped metadata bit | SIGNATURE_VERIFY |
| Random signature | SIGNATURE_VERIFY |
| Signed with a foreign key | SIGNATURE_VERIFY |
| Encrypted under a wrong key | INSTALL — garbage plaintext failed ESP-IDF's image-magic check on the first write, before the tag check was reached |
| Signed digest ≠ firmware | HASH_VERIFY |
| Truncated package | DOWNLOAD |
| Bad magic | METADATA |
| Older security version (rollback) | VERSION_VERIFY |
| Genuine old release, server lies about its version | VERSION_VERIFY |
| Genuine old release, honest metadata | Not downloaded (not newer) |
| Transfer cut at 50 % | DOWNLOAD |

## Recovery (row 12)

* **Power cut mid-download:** EN was pulled low at 40–59 % of the download. The device
  booted the previous firmware (35.0.0) both times, 0.85 s after the reset, and was
  back on the network after 12.7 s.
* **Signed image that fails its self-test:** v36 installed and booted, then failed its
  self-test. The bootloader returned to 35.0.0 both times. The device was back on the
  network 11.97 s after the install finished.

## Method notes

* Primitives were timed before Wi-Fi started, streamed in the same 4 KB chunks the OTA
  path uses.
* Host times come from the pure-Python reference packager. A C or hardware-accelerated
  packager would be much faster.
* The campaign firmware had anti-rollback **enabled** (`OTA_ALLOW_DOWNGRADE=0`) and a
  15 s check interval.
* Sample sizes are small, so these are early results.
