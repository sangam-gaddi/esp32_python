# Problem Statement

## Design of a Lightweight and Secure OTA System that Ensures the Integrity and Authenticity of the Firmware

---

## 1. Domain

Embedded Systems Security · Internet of Things · Applied Cryptography ·
Lightweight Cryptography (NIST SP 800-232)

**Target platform:** ESP32 (Xtensa LX6, 4 MB flash, 520 KB SRAM)

---

## 2. Background

An Internet of Things deployment is not a product that ships once. Devices stay
in the field for years, and the firmware inside them must be corrected,
patched and extended long after installation. Recalling a device, opening its
enclosure and reflashing it over a cable does not scale past a handful of
units, so firmware is delivered **over the air (OTA)** — downloaded by the
device itself over a network.

That convenience moves the firmware, the most privileged code on the device,
onto an untrusted channel. Firmware is not ordinary data: whatever arrives is
executed with complete control over the hardware. An OTA channel is therefore
the single most valuable target on an IoT device. Compromise it once and the
attacker owns every device that listens to it, permanently and invisibly.

The standard defence — TLS to the update server — is necessary but not
sufficient. TLS protects a *connection*; it says nothing about the *artefact*.
A compromised or malicious update server terminates TLS legitimately and can
then serve whatever it likes. The firmware image must therefore carry its own
proof of origin and its own proof of integrity, independent of how it travelled.

A second constraint makes this harder on IoT hardware. Conventional
cryptographic suites (AES-GCM with hardware acceleration, RSA-2048/4096,
SHA-256 with large constant tables) were designed for general-purpose
processors. On a constrained microcontroller — limited flash, limited RAM,
often battery powered — their code size, memory footprint and energy cost are
significant. In August 2023 NIST selected the **Ascon** family as the standard
for lightweight cryptography, published as **SP 800-232**, precisely for this
class of device. Its applicability to a real secure-update pipeline is what
this project sets out to demonstrate.

---

## 3. Problem Statement

Existing over-the-air firmware update mechanisms for resource-constrained IoT
devices generally exhibit one or more of the following weaknesses:

1. **Transport-only security.** Protection stops at TLS. The firmware image
   itself is unauthenticated, so a compromised update server, a malicious
   mirror, or anyone able to terminate the connection can substitute arbitrary
   firmware that the device will accept and execute.

2. **No cryptographic authenticity.** Many implementations verify only a CRC or
   an unkeyed checksum. These detect accidental corruption but offer no defence
   against a deliberate attacker, who simply recomputes the checksum after
   modifying the image.

3. **No confidentiality of the firmware image.** Firmware transmitted in
   plaintext can be captured and reverse engineered, exposing proprietary
   algorithms, embedded credentials and exploitable defects before a patch has
   propagated.

4. **No protection against rollback.** A device that accepts any correctly
   signed image will accept an *old* correctly signed image. An attacker
   replays a genuine earlier release whose vulnerability is publicly known,
   reintroducing the defect without breaking a single cryptographic primitive.

5. **Unsafe installation.** Writing an update over the running application
   leaves no recovery path. An interruption — power loss, network failure, a
   corrupted image — bricks the device permanently.

6. **Cryptographic cost unsuited to the platform.** Conventional primitives
   consume flash, RAM and energy that a constrained device cannot spare, which
   in practice leads developers to omit security altogether rather than accept
   the overhead.

7. **Key material concentrated on the update server.** Where the server holds
   signing keys, compromising the server is equivalent to compromising every
   device it serves.

**The problem, stated precisely:**

> Design, implement and evaluate an over-the-air firmware update system for a
> resource-constrained IoT device (ESP32) which guarantees the **integrity**,
> **authenticity** and **confidentiality** of a firmware image, resists
> **rollback** and **tampering**, remains **safe under interruption**, and does
> so using **lightweight cryptography** whose flash, RAM and computational cost
> are appropriate to the platform — while ensuring that compromise of the
> update server does **not** permit malicious firmware to be installed.

---

## 4. Motivation

* **The attack surface is unusually valuable.** Firmware executes with full
  hardware privilege. A single successful malicious update is persistent,
  invisible to the user, and survives reboot.

* **The failure mode is fleet-wide.** Unlike an attack on one device, a
  compromised update channel reaches every device that trusts it.

* **Deployed devices are long-lived.** Hardware installed today will receive
  updates for a decade. The trust model must not depend on the continued
  integrity of any single server.

* **Lightweight cryptography is newly standardised.** Ascon was selected by
  NIST in 2023 and standardised as SP 800-232. Demonstrating that a complete,
  correct secure-update pipeline can be built on it — and measuring what it
  actually costs — is directly relevant to the constrained devices the standard
  was written for.

* **Security omitted for cost is the common outcome.** If protection is
  expensive, it is left out. Showing that authenticated encryption and
  integrity for firmware can be obtained for under 2 KB of flash removes that
  excuse.

---

## 5. Objectives

| # | Objective | How it is met |
| --- | --- | --- |
| 1 | **Confidentiality** of the firmware in storage and in transit | Ascon-AEAD128 authenticated encryption with a fresh 128-bit nonce per package |
| 2 | **Integrity** — detect any modification of the image | Ascon-Hash256 digest over the plaintext firmware, bound into the signed header |
| 3 | **Authenticity** — prove the image was approved by the legitimate owner | Ed25519 signature over the package header |
| 4 | **Rejection of unauthorised firmware** | Trusted public key compiled into the device image; not obtained from the package or the network |
| 5 | **Anti-rollback protection** | Monotonic security version, signed, compared against state held in device NVS |
| 6 | **Safe installation** | Dual OTA partitions; boot target switched only after every check passes; automatic rollback if the new image fails self-test |
| 7 | **Lightweight footprint** suited to the ESP32 | Measure flash and RAM cost of the complete cryptographic stack |
| 8 | **Demonstrable rejection of attacks** | Implement an attack tool producing tampered packages; show each is rejected and name the check that caught it |
| 9 | **Server holds no secrets** | Signing performed on the build host; the update server stores and serves bytes only |

---

## 6. Scope

### 6.1 In scope

* A binary package format (`.sota`) carrying the encrypted firmware together
  with its digest, nonce, authentication tag, version metadata and signature.
* Host-side tooling: key generation, package creation, package verification,
  and a package-tampering tool for attack demonstration.
* Device-side firmware: OTA state machine, streaming decryption and
  verification, partition management, anti-rollback state, Wi-Fi management.
* An update server that distributes packages and holds no key material.
* A web interface for building, signing, publishing and monitoring updates.
* Validation against official cryptographic test vectors and a suite of
  negative (attack) test cases.
* Measurement of flash and RAM cost.

### 6.2 Out of scope

* Secure Boot and Flash Encryption. Both are chip-level, irreversible
  eFuse operations. They are documented as recommended hardening but are
  deliberately **not** performed, as no operation in this project burns an
  eFuse.
* Per-device key provisioning at manufacture, and hardware-backed key storage.
* Defence against an attacker with unrestricted physical access to the device.
* Protection against denial of service; an attacker controlling the network can
  always prevent an update from arriving.
* Formal security proof or third-party security audit.

---

## 7. Proposed Approach

### 7.1 Layered verification

Two independent cryptographic layers protect the package, each answering a
different question.

| Layer | Question answered | Key type |
| --- | --- | --- |
| Ascon-AEAD128 tag | Was the ciphertext or the metadata altered after encryption? | Symmetric — present on every device |
| Ascon-Hash256 + Ed25519 | Is this plaintext exactly what the owner approved? | Asymmetric — private half never leaves the build host |

The layering is deliberate. The symmetric key is necessarily present on every
device and must therefore be assumed extractable by an attacker with physical
access. Because the Ed25519 signature covers the AEAD authentication tag, an
attacker holding the extracted symmetric key can *decrypt and read* firmware
but **cannot forge** a package the device will accept. Confidentiality degrades
under physical attack; authenticity does not.

### 7.2 Separation of trust

| Party | Ed25519 private key | Ed25519 public key | Ascon key |
| --- | --- | --- | --- |
| Build / signing host | **Yes** | Yes | Yes |
| Update server | No | No | **No** |
| Device | **No** | Yes (compiled in) | Yes (NVS) |

The update server holds no key material of any kind. An attacker with complete
control of the server can delete packages, serve stale ones, or falsify its
metadata — but cannot produce a package any device will install, because the
device verifies the signature against a public key the server has never held.
Server metadata is treated as an untrusted hint; every value that matters is
re-read from the signed header on the device.

### 7.3 Device-side verification sequence

Checks are ordered so that the cheapest and most decisive runs first, and so
that no attacker-supplied data is processed before its origin is established.

```
1. Ed25519 signature      before any firmware bytes are downloaded
2. Version / anti-rollback  reject anything not strictly newer
3. Ascon-AEAD128 decrypt    streamed in 4 KB chunks; tag verified
4. Ascon-Hash256 compare    digest of plaintext vs. the signed digest
5. Switch boot partition    only if 1-4 all passed
```

Failure at any stage aborts the update. The running firmware is never modified,
so a rejected or interrupted update leaves the device exactly as it was.

### 7.4 Memory strategy

The firmware image is never held in RAM. It is downloaded, decrypted and
written to the inactive partition in 4 KB chunks, so peak additional memory is
independent of firmware size.

---

## 8. Expected Outcomes

1. A working end-to-end secure OTA system demonstrated on physical ESP32
   hardware.
2. A normative, documented package format.
3. Cryptographic implementations validated against official NIST SP 800-232
   known-answer test vectors and RFC 8032 Ed25519 vectors.
4. Quantified flash and RAM cost of the complete security stack.
5. A reproducible attack demonstration in which each tampered package is
   rejected and the responsible check is identified.
6. A demonstration that a fully compromised update server cannot install
   malicious firmware.

---

## 9. Evaluation Criteria

| Criterion | Measure of success |
| --- | --- |
| Correctness of cryptography | Matches every official KAT vector for Ascon-Hash256 and Ascon-AEAD128, and RFC 8032 vectors for Ed25519 |
| Integrity | Any single-bit modification of the ciphertext or metadata is detected |
| Authenticity | A package signed by any other key is rejected; a stolen symmetric key does not enable forgery |
| Anti-rollback | A correctly signed older package is rejected |
| Robustness | A truncated or interrupted transfer is rejected and the device continues on its existing firmware |
| Lightweight footprint | Cryptographic code size and peak RAM measured and reported from real build output |
| Field validity | A complete update cycle succeeds on physical hardware over a real network |

---

## 10. Constraints and Assumptions

**Constraints**

* ESP32 with **4 MB flash minimum** — three application partitions of 1.25 MB
  do not fit in 2 MB.
* ESP-IDF v5.3.1; installation performed exclusively through the `esp_ota_*`
  API, with no raw flash writes.
* No third-party cryptographic primitive is written from scratch; reference and
  vetted implementations are used unmodified wherever possible.

**Assumptions**

* The build host holding the Ed25519 private key is trusted and uncompromised.
  The private key is the root of authority; its compromise defeats the system
  by definition.
* The device has not already been compromised. Code executing with full
  privilege can patch out any verification, which is what Secure Boot exists to
  prevent and is outside this scope.
* The initial firmware and its embedded trust anchor are provisioned over a
  trusted channel (USB) before deployment.

---

## 11. Acknowledged Limitations

Stated explicitly, as a system of this kind should be judged on what it does
*not* claim as much as on what it does.

* **The symmetric Ascon key is extractable under physical attack.** It resides
  in plain NVS and, in this demonstration build, is compiled into the image.
  An attacker able to read the flash recovers it and can then decrypt firmware
  — though still not forge it. A production deployment requires per-device keys
  in eFuse together with Flash Encryption.
* **An already-compromised device cannot be protected.** Privileged code can
  remove the verification logic. Secure Boot addresses this and is irreversible,
  so it is documented rather than enabled.
* **A compromised signing host defeats the system.** The private key *is* the
  authority.
* **No protection against fault injection or physical side-channel analysis.**
  The Ascon implementation is not masked, although tag and digest comparisons
  are constant-time.
* **No protection against denial of service.** An attacker controlling the
  network can prevent updates from being delivered.
* **The system does not validate what the firmware does.** Cryptography proves
  *who* authorised an image, never *what it will do*. An owner who signs
  incorrect firmware will have it installed correctly. Content validation is a
  separate, non-cryptographic control.
* **Not independently audited.** This is an academic proof of concept that
  implements standard cryptography correctly and demonstrates it against
  official vectors. It is not claimed to be unbreakable.

---

## 12. Standards and References

| Item | Source |
| --- | --- |
| Ascon-Hash256, Ascon-AEAD128 | NIST SP 800-232, *Ascon-Based Lightweight Cryptography Standards for Constrained Devices* |
| Known-answer test vectors | `github.com/ascon/ascon-c` (SP 800-232 release) |
| Ed25519 signature scheme | RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)* |
| Ed25519 implementation | TweetNaCl (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers) — public domain |
| OTA partition mechanism | ESP-IDF `esp_ota_*` API, Espressif Systems |
| Firmware update threat model | IETF RFC 9019, *A Firmware Update Architecture for Internet of Things* |
