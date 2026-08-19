# OTA Package Format — `.sota` version 1

This is the normative specification. Two independent implementations follow it
and are tested against each other:

| Side | Implementation |
| --- | --- |
| Host (build / server) | `sotalib/package.py` |
| Device (ESP32) | `components/ota_package/` |

`tests/host/test_package_parser.c` runs the C parser over packages built by the
Python packager, and `tests/test_package.py` asserts every field offset below
literally. If the two ever disagree, those tests fail.

---

## 1. Layout

A package is a fixed 160-byte header followed by the encrypted firmware. There
are no optional fields, no padding, and no length-prefixed or nested structures —
an unambiguous format is much easier to parse safely on a microcontroller.

**All integers are little-endian.**

```
 offset  size  field               description
 ------  ----  -----------------   ---------------------------------------------
      0     4  magic               ASCII "SOTA" = 53 4F 54 41
      4     2  format_version      u16, = 1
      6     2  header_size         u16, = 160
      8     4  firmware_version    u32, major<<16 | minor<<8 | patch
     12     4  security_version    u32, monotonic counter
     16     4  firmware_size       u32, plaintext length in bytes
     20     4  ciphertext_size     u32, = firmware_size
     24     8  build_timestamp     u64, unix seconds (informational only)
     32    16  nonce               Ascon-AEAD128 nonce, fresh per package
     48    32  firmware_hash       Ascon-Hash256 of the PLAINTEXT firmware
 ==========================  bytes 0..80 = associated data  ==================
     80    16  auth_tag            Ascon-AEAD128 authentication tag
 ==========================  bytes 0..96 = signed region  ====================
     96    64  signature           Ed25519 over header[0:96]
    160     N  ciphertext          firmware_size bytes
```

Total size = `160 + firmware_size`.

### Field notes

**`magic`** — a fast, cheap rejection of anything that is not a package at all.
Not a security control.

**`format_version`** — the device refuses anything it does not recognise rather
than guessing. Version 1 is the only version defined.

**`header_size`** — redundant with the format version, and checked anyway. It
makes a truncated or mis-generated header fail immediately and unambiguously.

**`firmware_version`** — the release number, packed so that "is this newer?" is a
single unsigned comparison. Each component is 0..255, so `1.2.3` → `0x010203`.
Because the packing is big-endian *within* the integer, numeric order matches
semantic order: `10.0.0` (`0x0A0000`) correctly exceeds `2.0.0` (`0x020000`).

**`security_version`** — a separate monotonic counter, deliberately *not* derived
from the release number. See [§5](#5-versioning-and-anti-rollback).

**`firmware_size` / `ciphertext_size`** — both present and both checked. Ascon
AEAD is length-preserving so they must be equal; storing both and validating the
equality means the two can never be used inconsistently by accident. The device
also rejects `0` and anything above `OTA_PKG_MAX_FIRMWARE_SIZE` (8 MiB) so a
corrupt length field cannot trigger an enormous download.

**`build_timestamp`** — informational, for logs and the server's index page. It
is inside the signed region so it cannot be altered, but no security decision
depends on it. The device has no reliable clock at boot, so freshness is enforced
with version numbers, not time.

**`nonce`** — 128-bit, drawn from `os.urandom()` for every package. Not secret,
which is why it travels in the clear. Reusing a nonce under the same key would
reveal the XOR of two firmware images and destroy authenticity, so the packager
never accepts a caller-supplied nonce except behind an explicitly-warned testing
flag.

**`firmware_hash`** — Ascon-Hash256 of the **plaintext** firmware, not the
ciphertext. This is the value the Ed25519 signature ultimately attests to, so the
signature describes *what will actually execute*, independently of how it was
transported or encrypted.

**`auth_tag`** — the Ascon-AEAD128 tag over the ciphertext and the associated
data.

**`signature`** — Ed25519 over `header[0:96]`.

---

## 2. The two authenticated spans

These two boundaries are the whole design, so they are worth stating precisely.

### Associated data = `header[0:80]`

Everything descriptive — magic, versions, sizes, timestamp, nonce and the
declared hash — is fed to Ascon-AEAD128 as associated data. The tag therefore
covers the metadata as well as the payload, so a ciphertext **cannot be lifted
out of one package and replayed inside another** with different version numbers
or a different declared hash.

It stops at offset 80 for a simple reason: the tag lives at offset 80, and a tag
cannot authenticate itself.

### Signed region = `header[0:96]`

The Ed25519 signature covers the associated data **plus the tag**.

That extra 16 bytes is what makes Ed25519 — not the shared symmetric key — the
root of trust. Consider an attacker who steals the Ascon key:

* They can encrypt any firmware they like and compute a perfectly valid tag.
* But their tag differs from the one in the signed region of any genuine package.
* Replaying a genuine signature therefore fails, because that signature commits
  to a different tag.
* And they cannot produce a new signature without the Ed25519 private key.

So a leaked encryption key costs confidentiality, not authenticity.
`tests/test_signature.py::test_stealing_the_symmetric_key_does_not_allow_forgery`
is exactly this scenario.

### Canonical representation

Both spans are **literal prefixes of the received bytes**. The device verifies
`hdr->raw[0..96]` — the bytes that arrived — and never re-serialises its parsed
struct and hopes the result matches. Signing one representation and verifying
another is a classic way to produce a signature that does not cover what is
actually used, and the format is shaped to make that mistake impossible:

```c
/* components/ota_package/src/ota_package.c */
ed25519_verify(hdr->signature, hdr->raw, OTA_PKG_SIGNED_LEN, trusted_pk);
```

---

## 3. Cryptographic primitives

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Integrity | **Ascon-Hash256** | 256-bit digest, rate 8 bytes, `pa = pb = 12` |
| Confidentiality + payload integrity | **Ascon-AEAD128** | 128-bit key / nonce / tag, rate 16 bytes, `pa = 12`, `pb = 8` |
| Authenticity | **Ed25519** | 32-byte public key, 64-byte signature |

### A note on Ascon naming

NIST **SP 800-232** standardised the Ascon family and renamed the variants. This
project uses the standardised versions throughout:

| SP 800-232 name | Older Ascon v1.2 name | Used here for |
| --- | --- | --- |
| Ascon-AEAD128 | closest to Ascon-128a | firmware encryption |
| Ascon-Hash256 | Ascon-Hash | firmware digest |

"Ascon-128 AEAD" in the project brief means the 128-bit-security Ascon AEAD;
Ascon-AEAD128 is that algorithm in its standardised form, so that is what is
implemented. It matters that the two are not interchangeable: SP 800-232 also
changed byte ordering from big-endian to **little-endian**, which is why
Ascon-Hash256 and the older Ascon-Hash produce *different digests for the same
input*. Every load and store in both implementations is little-endian.

Both primitives are validated against the official Known-Answer-Test vectors in
`tests/vectors/`, taken verbatim from `github.com/ascon/ascon-c`:

* 1025 Ascon-Hash256 vectors
* 1089 Ascon-AEAD128 vectors

---

## 4. Build and verify order

### Building (host — `tools/create_ota_package.py`)

```
firmware.bin (plaintext)
      │
      ├──► Ascon-Hash256 ─────────────► firmware_hash (32 B)
      │
      │    assemble header[0:80] with the hash, versions, sizes and a
      │    fresh random nonce                         ← associated data is final
      │
      ├──► Ascon-AEAD128 encrypt ────► ciphertext + auth_tag (16 B)
      │       key   = provisioned Ascon key (NOT in the package)
      │       nonce = the fresh nonce
      │       ad    = header[0:80]
      │
      │    place auth_tag at offset 80                ← signed region is final
      │
      └──► Ed25519 sign header[0:96] ─► signature (64 B)

result: header(160) ‖ ciphertext(N)
```

The order is forced: the tag cannot exist before the associated data is final,
and the signature cannot exist before the tag is placed.

### Verifying (device — `components/ota_package/`)

```
1. read 160 bytes             ota_pkg_parse_header()
     magic, format_version, header_size, size sanity        → reject
2. Ed25519                    ota_pkg_verify_signature()
     signature over header[0:96] under the TRUSTED key      → reject
3. versions                   ota_pkg_check_versions()
     security_version >= accepted floor                     → reject (rollback)
     firmware_version >  installed                          → reject (not newer)
4. stream the payload         ota_pkg_payload_update()  × N
     Ascon-AEAD128 decrypt each chunk
     Ascon-Hash256 absorb each chunk
     write plaintext to the INACTIVE OTA partition
5. finalise                   ota_pkg_payload_final()
     Ascon-AEAD128 tag                                      → reject
     Ascon-Hash256 vs the signed digest                     → reject
6. activate                   esp_ota_set_boot_partition()
```

**Steps 2 and 3 precede the download.** The header is self-contained and arrives
first, so an unauthorised or downgraded package is rejected before any firmware
is transferred or written. That saves bandwidth, and it means unauthenticated
payload never reaches flash at all in the common attack cases.

**Why the hash is checked when the tag already passed.** They authenticate
different things under different keys. The tag proves the ciphertext came from
someone holding the *shared symmetric* key; the hash-inside-the-signature proves
the plaintext is what the *signer* approved. The hash comparison is the check
that catches a compromised or simply buggy build server — a package that is
correctly encrypted and correctly signed but whose declared digest does not
describe the firmware. `tools/tamper_package.py --mode hash-mismatch` constructs
exactly that case, and it is the only tamper mode that reaches step 5's second
check as the first failure.

---

## 5. Versioning and anti-rollback

Two independent numbers, because they answer different questions.

**`firmware_version`** — "is there something newer to install?"
Human-facing, e.g. `1.0.0` → `1.1.0` → `2.0.0`. Rule:

```
install only if  package.firmware_version > device.firmware_version
```

**`security_version`** — "is this allowed at all?"
A monotonic counter, raised when a release fixes something that must never be
downgraded past. Rule:

```
reject if  package.security_version < device.accepted_security_version
```

Equality is allowed, so ordinary releases need not touch it.

Both fields are inside the signed region. That is the point: a filename such as
`firmware_v2.bin` proves nothing, and an unsigned version field can simply be
edited by an attacker replaying an old package. `tests/test_signature.py::test_version_fields_are_authenticated`
checks that altering either field invalidates the signature.

The device's floor is stored in NVS and never lowered — see
`main/version_manager.c`, which also explains why the state is advanced *after* a
successful boot rather than before the reboot (recording it early would strand a
device that rolled back).

---

## 6. What is deliberately **not** in the package

| Absent | Why |
| --- | --- |
| **The Ascon encryption key** | The device already has it. Shipping the key alongside the ciphertext it decrypts would make the encryption decorative. `tests/test_package.py::test_encryption_key_does_not_appear_in_the_package` asserts it. |
| **The Ed25519 public key** | The trust anchor must come from the device's own configuration. A package-supplied key reduces the signature to a checksum any attacker can recompute. There is no field for one, and the header struct has no place to put one. |
| **The Ed25519 private key** | It never leaves the signing host. |
| **A plaintext copy of anything** | The payload is entirely ciphertext. |

---

## 7. Rejection codes

The device reports one reason per failure (`ota_pkg_strerror()`):

| Code | Meaning | Typical cause |
| --- | --- | --- |
| `OTA_PKG_ERR_TRUNCATED` | fewer bytes than the format needs | interrupted download |
| `OTA_PKG_ERR_MAGIC` | not a `.sota` package | wrong URL, HTML error page |
| `OTA_PKG_ERR_FORMAT_VERSION` | newer format than this firmware knows | server ahead of device |
| `OTA_PKG_ERR_HEADER_SIZE` | `header_size` disagrees with the format | corruption |
| `OTA_PKG_ERR_SIZE_RANGE` | `firmware_size` is 0 or over 8 MiB | corruption |
| `OTA_PKG_ERR_SIZE_MISMATCH` | `ciphertext_size != firmware_size` | corruption or tampering |
| `OTA_PKG_ERR_LENGTH` | payload length disagrees with the header | truncated or padded transfer |
| `OTA_PKG_ERR_SIGNATURE` | **INVALID SIGNATURE** | not signed by the trusted key, or metadata altered |
| `OTA_PKG_ERR_TAG` | **ASCON AUTHENTICATION FAILED** | ciphertext modified, or wrong encryption key |
| `OTA_PKG_ERR_HASH` | **HASH MISMATCH** | signed digest does not describe the firmware |
| `OTA_PKG_ERR_ROLLBACK` | **ROLLBACK DETECTED** | `security_version` below the accepted floor |
| `OTA_PKG_ERR_NOT_NEWER` | not an upgrade | already up to date |

---

## 8. Server metadata (not part of the format)

The server also answers `GET /api/firmware/latest` with JSON:

```json
{
  "format_version": 1,
  "firmware_version": "2.0.0",
  "firmware_version_code": 131072,
  "security_version": 2,
  "firmware_size": 178016,
  "package_size": 178176,
  "package_name": "firmware_v2.0.0.sota",
  "package_url": "/api/firmware/2.0.0/package",
  "firmware_hash": "5a770841e1bfedaf...",
  "built": "2026-08-19 07:31:15 UTC"
}
```

**This JSON is untrusted.** It is a hint that lets the device skip a download it
does not need. Every value that affects a security decision is re-read from the
signed package header. A hostile server can lie here freely; the worst it
achieves is making the device download a package that is then rejected.

---

## 9. Reference values

A package built from a 5003-byte test image, for orientation:

```
package size     = 160 + 5003 = 5163 bytes
overhead         = 160 bytes (3.1% here, 0.09% on a 178 KB image)
  of which:  32  Ascon-Hash256 digest
             64  Ed25519 signature
             16  Ascon-AEAD128 tag
             16  nonce
             32  magic, versions, sizes, timestamp
```

The cryptographic overhead is constant, so it becomes negligible on a real
firmware image.
