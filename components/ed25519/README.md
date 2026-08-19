# `ed25519` component — provenance

Ed25519 signature verification for the ESP32, wrapping **TweetNaCl**.

## Why this exists

ESP-IDF's bundled mbedTLS provides Curve25519 ECDH but **not** Ed25519/EdDSA
signatures, so there is no SDK function to call. The project rule is not to
implement elliptic-curve arithmetic by hand — that is a reliable way to produce
a verifier that accepts bad signatures — so a vetted implementation is bundled
instead.

## What is bundled

`src/tweetnacl.c` and `src/tweetnacl.h` are **unmodified** copies of TweetNaCl:

| Property | Value |
| --- | --- |
| Upstream | <https://tweetnacl.cr.yp.to/> |
| Version | `20140427` |
| Files | `https://tweetnacl.cr.yp.to/20140427/tweetnacl.c`, `.../tweetnacl.h` |
| Authors | Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe, Sjaak Smetsers |
| Licence | Public domain |
| `tweetnacl.c` | 16637 bytes, SHA-256 `02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4` |
| `tweetnacl.h` | 20014 bytes, SHA-256 `43f29ad721d9927b747b0100ab4160c119e7bb180c7c98a66e4bf79d31244287` |

Verify the copies at any time:

```bash
python -c "import hashlib;print(hashlib.sha256(open('components/ed25519/src/tweetnacl.c','rb').read()).hexdigest())"
```

Do not edit these two files. If they ever need updating, replace them wholesale
from upstream and update the hashes above.

## What this project adds

`src/ed25519_verify.c` and `include/ed25519_verify.h` — a wrapper providing one
function:

```c
int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msglen,
                   const uint8_t pk[32]);   /* 0 == valid */
```

It exists because NaCl's API is *combined mode* (`crypto_sign_open` expects the
signature and message concatenated and hands the message back), while the OTA
package format stores a detached signature in a fixed header field. The wrapper
reassembles `sig || msg`, calls `crypto_sign_open()`, and additionally checks
that the recovered message is byte-identical to the one it was asked about.

Only **verification** is exposed. The device never signs: the Ed25519 private
key belongs on the build host and must never enter a firmware image.

### `randombytes()`

TweetNaCl declares `randombytes()` extern because NaCl key generation and
`crypto_box` need entropy. Ed25519 *verification* never calls it, but the symbol
must still resolve. The wrapper supplies:

* on the device — `esp_fill_random()`, the ESP-IDF hardware RNG;
* on the host — `abort()`, because host builds only ever verify, and a function
  named `randombytes` that quietly returns predictable bytes is how weak keys
  get made.

### Header hygiene

`tweetnacl.h` is in `src/` (`PRIV_INCLUDE_DIRS`), not `include/`, because it
defines `crypto_hash` as a macro for SHA-512 — which would collide with the
Ascon component's `crypto_hash()` in any translation unit that saw both.
Dependents only ever see `ed25519_verify.h`.

## Performance note

TweetNaCl optimises for size and auditability, not speed, so it is
noticeably slower than an assembly-optimised Ed25519. That is a good trade here:
the device performs **one** verification per OTA attempt. If it ever mattered,
the drop-in alternative is the `libsodium` managed component
(`idf.py add-dependency "espressif/libsodium"`) and
`crypto_sign_verify_detached()`; `ed25519_verify()` is the only call site to
change.

No timing figure is quoted here because no ESP32 was available to measure one —
see `docs/BENCHMARKS.md`.
