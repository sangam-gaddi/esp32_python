/*
 * Ed25519 signature verification for the device.
 *
 * Why a bundled implementation: ESP-IDF's mbedTLS provides Curve25519 ECDH but
 * not Ed25519/EdDSA signatures, so there is nothing in the SDK to call. Rather
 * than write elliptic-curve arithmetic for this project -- a reliable way to
 * produce a subtly broken verifier -- this component wraps **TweetNaCl**, the
 * public-domain reference implementation of NaCl by Bernstein, Janssen, Lange
 * and Schwabe. See components/ed25519/README.md for provenance and hashes.
 *
 * Only verification is exposed. The device has no business signing anything:
 * the Ed25519 *private* key lives on the build/signing host and must never
 * appear in the firmware image.
 *
 * This header deliberately does not include tweetnacl.h -- that header defines
 * `crypto_hash` as a macro for SHA-512, which would collide with the Ascon
 * component's `crypto_hash()`. Only the .c file sees it.
 */

#ifndef ED25519_VERIFY_H_
#define ED25519_VERIFY_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ED25519_PUBLIC_KEY_BYTES 32
#define ED25519_SIGNATURE_BYTES 64

/* Largest message this verifier will accept. The signed part of an OTA package
 * header is 96 bytes; this cap keeps the verifier's two scratch buffers on the
 * stack at 2 x (64 + 256) = 640 bytes, which is bounded and predictable. */
#define ED25519_MAX_MESSAGE_BYTES 256

/*
 * Verify a detached Ed25519 signature.
 *
 *   sig      64-byte signature
 *   msg      the exact bytes that were signed
 *   msglen   length of msg, must be <= ED25519_MAX_MESSAGE_BYTES
 *   pk       32-byte trusted public key
 *
 * Returns 0 if and only if the signature is valid for (msg, pk).
 * Any nonzero return means REJECT -- do not fall back, do not retry, do not
 * treat a distinguishable error code as "probably fine".
 *
 * The public key must come from the device's own trusted configuration. Never
 * pass a key that arrived with the data being verified: that reduces the
 * signature to a checksum an attacker can recompute.
 */
int ed25519_verify(const uint8_t sig[ED25519_SIGNATURE_BYTES],
                   const uint8_t *msg, size_t msglen,
                   const uint8_t pk[ED25519_PUBLIC_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_VERIFY_H_ */
