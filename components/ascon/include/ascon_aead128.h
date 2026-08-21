/*
 * Ascon-AEAD128 (NIST SP 800-232) -- authenticated encryption.
 *
 * 128-bit key, 128-bit nonce, 128-bit tag, 128-bit rate, pa = 12, pb = 8.
 * This is the standardised form of the Ascon-128 AEAD family; see
 * docs/PACKAGE_FORMAT.md for the exact naming and why this variant was chosen.
 *
 * Both a one-shot and an incremental API are provided. The device uses the
 * incremental one: it decrypts a ~1 MB firmware image as it arrives off the
 * network, in fixed-size chunks, and can never buffer the whole image.
 *
 * THE TAG IS EVERYTHING. `ascon_aead128_decrypt_final()` is what tells you the
 * ciphertext was produced by someone holding the key and has not been altered.
 * Plaintext emitted by `ascon_aead128_decrypt_update()` before that call is
 * UNAUTHENTICATED and must not be executed, forwarded or otherwise acted upon.
 * Streaming decryption inherently releases plaintext early; the caller is
 * responsible for holding it somewhere inert until the tag verifies. In this
 * project it goes to the *inactive* OTA partition, which is never made bootable
 * unless the tag, the Ascon-Hash256 digest and the Ed25519 signature all check
 * out.
 *
 * NONCE REUSE IS FATAL. Never encrypt twice under the same (key, nonce) pair:
 * it reveals the XOR of the two plaintexts and destroys authenticity. The
 * packaging tool draws a fresh random nonce for every package.
 *
 * Validated against all 1089 official Ascon-AEAD128 KAT vectors by
 * tests/host/test_ascon_kat.c.
 */

#ifndef ASCON_AEAD128_H_
#define ASCON_AEAD128_H_

#include <stddef.h>
#include <stdint.h>

#include "ascon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_AEAD128_KEY_BYTES 16
#define ASCON_AEAD128_NONCE_BYTES 16
#define ASCON_AEAD128_TAG_BYTES 16
#define ASCON_AEAD128_RATE 16 /* bytes processed per permutation */

/* Worst-case output capacity needed for one *_update() call carrying `inlen`
 * input bytes: up to 15 previously buffered bytes can be flushed alongside. */
#define ASCON_AEAD128_UPDATE_OUT_MAX(inlen) ((size_t)(inlen) + ASCON_AEAD128_RATE - 1)

typedef struct {
  ascon_state_t s;
  uint64_t k0, k1;                /* key words, needed again at finalisation */
  uint8_t buf[ASCON_AEAD128_RATE]; /* partial block not yet processed */
  uint8_t buflen;                 /* 0 .. ASCON_AEAD128_RATE-1 after update */
} ascon_aead128_ctx_t;

/* ---------------------------------------------------------------- incremental */

/* Absorb key, nonce and all associated data. The associated data must be
 * supplied here in full -- Ascon absorbs it before any payload -- so it has to
 * fit in memory. In this project it is the 80-byte package header prefix.
 * Used for both encryption and decryption. */
void ascon_aead128_init(ascon_aead128_ctx_t *ctx,
                        const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                        const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                        const uint8_t *ad, size_t adlen);

/* Encrypt `len` plaintext bytes. Returns the number of ciphertext bytes written
 * to `out`, which lags the input by up to 15 bytes; size `out` with
 * ASCON_AEAD128_UPDATE_OUT_MAX(len). Neither pointer needs to be aligned.
 * `in` and `out` must not overlap: once a partial block is pending, `out` runs
 * ahead of `in`, so in-place operation would clobber unread input. (The
 * one-shot functions below do allow ct == pt.) */
size_t ascon_aead128_encrypt_update(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                    const uint8_t *in, size_t len);

/* Flush the final partial block (0..15 bytes to `out`, count in `*outlen`) and
 * produce the tag. Wipes the context. */
void ascon_aead128_encrypt_final(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                 size_t *outlen,
                                 uint8_t tag[ASCON_AEAD128_TAG_BYTES]);

/* Decrypt `len` ciphertext bytes. Same buffering contract as the encrypt
 * counterpart. The plaintext produced here is NOT yet authenticated. */
size_t ascon_aead128_decrypt_update(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                    const uint8_t *in, size_t len);

/* Flush the final partial block and verify `tag`.
 * Returns 0 if and only if the tag is correct; nonzero means the ciphertext,
 * nonce, associated data or key is wrong and everything decrypted from this
 * context must be discarded. Wipes the context either way. */
int ascon_aead128_decrypt_final(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                size_t *outlen,
                                const uint8_t tag[ASCON_AEAD128_TAG_BYTES]);

/* ------------------------------------------------------------------ one-shot */

/* `ct` needs `ptlen` bytes; may alias `pt`. */
void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_AEAD128_TAG_BYTES],
                           const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                           const uint8_t *pt, size_t ptlen, const uint8_t *ad,
                           size_t adlen);

/* Returns 0 on success (tag verified), nonzero on failure. On failure `pt` is
 * zeroed so unauthenticated plaintext cannot be used by mistake. */
int ascon_aead128_decrypt(uint8_t *pt,
                          const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                          const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t tag[ASCON_AEAD128_TAG_BYTES],
                          const uint8_t *ad, size_t adlen);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_AEAD128_H_ */
