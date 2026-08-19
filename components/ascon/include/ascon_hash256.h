/*
 * Ascon-Hash256 (NIST SP 800-232) -- incremental and one-shot.
 *
 * The incremental API is the point of this file. The device hashes a ~1 MB
 * firmware image while it streams off the network, so it can never hold the
 * whole message in RAM; the pre-existing `crypto_hash()` in this component is
 * one-shot only and would require exactly that. The context below is 64 bytes,
 * so the streaming state costs essentially nothing.
 *
 * Both this implementation and `crypto_hash()` run on the same audited P()
 * permutation and are checked against all 1025 official Ascon-Hash256 KAT
 * vectors by tests/host/test_ascon_kat.c.
 */

#ifndef ASCON_HASH256_H_
#define ASCON_HASH256_H_

#include <stddef.h>
#include <stdint.h>

#include "ascon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_HASH256_BYTES 32 /* digest length */
#define ASCON_HASH256_RATE 8   /* bytes absorbed per permutation */

typedef struct {
  ascon_state_t s;
  uint8_t buf[ASCON_HASH256_RATE]; /* partial block not yet absorbed */
  uint8_t buflen;                  /* 0 .. ASCON_HASH256_RATE-1 after update */
} ascon_hash256_ctx_t;

/* Start a new digest. */
void ascon_hash256_init(ascon_hash256_ctx_t *ctx);

/* Absorb len bytes. Any chunking is permitted; `in` need not be aligned. */
void ascon_hash256_update(ascon_hash256_ctx_t *ctx, const uint8_t *in,
                          size_t len);

/* Produce the 32-byte digest and wipe the context. Call once per context. */
void ascon_hash256_final(ascon_hash256_ctx_t *ctx,
                         uint8_t out[ASCON_HASH256_BYTES]);

/* One-shot convenience wrapper over the three calls above. */
void ascon_hash256(uint8_t out[ASCON_HASH256_BYTES], const uint8_t *in,
                   size_t len);

/* Constant-time digest comparison. Returns 0 when the 32 bytes are equal.
 * Use this rather than memcmp so that rejecting a bad image does not leak how
 * many leading bytes matched. */
int ascon_hash256_equal(const uint8_t a[ASCON_HASH256_BYTES],
                        const uint8_t b[ASCON_HASH256_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_HASH256_H_ */
