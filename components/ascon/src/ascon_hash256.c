/*
 * Ascon-Hash256 (NIST SP 800-232), incremental.
 *
 * Sponge construction over the audited P() permutation from permutations.c:
 *
 *   init     state <- IV, then p^12       (IV0..IV4 are the precomputed result)
 *   absorb   x0 ^= block, p^12            8-byte rate
 *   pad      x0 ^= 0x01 << 8*len          single always-present partial block
 *   squeeze  emit x0, p^12                until 32 bytes are out
 *
 * pa = pb = 12 rounds for Ascon-Hash256.
 */

#include "ascon_hash256.h"

#include <string.h>

#include "ascon_word.h"
#include "constants.h"
#include "permutations.h"

void ascon_hash256_init(ascon_hash256_ctx_t *ctx) {
  /* ASCON_HASH_IV0..4 are the state *after* the initial p^12, so no
   * permutation call is needed here. */
  ctx->s.x[0] = ASCON_HASH_IV0;
  ctx->s.x[1] = ASCON_HASH_IV1;
  ctx->s.x[2] = ASCON_HASH_IV2;
  ctx->s.x[3] = ASCON_HASH_IV3;
  ctx->s.x[4] = ASCON_HASH_IV4;
  ctx->buflen = 0;
}

static void absorb_block(ascon_hash256_ctx_t *ctx, const uint8_t *block) {
  ctx->s.x[0] ^= ascon_load(block, ASCON_HASH256_RATE);
  P(&ctx->s, ASCON_P12);
}

void ascon_hash256_update(ascon_hash256_ctx_t *ctx, const uint8_t *in,
                          size_t len) {
  if (len == 0) return;

  /* Top up a partial block left over from a previous call. */
  if (ctx->buflen) {
    size_t take = ASCON_HASH256_RATE - ctx->buflen;
    if (take > len) take = len;
    memcpy(ctx->buf + ctx->buflen, in, take);
    ctx->buflen += (uint8_t)take;
    in += take;
    len -= take;
    if (ctx->buflen < ASCON_HASH256_RATE) return; /* still short of a block */
    absorb_block(ctx, ctx->buf);
    ctx->buflen = 0;
  }

  /* Absorb whole blocks straight from the caller's buffer. */
  while (len >= ASCON_HASH256_RATE) {
    absorb_block(ctx, in);
    in += ASCON_HASH256_RATE;
    len -= ASCON_HASH256_RATE;
  }

  /* Keep the remainder for next time. */
  if (len) {
    memcpy(ctx->buf, in, len);
    ctx->buflen = (uint8_t)len;
  }
}

void ascon_hash256_final(ascon_hash256_ctx_t *ctx,
                         uint8_t out[ASCON_HASH256_BYTES]) {
  /* Final partial block: 0..7 buffered bytes plus the 0x01 pad byte. This
   * block always exists, even for a message that is a multiple of the rate. */
  ctx->s.x[0] ^= ascon_load(ctx->buf, ctx->buflen);
  ctx->s.x[0] ^= ascon_pad(ctx->buflen);
  P(&ctx->s, ASCON_P12);

  size_t left = ASCON_HASH256_BYTES;
  while (left > ASCON_HASH256_RATE) {
    ascon_store(out, ctx->s.x[0], ASCON_HASH256_RATE);
    P(&ctx->s, ASCON_P12);
    out += ASCON_HASH256_RATE;
    left -= ASCON_HASH256_RATE;
  }
  ascon_store(out, ctx->s.x[0], (unsigned)left);

  /* The state is not secret for a hash, but wiping keeps the habit and stops a
   * stale context being reused by accident. */
  ascon_wipe(ctx, sizeof *ctx);
}

void ascon_hash256(uint8_t out[ASCON_HASH256_BYTES], const uint8_t *in,
                   size_t len) {
  ascon_hash256_ctx_t ctx;
  ascon_hash256_init(&ctx);
  ascon_hash256_update(&ctx, in, len);
  ascon_hash256_final(&ctx, out);
}

int ascon_hash256_equal(const uint8_t a[ASCON_HASH256_BYTES],
                        const uint8_t b[ASCON_HASH256_BYTES]) {
  uint8_t diff = 0;
  for (unsigned i = 0; i < ASCON_HASH256_BYTES; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  /* fold to 0 / 1 without branching on diff */
  return (int)((uint8_t)((diff | (uint8_t)(0u - diff)) >> 7));
}
