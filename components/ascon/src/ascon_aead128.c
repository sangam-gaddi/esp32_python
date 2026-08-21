/*
 * Ascon-AEAD128 (NIST SP 800-232) on the audited P() permutation.
 *
 * Duplex construction, 16-byte rate over words x0 and x1:
 *
 *   init    x0 <- IV, x1..x2 <- key, x3..x4 <- nonce, p^12, then x3..x4 ^= key
 *   ad      x0,x1 ^= ad block, p^8   (final partial block always padded)
 *   dsep    x4 ^= 0x80 << 56
 *   enc     x0,x1 ^= plaintext, emit x0,x1, p^8
 *   dec     emit x0,x1 ^ ciphertext, x0,x1 <- ciphertext, p^8
 *   final   x2,x3 ^= key, p^12, tag <- (x3 ^ k0) || (x4 ^ k1)
 *
 * The mode logic follows the upstream ascon-c reference implementation
 * (crypto_aead/asconaead128) so that no cryptographic construction is
 * reinvented here; the only change is restructuring into an incremental API,
 * which the streaming OTA path needs.
 */

#include "ascon_aead128.h"

#include <string.h>

#include "ascon_word.h"
#include "constants.h"
#include "permutations.h"

/* --------------------------------------------------------------------------
 * initialisation
 * -------------------------------------------------------------------------- */

void ascon_aead128_init(ascon_aead128_ctx_t *ctx,
                        const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                        const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                        const uint8_t *ad, size_t adlen) {
  ctx->k0 = ascon_load(key, 8);
  ctx->k1 = ascon_load(key + 8, 8);

  ctx->s.x[0] = ASCON_AEAD128_IV;
  ctx->s.x[1] = ctx->k0;
  ctx->s.x[2] = ctx->k1;
  ctx->s.x[3] = ascon_load(nonce, 8);
  ctx->s.x[4] = ascon_load(nonce + 8, 8);
  P(&ctx->s, ASCON_P12);
  ctx->s.x[3] ^= ctx->k0;
  ctx->s.x[4] ^= ctx->k1;

  /* associated data */
  if (adlen) {
    while (adlen >= ASCON_AEAD128_RATE) {
      ctx->s.x[0] ^= ascon_load(ad, 8);
      ctx->s.x[1] ^= ascon_load(ad + 8, 8);
      P(&ctx->s, ASCON_P8);
      ad += ASCON_AEAD128_RATE;
      adlen -= ASCON_AEAD128_RATE;
    }
    /* final associated-data block: 0..15 bytes plus padding */
    if (adlen >= 8) {
      ctx->s.x[0] ^= ascon_load(ad, 8);
      adlen -= 8;
      ad += 8;
      ctx->s.x[1] ^= ascon_load(ad, (unsigned)adlen) ^ ascon_pad((unsigned)adlen);
    } else {
      ctx->s.x[0] ^= ascon_load(ad, (unsigned)adlen) ^ ascon_pad((unsigned)adlen);
    }
    P(&ctx->s, ASCON_P8);
  }

  /* Domain separation happens whether or not there was any associated data. */
  ctx->s.x[4] ^= ascon_dsep();

  ctx->buflen = 0;
  memset(ctx->buf, 0, sizeof ctx->buf);
}

/* --------------------------------------------------------------------------
 * full-block workers
 * -------------------------------------------------------------------------- */

static void enc_block(ascon_aead128_ctx_t *ctx, uint8_t *out,
                      const uint8_t *in) {
  ctx->s.x[0] ^= ascon_load(in, 8);
  ctx->s.x[1] ^= ascon_load(in + 8, 8);
  ascon_store(out, ctx->s.x[0], 8);
  ascon_store(out + 8, ctx->s.x[1], 8);
  P(&ctx->s, ASCON_P8);
}

static void dec_block(ascon_aead128_ctx_t *ctx, uint8_t *out,
                      const uint8_t *in) {
  uint64_t c0 = ascon_load(in, 8);
  uint64_t c1 = ascon_load(in + 8, 8);
  ascon_store(out, ctx->s.x[0] ^ c0, 8);
  ascon_store(out + 8, ctx->s.x[1] ^ c1, 8);
  ctx->s.x[0] = c0;
  ctx->s.x[1] = c1;
  P(&ctx->s, ASCON_P8);
}

/* Shared block-buffering driver for encrypt/decrypt update. `worker` handles
 * one complete 16-byte block. */
static size_t update_buffered(ascon_aead128_ctx_t *ctx, uint8_t *out,
                              const uint8_t *in, size_t len,
                              void (*worker)(ascon_aead128_ctx_t *, uint8_t *,
                                             const uint8_t *)) {
  size_t written = 0;

  if (ctx->buflen) {
    size_t take = ASCON_AEAD128_RATE - ctx->buflen;
    if (take > len) take = len;
    memcpy(ctx->buf + ctx->buflen, in, take);
    ctx->buflen += (uint8_t)take;
    in += take;
    len -= take;
    if (ctx->buflen < ASCON_AEAD128_RATE) return 0;
    worker(ctx, out, ctx->buf);
    out += ASCON_AEAD128_RATE;
    written += ASCON_AEAD128_RATE;
    ctx->buflen = 0;
  }

  while (len >= ASCON_AEAD128_RATE) {
    worker(ctx, out, in);
    in += ASCON_AEAD128_RATE;
    out += ASCON_AEAD128_RATE;
    len -= ASCON_AEAD128_RATE;
    written += ASCON_AEAD128_RATE;
  }

  if (len) {
    memcpy(ctx->buf, in, len);
    ctx->buflen = (uint8_t)len;
  }
  return written;
}

size_t ascon_aead128_encrypt_update(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                    const uint8_t *in, size_t len) {
  return update_buffered(ctx, out, in, len, enc_block);
}

size_t ascon_aead128_decrypt_update(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                    const uint8_t *in, size_t len) {
  return update_buffered(ctx, out, in, len, dec_block);
}

/* --------------------------------------------------------------------------
 * finalisation
 * -------------------------------------------------------------------------- */

/* x2,x3 ^= key; p^12; tag = (x3 ^ k0) || (x4 ^ k1) */
static void compute_tag(ascon_aead128_ctx_t *ctx,
                        uint8_t tag[ASCON_AEAD128_TAG_BYTES]) {
  ctx->s.x[2] ^= ctx->k0;
  ctx->s.x[3] ^= ctx->k1;
  P(&ctx->s, ASCON_P12);
  ascon_store(tag, ctx->s.x[3] ^ ctx->k0, 8);
  ascon_store(tag + 8, ctx->s.x[4] ^ ctx->k1, 8);
}

void ascon_aead128_encrypt_final(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                 size_t *outlen,
                                 uint8_t tag[ASCON_AEAD128_TAG_BYTES]) {
  unsigned n = ctx->buflen; /* 0..15 */
  const uint8_t *m = ctx->buf;
  size_t w = 0;

  /* First half of the rate, if the tail reaches into it. */
  if (n >= 8) {
    ctx->s.x[0] ^= ascon_load(m, 8);
    ascon_store(out, ctx->s.x[0], 8);
    out += 8;
    w += 8;
    m += 8;
    n -= 8;
    ctx->s.x[1] ^= ascon_load(m, n) ^ ascon_pad(n);
    if (n) {
      ascon_store(out, ctx->s.x[1], n);
      w += n;
    }
  } else {
    ctx->s.x[0] ^= ascon_load(m, n) ^ ascon_pad(n);
    if (n) {
      ascon_store(out, ctx->s.x[0], n);
      w += n;
    }
  }

  *outlen = w;
  compute_tag(ctx, tag);
  ascon_wipe(ctx, sizeof *ctx);
}

int ascon_aead128_decrypt_final(ascon_aead128_ctx_t *ctx, uint8_t *out,
                                size_t *outlen,
                                const uint8_t tag[ASCON_AEAD128_TAG_BYTES]) {
  unsigned n = ctx->buflen; /* 0..15 */
  const uint8_t *c = ctx->buf;
  size_t w = 0;
  uint64_t *px = &ctx->s.x[0];

  if (n >= 8) {
    uint64_t c0 = ascon_load(c, 8);
    ascon_store(out, ctx->s.x[0] ^ c0, 8);
    ctx->s.x[0] = c0;
    out += 8;
    w += 8;
    c += 8;
    n -= 8;
    px = &ctx->s.x[1];
  }

  /* Pad first, then overlay the tail: the pad byte sits at offset n, above the
   * n plaintext bytes, so it never disturbs the output. */
  *px ^= ascon_pad(n);
  if (n) {
    uint64_t cx = ascon_load(c, n);
    *px ^= cx;
    ascon_store(out, *px, n);
    w += n;
    *px = ascon_clear(*px, n) ^ cx;
  }
  *outlen = w;

  uint8_t computed[ASCON_AEAD128_TAG_BYTES];
  compute_tag(ctx, computed);

  /* Constant-time comparison via the state words, so failure timing does not
   * reveal how much of the tag matched. */
  int bad = ascon_notzero(
      ascon_load(computed, 8) ^ ascon_load(tag, 8),
      ascon_load(computed + 8, 8) ^ ascon_load(tag + 8, 8));

  ascon_wipe(computed, sizeof computed);
  ascon_wipe(ctx, sizeof *ctx);
  return bad;
}

/* --------------------------------------------------------------------------
 * one-shot wrappers (used by the host test harness and small payloads)
 * -------------------------------------------------------------------------- */

void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_AEAD128_TAG_BYTES],
                           const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                           const uint8_t *pt, size_t ptlen, const uint8_t *ad,
                           size_t adlen) {
  ascon_aead128_ctx_t ctx;
  ascon_aead128_init(&ctx, key, nonce, ad, adlen);

  /* Whole blocks straight through, so no output lag and no extra buffer. */
  size_t full = ptlen - (ptlen % ASCON_AEAD128_RATE);
  for (size_t off = 0; off < full; off += ASCON_AEAD128_RATE)
    enc_block(&ctx, ct + off, pt + off);

  size_t tail = ptlen - full;
  if (tail) {
    memcpy(ctx.buf, pt + full, tail);
    ctx.buflen = (uint8_t)tail;
  }
  size_t outlen = 0;
  ascon_aead128_encrypt_final(&ctx, ct + full, &outlen, tag);
}

int ascon_aead128_decrypt(uint8_t *pt,
                          const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                          const uint8_t nonce[ASCON_AEAD128_NONCE_BYTES],
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t tag[ASCON_AEAD128_TAG_BYTES],
                          const uint8_t *ad, size_t adlen) {
  ascon_aead128_ctx_t ctx;
  ascon_aead128_init(&ctx, key, nonce, ad, adlen);

  size_t full = ctlen - (ctlen % ASCON_AEAD128_RATE);
  for (size_t off = 0; off < full; off += ASCON_AEAD128_RATE)
    dec_block(&ctx, pt + off, ct + off);

  size_t tail = ctlen - full;
  if (tail) {
    memcpy(ctx.buf, ct + full, tail);
    ctx.buflen = (uint8_t)tail;
  }
  size_t outlen = 0;
  int bad = ascon_aead128_decrypt_final(&ctx, pt + full, &outlen, tag);

  if (bad) {
    /* Never hand back plaintext that failed to authenticate. */
    ascon_wipe(pt, ctlen);
  }
  return bad;
}
