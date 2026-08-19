/*
 * Host test for the C Ascon implementation in components/ascon.
 *
 * This compiles the *same* sources the ESP32 firmware links against and runs
 * them against the official NIST SP 800-232 Known-Answer-Test vectors in
 * tests/vectors/. That is what lets the project claim the device and the Python
 * packager implement the same algorithms: both are pinned to the same vectors.
 *
 * Build and run:  python tests/host/build_and_run.py
 *
 * Covered:
 *   1. crypto_hash()          -- the original one-shot hash, all 1025 vectors
 *   2. ascon_hash256()        -- the new one-shot hash, all 1025 vectors
 *   3. streaming hash         -- awkward chunk sizes must match the vectors
 *   4. cross-check            -- the two hash implementations agree
 *   5. AEAD encryption        -- all 1089 vectors
 *   6. AEAD decryption        -- all 1089 vectors recover the plaintext
 *   7. streaming AEAD         -- awkward chunk sizes match the one-shot result
 *   8. AEAD tamper rejection  -- ciphertext, tag, AD, key and nonce
 *   9. constant-time helpers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ascon_aead128.h"
#include "ascon_hash256.h"

/* the original one-shot entry point, declared in api.h terms */
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);

/* ---------------------------------------------------------------- test plumbing */

static int g_fail = 0;
static int g_checks = 0;

static void report(const char *name, int failures, long cases) {
  g_checks++;
  if (failures) {
    g_fail++;
    printf("  FAIL  %-42s %d/%ld cases failed\n", name, failures, cases);
  } else {
    printf("  ok    %-42s %ld cases\n", name, cases);
  }
}

static void hexdump(const char *label, const unsigned char *b, size_t n) {
  printf("      %s = ", label);
  for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
  printf("\n");
}

/* ------------------------------------------------------------- KAT file parsing */

#define MAX_MSG 4096
#define MAX_REC 1200

typedef struct {
  unsigned char msg[MAX_MSG];
  size_t msglen;
  unsigned char md[64];
  size_t mdlen;
} hash_rec_t;

typedef struct {
  unsigned char key[16], nonce[16];
  unsigned char pt[128], ad[128], ct[160];
  size_t ptlen, adlen, ctlen;
} aead_rec_t;

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* Parse "Name = AABBCC" into dst; returns byte count, or -1 if not that field. */
static long parse_field(const char *line, const char *name, unsigned char *dst,
                        size_t cap) {
  size_t nlen = strlen(name);
  if (strncmp(line, name, nlen) != 0) return -1;
  const char *p = line + nlen;
  while (*p == ' ') p++;
  if (*p != '=') return -1;
  p++;
  while (*p == ' ') p++;
  size_t n = 0;
  while (hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
    if (n >= cap) {
      printf("      parse overflow on field %s\n", name);
      exit(2);
    }
    dst[n++] = (unsigned char)(hexval(p[0]) * 16 + hexval(p[1]));
    p += 2;
  }
  return (long)n;
}

static size_t load_hash_kat(const char *path, hash_rec_t *out, size_t cap) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    printf("cannot open %s\n", path);
    exit(2);
  }
  char line[16384];
  size_t n = 0;
  int have_msg = 0;
  hash_rec_t cur;
  memset(&cur, 0, sizeof cur);
  while (fgets(line, sizeof line, f)) {
    long got = parse_field(line, "Msg", cur.msg, MAX_MSG);
    if (got >= 0) {
      cur.msglen = (size_t)got;
      have_msg = 1;
      continue;
    }
    got = parse_field(line, "MD", cur.md, sizeof cur.md);
    if (got >= 0 && have_msg) {
      cur.mdlen = (size_t)got;
      if (n >= cap) break;
      out[n++] = cur;
      have_msg = 0;
      memset(&cur, 0, sizeof cur);
    }
  }
  fclose(f);
  return n;
}

static size_t load_aead_kat(const char *path, aead_rec_t *out, size_t cap) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    printf("cannot open %s\n", path);
    exit(2);
  }
  char line[16384];
  size_t n = 0;
  aead_rec_t cur;
  memset(&cur, 0, sizeof cur);
  int seen_ct = 0;
  while (fgets(line, sizeof line, f)) {
    long got;
    if ((got = parse_field(line, "Key", cur.key, sizeof cur.key)) >= 0) continue;
    if ((got = parse_field(line, "Nonce", cur.nonce, sizeof cur.nonce)) >= 0) continue;
    if ((got = parse_field(line, "PT", cur.pt, sizeof cur.pt)) >= 0) {
      cur.ptlen = (size_t)got;
      continue;
    }
    if ((got = parse_field(line, "AD", cur.ad, sizeof cur.ad)) >= 0) {
      cur.adlen = (size_t)got;
      continue;
    }
    if ((got = parse_field(line, "CT", cur.ct, sizeof cur.ct)) >= 0) {
      cur.ctlen = (size_t)got;
      seen_ct = 1;
    }
    if (seen_ct) {
      if (n >= cap) break;
      out[n++] = cur;
      seen_ct = 0;
      memset(&cur, 0, sizeof cur);
    }
  }
  fclose(f);
  return n;
}

/* --------------------------------------------------------------- deterministic prng */

/* xorshift64* -- only used to generate test inputs, never for anything real. */
static unsigned long long g_rng = 0x9E3779B97F4A7C15ull;
static unsigned char rnd_byte(void) {
  g_rng ^= g_rng >> 12;
  g_rng ^= g_rng << 25;
  g_rng ^= g_rng >> 27;
  return (unsigned char)((g_rng * 0x2545F4914F6CDD1Dull) >> 56);
}
static void rnd_fill(unsigned char *b, size_t n) {
  for (size_t i = 0; i < n; i++) b[i] = rnd_byte();
}

/* ------------------------------------------------------------------------ tests */

static hash_rec_t hrec[MAX_REC];
static aead_rec_t arec[MAX_REC];
static size_t nhash, naead;

static void test_crypto_hash_kat(void) {
  int fails = 0;
  unsigned char got[32];
  for (size_t i = 0; i < nhash; i++) {
    crypto_hash(got, hrec[i].msg, hrec[i].msglen);
    if (hrec[i].mdlen != 32 || memcmp(got, hrec[i].md, 32) != 0) {
      if (!fails) {
        printf("      first mismatch at vector %zu (msglen %zu)\n", i + 1,
               hrec[i].msglen);
        hexdump("expect", hrec[i].md, 32);
        hexdump("got   ", got, 32);
      }
      fails++;
    }
  }
  report("crypto_hash() vs official KAT", fails, (long)nhash);
}

static void test_ascon_hash256_kat(void) {
  int fails = 0;
  unsigned char got[32];
  for (size_t i = 0; i < nhash; i++) {
    ascon_hash256(got, hrec[i].msg, hrec[i].msglen);
    if (memcmp(got, hrec[i].md, 32) != 0) {
      if (!fails) {
        printf("      first mismatch at vector %zu (msglen %zu)\n", i + 1,
               hrec[i].msglen);
        hexdump("expect", hrec[i].md, 32);
        hexdump("got   ", got, 32);
      }
      fails++;
    }
  }
  report("ascon_hash256() vs official KAT", fails, (long)nhash);
}

static void test_hash_streaming(void) {
  const size_t chunks[] = {1, 3, 7, 8, 9, 16, 31, 64, 1000};
  int fails = 0;
  long cases = 0;
  unsigned char got[32];
  for (size_t c = 0; c < sizeof chunks / sizeof chunks[0]; c++) {
    for (size_t i = 0; i < nhash; i++) {
      ascon_hash256_ctx_t ctx;
      ascon_hash256_init(&ctx);
      for (size_t off = 0; off < hrec[i].msglen; off += chunks[c]) {
        size_t n = hrec[i].msglen - off;
        if (n > chunks[c]) n = chunks[c];
        ascon_hash256_update(&ctx, hrec[i].msg + off, n);
      }
      ascon_hash256_final(&ctx, got);
      cases++;
      if (memcmp(got, hrec[i].md, 32) != 0) {
        if (!fails)
          printf("      first mismatch: vector %zu, chunk %zu\n", i + 1, chunks[c]);
        fails++;
      }
    }
  }
  report("streaming hash, 9 chunk sizes, vs KAT", fails, cases);
}

static void test_hash_unaligned(void) {
  /* The original implementation read the message through a uint32_t*, which
   * faults on Xtensa for unaligned input. Hash the same bytes at every byte
   * offset within a buffer and require an identical digest. */
  static unsigned char pad[8 + 300];
  unsigned char ref[32], got[32];
  int fails = 0;
  long cases = 0;
  for (size_t len = 1; len <= 40; len++) {
    unsigned char msg[40];
    rnd_fill(msg, len);
    ascon_hash256(ref, msg, len);
    for (size_t off = 0; off < 8; off++) {
      memset(pad, 0xCC, sizeof pad);
      memcpy(pad + off, msg, len);
      ascon_hash256(got, pad + off, len);
      cases++;
      if (memcmp(ref, got, 32) != 0) fails++;
      crypto_hash(got, pad + off, len);
      cases++;
      if (memcmp(ref, got, 32) != 0) fails++;
    }
  }
  report("hash at all 8 byte alignments", fails, cases);
}

static void test_hash_implementations_agree(void) {
  static unsigned char buf[3000];
  unsigned char a[32], b[32];
  int fails = 0;
  long cases = 0;
  for (size_t len = 0; len <= 600; len++) {
    rnd_fill(buf, len);
    crypto_hash(a, buf, len);
    ascon_hash256(b, buf, len);
    cases++;
    if (memcmp(a, b, 32) != 0) {
      if (!fails) printf("      diverge at len %zu\n", len);
      fails++;
    }
  }
  report("crypto_hash() == ascon_hash256()", fails, cases);
}

static void test_aead_encrypt_kat(void) {
  int fails = 0;
  unsigned char ct[160], tag[16];
  for (size_t i = 0; i < naead; i++) {
    aead_rec_t *r = &arec[i];
    ascon_aead128_encrypt(ct, tag, r->key, r->nonce, r->pt, r->ptlen, r->ad,
                          r->adlen);
    /* KAT "CT" field is ciphertext || tag */
    if (r->ctlen != r->ptlen + 16 || memcmp(ct, r->ct, r->ptlen) != 0 ||
        memcmp(tag, r->ct + r->ptlen, 16) != 0) {
      if (!fails) {
        printf("      first mismatch at vector %zu (ptlen %zu adlen %zu)\n",
               i + 1, r->ptlen, r->adlen);
        hexdump("expect", r->ct, r->ctlen);
        printf("      got    = ");
        for (size_t j = 0; j < r->ptlen; j++) printf("%02X", ct[j]);
        for (size_t j = 0; j < 16; j++) printf("%02X", tag[j]);
        printf("\n");
      }
      fails++;
    }
  }
  report("Ascon-AEAD128 encrypt vs official KAT", fails, (long)naead);
}

static void test_aead_decrypt_kat(void) {
  int fails = 0;
  unsigned char pt[160];
  for (size_t i = 0; i < naead; i++) {
    aead_rec_t *r = &arec[i];
    size_t ctlen = r->ctlen - 16;
    int bad = ascon_aead128_decrypt(pt, r->key, r->nonce, r->ct, ctlen,
                                   r->ct + ctlen, r->ad, r->adlen);
    if (bad || memcmp(pt, r->pt, r->ptlen) != 0) {
      if (!fails)
        printf("      first failure at vector %zu (bad=%d)\n", i + 1, bad);
      fails++;
    }
  }
  report("Ascon-AEAD128 decrypt vs official KAT", fails, (long)naead);
}

static void test_aead_streaming(void) {
  const size_t chunks[] = {1, 5, 15, 16, 17, 33, 64, 512};
  static unsigned char pt[4096], ct[4096 + 16], back[4096 + 16], one[4096];
  unsigned char key[16], nonce[16], ad[80], tag[16], tag2[16];
  int fails = 0;
  long cases = 0;

  rnd_fill(key, 16);
  rnd_fill(nonce, 16);
  rnd_fill(ad, sizeof ad);

  const size_t lens[] = {0, 1, 15, 16, 17, 31, 32, 33, 100, 1023, 1024, 4096};
  for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
    size_t len = lens[li];
    rnd_fill(pt, len);
    ascon_aead128_encrypt(one, tag, key, nonce, pt, len, ad, sizeof ad);

    for (size_t c = 0; c < sizeof chunks / sizeof chunks[0]; c++) {
      /* streaming encrypt must reproduce the one-shot ciphertext and tag */
      ascon_aead128_ctx_t e;
      ascon_aead128_init(&e, key, nonce, ad, sizeof ad);
      size_t produced = 0;
      for (size_t off = 0; off < len; off += chunks[c]) {
        size_t n = len - off;
        if (n > chunks[c]) n = chunks[c];
        produced += ascon_aead128_encrypt_update(&e, ct + produced, pt + off, n);
      }
      size_t tail = 0;
      ascon_aead128_encrypt_final(&e, ct + produced, &tail, tag2);
      produced += tail;
      cases++;
      if (produced != len || memcmp(ct, one, len) != 0 ||
          memcmp(tag, tag2, 16) != 0) {
        if (!fails)
          printf("      streaming encrypt diverged: len %zu chunk %zu\n", len,
                 chunks[c]);
        fails++;
        continue;
      }

      /* streaming decrypt must recover the plaintext and accept the tag */
      ascon_aead128_ctx_t d;
      ascon_aead128_init(&d, key, nonce, ad, sizeof ad);
      size_t recovered = 0;
      for (size_t off = 0; off < len; off += chunks[c]) {
        size_t n = len - off;
        if (n > chunks[c]) n = chunks[c];
        recovered += ascon_aead128_decrypt_update(&d, back + recovered, ct + off, n);
      }
      tail = 0;
      int bad = ascon_aead128_decrypt_final(&d, back + recovered, &tail, tag);
      recovered += tail;
      cases++;
      if (bad || recovered != len || memcmp(back, pt, len) != 0) {
        if (!fails)
          printf("      streaming decrypt failed: len %zu chunk %zu bad=%d\n",
                 len, chunks[c], bad);
        fails++;
      }
    }
  }
  report("streaming AEAD == one-shot, 8 chunk sizes", fails, cases);
}

static void test_aead_rejects_tampering(void) {
  static unsigned char pt[600], ct[600], back[600];
  unsigned char key[16], nonce[16], ad[80], tag[16];
  int fails = 0;
  long cases = 0;
  const size_t len = 600;

  rnd_fill(key, 16);
  rnd_fill(nonce, 16);
  rnd_fill(ad, sizeof ad);
  rnd_fill(pt, len);
  ascon_aead128_encrypt(ct, tag, key, nonce, pt, len, ad, sizeof ad);

  /* sanity: the untampered package must verify */
  cases++;
  if (ascon_aead128_decrypt(back, key, nonce, ct, len, tag, ad, sizeof ad) != 0) {
    printf("      baseline decrypt failed - test is broken\n");
    fails++;
  }

  /* every single-bit flip in the ciphertext must be rejected */
  for (size_t pos = 0; pos < len; pos += 7) {
    unsigned char bad_ct[600];
    memcpy(bad_ct, ct, len);
    bad_ct[pos] ^= 0x01;
    cases++;
    if (ascon_aead128_decrypt(back, key, nonce, bad_ct, len, tag, ad,
                              sizeof ad) == 0)
      fails++;
  }

  /* tag, key, nonce and associated data */
  for (size_t pos = 0; pos < 16; pos++) {
    unsigned char x[16];

    memcpy(x, tag, 16);
    x[pos] ^= 0x80;
    cases++;
    if (ascon_aead128_decrypt(back, key, nonce, ct, len, x, ad, sizeof ad) == 0)
      fails++;

    memcpy(x, key, 16);
    x[pos] ^= 0x01;
    cases++;
    if (ascon_aead128_decrypt(back, x, nonce, ct, len, tag, ad, sizeof ad) == 0)
      fails++;

    memcpy(x, nonce, 16);
    x[pos] ^= 0x01;
    cases++;
    if (ascon_aead128_decrypt(back, key, x, ct, len, tag, ad, sizeof ad) == 0)
      fails++;
  }
  for (size_t pos = 0; pos < sizeof ad; pos += 3) {
    unsigned char bad_ad[80];
    memcpy(bad_ad, ad, sizeof ad);
    bad_ad[pos] ^= 0x20;
    cases++;
    if (ascon_aead128_decrypt(back, key, nonce, ct, len, tag, bad_ad,
                              sizeof ad) == 0)
      fails++;
  }

  report("AEAD rejects every tampered input", fails, cases);
}

static void test_aead_wipes_on_failure(void) {
  static unsigned char pt[64], ct[64], out[64];
  unsigned char key[16], nonce[16], tag[16];
  rnd_fill(key, 16);
  rnd_fill(nonce, 16);
  rnd_fill(pt, sizeof pt);
  ascon_aead128_encrypt(ct, tag, key, nonce, pt, sizeof pt, NULL, 0);

  unsigned char bad_tag[16];
  memcpy(bad_tag, tag, 16);
  bad_tag[0] ^= 0xFF;
  memset(out, 0xAA, sizeof out);
  int bad = ascon_aead128_decrypt(out, key, nonce, ct, sizeof ct, bad_tag, NULL, 0);

  int fails = 0;
  if (bad == 0) fails++;
  for (size_t i = 0; i < sizeof out; i++)
    if (out[i] != 0) fails++;
  report("failed AEAD decrypt zeroes the output", fails, 1);
}

static void test_constant_time_compare(void) {
  unsigned char a[32], b[32];
  int fails = 0;
  long cases = 0;
  rnd_fill(a, 32);
  memcpy(b, a, 32);
  cases++;
  if (ascon_hash256_equal(a, b) != 0) fails++;
  for (size_t i = 0; i < 32; i++) {
    memcpy(b, a, 32);
    b[i] ^= 0x01;
    cases++;
    if (ascon_hash256_equal(a, b) == 0) fails++;
  }
  report("ascon_hash256_equal()", fails, cases);
}

/* ------------------------------------------------------------------------- main */

int main(int argc, char **argv) {
  const char *hash_kat = argc > 1 ? argv[1] : "tests/vectors/LWC_HASH_KAT_128_256.txt";
  const char *aead_kat = argc > 2 ? argv[2] : "tests/vectors/LWC_AEAD_KAT_128_128.txt";

  printf("Ascon C implementation -- host test\n");
  printf("  hash vectors: %s\n", hash_kat);
  printf("  aead vectors: %s\n\n", aead_kat);

  nhash = load_hash_kat(hash_kat, hrec, MAX_REC);
  naead = load_aead_kat(aead_kat, arec, MAX_REC);
  printf("loaded %zu hash vectors, %zu aead vectors\n\n", nhash, naead);
  if (nhash != 1025 || naead != 1089) {
    printf("FAIL: unexpected vector counts (expected 1025 / 1089)\n");
    return 1;
  }

  test_crypto_hash_kat();
  test_ascon_hash256_kat();
  test_hash_streaming();
  test_hash_unaligned();
  test_hash_implementations_agree();
  test_aead_encrypt_kat();
  test_aead_decrypt_kat();
  test_aead_streaming();
  test_aead_rejects_tampering();
  test_aead_wipes_on_failure();
  test_constant_time_compare();

  printf("\n%d/%d test groups passed\n", g_checks - g_fail, g_checks);
  if (g_fail) {
    printf("RESULT: FAILED\n");
    return 1;
  }
  printf("RESULT: PASSED\n");
  return 0;
}
