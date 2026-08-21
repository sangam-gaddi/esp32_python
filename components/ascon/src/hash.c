/*
 * Ascon-Hash256 (NIST SP 800-232), one-shot -- the original implementation that
 * came with this component, with the portability defects fixed.
 *
 * This file is kept because it is independently KAT-correct: it passed all 1025
 * official Ascon-Hash256 vectors during the Phase 1 audit (see
 * docs/IMPLEMENTATION_AUDIT.md). Keeping it means the streaming implementation
 * in ascon_hash256.c has an independent second opinion in the test suite: both
 * are run against the same vectors, and tests/host/test_ascon_kat.c also checks
 * they agree byte-for-byte on random inputs.
 *
 * Fixes applied to the original (audit sections 3.1, 3.4, 3.5):
 *
 *  - Message loads and digest stores went through `((uint32_t*)p)[i]`. That
 *    faults on the ESP32 whenever the pointer is not 4-byte aligned -- Xtensa
 *    LX6 has no unaligned data access -- and it violates C strict aliasing.
 *    They now use the memcpy-based helpers in ascon_word.h.
 *  - `unsigned long len = inlen` silently truncated on 32-bit targets; `len` is
 *    now size_t and the parameter is used directly.
 *  - The digest tail used to be copied out through a pointer that aliased a
 *    local union 27 lines earlier. It now stores from the state directly.
 *
 * The algorithm, IV, rate, round count and padding are untouched.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "ascon_word.h"
#include "constants.h"
#include "lendian.h"
#include "permutations.h"
#include "printstate.h"

#if ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_HASH_IV##i
#define PB_START_ROUND ASCON_P12
#elif ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_HASHA_IV##i
#define PB_START_ROUND ASCON_P8
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_XOF_IV##i
#define PB_START_ROUND ASCON_P12
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_XOFA_IV##i
#define PB_START_ROUND ASCON_P8
#endif

#define PA_START_ROUND ASCON_P12

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long inlen) {
  printbytes("m", in, inlen);
  ascon_state_t s;
  size_t len = (size_t)inlen;

  /* initialization: IV0..IV4 are the state after the initial p^12 */
#ifdef ASCON_PRINT_STATE
  s = (ascon_state_t){{ASCON_HASH_IV, 0, 0, 0, 0}};
  printstate("initial value", &s);
  P(&s, PA_START_ROUND);
#else
  s = (ascon_state_t){{IV(0), IV(1), IV(2), IV(3), IV(4)}};
#endif
  printstate("initialization", &s);

  /* absorb full rate blocks */
  while (len >= ASCON_HASH_RATE) {
    s.x[0] ^= ascon_load(in, ASCON_HASH_RATE);
    printstate("absorb plaintext", &s);

    P(&s, PB_START_ROUND);

    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }

  /* absorb the final partial block plus padding (always present) */
  s.x[0] ^= ascon_load(in, (unsigned)len);
  s.x[0] ^= ascon_pad((unsigned)len);
  printstate("pad plaintext", &s);

  P(&s, PA_START_ROUND);

  /* squeeze the digest */
  unsigned char* const out0 = out;
  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    ascon_store(out, s.x[0], ASCON_HASH_RATE);
    printstate("squeeze output", &s);

    P(&s, PB_START_ROUND);

    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  ascon_store(out, s.x[0], (unsigned)len);
  printstate("squeeze output", &s);
  printbytes("h", out0, CRYPTO_BYTES);
  (void)out0;
  return 0;
}
