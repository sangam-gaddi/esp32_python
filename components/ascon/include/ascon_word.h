/*
 * Word-level helpers shared by the Ascon modes in this component.
 *
 * These exist for one reason above all others: the ESP32's Xtensa LX6 core
 * cannot perform unaligned 32/64-bit loads or stores against data memory. It
 * raises a LoadStoreAlignment exception, which panics the device. The original
 * hash implementation in this component read the message through
 * `((uint32_t*)in)[0]`, which also violates C strict aliasing. Every load and
 * store below therefore goes through memcpy, which is both alignment-safe and
 * alias-safe; compilers fold it back into a single instruction wherever the
 * pointer provably permits.
 *
 * Byte order follows NIST SP 800-232: bytes convert to and from the 64-bit
 * state words **little-endian**. (Ascon v1.2 was big-endian; that is why the
 * two produce different digests.) `lendian.h` keeps this correct on big-endian
 * hosts too, so the same sources run on the device and in the host test suite.
 */

#ifndef ASCON_WORD_H_
#define ASCON_WORD_H_

#include <stdint.h>
#include <string.h>

#include "lendian.h"

/* Round-count selectors for P(). The existing P() encodes the number of rounds
 * in its start constant and decrements by 15 per round down to 0x4b, so these
 * three values select p^12, p^8 and p^6 respectively. */
#define ASCON_P12 0xf0
#define ASCON_P8 0xb4
#define ASCON_P6 0x96

/* Load n bytes (0..8) little-endian into a state word; high bytes read zero. */
static inline uint64_t ascon_load(const uint8_t *bytes, unsigned n) {
  uint64_t x = 0;
  if (n) memcpy(&x, bytes, n);
  return U64LE(x);
}

/* Store the low n bytes (0..8) of a state word little-endian. */
static inline void ascon_store(uint8_t *bytes, uint64_t w, unsigned n) {
  uint64_t x = U64LE(w);
  if (n) memcpy(bytes, &x, n);
}

/* Ascon padding word for a partial block of n bytes: a single 0x01 byte at
 * offset n. Defined for n in 0..7. */
static inline uint64_t ascon_pad(unsigned n) {
  return (uint64_t)0x01 << (8 * n);
}

/* Domain separation constant, XORed into x4 between associated data and
 * payload. */
static inline uint64_t ascon_dsep(void) { return (uint64_t)0x80 << 56; }

/* Zero the low n bytes of w. Safe for n in 0..8 (unlike the upstream helper,
 * which is undefined at the ends). */
static inline uint64_t ascon_clear(uint64_t w, unsigned n) {
  if (n == 0) return w;
  if (n >= 8) return 0;
  return w & (~(uint64_t)0 << (8 * n));
}

/* Branch-free "is (a|b) nonzero": returns 0 when both words are zero and -1
 * otherwise. Used for tag comparison so the result does not depend on which
 * byte differed. */
static inline int ascon_notzero(uint64_t a, uint64_t b) {
  uint64_t r = a | b;
  r |= r >> 32;
  r |= r >> 16;
  r |= r >> 8;
  return ((((int)(r & 0xff) - 1) >> 8) & 1) - 1;
}

/* Wipe a buffer without the compiler optimising the write away. */
static inline void ascon_wipe(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

#endif /* ASCON_WORD_H_ */
