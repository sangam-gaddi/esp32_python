/*
 * Thin wrapper turning TweetNaCl's combined-mode crypto_sign_open() into the
 * detached-signature verify the OTA package format needs.
 *
 * NaCl's signing API works on a "signed message" -- the 64-byte signature
 * immediately followed by the message. Our package header stores the signature
 * in a fixed field, so we reassemble sig||msg here.
 */

#include "ed25519_verify.h"

#include <string.h>

#include "tweetnacl.h"

/* TweetNaCl declares randombytes() as extern because NaCl's key generation and
 * crypto_box need entropy. Signature *verification* never calls it, but the
 * symbol still has to resolve at link time. Provide a real implementation on
 * the device, and a loud failure elsewhere -- silently returning predictable
 * bytes from something named randombytes is how weak keys get generated. */
#ifdef ESP_PLATFORM
#include "esp_random.h"
void randombytes(unsigned char *buf, unsigned long long n) {
  esp_fill_random(buf, (size_t)n);
}
#else
#include <stdlib.h>
void randombytes(unsigned char *buf, unsigned long long n) {
  (void)buf;
  (void)n;
  /* Host builds only ever verify. Reaching here means someone called a
   * key-generation or encryption routine that needs entropy we have not wired
   * up, so refuse rather than produce insecure output. */
  abort();
}
#endif

int ed25519_verify(const uint8_t sig[ED25519_SIGNATURE_BYTES],
                   const uint8_t *msg, size_t msglen,
                   const uint8_t pk[ED25519_PUBLIC_KEY_BYTES]) {
  if (sig == NULL || pk == NULL || (msg == NULL && msglen != 0)) return -1;
  if (msglen > ED25519_MAX_MESSAGE_BYTES) return -1;

  /* signed message: signature || message */
  unsigned char sm[ED25519_SIGNATURE_BYTES + ED25519_MAX_MESSAGE_BYTES];
  unsigned char out[ED25519_SIGNATURE_BYTES + ED25519_MAX_MESSAGE_BYTES];
  unsigned long long smlen = (unsigned long long)ED25519_SIGNATURE_BYTES + msglen;
  unsigned long long outlen = 0;

  memcpy(sm, sig, ED25519_SIGNATURE_BYTES);
  if (msglen) memcpy(sm + ED25519_SIGNATURE_BYTES, msg, msglen);

  int rc = crypto_sign_open(out, &outlen, sm, smlen, pk);

  /* Belt and braces: a valid result must also have returned exactly the message
   * we asked about. If either check disagrees, reject. */
  int ok = (rc == 0) && (outlen == (unsigned long long)msglen) &&
           (msglen == 0 || memcmp(out, msg, msglen) == 0);

  /* Nothing here is secret -- the message and public key are public, and the
   * signature is too -- but clear the scratch buffers so stale package bytes do
   * not linger on the stack. */
  memset(sm, 0, sizeof sm);
  memset(out, 0, sizeof out);

  return ok ? 0 : -1;
}
