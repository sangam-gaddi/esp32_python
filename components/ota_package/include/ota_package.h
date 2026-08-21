/*
 * `.sota` OTA package parsing and cryptographic verification.
 *
 * This component contains no ESP-IDF dependencies at all -- only the Ascon and
 * Ed25519 components and the C standard library. That is deliberate: it means
 * the exact code the device trusts can be compiled and executed on the
 * development host and run against packages produced by the Python packager
 * (tests/host/test_package_parser.c). A parser that only ever runs on the target
 * is a parser nobody has really tested.
 *
 * Format (all integers little-endian; see docs/PACKAGE_FORMAT.md):
 *
 *     off  size  field
 *       0     4  magic "SOTA"
 *       4     2  format_version = 1
 *       6     2  header_size = 160
 *       8     4  firmware_version   major<<16 | minor<<8 | patch
 *      12     4  security_version   monotonic counter
 *      16     4  firmware_size      plaintext length
 *      20     4  ciphertext_size    == firmware_size
 *      24     8  build_timestamp    unix seconds, informational
 *      32    16  nonce
 *      48    32  firmware_hash      Ascon-Hash256 of the PLAINTEXT firmware
 *     ------------- bytes 0..80  = AEAD associated data -------------
 *      80    16  auth_tag           Ascon-AEAD128 tag
 *     ------------- bytes 0..96  = Ed25519-signed region ------------
 *      96    64  signature
 *     160     N  ciphertext
 *
 * Verification order, and why:
 *
 *   1. parse the header               (structure only, nothing trusted yet)
 *   2. ota_pkg_verify_signature()     Ed25519 over header[0:96]
 *   3. ota_pkg_check_versions()       anti-rollback, on now-authenticated values
 *   4. stream the payload             decrypt + hash, chunk by chunk
 *   5. ota_pkg_payload_final()        AEAD tag, then Ascon-Hash256 comparison
 *
 * Steps 2 and 3 come first because the header arrives before the payload: an
 * unauthorised or rolled-back package is rejected without downloading a single
 * byte of firmware. Only after step 5 returns OTA_PKG_OK may anything that was
 * decrypted be treated as genuine.
 */

#ifndef OTA_PACKAGE_H_
#define OTA_PACKAGE_H_

#include <stddef.h>
#include <stdint.h>

#include "ascon_aead128.h"
#include "ascon_hash256.h"
#include "ed25519_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OTA_PKG_MAGIC "SOTA"
#define OTA_PKG_MAGIC_LEN 4
#define OTA_PKG_FORMAT_VERSION 1
#define OTA_PKG_HEADER_SIZE 160
#define OTA_PKG_AD_LEN 80     /* associated data span: header[0:80]  */
#define OTA_PKG_SIGNED_LEN 96 /* signed span:          header[0:96]  */

/* Refuse absurd sizes early so a corrupt length field cannot make the device
 * attempt a multi-gigabyte download. Larger than any ESP32 app partition. */
#define OTA_PKG_MAX_FIRMWARE_SIZE (8u * 1024u * 1024u)

typedef enum {
  OTA_PKG_OK = 0,
  OTA_PKG_ERR_ARG,            /* NULL pointer or nonsensical argument       */
  OTA_PKG_ERR_TRUNCATED,      /* fewer bytes than the format requires       */
  OTA_PKG_ERR_MAGIC,          /* not a .sota package at all                 */
  OTA_PKG_ERR_FORMAT_VERSION, /* newer format than this firmware knows      */
  OTA_PKG_ERR_HEADER_SIZE,    /* header_size field disagrees with the format */
  OTA_PKG_ERR_SIZE_RANGE,     /* firmware_size zero or over the limit       */
  OTA_PKG_ERR_SIZE_MISMATCH,  /* ciphertext_size != firmware_size           */
  OTA_PKG_ERR_LENGTH,         /* payload longer or shorter than declared    */
  OTA_PKG_ERR_SIGNATURE,      /* Ed25519 verification failed                */
  OTA_PKG_ERR_TAG,            /* Ascon-AEAD128 tag verification failed      */
  OTA_PKG_ERR_HASH,           /* Ascon-Hash256 of the plaintext mismatched  */
  OTA_PKG_ERR_ROLLBACK,       /* security_version older than ours           */
  OTA_PKG_ERR_NOT_NEWER,      /* firmware_version not an upgrade            */
  OTA_PKG_ERR_STATE,          /* API used out of order                      */
} ota_pkg_err_t;

/* Short human-readable reason, safe to print to a console. */
const char *ota_pkg_strerror(ota_pkg_err_t err);

/* Parsed header. `raw` keeps the header bytes verbatim so the authenticated
 * spans are the exact bytes that were signed -- the device never re-serialises
 * the fields and hopes the result matches. */
typedef struct {
  uint16_t format_version;
  uint16_t header_size;
  uint32_t firmware_version;
  uint32_t security_version;
  uint32_t firmware_size;
  uint32_t ciphertext_size;
  uint64_t build_timestamp;
  uint8_t nonce[ASCON_AEAD128_NONCE_BYTES];
  uint8_t firmware_hash[ASCON_HASH256_BYTES];
  uint8_t auth_tag[ASCON_AEAD128_TAG_BYTES];
  uint8_t signature[ED25519_SIGNATURE_BYTES];
  uint8_t raw[OTA_PKG_HEADER_SIZE];
} ota_pkg_header_t;

/* Device's current version state, for the anti-rollback check. */
typedef struct {
  uint32_t firmware_version;
  uint32_t security_version;
} ota_pkg_version_state_t;

/*
 * Parse and structurally validate a header. `len` must be at least
 * OTA_PKG_HEADER_SIZE; extra bytes are ignored, so this can be called on the
 * first chunk of a download.
 *
 * Nothing returned here is authenticated. Never act on any field until
 * ota_pkg_verify_signature() has returned OTA_PKG_OK.
 */
ota_pkg_err_t ota_pkg_parse_header(ota_pkg_header_t *out, const uint8_t *buf,
                                  size_t len);

/*
 * Verify the Ed25519 signature over header[0:96] using the device's trusted
 * public key.
 *
 * `trusted_pk` must come from the device's own configuration. Never pass a key
 * that travelled with the package -- that turns the signature into a checksum
 * any attacker can recompute.
 */
ota_pkg_err_t ota_pkg_verify_signature(const ota_pkg_header_t *hdr,
                                       const uint8_t trusted_pk[ED25519_PUBLIC_KEY_BYTES]);

/*
 * Anti-rollback and freshness check against the device's current state.
 *
 *   security_version <  current  -> OTA_PKG_ERR_ROLLBACK  (reject: downgrade)
 *   firmware_version <= current  -> OTA_PKG_ERR_NOT_NEWER (nothing to install)
 *
 * Only meaningful after the signature has verified: unauthenticated version
 * fields are attacker-controlled.
 */
ota_pkg_err_t ota_pkg_check_versions(const ota_pkg_header_t *hdr,
                                     const ota_pkg_version_state_t *current);

/* ------------------------------------------------------- streaming payload */

/*
 * Streaming decrypt-and-hash of the ciphertext, so a ~1 MB image never has to
 * fit in RAM. Total footprint is this struct: 200 bytes.
 */
typedef struct {
  ascon_aead128_ctx_t aead;
  ascon_hash256_ctx_t hash;
  uint32_t remaining;     /* ciphertext bytes still expected */
  uint32_t produced;      /* plaintext bytes emitted so far  */
  uint8_t expected_hash[ASCON_HASH256_BYTES];
  uint8_t tag[ASCON_AEAD128_TAG_BYTES];
  uint8_t finished;
} ota_pkg_payload_ctx_t;

/*
 * Begin payload processing. `key` is the device's provisioned 128-bit Ascon key.
 * The header's associated-data span is absorbed here, binding the ciphertext to
 * this package's metadata.
 */
ota_pkg_err_t ota_pkg_payload_init(ota_pkg_payload_ctx_t *ctx,
                                   const ota_pkg_header_t *hdr,
                                   const uint8_t key[ASCON_AEAD128_KEY_BYTES]);

/*
 * Feed `inlen` ciphertext bytes; writes decrypted bytes to `out` and reports the
 * count in `*outlen`. Output lags input by up to 15 bytes, so `out` must have
 * room for ASCON_AEAD128_UPDATE_OUT_MAX(inlen). `in` and `out` must not overlap.
 *
 * THE PLAINTEXT WRITTEN HERE IS NOT YET AUTHENTICATED. Park it somewhere inert
 * (this project writes it to the inactive OTA partition) until
 * ota_pkg_payload_final() returns OTA_PKG_OK.
 */
ota_pkg_err_t ota_pkg_payload_update(ota_pkg_payload_ctx_t *ctx, uint8_t *out,
                                     size_t *outlen, const uint8_t *in,
                                     size_t inlen);

/*
 * Finish: flush the last partial block, verify the Ascon-AEAD128 tag, then
 * compare the Ascon-Hash256 of everything decrypted against the signed digest.
 *
 * Returns OTA_PKG_OK only when the full declared payload arrived, the tag
 * verified, and the hash matched. On any failure `*outlen` is set to 0 and the
 * tail bytes in `out` are zeroed, so a caller that ignores the return value
 * still cannot commit unauthenticated bytes.
 *
 * `out` needs room for ASCON_AEAD128_RATE - 1 bytes.
 */
ota_pkg_err_t ota_pkg_payload_final(ota_pkg_payload_ctx_t *ctx, uint8_t *out,
                                    size_t *outlen);

/* ------------------------------------------------------------- convenience */

/*
 * Verify a complete in-memory package: structure, signature, tag and hash.
 * `firmware_out` must hold hdr->firmware_size bytes.
 *
 * Only for small payloads and the host test suite -- the device must use the
 * streaming API instead of buffering a whole image.
 */
ota_pkg_err_t ota_pkg_verify_all(const uint8_t *pkg, size_t pkglen,
                                 const uint8_t key[ASCON_AEAD128_KEY_BYTES],
                                 const uint8_t trusted_pk[ED25519_PUBLIC_KEY_BYTES],
                                 ota_pkg_header_t *hdr_out,
                                 uint8_t *firmware_out, size_t firmware_cap);

/* Format a version code as "major.minor.patch". `buf` needs 16 bytes. */
const char *ota_pkg_version_str(uint32_t code, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* OTA_PACKAGE_H_ */
