/*
 * `.sota` package parsing and verification. See ota_package.h for the format
 * and the reasoning behind the verification order.
 *
 * Two rules shape this file:
 *
 *  - Integers are read byte-by-byte, little-endian, never by casting the buffer
 *    to a struct pointer. The buffer comes straight off the network at an
 *    arbitrary alignment, and the ESP32 cannot do unaligned word loads.
 *
 *  - The authenticated spans are slices of the *received* header bytes
 *    (`hdr->raw`), never a re-serialisation of the parsed fields. Signing one
 *    representation and verifying another is the classic way to end up with a
 *    signature that does not actually cover what gets used.
 */

#include "ota_package.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------ field offsets */

#define OFF_MAGIC 0
#define OFF_FORMAT_VERSION 4
#define OFF_HEADER_SIZE 6
#define OFF_FIRMWARE_VERSION 8
#define OFF_SECURITY_VERSION 12
#define OFF_FIRMWARE_SIZE 16
#define OFF_CIPHERTEXT_SIZE 20
#define OFF_BUILD_TIMESTAMP 24
#define OFF_NONCE 32
#define OFF_FIRMWARE_HASH 48
#define OFF_AUTH_TAG 80
#define OFF_SIGNATURE 96

/* ------------------------------------------------ little-endian field reads */

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
  return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* --------------------------------------------------------------- messages */

const char *ota_pkg_strerror(ota_pkg_err_t err) {
  switch (err) {
    case OTA_PKG_OK: return "ok";
    case OTA_PKG_ERR_ARG: return "invalid argument";
    case OTA_PKG_ERR_TRUNCATED: return "package truncated";
    case OTA_PKG_ERR_MAGIC: return "bad magic (not a .sota package)";
    case OTA_PKG_ERR_FORMAT_VERSION: return "unsupported package format version";
    case OTA_PKG_ERR_HEADER_SIZE: return "bad header_size field";
    case OTA_PKG_ERR_SIZE_RANGE: return "firmware_size out of range";
    case OTA_PKG_ERR_SIZE_MISMATCH: return "ciphertext_size != firmware_size";
    case OTA_PKG_ERR_LENGTH: return "payload length does not match header";
    case OTA_PKG_ERR_SIGNATURE: return "INVALID SIGNATURE";
    case OTA_PKG_ERR_TAG: return "ASCON AUTHENTICATION FAILED (tag mismatch)";
    case OTA_PKG_ERR_HASH: return "HASH MISMATCH";
    case OTA_PKG_ERR_ROLLBACK: return "ROLLBACK DETECTED";
    case OTA_PKG_ERR_NOT_NEWER: return "firmware is not newer than installed";
    case OTA_PKG_ERR_STATE: return "package API called out of order";
    default: return "unknown error";
  }
}

const char *ota_pkg_version_str(uint32_t code, char *buf, size_t buflen) {
  if (buf == NULL || buflen == 0) return "";
  snprintf(buf, buflen, "%u.%u.%u", (unsigned)((code >> 16) & 0xFF),
           (unsigned)((code >> 8) & 0xFF), (unsigned)(code & 0xFF));
  return buf;
}

/* ------------------------------------------------------------ header parsing */

ota_pkg_err_t ota_pkg_parse_header(ota_pkg_header_t *out, const uint8_t *buf,
                                   size_t len) {
  if (out == NULL || buf == NULL) return OTA_PKG_ERR_ARG;
  if (len < OTA_PKG_HEADER_SIZE) return OTA_PKG_ERR_TRUNCATED;

  memset(out, 0, sizeof *out);
  memcpy(out->raw, buf, OTA_PKG_HEADER_SIZE);

  if (memcmp(out->raw + OFF_MAGIC, OTA_PKG_MAGIC, OTA_PKG_MAGIC_LEN) != 0)
    return OTA_PKG_ERR_MAGIC;

  out->format_version = rd16(out->raw + OFF_FORMAT_VERSION);
  if (out->format_version != OTA_PKG_FORMAT_VERSION)
    return OTA_PKG_ERR_FORMAT_VERSION;

  out->header_size = rd16(out->raw + OFF_HEADER_SIZE);
  if (out->header_size != OTA_PKG_HEADER_SIZE) return OTA_PKG_ERR_HEADER_SIZE;

  out->firmware_version = rd32(out->raw + OFF_FIRMWARE_VERSION);
  out->security_version = rd32(out->raw + OFF_SECURITY_VERSION);
  out->firmware_size = rd32(out->raw + OFF_FIRMWARE_SIZE);
  out->ciphertext_size = rd32(out->raw + OFF_CIPHERTEXT_SIZE);
  out->build_timestamp = rd64(out->raw + OFF_BUILD_TIMESTAMP);

  memcpy(out->nonce, out->raw + OFF_NONCE, sizeof out->nonce);
  memcpy(out->firmware_hash, out->raw + OFF_FIRMWARE_HASH,
         sizeof out->firmware_hash);
  memcpy(out->auth_tag, out->raw + OFF_AUTH_TAG, sizeof out->auth_tag);
  memcpy(out->signature, out->raw + OFF_SIGNATURE, sizeof out->signature);

  if (out->firmware_size == 0 ||
      out->firmware_size > OTA_PKG_MAX_FIRMWARE_SIZE)
    return OTA_PKG_ERR_SIZE_RANGE;

  /* Ascon-AEAD128 is length-preserving, so these must agree. Checking it here
   * removes any chance of the two being used inconsistently later. */
  if (out->ciphertext_size != out->firmware_size)
    return OTA_PKG_ERR_SIZE_MISMATCH;

  return OTA_PKG_OK;
}

/* --------------------------------------------------------------- signature */

ota_pkg_err_t ota_pkg_verify_signature(
    const ota_pkg_header_t *hdr,
    const uint8_t trusted_pk[ED25519_PUBLIC_KEY_BYTES]) {
  if (hdr == NULL || trusted_pk == NULL) return OTA_PKG_ERR_ARG;

  /* Exactly the received bytes 0..96 -- the same span the packager signed. */
  if (ed25519_verify(hdr->signature, hdr->raw, OTA_PKG_SIGNED_LEN,
                     trusted_pk) != 0)
    return OTA_PKG_ERR_SIGNATURE;

  return OTA_PKG_OK;
}

/* ------------------------------------------------------------ version check */

ota_pkg_err_t ota_pkg_check_versions(const ota_pkg_header_t *hdr,
                                     const ota_pkg_version_state_t *current) {
  if (hdr == NULL || current == NULL) return OTA_PKG_ERR_ARG;

  /* Anti-rollback first: a downgrade is an attack, not a stale index. Equal is
   * allowed so a security-version bump is not required for every release. */
  if (hdr->security_version < current->security_version)
    return OTA_PKG_ERR_ROLLBACK;

  /* Then freshness. Re-offering the running version is not an error worth
   * shouting about, but it is not an update either. */
  if (hdr->firmware_version <= current->firmware_version)
    return OTA_PKG_ERR_NOT_NEWER;

  return OTA_PKG_OK;
}

/* --------------------------------------------------------- streaming payload */

ota_pkg_err_t ota_pkg_payload_init(ota_pkg_payload_ctx_t *ctx,
                                   const ota_pkg_header_t *hdr,
                                   const uint8_t key[ASCON_AEAD128_KEY_BYTES]) {
  if (ctx == NULL || hdr == NULL || key == NULL) return OTA_PKG_ERR_ARG;

  memset(ctx, 0, sizeof *ctx);

  /* Associated data is header[0:80] as received: it binds the ciphertext to
   * this package's versions, sizes, nonce and declared hash. */
  ascon_aead128_init(&ctx->aead, key, hdr->nonce, hdr->raw, OTA_PKG_AD_LEN);
  ascon_hash256_init(&ctx->hash);

  ctx->remaining = hdr->ciphertext_size;
  ctx->produced = 0;
  memcpy(ctx->expected_hash, hdr->firmware_hash, sizeof ctx->expected_hash);
  memcpy(ctx->tag, hdr->auth_tag, sizeof ctx->tag);
  ctx->finished = 0;

  return OTA_PKG_OK;
}

ota_pkg_err_t ota_pkg_payload_update(ota_pkg_payload_ctx_t *ctx, uint8_t *out,
                                     size_t *outlen, const uint8_t *in,
                                     size_t inlen) {
  if (ctx == NULL || out == NULL || outlen == NULL || in == NULL)
    return OTA_PKG_ERR_ARG;
  if (ctx->finished) return OTA_PKG_ERR_STATE;

  *outlen = 0;
  if (inlen == 0) return OTA_PKG_OK;

  /* More payload than the signed header declared: reject rather than process
   * bytes nobody vouched for. */
  if (inlen > ctx->remaining) return OTA_PKG_ERR_LENGTH;

  size_t n = ascon_aead128_decrypt_update(&ctx->aead, out, in, inlen);
  ascon_hash256_update(&ctx->hash, out, n);

  ctx->remaining -= (uint32_t)inlen;
  ctx->produced += (uint32_t)n;
  *outlen = n;
  return OTA_PKG_OK;
}

ota_pkg_err_t ota_pkg_payload_final(ota_pkg_payload_ctx_t *ctx, uint8_t *out,
                                    size_t *outlen) {
  if (ctx == NULL || out == NULL || outlen == NULL) return OTA_PKG_ERR_ARG;
  if (ctx->finished) return OTA_PKG_ERR_STATE;
  ctx->finished = 1;
  *outlen = 0;

  /* The download stopped early. Nothing to verify. */
  if (ctx->remaining != 0) return OTA_PKG_ERR_TRUNCATED;

  size_t tail = 0;
  int tag_bad = ascon_aead128_decrypt_final(&ctx->aead, out, &tail, ctx->tag);

  /* Hash the tail before finalising the digest, whatever the tag said: the
   * digest must cover the whole plaintext for the comparison to mean anything. */
  ascon_hash256_update(&ctx->hash, out, tail);
  ctx->produced += (uint32_t)tail;

  uint8_t computed[ASCON_HASH256_BYTES];
  ascon_hash256_final(&ctx->hash, computed);

  ota_pkg_err_t rc = OTA_PKG_OK;
  if (tag_bad) {
    rc = OTA_PKG_ERR_TAG;
  } else if (ascon_hash256_equal(computed, ctx->expected_hash) != 0) {
    /* Reachable only if the packaging step was wrong or the signing key was
     * used to sign a digest that does not describe the firmware -- the tag
     * already covers transport tampering. Kept as defence in depth: the
     * Ed25519 signature attests to this digest, so this is the check that ties
     * the signer's authority to the bytes about to be executed. */
    rc = OTA_PKG_ERR_HASH;
  }

  if (rc == OTA_PKG_OK) {
    *outlen = tail;
  } else {
    /* Do not hand back tail bytes that failed to authenticate. */
    memset(out, 0, tail);
  }

  memset(computed, 0, sizeof computed);
  return rc;
}

/* ------------------------------------------------------------- convenience */

ota_pkg_err_t ota_pkg_verify_all(
    const uint8_t *pkg, size_t pkglen,
    const uint8_t key[ASCON_AEAD128_KEY_BYTES],
    const uint8_t trusted_pk[ED25519_PUBLIC_KEY_BYTES],
    ota_pkg_header_t *hdr_out, uint8_t *firmware_out, size_t firmware_cap) {
  if (pkg == NULL || key == NULL || trusted_pk == NULL || hdr_out == NULL)
    return OTA_PKG_ERR_ARG;

  ota_pkg_err_t rc = ota_pkg_parse_header(hdr_out, pkg, pkglen);
  if (rc != OTA_PKG_OK) return rc;

  if (pkglen != (size_t)OTA_PKG_HEADER_SIZE + hdr_out->ciphertext_size)
    return OTA_PKG_ERR_LENGTH;
  if (firmware_out == NULL || firmware_cap < hdr_out->firmware_size)
    return OTA_PKG_ERR_ARG;

  rc = ota_pkg_verify_signature(hdr_out, trusted_pk);
  if (rc != OTA_PKG_OK) return rc;

  ota_pkg_payload_ctx_t ctx;
  rc = ota_pkg_payload_init(&ctx, hdr_out, key);
  if (rc != OTA_PKG_OK) return rc;

  /* Feed the payload in whole rate blocks so no output lag buffer is needed. */
  const uint8_t *ct = pkg + OTA_PKG_HEADER_SIZE;
  size_t ctlen = hdr_out->ciphertext_size;
  size_t full = ctlen - (ctlen % ASCON_AEAD128_RATE);
  size_t written = 0, n = 0;

  if (full) {
    rc = ota_pkg_payload_update(&ctx, firmware_out, &n, ct, full);
    if (rc != OTA_PKG_OK) return rc;
    written += n;
  }
  if (ctlen - full) {
    rc = ota_pkg_payload_update(&ctx, firmware_out + written, &n, ct + full,
                                ctlen - full);
    if (rc != OTA_PKG_OK) return rc;
    written += n;
  }

  rc = ota_pkg_payload_final(&ctx, firmware_out + written, &n);
  if (rc != OTA_PKG_OK) {
    memset(firmware_out, 0, hdr_out->firmware_size);
    return rc;
  }
  written += n;

  if (written != hdr_out->firmware_size) {
    memset(firmware_out, 0, hdr_out->firmware_size);
    return OTA_PKG_ERR_LENGTH;
  }
  return OTA_PKG_OK;
}
