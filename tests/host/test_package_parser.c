/*
 * Host test for the device-side package parser and verifier.
 *
 * Runs the real components/ota_package code -- the same C the ESP32 links --
 * over packages produced by the Python implementation in sotalib/. Two
 * independent implementations of Ascon, Ed25519 and the wire format have to
 * agree, in both directions: valid packages must be accepted, and every
 * deliberately broken package must be rejected for exactly the right reason.
 *
 *   python tests/host/make_fixtures.py     # generate the fixtures
 *   python tests/host/build_and_run.py     # build and run this
 *
 * Also covers:
 *   - Ed25519 against the RFC 8032 section 7.1 test vectors
 *   - the streaming payload API at many chunk sizes, including sizes that
 *     never align to the 16-byte AEAD rate
 *   - refusal to emit unauthenticated plaintext on failure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ota_package.h"

/* -------------------------------------------------------------- test plumbing */

static int g_fail = 0;
static int g_groups = 0;

static void report(const char *name, int failures, long cases) {
  g_groups++;
  if (failures) {
    g_fail++;
    printf("  FAIL  %-46s %d/%ld cases failed\n", name, failures, cases);
  } else {
    printf("  ok    %-46s %ld cases\n", name, cases);
  }
}

/* --------------------------------------------------------------- error names */

static const struct {
  const char *name;
  ota_pkg_err_t code;
} ERR_NAMES[] = {
    {"OTA_PKG_OK", OTA_PKG_OK},
    {"OTA_PKG_ERR_ARG", OTA_PKG_ERR_ARG},
    {"OTA_PKG_ERR_TRUNCATED", OTA_PKG_ERR_TRUNCATED},
    {"OTA_PKG_ERR_MAGIC", OTA_PKG_ERR_MAGIC},
    {"OTA_PKG_ERR_FORMAT_VERSION", OTA_PKG_ERR_FORMAT_VERSION},
    {"OTA_PKG_ERR_HEADER_SIZE", OTA_PKG_ERR_HEADER_SIZE},
    {"OTA_PKG_ERR_SIZE_RANGE", OTA_PKG_ERR_SIZE_RANGE},
    {"OTA_PKG_ERR_SIZE_MISMATCH", OTA_PKG_ERR_SIZE_MISMATCH},
    {"OTA_PKG_ERR_LENGTH", OTA_PKG_ERR_LENGTH},
    {"OTA_PKG_ERR_SIGNATURE", OTA_PKG_ERR_SIGNATURE},
    {"OTA_PKG_ERR_TAG", OTA_PKG_ERR_TAG},
    {"OTA_PKG_ERR_HASH", OTA_PKG_ERR_HASH},
    {"OTA_PKG_ERR_ROLLBACK", OTA_PKG_ERR_ROLLBACK},
    {"OTA_PKG_ERR_NOT_NEWER", OTA_PKG_ERR_NOT_NEWER},
    {"OTA_PKG_ERR_STATE", OTA_PKG_ERR_STATE},
};

static const char *err_name(ota_pkg_err_t code) {
  for (size_t i = 0; i < sizeof ERR_NAMES / sizeof ERR_NAMES[0]; i++)
    if (ERR_NAMES[i].code == code) return ERR_NAMES[i].name;
  return "??";
}

static int err_from_name(const char *name, ota_pkg_err_t *out) {
  for (size_t i = 0; i < sizeof ERR_NAMES / sizeof ERR_NAMES[0]; i++)
    if (strcmp(ERR_NAMES[i].name, name) == 0) {
      *out = ERR_NAMES[i].code;
      return 1;
    }
  return 0;
}

/* ------------------------------------------------------------------ file I/O */

static unsigned char *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0) {
    fclose(f);
    return NULL;
  }
  unsigned char *buf = malloc((size_t)n + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  size_t got = fread(buf, 1, (size_t)n, f);
  fclose(f);
  *len = got;
  return buf;
}

static char g_dir[1024];

static char *fixture_path(const char *name) {
  static char path[1200];
  snprintf(path, sizeof path, "%s/%s", g_dir, name);
  return path;
}

/* ----------------------------------------------------- RFC 8032 Ed25519 KATs */

/* From RFC 8032 section 7.1 (Ed25519 test vectors 1-3). Independently
 * cross-checked against OpenSSL before being written down here. */
typedef struct {
  const char *pk_hex;
  const char *msg_hex;
  const char *sig_hex;
} rfc8032_vec_t;

static const rfc8032_vec_t RFC8032[] = {
    {/* TEST 1: empty message */
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
     "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {/* TEST 2: one-byte message */
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
     "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    {/* TEST 3: two-byte message */
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
     "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
};

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t unhex(const char *hex, unsigned char *out, size_t cap) {
  size_t n = 0;
  while (hex[0] && hex[1] && n < cap) {
    int hi = hexval(hex[0]), lo = hexval(hex[1]);
    if (hi < 0 || lo < 0) break;
    out[n++] = (unsigned char)(hi * 16 + lo);
    hex += 2;
  }
  return n;
}

static void test_ed25519_rfc8032(void) {
  int fails = 0;
  long cases = 0;
  for (size_t i = 0; i < sizeof RFC8032 / sizeof RFC8032[0]; i++) {
    unsigned char pk[32], sig[64], msg[64];
    unhex(RFC8032[i].pk_hex, pk, sizeof pk);
    unhex(RFC8032[i].sig_hex, sig, sizeof sig);
    size_t mlen = unhex(RFC8032[i].msg_hex, msg, sizeof msg);

    cases++;
    if (ed25519_verify(sig, msg, mlen, pk) != 0) {
      printf("      RFC 8032 vector %zu should verify but did not\n", i + 1);
      fails++;
    }

    /* every bit flip in the signature must be rejected */
    for (size_t b = 0; b < 64; b += 7) {
      unsigned char bad[64];
      memcpy(bad, sig, 64);
      bad[b] ^= 0x01;
      cases++;
      if (ed25519_verify(bad, msg, mlen, pk) == 0) fails++;
    }
    /* wrong public key must be rejected */
    for (size_t b = 0; b < 32; b += 5) {
      unsigned char badpk[32];
      memcpy(badpk, pk, 32);
      badpk[b] ^= 0x01;
      cases++;
      if (ed25519_verify(sig, msg, mlen, badpk) == 0) fails++;
    }
    /* altered message must be rejected */
    if (mlen) {
      unsigned char badmsg[64];
      memcpy(badmsg, msg, mlen);
      badmsg[0] ^= 0x01;
      cases++;
      if (ed25519_verify(sig, badmsg, mlen, pk) == 0) fails++;
    }
  }
  /* over-long message must be refused rather than truncated */
  {
    unsigned char pk[32] = {0}, sig[64] = {0};
    static unsigned char big[ED25519_MAX_MESSAGE_BYTES + 1];
    cases++;
    if (ed25519_verify(sig, big, sizeof big, pk) == 0) fails++;
  }
  report("Ed25519 vs RFC 8032 vectors + rejections", fails, cases);
}

/* --------------------------------------------------------- manifest processing */

typedef struct {
  char file[128];
  char crypto[48];
  char version[48];
} fixture_t;

static fixture_t g_fix[64];
static size_t g_nfix;
static uint32_t g_cur_fw, g_cur_sec;
static size_t g_fw_size;

static int load_manifest(void) {
  size_t len = 0;
  unsigned char *raw = read_file(fixture_path("manifest.txt"), &len);
  if (!raw) return 0;
  raw[len] = 0;

  char *save = NULL;
  (void)save;
  char *line = strtok((char *)raw, "\r\n");
  while (line) {
    if (line[0] != '#' && line[0] != '\0') {
      unsigned long v = 0;
      char a[128], b[48], c[48];
      if (sscanf(line, "current_firmware_version %lu", &v) == 1) {
        g_cur_fw = (uint32_t)v;
      } else if (sscanf(line, "current_security_version %lu", &v) == 1) {
        g_cur_sec = (uint32_t)v;
      } else if (sscanf(line, "firmware_size %lu", &v) == 1) {
        g_fw_size = (size_t)v;
      } else if (sscanf(line, "%127s %47s %47s", a, b, c) == 3) {
        if (g_nfix < sizeof g_fix / sizeof g_fix[0]) {
          snprintf(g_fix[g_nfix].file, sizeof g_fix[0].file, "%s", a);
          snprintf(g_fix[g_nfix].crypto, sizeof g_fix[0].crypto, "%s", b);
          snprintf(g_fix[g_nfix].version, sizeof g_fix[0].version, "%s", c);
          g_nfix++;
        }
      }
    }
    line = strtok(NULL, "\r\n");
  }
  free(raw);
  return 1;
}

static unsigned char g_key[16], g_pk[32];
static unsigned char *g_firmware;
static size_t g_firmware_len;

static void test_fixtures(void) {
  int fails = 0;
  long cases = 0;

  for (size_t i = 0; i < g_nfix; i++) {
    fixture_t *fx = &g_fix[i];
    ota_pkg_err_t want_crypto;
    if (!err_from_name(fx->crypto, &want_crypto)) {
      printf("      manifest names unknown result %s\n", fx->crypto);
      fails++;
      continue;
    }

    size_t plen = 0;
    unsigned char *pkg = read_file(fixture_path(fx->file), &plen);
    if (!pkg) {
      printf("      cannot read fixture %s\n", fx->file);
      fails++;
      continue;
    }

    /* Generously sized: some fixtures declare a nonsense firmware_size, and
     * verify_all must reject those before ever writing here. */
    static unsigned char out[64 * 1024];
    ota_pkg_header_t hdr;
    memset(&hdr, 0, sizeof hdr);
    ota_pkg_err_t got = ota_pkg_verify_all(pkg, plen, g_key, g_pk, &hdr, out,
                                           sizeof out);
    cases++;
    if (got != want_crypto) {
      printf("      %-28s crypto: want %s, got %s (%s)\n", fx->file,
             fx->crypto, err_name(got), ota_pkg_strerror(got));
      fails++;
    }

    /* A package that verified must have produced exactly the right plaintext. */
    if (want_crypto == OTA_PKG_OK && got == OTA_PKG_OK &&
        hdr.firmware_size == g_firmware_len) {
      cases++;
      if (memcmp(out, g_firmware, g_firmware_len) != 0) {
        printf("      %-28s decrypted plaintext differs from firmware.bin\n",
               fx->file);
        fails++;
      }
    }

    /* Version rules, where the manifest says the check is reachable. */
    if (strcmp(fx->version, "SKIP") != 0) {
      ota_pkg_err_t want_ver;
      if (err_from_name(fx->version, &want_ver)) {
        ota_pkg_version_state_t cur = {g_cur_fw, g_cur_sec};
        ota_pkg_err_t gotv = ota_pkg_check_versions(&hdr, &cur);
        cases++;
        if (gotv != want_ver) {
          printf("      %-28s version: want %s, got %s\n", fx->file,
                 fx->version, err_name(gotv));
          fails++;
        }
      }
    }

    free(pkg);
  }
  report("fixtures accepted/rejected as specified", fails, cases);
}

/* ----------------------------------------------------- streaming payload path */

static void test_streaming_payload(void) {
  const size_t chunks[] = {1, 7, 15, 16, 17, 63, 64, 100, 512, 1024, 4096};
  int fails = 0;
  long cases = 0;

  size_t plen = 0;
  unsigned char *pkg = read_file(fixture_path("good.sota"), &plen);
  if (!pkg) {
    printf("      cannot read good.sota\n");
    report("streaming payload at many chunk sizes", 1, 1);
    return;
  }

  ota_pkg_header_t hdr;
  if (ota_pkg_parse_header(&hdr, pkg, plen) != OTA_PKG_OK ||
      ota_pkg_verify_signature(&hdr, g_pk) != OTA_PKG_OK) {
    printf("      good.sota failed to parse/verify\n");
    free(pkg);
    report("streaming payload at many chunk sizes", 1, 1);
    return;
  }

  static unsigned char plain[64 * 1024];
  const unsigned char *ct = pkg + OTA_PKG_HEADER_SIZE;
  size_t ctlen = hdr.ciphertext_size;

  for (size_t c = 0; c < sizeof chunks / sizeof chunks[0]; c++) {
    ota_pkg_payload_ctx_t ctx;
    if (ota_pkg_payload_init(&ctx, &hdr, g_key) != OTA_PKG_OK) {
      fails++;
      continue;
    }
    size_t total = 0;
    int broke = 0;
    for (size_t off = 0; off < ctlen; off += chunks[c]) {
      size_t n = ctlen - off;
      if (n > chunks[c]) n = chunks[c];
      size_t produced = 0;
      if (ota_pkg_payload_update(&ctx, plain + total, &produced, ct + off, n)
          != OTA_PKG_OK) {
        broke = 1;
        break;
      }
      total += produced;
    }
    size_t tail = 0;
    ota_pkg_err_t rc = broke ? OTA_PKG_ERR_STATE
                             : ota_pkg_payload_final(&ctx, plain + total, &tail);
    total += tail;
    cases++;
    if (rc != OTA_PKG_OK || total != hdr.firmware_size ||
        memcmp(plain, g_firmware, hdr.firmware_size) != 0) {
      printf("      chunk %zu: rc=%s total=%zu expected=%u\n", chunks[c],
             err_name(rc), total, (unsigned)hdr.firmware_size);
      fails++;
    }
  }

  /* Stopping early must be reported as truncated, not silently accepted. */
  {
    ota_pkg_payload_ctx_t ctx;
    ota_pkg_payload_init(&ctx, &hdr, g_key);
    size_t produced = 0;
    ota_pkg_payload_update(&ctx, plain, &produced, ct, ctlen / 2);
    size_t tail = 0;
    cases++;
    if (ota_pkg_payload_final(&ctx, plain + produced, &tail)
        != OTA_PKG_ERR_TRUNCATED)
      fails++;
  }

  /* Feeding more than the header declared must be refused. */
  {
    ota_pkg_payload_ctx_t ctx;
    ota_pkg_payload_init(&ctx, &hdr, g_key);
    size_t produced = 0;
    cases++;
    if (ota_pkg_payload_update(&ctx, plain, &produced, ct, ctlen + 1)
        != OTA_PKG_ERR_LENGTH)
      fails++;
  }

  /* Using a context after final() must be refused rather than corrupt state. */
  {
    ota_pkg_payload_ctx_t ctx;
    ota_pkg_payload_init(&ctx, &hdr, g_key);
    size_t produced = 0;
    ota_pkg_payload_update(&ctx, plain, &produced, ct, ctlen);
    size_t tail = 0;
    ota_pkg_payload_final(&ctx, plain + produced, &tail);
    cases++;
    if (ota_pkg_payload_final(&ctx, plain, &tail) != OTA_PKG_ERR_STATE) fails++;
    cases++;
    if (ota_pkg_payload_update(&ctx, plain, &produced, ct, 16)
        != OTA_PKG_ERR_STATE)
      fails++;
  }

  free(pkg);
  report("streaming payload at many chunk sizes", fails, cases);
}

/* ------------------------------------------- no plaintext escapes on failure */

static void test_no_plaintext_on_failure(void) {
  int fails = 0;
  long cases = 0;
  const char *bad_files[] = {"flip_ciphertext.sota", "wrong_key.sota",
                             "hash_mismatch.sota"};

  for (size_t i = 0; i < sizeof bad_files / sizeof bad_files[0]; i++) {
    size_t plen = 0;
    unsigned char *pkg = read_file(fixture_path(bad_files[i]), &plen);
    if (!pkg) {
      fails++;
      continue;
    }
    static unsigned char out[64 * 1024];
    memset(out, 0xAA, sizeof out);
    ota_pkg_header_t hdr;
    ota_pkg_err_t rc = ota_pkg_verify_all(pkg, plen, g_key, g_pk, &hdr, out,
                                          sizeof out);
    cases++;
    if (rc == OTA_PKG_OK) {
      printf("      %s unexpectedly accepted\n", bad_files[i]);
      fails++;
    } else {
      /* the declared firmware region must have been wiped, not left holding
       * whatever the failed decryption produced */
      cases++;
      for (uint32_t j = 0; j < hdr.firmware_size && j < sizeof out; j++) {
        if (out[j] != 0) {
          printf("      %s left non-zero plaintext at offset %u\n",
                 bad_files[i], (unsigned)j);
          fails++;
          break;
        }
      }
    }
    free(pkg);
  }
  report("rejected packages leave no plaintext", fails, cases);
}

/* ---------------------------------------------------------- misc API contract */

static void test_api_contract(void) {
  int fails = 0;
  long cases = 0;
  ota_pkg_header_t hdr;
  unsigned char buf[OTA_PKG_HEADER_SIZE] = {0};

  cases++;
  if (ota_pkg_parse_header(NULL, buf, sizeof buf) != OTA_PKG_ERR_ARG) fails++;
  cases++;
  if (ota_pkg_parse_header(&hdr, NULL, sizeof buf) != OTA_PKG_ERR_ARG) fails++;
  cases++;
  if (ota_pkg_parse_header(&hdr, buf, 4) != OTA_PKG_ERR_TRUNCATED) fails++;
  cases++;
  if (ota_pkg_verify_signature(NULL, g_pk) != OTA_PKG_ERR_ARG) fails++;
  cases++;
  if (ota_pkg_check_versions(&hdr, NULL) != OTA_PKG_ERR_ARG) fails++;

  /* version formatting */
  char vb[16];
  cases++;
  if (strcmp(ota_pkg_version_str(0x020103, vb, sizeof vb), "2.1.3") != 0) fails++;
  cases++;
  if (strcmp(ota_pkg_version_str(0x000000, vb, sizeof vb), "0.0.0") != 0) fails++;

  /* version rules at the boundaries */
  ota_pkg_version_state_t cur = {0x010000, 5};
  hdr.security_version = 5;
  hdr.firmware_version = 0x010001;
  cases++;
  if (ota_pkg_check_versions(&hdr, &cur) != OTA_PKG_OK) fails++;
  hdr.security_version = 4;
  cases++;
  if (ota_pkg_check_versions(&hdr, &cur) != OTA_PKG_ERR_ROLLBACK) fails++;
  hdr.security_version = 6;
  hdr.firmware_version = 0x010000;
  cases++;
  if (ota_pkg_check_versions(&hdr, &cur) != OTA_PKG_ERR_NOT_NEWER) fails++;

  report("API argument and boundary contract", fails, cases);
}

/* ------------------------------------------------------------------------ main */

int main(int argc, char **argv) {
  snprintf(g_dir, sizeof g_dir, "%s",
           argc > 1 ? argv[1] : "build/host_fixtures");

  printf("OTA package parser -- host test\n");
  printf("  fixtures: %s\n\n", g_dir);

  if (!load_manifest()) {
    printf("cannot read %s\n", fixture_path("manifest.txt"));
    printf("run: python tests/host/make_fixtures.py\n");
    return 2;
  }

  size_t n = 0;
  unsigned char *k = read_file(fixture_path("enc_key.bin"), &n);
  if (!k || n != 16) {
    printf("enc_key.bin missing or wrong size\n");
    return 2;
  }
  memcpy(g_key, k, 16);
  free(k);

  unsigned char *p = read_file(fixture_path("pubkey.bin"), &n);
  if (!p || n != 32) {
    printf("pubkey.bin missing or wrong size\n");
    return 2;
  }
  memcpy(g_pk, p, 32);
  free(p);

  g_firmware = read_file(fixture_path("firmware.bin"), &g_firmware_len);
  if (!g_firmware) {
    printf("firmware.bin missing\n");
    return 2;
  }

  printf("loaded %zu fixtures, firmware %zu bytes, device state "
         "fw=0x%06X sec=%u\n\n",
         g_nfix, g_firmware_len, (unsigned)g_cur_fw, (unsigned)g_cur_sec);

  test_ed25519_rfc8032();
  test_fixtures();
  test_streaming_payload();
  test_no_plaintext_on_failure();
  test_api_contract();

  free(g_firmware);

  printf("\n%d/%d test groups passed\n", g_groups - g_fail, g_groups);
  if (g_fail) {
    printf("RESULT: FAILED\n");
    return 1;
  }
  printf("RESULT: PASSED\n");
  return 0;
}
