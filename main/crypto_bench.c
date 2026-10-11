/*
 * On-device microbenchmark of the OTA cryptography.
 *
 * Each primitive is timed over a firmware-sized input (BENCH_FW_BYTES), streamed
 * through the same 4 KB buffers and the same incremental APIs the OTA path
 * uses, so the figures are directly comparable to a real update minus the
 * network and the flash. Ed25519 is timed on a real signed package header
 * against the device's trusted public key. Runs before Wi-Fi starts so radio
 * interrupts do not perturb it.
 */
#include "crypto_bench.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "ascon_aead128.h"
#include "ascon_hash256.h"
#include "bench_header.h"
#include "device_keys.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "ota_package.h"

static const char *TAG = "BENCH";

#define BENCH_FW_BYTES 938688u /* size of the 24.0.0 firmware image */
#define BENCH_RUNS 5
#define BENCH_SIG_RUNS 10

static void fill(uint8_t *buf, size_t n, uint32_t seed) {
  for (size_t i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    buf[i] = (uint8_t)(seed >> 24);
  }
}

static void log_run(const char *what, int run, int64_t us) {
  ESP_LOGI(TAG, "%s run=%d bytes=%u us=%" PRId64 " kbps=%" PRId64, what, run,
           (unsigned)BENCH_FW_BYTES, us,
           (int64_t)BENCH_FW_BYTES * 1000000 / 1024 / (us ? us : 1));
}

void crypto_bench_run(void) {
  const size_t chunk = OTA_DOWNLOAD_CHUNK_SIZE;
  uint8_t *in = malloc(chunk);
  uint8_t *out = malloc(ASCON_AEAD128_UPDATE_OUT_MAX(chunk));
  if (in == NULL || out == NULL) {
    ESP_LOGE(TAG, "out of memory");
    free(in);
    free(out);
    return;
  }
  fill(in, chunk, 1);

  uint8_t key[ASCON_AEAD128_KEY_BYTES], nonce[ASCON_AEAD128_NONCE_BYTES];
  uint8_t tag[ASCON_AEAD128_TAG_BYTES], digest[ASCON_HASH256_BYTES];
  uint8_t ad[80];
  fill(key, sizeof key, 2);
  fill(nonce, sizeof nonce, 3);
  fill(ad, sizeof ad, 4);
  size_t outlen;

  ESP_LOGI(TAG, "start: cpu %d MHz, chunk %u B, input %u B, heap %" PRIu32,
           CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ, (unsigned)chunk,
           (unsigned)BENCH_FW_BYTES, esp_get_free_heap_size());

  for (int r = 1; r <= BENCH_RUNS; r++) {
    /* Ascon-AEAD128 encryption */
    ascon_aead128_ctx_t ctx;
    int64_t t = esp_timer_get_time();
    ascon_aead128_init(&ctx, key, nonce, ad, sizeof ad);
    for (size_t done = 0; done < BENCH_FW_BYTES; done += chunk) {
      size_t n = BENCH_FW_BYTES - done < chunk ? BENCH_FW_BYTES - done : chunk;
      ascon_aead128_encrypt_update(&ctx, out, in, n);
    }
    ascon_aead128_encrypt_final(&ctx, out, &outlen, tag);
    log_run("aead_encrypt", r, esp_timer_get_time() - t);

    /* Ascon-AEAD128 decryption including the tag check (the tag will not
     * match, since the input is not real ciphertext; the work is identical) */
    t = esp_timer_get_time();
    ascon_aead128_init(&ctx, key, nonce, ad, sizeof ad);
    for (size_t done = 0; done < BENCH_FW_BYTES; done += chunk) {
      size_t n = BENCH_FW_BYTES - done < chunk ? BENCH_FW_BYTES - done : chunk;
      ascon_aead128_decrypt_update(&ctx, out, in, n);
    }
    (void)ascon_aead128_decrypt_final(&ctx, out, &outlen, tag);
    log_run("aead_decrypt", r, esp_timer_get_time() - t);

    /* Ascon-Hash256 */
    ascon_hash256_ctx_t h;
    t = esp_timer_get_time();
    ascon_hash256_init(&h);
    for (size_t done = 0; done < BENCH_FW_BYTES; done += chunk) {
      size_t n = BENCH_FW_BYTES - done < chunk ? BENCH_FW_BYTES - done : chunk;
      ascon_hash256_update(&h, in, n);
    }
    ascon_hash256_final(&h, digest);
    log_run("hash256", r, esp_timer_get_time() - t);
  }

  /* Ed25519 over the real 96-byte signed span of a real package */
  ota_pkg_header_t hdr;
  if (ota_pkg_parse_header(&hdr, BENCH_SIGNED_HEADER,
                           sizeof BENCH_SIGNED_HEADER) != OTA_PKG_OK) {
    ESP_LOGE(TAG, "bench header does not parse");
  } else {
    for (int r = 1; r <= BENCH_SIG_RUNS; r++) {
      int64_t t = esp_timer_get_time();
      ota_pkg_err_t rc =
          ota_pkg_verify_signature(&hdr, device_keys_trusted_pubkey());
      int64_t us = esp_timer_get_time() - t;
      ESP_LOGI(TAG, "ed25519_verify run=%d us=%" PRId64 " valid=%d", r, us,
               rc == OTA_PKG_OK);
    }
  }

  ESP_LOGI(TAG, "done: heap %" PRIu32 ", min ever %" PRIu32,
           esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
  free(in);
  free(out);
}
