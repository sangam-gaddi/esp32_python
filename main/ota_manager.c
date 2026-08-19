#include "ota_manager.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "ascon_word.h"
#include "cJSON.h"
#include "device_keys.h"
#include "esp_app_format.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "ota_package.h"
#include "version_manager.h"
#include "wifi_manager.h"

static const char *TAG = "OTA";

/* The development CA certificate, embedded by main/CMakeLists.txt. Used to
 * verify the server when OTA_SERVER_URL is https://. */
extern const uint8_t server_ca_cert_pem_start[] asm("_binary_server_ca_cert_pem_start");
extern const uint8_t server_ca_cert_pem_end[] asm("_binary_server_ca_cert_pem_end");

static volatile ota_state_t s_state = OTA_IDLE;
static SemaphoreHandle_t s_trigger;
static uint32_t s_cycles;
static uint32_t s_rejections;

/* Metadata from the server's JSON hint. Untrusted -- see the header comment. */
typedef struct {
  uint32_t firmware_version;
  uint32_t security_version;
  uint32_t package_size;
  char package_url[256];
} server_hint_t;

const char *ota_state_name(ota_state_t s) {
  switch (s) {
    case OTA_IDLE: return "IDLE";
    case OTA_CHECK: return "CHECK";
    case OTA_METADATA: return "METADATA";
    case OTA_DOWNLOAD: return "DOWNLOAD";
    case OTA_DECRYPT: return "DECRYPT";
    case OTA_HASH_VERIFY: return "HASH_VERIFY";
    case OTA_SIGNATURE_VERIFY: return "SIGNATURE_VERIFY";
    case OTA_VERSION_VERIFY: return "VERSION_VERIFY";
    case OTA_INSTALL: return "INSTALL";
    case OTA_REBOOT: return "REBOOT";
    case OTA_FAILED: return "FAILED";
    default: return "?";
  }
}

static void set_state(ota_state_t next) {
  s_state = next;
  ESP_LOGI(TAG, "state -> %s", ota_state_name(next));
}

/* Announce a rejection in a form that reads unambiguously in a demo log. */
static void reject(const char *stage, const char *reason) {
  s_rejections++;
  ESP_LOGE(TAG, "%s", reason);
  ESP_LOGE(TAG, "UPDATE REJECTED at %s -- running firmware is unchanged", stage);
  set_state(OTA_FAILED);
}

static bool url_is_https(const char *url) {
  return strncmp(url, "https://", 8) == 0;
}

/* Fill in the parts of an esp_http_client config that depend on the scheme.
 * Certificate verification is never disabled: for https the embedded CA is
 * pinned, and for http there is nothing to verify (and a warning is logged). */
static void configure_transport(esp_http_client_config_t *cfg, const char *url) {
  cfg->url = url;
  cfg->timeout_ms = OTA_HTTP_TIMEOUT_MS;
  cfg->keep_alive_enable = true;

  if (url_is_https(url)) {
    cfg->cert_pem = (const char *)server_ca_cert_pem_start;
    cfg->skip_cert_common_name_check = false;
  }
}

static void warn_if_insecure_transport(const char *url) {
  if (url_is_https(url)) return;
  ESP_LOGW(TAG, "----------------------------------------------------------");
  ESP_LOGW(TAG, "Transport is plain HTTP -- DEVELOPMENT ONLY, not secure.");
  ESP_LOGW(TAG, "The package's Ed25519 signature, Ascon-AEAD128 tag and");
  ESP_LOGW(TAG, "Ascon-Hash256 digest are still fully enforced, so tampered");
  ESP_LOGW(TAG, "firmware is still rejected. HTTP simply does not protect the");
  ESP_LOGW(TAG, "metadata or hide that an update is happening.");
  ESP_LOGW(TAG, "----------------------------------------------------------");
}

/* ------------------------------------------------------------ http helpers */

/* esp_http_client_read() may return short reads. Loop until `want` bytes have
 * arrived, the peer closes, or an error occurs. Returns bytes actually read. */
static int read_exact(esp_http_client_handle_t client, uint8_t *buf,
                      int want) {
  int got = 0;
  while (got < want) {
    int n = esp_http_client_read(client, (char *)buf + got, want - got);
    if (n <= 0) break; /* 0 = closed, <0 = error */
    got += n;
  }
  return got;
}

/*
 * Ask the server what it has. This is a convenience so the device does not
 * download a package it already runs; it is NOT trusted. Every value returned
 * here is re-derived from the signed header before it can affect anything.
 */
static esp_err_t fetch_server_hint(server_hint_t *hint) {
  char url[sizeof hint->package_url + 64];
  snprintf(url, sizeof url, "%s%s?device=%s", OTA_SERVER_URL,
           OTA_METADATA_PATH, OTA_DEVICE_ID);
  ESP_LOGI(TAG, "Checking for update: %s", url);

  esp_http_client_config_t cfg = {0};
  configure_transport(&cfg, url);

  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (client == NULL) {
    ESP_LOGE(TAG, "esp_http_client_init failed");
    return ESP_FAIL;
  }

  esp_err_t result = ESP_FAIL;
  char *body = NULL;

  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Cannot reach the OTA server: %s", esp_err_to_name(err));
    ESP_LOGE(TAG, "Is server/app.py running, and is OTA_SERVER_URL correct?");
    goto done;
  }

  int64_t len = esp_http_client_fetch_headers(client);
  int status = esp_http_client_get_status_code(client);
  if (status != 200) {
    ESP_LOGE(TAG, "Metadata request returned HTTP %d", status);
    goto done;
  }
  if (len <= 0 || len > 4096) {
    /* Either chunked (len <= 0) or implausibly large for this endpoint. Cap it
     * rather than trusting Content-Length. */
    len = 4096;
  }

  body = malloc((size_t)len + 1);
  if (body == NULL) {
    ESP_LOGE(TAG, "Out of memory reading metadata (%d bytes)", (int)len);
    goto done;
  }
  int got = read_exact(client, (uint8_t *)body, (int)len);
  if (got <= 0) {
    ESP_LOGE(TAG, "Empty metadata response");
    goto done;
  }
  body[got] = '\0';

  cJSON *root = cJSON_Parse(body);
  if (root == NULL) {
    ESP_LOGE(TAG, "Metadata is not valid JSON");
    goto done;
  }

  const cJSON *fw = cJSON_GetObjectItemCaseSensitive(root, "firmware_version_code");
  const cJSON *sec = cJSON_GetObjectItemCaseSensitive(root, "security_version");
  const cJSON *sz = cJSON_GetObjectItemCaseSensitive(root, "package_size");
  const cJSON *purl = cJSON_GetObjectItemCaseSensitive(root, "package_url");

  if (!cJSON_IsNumber(fw) || !cJSON_IsNumber(sec) || !cJSON_IsString(purl)) {
    ESP_LOGE(TAG, "Metadata is missing required fields");
    cJSON_Delete(root);
    goto done;
  }

  memset(hint, 0, sizeof *hint);
  hint->firmware_version = (uint32_t)fw->valuedouble;
  hint->security_version = (uint32_t)sec->valuedouble;
  hint->package_size = cJSON_IsNumber(sz) ? (uint32_t)sz->valuedouble : 0;

  if (strncmp(purl->valuestring, "http://", 7) == 0 ||
      strncmp(purl->valuestring, "https://", 8) == 0) {
    snprintf(hint->package_url, sizeof hint->package_url, "%s",
             purl->valuestring);
  } else {
    snprintf(hint->package_url, sizeof hint->package_url, "%s%s",
             OTA_SERVER_URL, purl->valuestring);
  }

  cJSON_Delete(root);
  result = ESP_OK;

done:
  free(body);
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return result;
}

/* --------------------------------------------------------- the update cycle */

static void run_update_cycle(void) {
  s_cycles++;

  uint8_t key[ASCON_AEAD128_KEY_BYTES];
  uint8_t *inbuf = NULL;
  uint8_t *outbuf = NULL;
  esp_http_client_handle_t client = NULL;
  esp_ota_handle_t ota = 0;
  bool ota_open = false;
  ota_pkg_header_t hdr;
  server_hint_t hint;
  char vbuf[16], vbuf2[16];

  memset(key, 0, sizeof key);

  /* ---- OTA_CHECK ------------------------------------------------------- */
  set_state(OTA_CHECK);
  warn_if_insecure_transport(OTA_SERVER_URL);

  if (fetch_server_hint(&hint) != ESP_OK) {
    ESP_LOGW(TAG, "Update check failed; will retry later");
    set_state(OTA_IDLE);
    return;
  }

  ota_pkg_version_state_t current;
  version_manager_get(&current);

  ESP_LOGI(TAG, "Server offers firmware %s (security %u); device has %s "
                "(security %u)",
           ota_pkg_version_str(hint.firmware_version, vbuf, sizeof vbuf),
           (unsigned)hint.security_version,
           ota_pkg_version_str(current.firmware_version, vbuf2, sizeof vbuf2),
           (unsigned)current.security_version);

  if (hint.firmware_version <= current.firmware_version) {
    ESP_LOGI(TAG, "Already up to date; nothing to do");
    set_state(OTA_IDLE);
    return;
  }
  ESP_LOGI(TAG, "Update available: version %s",
           ota_pkg_version_str(hint.firmware_version, vbuf, sizeof vbuf));

  /* ---- OTA_METADATA: fetch and parse the signed header ----------------- */
  set_state(OTA_METADATA);
  ESP_LOGI(TAG, "Downloading package: %s", hint.package_url);

  esp_http_client_config_t cfg = {0};
  configure_transport(&cfg, hint.package_url);
  client = esp_http_client_init(&cfg);
  if (client == NULL) {
    reject("METADATA", "Cannot create HTTP client");
    goto cleanup;
  }

  if (esp_http_client_open(client, 0) != ESP_OK) {
    reject("METADATA", "Cannot open the package URL");
    goto cleanup;
  }

  int64_t content_length = esp_http_client_fetch_headers(client);
  int status = esp_http_client_get_status_code(client);
  if (status != 200) {
    char msg[64];
    snprintf(msg, sizeof msg, "Package request returned HTTP %d", status);
    reject("METADATA", msg);
    goto cleanup;
  }

  uint8_t header_bytes[OTA_PKG_HEADER_SIZE];
  int got = read_exact(client, header_bytes, OTA_PKG_HEADER_SIZE);
  if (got != OTA_PKG_HEADER_SIZE) {
    char msg[80];
    snprintf(msg, sizeof msg,
             "Package header truncated: got %d of %d bytes", got,
             OTA_PKG_HEADER_SIZE);
    reject("METADATA", msg);
    goto cleanup;
  }

  ota_pkg_err_t rc =
      ota_pkg_parse_header(&hdr, header_bytes, OTA_PKG_HEADER_SIZE);
  if (rc != OTA_PKG_OK) {
    reject("METADATA", ota_pkg_strerror(rc));
    goto cleanup;
  }

  ESP_LOGI(TAG, "Package header parsed:");
  ESP_LOGI(TAG, "  firmware version  %s",
           ota_pkg_version_str(hdr.firmware_version, vbuf, sizeof vbuf));
  ESP_LOGI(TAG, "  security version  %u", (unsigned)hdr.security_version);
  ESP_LOGI(TAG, "  firmware size     %" PRIu32 " bytes", hdr.firmware_size);
  ESP_LOGI(TAG, "  Ascon-Hash256     %02x%02x%02x%02x...%02x%02x%02x%02x",
           hdr.firmware_hash[0], hdr.firmware_hash[1], hdr.firmware_hash[2],
           hdr.firmware_hash[3], hdr.firmware_hash[28], hdr.firmware_hash[29],
           hdr.firmware_hash[30], hdr.firmware_hash[31]);

  /* Cross-check the declared size against what the server said it would send.
   * A mismatch is not itself an attack -- the crypto would catch that -- but it
   * is a clear early failure. */
  if (content_length > 0 &&
      content_length != (int64_t)OTA_PKG_HEADER_SIZE + hdr.ciphertext_size) {
    ESP_LOGW(TAG, "Content-Length %" PRId64 " disagrees with the header's "
                  "%" PRIu32 " -- continuing; the tag check is authoritative",
             content_length,
             (uint32_t)(OTA_PKG_HEADER_SIZE + hdr.ciphertext_size));
  }

  /* ---- OTA_SIGNATURE_VERIFY ------------------------------------------- */
  set_state(OTA_SIGNATURE_VERIFY);
  ESP_LOGI(TAG, "Verifying Ed25519 signature over the %d-byte signed header...",
           OTA_PKG_SIGNED_LEN);

  int64_t t0 = esp_timer_get_time();
  rc = ota_pkg_verify_signature(&hdr, device_keys_trusted_pubkey());
  int64_t sig_us = esp_timer_get_time() - t0;

  if (rc != OTA_PKG_OK) {
    reject("SIGNATURE_VERIFY", ota_pkg_strerror(rc));
    ESP_LOGE(TAG, "This package was not signed by the trusted key, or its "
                  "metadata was altered in transit.");
    goto cleanup;
  }
  ESP_LOGI(TAG, "Signature verification successful (%" PRId64 " us)", sig_us);

  /* ---- OTA_VERSION_VERIFY -------------------------------------------- */
  set_state(OTA_VERSION_VERIFY);
  ESP_LOGI(TAG, "Checking firmware version and anti-rollback...");
  rc = ota_pkg_check_versions(&hdr, &current);
  if (rc == OTA_PKG_ERR_ROLLBACK) {
    ESP_LOGE(TAG, "Package security version %u is below the accepted floor %u",
             (unsigned)hdr.security_version,
             (unsigned)current.security_version);
    reject("VERSION_VERIFY", ota_pkg_strerror(rc));
    goto cleanup;
  }
  if (rc != OTA_PKG_OK) {
    reject("VERSION_VERIFY", ota_pkg_strerror(rc));
    goto cleanup;
  }
  ESP_LOGI(TAG, "Version accepted");

  /* ---- prepare the inactive partition -------------------------------- */
  const esp_partition_t *running = esp_ota_get_running_partition();
  const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
  if (target == NULL) {
    reject("INSTALL", "No OTA partition available -- check partitions.csv");
    goto cleanup;
  }
  ESP_LOGI(TAG, "Running from '%s' at 0x%08" PRIx32
                "; writing to '%s' at 0x%08" PRIx32,
           running ? running->label : "?", running ? running->address : 0,
           target->label, target->address);

  if (hdr.firmware_size > target->size) {
    char msg[96];
    snprintf(msg, sizeof msg,
             "Firmware is %" PRIu32 " bytes; partition '%s' holds %" PRIu32,
             hdr.firmware_size, target->label, target->size);
    reject("INSTALL", msg);
    goto cleanup;
  }

  if (device_keys_get_ota_key(key) != ESP_OK) {
    reject("DECRYPT", "No Ascon OTA key available on this device");
    goto cleanup;
  }

  inbuf = malloc(OTA_DOWNLOAD_CHUNK_SIZE);
  outbuf = malloc(ASCON_AEAD128_UPDATE_OUT_MAX(OTA_DOWNLOAD_CHUNK_SIZE));
  if (inbuf == NULL || outbuf == NULL) {
    reject("DOWNLOAD", "Out of memory allocating download buffers");
    goto cleanup;
  }

  ota_pkg_payload_ctx_t payload;
  rc = ota_pkg_payload_init(&payload, &hdr, key);
  ascon_wipe(key, sizeof key); /* the AEAD context holds what it needs now */
  if (rc != OTA_PKG_OK) {
    reject("DECRYPT", ota_pkg_strerror(rc));
    goto cleanup;
  }

  esp_err_t err = esp_ota_begin(target, hdr.firmware_size, &ota);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
    reject("INSTALL", "Cannot open the OTA partition for writing");
    goto cleanup;
  }
  ota_open = true;

  /* ---- OTA_DOWNLOAD + OTA_DECRYPT ------------------------------------ */
  set_state(OTA_DOWNLOAD);
  ESP_LOGI(TAG, "Streaming %" PRIu32 " bytes; decrypting and hashing in "
                "%d-byte chunks",
           hdr.ciphertext_size, OTA_DOWNLOAD_CHUNK_SIZE);
  set_state(OTA_DECRYPT);

  uint32_t received = 0;
  uint32_t written = 0;
  uint32_t next_log = OTA_PROGRESS_LOG_INTERVAL;
  int64_t t_start = esp_timer_get_time();

  while (received < hdr.ciphertext_size) {
    uint32_t want = hdr.ciphertext_size - received;
    if (want > OTA_DOWNLOAD_CHUNK_SIZE) want = OTA_DOWNLOAD_CHUNK_SIZE;

    int n = esp_http_client_read(client, (char *)inbuf, (int)want);
    if (n < 0) {
      reject("DOWNLOAD", "Network error while downloading the package");
      goto cleanup;
    }
    if (n == 0) {
      char msg[96];
      snprintf(msg, sizeof msg,
               "Connection closed after %" PRIu32 " of %" PRIu32 " bytes",
               received, hdr.ciphertext_size);
      reject("DOWNLOAD", msg);
      goto cleanup;
    }

    size_t produced = 0;
    rc = ota_pkg_payload_update(&payload, outbuf, &produced, inbuf, (size_t)n);
    if (rc != OTA_PKG_OK) {
      reject("DECRYPT", ota_pkg_strerror(rc));
      goto cleanup;
    }
    received += (uint32_t)n;

    if (produced) {
      err = esp_ota_write(ota, outbuf, produced);
      if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
        reject("INSTALL", "Flash write failed");
        goto cleanup;
      }
      written += (uint32_t)produced;
    }

    if (received >= next_log) {
      ESP_LOGI(TAG, "  %" PRIu32 " / %" PRIu32 " bytes (%u%%), heap %" PRIu32,
               received, hdr.ciphertext_size,
               (unsigned)((uint64_t)received * 100 / hdr.ciphertext_size),
               esp_get_free_heap_size());
      next_log += OTA_PROGRESS_LOG_INTERVAL;
    }
  }

  int64_t dl_us = esp_timer_get_time() - t_start;
  ESP_LOGI(TAG, "Package downloaded (%" PRIu32 " bytes in %" PRId64 " ms)",
           received, dl_us / 1000);

  /* ---- OTA_HASH_VERIFY: AEAD tag, then the signed digest ------------- */
  set_state(OTA_HASH_VERIFY);
  ESP_LOGI(TAG, "Finalising Ascon-AEAD128 and comparing Ascon-Hash256...");

  size_t tail = 0;
  rc = ota_pkg_payload_final(&payload, outbuf, &tail);

  if (rc == OTA_PKG_ERR_TAG) {
    reject("DECRYPT", ota_pkg_strerror(rc));
    ESP_LOGE(TAG, "Either the ciphertext was modified, or this device's "
                  "encryption key does not match the one used to build it.");
    goto cleanup;
  }
  if (rc == OTA_PKG_ERR_HASH) {
    reject("HASH_VERIFY", ota_pkg_strerror(rc));
    ESP_LOGE(TAG, "The decrypted firmware does not match the digest the "
                  "signature attests to.");
    goto cleanup;
  }
  if (rc != OTA_PKG_OK) {
    reject("HASH_VERIFY", ota_pkg_strerror(rc));
    goto cleanup;
  }

  if (tail) {
    err = esp_ota_write(ota, outbuf, tail);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "esp_ota_write failed on the final block: %s",
               esp_err_to_name(err));
      reject("INSTALL", "Flash write failed");
      goto cleanup;
    }
    written += (uint32_t)tail;
  }

  ESP_LOGI(TAG, "Ascon authentication successful (tag verified)");
  ESP_LOGI(TAG, "Hash verification successful");

  if (written != hdr.firmware_size) {
    char msg[96];
    snprintf(msg, sizeof msg,
             "Wrote %" PRIu32 " bytes but the header declared %" PRIu32,
             written, hdr.firmware_size);
    reject("INSTALL", msg);
    goto cleanup;
  }

  /* ---- OTA_INSTALL --------------------------------------------------- */
  set_state(OTA_INSTALL);
  ESP_LOGI(TAG, "Writing OTA partition...");

  err = esp_ota_end(ota);
  ota_open = false; /* esp_ota_end consumes the handle either way */
  if (err != ESP_OK) {
    /* Includes ESP_ERR_OTA_VALIDATE_FAILED: the bytes verified cryptographically
     * but are not a valid ESP32 application image. */
    ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
    if (err == ESP_ERR_OTA_VALIDATE_FAILED)
      ESP_LOGE(TAG, "The image is authentic but is not a bootable ESP32 "
                    "application. Did you package the right .bin?");
    reject("INSTALL", "OTA image validation failed");
    goto cleanup;
  }

  err = esp_ota_set_boot_partition(target);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s",
             esp_err_to_name(err));
    reject("INSTALL", "Could not select the new partition for boot");
    goto cleanup;
  }

  ESP_LOGI(TAG, "OTA update successful");
  ESP_LOGI(TAG, "  installed version %s (security %u) into '%s'",
           ota_pkg_version_str(hdr.firmware_version, vbuf, sizeof vbuf),
           (unsigned)hdr.security_version, target->label);

  /* ---- OTA_REBOOT ---------------------------------------------------- */
  set_state(OTA_REBOOT);
  ESP_LOGI(TAG, "Rebooting in %d ms...", OTA_REBOOT_DELAY_MS);

  free(inbuf);
  free(outbuf);
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  ascon_wipe(key, sizeof key);

  vTaskDelay(pdMS_TO_TICKS(OTA_REBOOT_DELAY_MS));
  esp_restart();
  /* not reached */

cleanup:
  /* One exit path for every failure. The running firmware is untouched: the
   * boot partition is only ever changed on the success path above. */
  if (ota_open) esp_ota_abort(ota);
  free(inbuf);
  free(outbuf);
  if (client) {
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
  }
  ascon_wipe(key, sizeof key);

  if (s_state == OTA_FAILED) {
    ESP_LOGI(TAG, "Device continues running firmware %s",
             FIRMWARE_VERSION_STRING);
  }
  set_state(OTA_IDLE);
}

/* ------------------------------------------------------------------ the task */

static void ota_task(void *arg) {
  (void)arg;

  ESP_LOGI(TAG, "OTA task started; waiting for Wi-Fi");
  if (wifi_manager_wait_connected(WIFI_CONNECT_TIMEOUT_MS) != ESP_OK)
    ESP_LOGW(TAG, "Wi-Fi not up yet; will keep trying on each cycle");

  ESP_LOGI(TAG, "First update check in %d s", OTA_FIRST_CHECK_DELAY_MS / 1000);
  TickType_t wait = pdMS_TO_TICKS(OTA_FIRST_CHECK_DELAY_MS);

  for (;;) {
    /* Wake on the interval, or early if something calls trigger_now(). */
    if (xSemaphoreTake(s_trigger, wait) == pdTRUE)
      ESP_LOGI(TAG, "Manual update check requested");

    wait = pdMS_TO_TICKS(OTA_CHECK_INTERVAL_MS);

    if (!wifi_manager_is_connected()) {
      ESP_LOGW(TAG, "Skipping check: Wi-Fi is not connected");
      continue;
    }

    run_update_cycle();
  }
}

esp_err_t ota_manager_start(void) {
  s_trigger = xSemaphoreCreateBinary();
  if (s_trigger == NULL) return ESP_ERR_NO_MEM;

  /* 8 KB: TLS handshake plus Ed25519 verification plus the HTTP client all run
   * on this stack. The Ascon contexts are small and the download buffers are
   * heap-allocated. */
  BaseType_t ok = xTaskCreate(ota_task, "ota_task", 8192, NULL, 5, NULL);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "Cannot create the OTA task");
    return ESP_ERR_NO_MEM;
  }
  return ESP_OK;
}

void ota_manager_trigger_now(void) {
  if (s_trigger) xSemaphoreGive(s_trigger);
}

ota_state_t ota_manager_state(void) { return s_state; }

void ota_manager_get_stats(uint32_t *cycles, uint32_t *rejections) {
  if (cycles) *cycles = s_cycles;
  if (rejections) *rejections = s_rejections;
}
