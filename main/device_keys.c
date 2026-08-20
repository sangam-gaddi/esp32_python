#include "device_keys.h"

#include <string.h>

#include <stdio.h>

#include "app_config.h"
#include "ascon_hash256.h"
#include "ascon_word.h"
#include "crypto_config.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "CRYPTO";

/* Where the key in use came from, for the status log. */
static enum { SRC_UNKNOWN, SRC_NVS, SRC_PROVISIONED } s_key_source = SRC_UNKNOWN;

/* Ascon-Hash256 of a key, truncated. Safe to print: it identifies the key
 * without revealing it. Both sides can compare fingerprints to confirm they
 * hold the same secret. */
static void fingerprint(const uint8_t *data, size_t len, char *out,
                        size_t outlen) {
  uint8_t digest[ASCON_HASH256_BYTES];
  ascon_hash256(digest, data, len);
  size_t chars = outlen - 1;
  if (chars > 16) chars = 16; /* 8 bytes is plenty to spot a mismatch */
  for (size_t i = 0; i < chars / 2; i++)
    snprintf(out + i * 2, outlen - i * 2, "%02x", digest[i]);
  out[chars] = '\0';
  ascon_wipe(digest, sizeof digest);
}

esp_err_t device_keys_init(void) {
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE_KEYS, NVS_READWRITE, &h);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Cannot open NVS namespace '%s': %s", NVS_NAMESPACE_KEYS,
             esp_err_to_name(err));
    return err;
  }

  uint8_t key[ASCON_AEAD128_KEY_BYTES];
  size_t len = sizeof key;
  err = nvs_get_blob(h, NVS_BLOB_OTA_KEY, key, &len);

  if (err == ESP_OK && len == sizeof key) {
    s_key_source = SRC_NVS;
    ESP_LOGI(TAG, "Ascon OTA key loaded from NVS");
  } else if (err == ESP_ERR_NVS_NOT_FOUND || len != sizeof key) {
    /* First boot on this device: provision from the compiled-in key. */
    ESP_LOGW(TAG, "No OTA key in NVS -- provisioning the compiled-in "
                  "DEMONSTRATION key");
    ESP_LOGW(TAG, "Production devices must be provisioned per-unit at "
                  "manufacture; see docs/SECURITY.md");
    memcpy(key, OTA_DEFAULT_ENCRYPTION_KEY, sizeof key);
    err = nvs_set_blob(h, NVS_BLOB_OTA_KEY, key, sizeof key);
    if (err == ESP_OK) err = nvs_commit(h);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to store OTA key in NVS: %s", esp_err_to_name(err));
      ascon_wipe(key, sizeof key);
      nvs_close(h);
      return err;
    }
    s_key_source = SRC_PROVISIONED;
  } else {
    ESP_LOGE(TAG, "NVS read of OTA key failed: %s", esp_err_to_name(err));
    nvs_close(h);
    return err;
  }

  ascon_wipe(key, sizeof key);
  nvs_close(h);
  return ESP_OK;
}

esp_err_t device_keys_get_ota_key(uint8_t key[ASCON_AEAD128_KEY_BYTES]) {
  if (key == NULL) return ESP_ERR_INVALID_ARG;

  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE_KEYS, NVS_READONLY, &h);
  if (err != ESP_OK) return err;

  size_t len = ASCON_AEAD128_KEY_BYTES;
  err = nvs_get_blob(h, NVS_BLOB_OTA_KEY, key, &len);
  nvs_close(h);

  if (err != ESP_OK) return err;
  if (len != ASCON_AEAD128_KEY_BYTES) {
    ascon_wipe(key, ASCON_AEAD128_KEY_BYTES);
    return ESP_ERR_INVALID_SIZE;
  }
  return ESP_OK;
}

const uint8_t *device_keys_trusted_pubkey(void) {
  return OTA_TRUSTED_ED25519_PUBLIC_KEY;
}

/*
 * The two accessors below hand out the same fingerprints device_keys_log_status()
 * already prints. A fingerprint is Ascon-Hash256 of the key, truncated: it lets
 * the dashboard show that host and device hold matching key material without
 * either end ever transmitting a key. No function here returns key bytes.
 */
void device_keys_signer_fingerprint(char *out, size_t outlen) {
  if (out == NULL || outlen == 0) return;
  fingerprint(OTA_TRUSTED_ED25519_PUBLIC_KEY,
              sizeof OTA_TRUSTED_ED25519_PUBLIC_KEY, out, outlen);
}

void device_keys_ota_key_fingerprint(char *out, size_t outlen) {
  if (out == NULL || outlen == 0) return;
  uint8_t key[ASCON_AEAD128_KEY_BYTES];
  if (device_keys_get_ota_key(key) != ESP_OK) {
    snprintf(out, outlen, "unavailable");
    return;
  }
  fingerprint(key, sizeof key, out, outlen);
  ascon_wipe(key, sizeof key);
}

void device_keys_log_status(void) {
  char fp[17];

  fingerprint(OTA_TRUSTED_ED25519_PUBLIC_KEY,
              sizeof OTA_TRUSTED_ED25519_PUBLIC_KEY, fp, sizeof fp);
  ESP_LOGI(TAG, "Trusted Ed25519 public key: %02x%02x..%02x%02x "
                "(fingerprint %s)",
           OTA_TRUSTED_ED25519_PUBLIC_KEY[0], OTA_TRUSTED_ED25519_PUBLIC_KEY[1],
           OTA_TRUSTED_ED25519_PUBLIC_KEY[30],
           OTA_TRUSTED_ED25519_PUBLIC_KEY[31], fp);

  uint8_t key[ASCON_AEAD128_KEY_BYTES];
  if (device_keys_get_ota_key(key) == ESP_OK) {
    fingerprint(key, sizeof key, fp, sizeof fp);
    ESP_LOGI(TAG, "Ascon-AEAD128 OTA key: present, fingerprint %s (%s)", fp,
             s_key_source == SRC_NVS ? "from NVS"
                                     : "provisioned this boot");
    ESP_LOGI(TAG, "Key material is never printed; the fingerprint is "
                  "Ascon-Hash256 of the key");
    ascon_wipe(key, sizeof key);
  } else {
    ESP_LOGE(TAG, "Ascon-AEAD128 OTA key: MISSING -- updates cannot be "
                  "decrypted");
  }

  /* A zeroed public key means crypto_config.h was never generated. Nothing
   * would verify, so say so plainly rather than failing mysteriously later. */
  bool all_zero = true;
  for (size_t i = 0; i < sizeof OTA_TRUSTED_ED25519_PUBLIC_KEY; i++)
    if (OTA_TRUSTED_ED25519_PUBLIC_KEY[i] != 0) all_zero = false;
  if (all_zero) {
    ESP_LOGE(TAG, "Trusted public key is all zeroes -- this is the template!");
    ESP_LOGE(TAG, "Run: python tools/generate_keys.py --write-device-config");
    ESP_LOGE(TAG, "Every update will be rejected until this is fixed.");
  }
}
