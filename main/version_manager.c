#include "version_manager.h"

#include <stdbool.h>

#include "app_config.h"
#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "VERSION";

static ota_pkg_version_state_t s_state = {
    .firmware_version = FIRMWARE_VERSION_CODE,
    .security_version = SECURITY_VERSION,
};

esp_err_t version_manager_init(void) {
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE_VERSION, NVS_READWRITE, &h);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Cannot open NVS namespace '%s': %s", NVS_NAMESPACE_VERSION,
             esp_err_to_name(err));
    /* Fall back to the compiled-in values. Anti-rollback still works within
     * this boot; it just cannot remember across reboots. */
    ESP_LOGW(TAG, "Using compiled-in versions only; rollback state will not "
                  "persist across reboots");
    return err;
  }

  uint32_t stored_fw = 0, stored_sec = 0;
  esp_err_t e1 = nvs_get_u32(h, NVS_KEY_FIRMWARE_VERSION, &stored_fw);
  esp_err_t e2 = nvs_get_u32(h, NVS_KEY_SECURITY_VERSION, &stored_sec);

  if (e1 == ESP_ERR_NVS_NOT_FOUND || e2 == ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGI(TAG, "No stored version state (first boot on this device)");
  }

  /* Never lower either number. Take the maximum of what is stored and what this
   * image declares. */
  s_state.firmware_version = FIRMWARE_VERSION_CODE;
  if (e1 == ESP_OK && stored_fw > s_state.firmware_version) {
    /* Stored version is ahead of the running image. That is what a rollback
     * looks like: a newer image was installed, failed, and the bootloader
     * reverted. Trust the running image's number for freshness so the update
     * can be retried. */
    ESP_LOGW(TAG, "Stored firmware version 0x%06X is newer than the running "
                  "image 0x%06X -- a rolled-back update?",
             (unsigned)stored_fw, (unsigned)FIRMWARE_VERSION_CODE);
    ESP_LOGW(TAG, "Using the running image's version so the update can be "
                  "retried");
  }

  s_state.security_version = SECURITY_VERSION;
  if (e2 == ESP_OK && stored_sec > s_state.security_version) {
    /* Security version is different: it must never go backwards, even after a
     * rollback. Keep the higher stored value. */
    ESP_LOGW(TAG, "Stored security version %u exceeds this image's %u -- "
                  "keeping the higher value (anti-rollback is monotonic)",
             (unsigned)stored_sec, (unsigned)SECURITY_VERSION);
    s_state.security_version = stored_sec;
  }

  bool dirty = (e1 != ESP_OK) || (e2 != ESP_OK) ||
               (stored_fw != s_state.firmware_version) ||
               (stored_sec != s_state.security_version);

  if (dirty) {
    esp_err_t w1 = nvs_set_u32(h, NVS_KEY_FIRMWARE_VERSION,
                               s_state.firmware_version);
    esp_err_t w2 = nvs_set_u32(h, NVS_KEY_SECURITY_VERSION,
                               s_state.security_version);
    if (w1 == ESP_OK && w2 == ESP_OK) {
      err = nvs_commit(h);
      if (err == ESP_OK)
        ESP_LOGI(TAG, "Version state persisted: firmware 0x%06X, security %u",
                 (unsigned)s_state.firmware_version,
                 (unsigned)s_state.security_version);
      else
        ESP_LOGE(TAG, "nvs_commit failed: %s", esp_err_to_name(err));
    } else {
      ESP_LOGE(TAG, "Failed to write version state: %s / %s",
               esp_err_to_name(w1), esp_err_to_name(w2));
    }
  }

  nvs_close(h);
  return ESP_OK;
}

void version_manager_get(ota_pkg_version_state_t *out) {
  if (out == NULL) return;
  *out = s_state;
}

void version_manager_log_status(void) {
  char running[16], accepted[16];
  ota_pkg_version_str(FIRMWARE_VERSION_CODE, running, sizeof running);
  ota_pkg_version_str(s_state.firmware_version, accepted, sizeof accepted);

  ESP_LOGI(TAG, "Running firmware version : %s (0x%06X)", running,
           (unsigned)FIRMWARE_VERSION_CODE);
  ESP_LOGI(TAG, "Running security version : %u", (unsigned)SECURITY_VERSION);
  ESP_LOGI(TAG, "Accepted floor           : firmware > %s, security >= %u",
           accepted, (unsigned)s_state.security_version);
}
