/*
 * Secure OTA Firmware Update with Lightweight Cryptography
 * -------------------------------------------------------
 *
 * Application entry point. Deliberately thin: it brings up storage, keys,
 * version state and Wi-Fi, confirms the running image is good, then hands off to
 * the OTA state machine in ota_manager.c.
 *
 * The security work lives elsewhere, separated from the networking:
 *
 *   components/ascon        Ascon-Hash256 and Ascon-AEAD128 (NIST SP 800-232)
 *   components/ed25519      Ed25519 verification (TweetNaCl)
 *   components/ota_package  package parsing and the verification sequence
 *   main/ota_manager.c      download, install, reboot
 *   main/version_manager.c  anti-rollback state
 *   main/device_keys.c      provisioned key storage
 */

#include <inttypes.h>
#include <stdio.h>

#include "app_config.h"
#include "device_keys.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "ota_manager.h"
#include "version_manager.h"
#include "wifi_manager.h"

static const char *TAG = "BOOT";

/*
 * With CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE a freshly installed image boots in
 * PENDING_VERIFY state. If it never calls esp_ota_mark_app_valid_cancel_rollback()
 * the bootloader reverts to the previous slot on the next restart. So the call
 * is made only after the basics work -- storage, keys and Wi-Fi -- which is what
 * makes a bad update self-healing rather than a brick.
 */
static void confirm_image_is_good(void) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;

  if (running == NULL ||
      esp_ota_get_state_partition(running, &state) != ESP_OK) {
    ESP_LOGW(TAG, "Cannot read the OTA state of the running partition");
    return;
  }

  if (state != ESP_OTA_IMG_PENDING_VERIFY) {
    ESP_LOGI(TAG, "Running image is already marked valid");
    return;
  }

  ESP_LOGI(TAG, "This image is on probation (PENDING_VERIFY) after an update");
  if (wifi_manager_is_connected()) {
    if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK)
      ESP_LOGI(TAG, "Self-test passed -- image marked valid, rollback "
                    "cancelled");
    else
      ESP_LOGE(TAG, "Failed to mark the image valid");
  } else {
    ESP_LOGE(TAG, "Wi-Fi did not come up; NOT marking this image valid.");
    ESP_LOGE(TAG, "The bootloader will roll back to the previous firmware on "
                  "the next restart.");
  }
}

static void log_banner(void) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  const esp_app_desc_t *app = esp_app_get_description();

  ESP_LOGI(TAG, "==========================================================");
  ESP_LOGI(TAG, " Secure OTA Firmware Update with Lightweight Cryptography");
  ESP_LOGI(TAG, "==========================================================");
  ESP_LOGI(TAG, "Current Firmware Version: %s", FIRMWARE_VERSION_STRING);
  ESP_LOGI(TAG, "Security Version        : %u", (unsigned)SECURITY_VERSION);
  ESP_LOGI(TAG, "Built                   : %s %s", app->date, app->time);
  ESP_LOGI(TAG, "ESP-IDF                 : %s", app->idf_ver);
  ESP_LOGI(TAG, "Running partition       : %s @ 0x%08" PRIx32,
           running ? running->label : "?", running ? running->address : 0);
  ESP_LOGI(TAG, "Free heap               : %" PRIu32 " bytes",
           esp_get_free_heap_size());
  ESP_LOGI(TAG, "Crypto                  : Ascon-Hash256 + Ascon-AEAD128 "
                "(NIST SP 800-232), Ed25519");
  ESP_LOGI(TAG, "==========================================================");
}

void app_main(void) {
  log_banner();

  /* ---- storage --------------------------------------------------------- */
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_LOGW(TAG, "NVS needs erasing (%s); reinitialising",
             esp_err_to_name(err));
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  ESP_LOGI(TAG, "NVS ready");

  /* ---- keys and version state ------------------------------------------ */
  if (device_keys_init() != ESP_OK)
    ESP_LOGE(TAG, "Key initialisation failed; updates will be rejected");
  device_keys_log_status();

  version_manager_init();
  version_manager_log_status();

  /* ---- network --------------------------------------------------------- */
  ESP_ERROR_CHECK(wifi_manager_init());
  if (wifi_manager_wait_connected(WIFI_CONNECT_TIMEOUT_MS) == ESP_OK) {
    char ip[16];
    wifi_manager_get_ip(ip, sizeof ip);
    ESP_LOGI(TAG, "Network ready at %s; OTA server is %s", ip, OTA_SERVER_URL);
  } else {
    ESP_LOGE(TAG, "Wi-Fi did not connect within %d ms",
             WIFI_CONNECT_TIMEOUT_MS);
  }

  /* Only now is it safe to say this image works. */
  confirm_image_is_good();

  /* ---- OTA ------------------------------------------------------------- */
  ESP_ERROR_CHECK(ota_manager_start());

  /* ---- idle loop: a heartbeat so the demo log shows the device is alive - */
  uint32_t ticks = 0;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(15000));
    ticks++;

    uint32_t cycles = 0, rejections = 0;
    ota_manager_get_stats(&cycles, &rejections);
    ESP_LOGI(TAG, "alive: firmware %s, OTA state %s, checks %" PRIu32
                  ", rejections %" PRIu32 ", heap %" PRIu32,
             FIRMWARE_VERSION_STRING, ota_state_name(ota_manager_state()),
             cycles, rejections, esp_get_free_heap_size());

    /* Nudge the OTA task roughly every couple of minutes even if its own timer
     * has drifted, so a live demonstration does not stall waiting. */
    if (ticks % 8 == 0) ota_manager_trigger_now();
  }
}
