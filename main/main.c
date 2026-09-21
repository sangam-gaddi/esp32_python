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
#include "device_report.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_chip_info.h"
#include "esp_clk_tree.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
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

/* ------------------------------------------------------- system monitor ---
 *
 * The chip report and the periodic uptime/heap lines an Arduino sketch would
 * print from setup() and loop(), written against ESP-IDF so they live
 * alongside the OTA client instead of replacing it. A monitor task is the
 * FreeRTOS equivalent of loop(): the OTA state machine, the Wi-Fi stack and
 * the reporting task all keep running while this prints.
 *
 * Reading only -- nothing here touches the update path.
 */
static const char *MON_TAG = "MONITOR";

static void log_chip_report(void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);

  uint32_t flash_bytes = 0;
  if (esp_flash_get_size(NULL, &flash_bytes) != ESP_OK) flash_bytes = 0;

  uint32_t cpu_hz = 0;
  if (esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU,
                                   ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED,
                                   &cpu_hz) != ESP_OK)
    cpu_hz = 0;

  const char *model = (chip.model == CHIP_ESP32)    ? "ESP32"
                      : (chip.model == CHIP_ESP32S2) ? "ESP32-S2"
                      : (chip.model == CHIP_ESP32S3) ? "ESP32-S3"
                      : (chip.model == CHIP_ESP32C3) ? "ESP32-C3"
                                                     : "unknown";

  ESP_LOGI(MON_TAG, "================================");
  ESP_LOGI(MON_TAG, "       ESP32 SYSTEM MONITOR");
  ESP_LOGI(MON_TAG, "================================");
  ESP_LOGI(MON_TAG, "Chip Model    : %s", model);
  ESP_LOGI(MON_TAG, "Chip Revision : %d", chip.revision);
  ESP_LOGI(MON_TAG, "CPU Cores     : %d", chip.cores);
  ESP_LOGI(MON_TAG, "CPU Frequency : %" PRIu32 " MHz", cpu_hz / 1000000);
  ESP_LOGI(MON_TAG, "Flash Size    : %" PRIu32 " MB", flash_bytes / (1024 * 1024));
  ESP_LOGI(MON_TAG, "SDK Version   : %s", esp_get_idf_version());
  ESP_LOGI(MON_TAG, "================================");
}

static void monitor_task(void *arg) {
  (void)arg;
  log_chip_report();

  for (;;) {
    ESP_LOGI(MON_TAG, "Uptime    : %lld seconds",
             esp_timer_get_time() / 1000000LL);
    ESP_LOGI(MON_TAG, "Free Heap : %" PRIu32 " bytes", esp_get_free_heap_size());
    ESP_LOGI(MON_TAG, "Free PSRAM: %u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ESP_LOGI(MON_TAG, "--------------------------------");
    vTaskDelay(pdMS_TO_TICKS(MONITOR_PERIOD_MS));
  }
}

/* ---------------------------------------------------------------- the LED --
 *
 * A visible answer to "did the update actually land?". The blink period is
 * derived from FIRMWARE_VERSION_MAJOR, so the board announces which image it
 * booted without anyone reading a serial log: version 6 blinks slowly, version
 * 7 twice as fast, and so on. Nothing here participates in the update; it is a
 * demonstration aid and it is the only thing in this file that touches a pin.
 */
#define STATUS_LED_GPIO 2

static void blink_task(void *arg) {
  (void)arg;
  gpio_config_t cfg = {
      .pin_bit_mask = 1ULL << STATUS_LED_GPIO,
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  ESP_ERROR_CHECK(gpio_config(&cfg));

  /* 1000 ms for v1, 500 ms for v2, ... floored at 100 ms so a high version
   * number cannot turn the LED into a blur. */
  uint32_t period = 1000u / (FIRMWARE_VERSION_MAJOR ? FIRMWARE_VERSION_MAJOR : 1);
  if (period < 100u) period = 100u;

  ESP_LOGI(TAG, "Status LED on GPIO%d: %" PRIu32 " ms period (firmware %s)",
           STATUS_LED_GPIO, period, FIRMWARE_VERSION_STRING);

  for (;;) {
    gpio_set_level(STATUS_LED_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(period));
    gpio_set_level(STATUS_LED_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(period));
  }
}

void app_main(void) {
  log_banner();

  /* Started first, so the LED is already blinking while Wi-Fi associates. */
  xTaskCreate(blink_task, "blink", 2048, NULL, 2, NULL);
  xTaskCreate(monitor_task, "monitor", 3072, NULL, 2, NULL);

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

  /* ---- dashboard reporting --------------------------------------------- *
   * Telemetry out, three possible commands in. If the dashboard is not
   * running this task simply fails to connect and retries; the OTA path does
   * not depend on it in any way. */
  if (device_report_start() != ESP_OK)
    ESP_LOGW(TAG, "Reporting task did not start; the dashboard will show this "
                  "device as OFFLINE");

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
