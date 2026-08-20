#include "device_report.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "cJSON.h"
#include "device_keys.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "ota_manager.h"
#include "wifi_manager.h"

static const char *TAG = "REPORT";

/* Same pinned development CA as the OTA client, embedded by main/CMakeLists.txt. */
extern const uint8_t server_ca_cert_pem_start[] asm("_binary_server_ca_cert_pem_start");

typedef struct {
  char event[16];
  char stage[24];
  char result[16];
  char reason[144];
  char from_version[16];
  char to_version[16];
  uint32_t security_version;
  uint32_t duration_ms;
} report_event_t;

static QueueHandle_t s_events;

/* Built once at start-up: values that cannot change while the device runs. */
static char s_chip_model[16] = "?";
static char s_chip_rev[12] = "?";
static int s_chip_cores;
static uint32_t s_flash_size;
static char s_mac[18] = "";
static char s_key_fp[17] = "";
static char s_signer_fp[17] = "";

/* One buffer, used only by the reporting task. Keeps it off the stack. */
static char s_body[1100];
static char s_url[192];
static char s_resp[320];

static bool url_is_https(const char *url) {
  return strncmp(url, "https://", 8) == 0;
}

static void collect_static_info(void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  s_chip_cores = chip.cores;
  switch (chip.model) {
    case CHIP_ESP32:   snprintf(s_chip_model, sizeof s_chip_model, "ESP32"); break;
    case CHIP_ESP32S2: snprintf(s_chip_model, sizeof s_chip_model, "ESP32-S2"); break;
    case CHIP_ESP32S3: snprintf(s_chip_model, sizeof s_chip_model, "ESP32-S3"); break;
    case CHIP_ESP32C3: snprintf(s_chip_model, sizeof s_chip_model, "ESP32-C3"); break;
    default:           snprintf(s_chip_model, sizeof s_chip_model, "ESP32-family"); break;
  }
  /* esp_chip_info reports the revision as major*100 + minor. */
  snprintf(s_chip_rev, sizeof s_chip_rev, "v%d.%d", chip.revision / 100,
           chip.revision % 100);

  if (esp_flash_get_size(NULL, &s_flash_size) != ESP_OK) s_flash_size = 0;

  uint8_t mac[6] = {0};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK)
    snprintf(s_mac, sizeof s_mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
             mac[1], mac[2], mac[3], mac[4], mac[5]);

  /* Fingerprints, not keys. See device_keys.h. */
  device_keys_ota_key_fingerprint(s_key_fp, sizeof s_key_fp);
  device_keys_signer_fingerprint(s_signer_fp, sizeof s_signer_fp);
}

/* --------------------------------------------------------------- HTTP helper */

/*
 * POST `body` to `path` and copy the response into s_resp. Returns the HTTP
 * status, or -1 if the request could not be made. Reporting failures are
 * logged at DEBUG: a dashboard that is not running must never produce a wall of
 * errors during a demonstration, and must never affect the OTA path.
 */
static int post_json(const char *path, const char *body) {
  snprintf(s_url, sizeof s_url, "%s%s", OTA_SERVER_URL, path);

  esp_http_client_config_t cfg = {0};
  cfg.url = s_url;
  cfg.method = HTTP_METHOD_POST;
  cfg.timeout_ms = DEVICE_REPORT_TIMEOUT_MS;
  if (url_is_https(s_url)) {
    cfg.cert_pem = (const char *)server_ca_cert_pem_start;
    cfg.skip_cert_common_name_check = false;
  }

  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (client == NULL) return -1;

  int status = -1;
  size_t len = strlen(body);
  s_resp[0] = '\0';

  esp_http_client_set_header(client, "Content-Type", "application/json");

  if (esp_http_client_open(client, (int)len) != ESP_OK) {
    ESP_LOGD(TAG, "dashboard unreachable at %s", s_url);
    goto done;
  }
  if (esp_http_client_write(client, body, len) < 0) goto done;
  if (esp_http_client_fetch_headers(client) < 0) goto done;

  status = esp_http_client_get_status_code(client);
  int got = esp_http_client_read_response(client, s_resp, sizeof s_resp - 1);
  s_resp[got > 0 ? got : 0] = '\0';

done:
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return status;
}

/* ------------------------------------------------------------------ commands */

static void handle_command(const char *command) {
  /* An explicit list. Nothing here interprets, concatenates or executes the
   * string; it is only ever compared. */
  if (strcmp(command, "CHECK_UPDATE") == 0 || strcmp(command, "START_OTA") == 0) {
    ESP_LOGI(TAG, "Dashboard requested %s -- waking the OTA task", command);
    ota_manager_trigger_now();
  } else if (strcmp(command, "REBOOT") == 0) {
    ESP_LOGW(TAG, "Dashboard requested REBOOT -- restarting in 1 s");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
  } else {
    ESP_LOGW(TAG, "Ignoring unknown command from the dashboard (%d bytes)",
             (int)strlen(command));
  }
}

static void handle_command_response(void) {
  if (s_resp[0] == '\0') return;

  cJSON *root = cJSON_Parse(s_resp);
  if (root == NULL) return;

  const cJSON *commands = cJSON_GetObjectItemCaseSensitive(root, "commands");
  if (cJSON_IsArray(commands)) {
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, commands) {
      if (cJSON_IsString(item) && item->valuestring != NULL)
        handle_command(item->valuestring);
    }
  }
  cJSON_Delete(root);
}

/* ----------------------------------------------------------------- heartbeat */

static void send_heartbeat(void) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  const esp_app_desc_t *app = esp_app_get_description();

  char ip[16] = "0.0.0.0";
  wifi_manager_get_ip(ip, sizeof ip);

  int rssi = 0;
  char ssid[33] = "";
  wifi_ap_record_t ap;
  if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
    rssi = ap.rssi;
    snprintf(ssid, sizeof ssid, "%s", (const char *)ap.ssid);
  }

  uint32_t cycles = 0, rejections = 0, done = 0, total = 0;
  ota_manager_get_stats(&cycles, &rejections);
  ota_manager_get_progress(&done, &total);

  snprintf(s_body, sizeof s_body,
           "{\"device_id\":\"%s\",\"ip\":\"%s\","
           "\"firmware_version\":\"%s\",\"firmware_version_code\":%" PRIu32 ","
           "\"security_version\":%u,"
           "\"partition\":\"%s\",\"partition_addr\":\"0x%08" PRIx32 "\","
           "\"free_heap\":%" PRIu32 ",\"min_free_heap\":%" PRIu32 ","
           "\"uptime_s\":%" PRId64 ","
           "\"ota_state\":\"%s\",\"ota_done\":%" PRIu32 ",\"ota_total\":%" PRIu32 ","
           "\"ota_checks\":%" PRIu32 ",\"ota_rejections\":%" PRIu32 ","
           "\"wifi_rssi\":%d,\"wifi_ssid\":\"%s\","
           "\"chip_model\":\"%s\",\"chip_revision\":\"%s\",\"chip_cores\":%d,"
           "\"flash_size\":%" PRIu32 ",\"mac\":\"%s\","
           "\"idf_version\":\"%s\",\"build_time\":\"%s %s\","
           "\"app_version\":\"%s\","
           "\"key_fingerprint\":\"%s\",\"signer_fingerprint\":\"%s\","
           "\"last_error\":\"%s\"}",
           OTA_DEVICE_ID, ip,
           FIRMWARE_VERSION_STRING, (uint32_t)FIRMWARE_VERSION_CODE,
           (unsigned)SECURITY_VERSION,
           running ? running->label : "?", running ? running->address : 0,
           esp_get_free_heap_size(), esp_get_minimum_free_heap_size(),
           esp_timer_get_time() / 1000000,
           ota_state_name(ota_manager_state()), done, total,
           cycles, rejections,
           rssi, ssid,
           s_chip_model, s_chip_rev, s_chip_cores,
           s_flash_size, s_mac,
           app->idf_ver, app->date, app->time,
           app->version,
           s_key_fp, s_signer_fp,
           ota_manager_last_error());

  int status = post_json("/api/device/heartbeat", s_body);
  if (status == 200) handle_command_response();
}

/* --------------------------------------------------------------- OTA events */

/* Escape the few characters that would break the JSON string we build by hand.
 * Reasons come from the firmware's own message table, but escaping keeps this
 * honest even if one day they do not. */
static void json_escape(const char *in, char *out, size_t outlen) {
  size_t o = 0;
  for (size_t i = 0; in[i] != '\0' && o + 2 < outlen; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '"' || c == '\\') {
      out[o++] = '\\';
      out[o++] = (char)c;
    } else if (c < 0x20) {
      out[o++] = ' ';
    } else {
      out[o++] = (char)c;
    }
  }
  out[o] = '\0';
}

static void send_event(const report_event_t *ev) {
  char reason[2 * sizeof ev->reason];
  json_escape(ev->reason, reason, sizeof reason);

  snprintf(s_body, sizeof s_body,
           "{\"event\":\"%s\",\"stage\":\"%s\",\"result\":\"%s\","
           "\"reason\":\"%s\",\"from_version\":\"%s\",\"to_version\":\"%s\","
           "\"security_version\":%" PRIu32 ",\"duration_ms\":%" PRIu32 "}",
           ev->event, ev->stage, ev->result, reason, ev->from_version,
           ev->to_version, ev->security_version, ev->duration_ms);

  char path[96];
  snprintf(path, sizeof path, "/api/device/%s/event", OTA_DEVICE_ID);
  post_json(path, s_body);
}

void device_report_ota_event(const char *event, const char *stage,
                             const char *result, const char *reason,
                             const char *from_version, const char *to_version,
                             uint32_t security_version, uint32_t duration_ms) {
  if (s_events == NULL) return;

  report_event_t ev = {0};
  snprintf(ev.event, sizeof ev.event, "%s", event ? event : "");
  snprintf(ev.stage, sizeof ev.stage, "%s", stage ? stage : "");
  snprintf(ev.result, sizeof ev.result, "%s", result ? result : "");
  snprintf(ev.reason, sizeof ev.reason, "%s", reason ? reason : "");
  snprintf(ev.from_version, sizeof ev.from_version, "%s",
           from_version ? from_version : "");
  snprintf(ev.to_version, sizeof ev.to_version, "%s",
           to_version ? to_version : "");
  ev.security_version = security_version;
  ev.duration_ms = duration_ms;

  /* Never block the OTA task. A dropped report costs a dashboard row. */
  if (xQueueSend(s_events, &ev, 0) != pdTRUE)
    ESP_LOGD(TAG, "report queue full; dropping %s event", ev.event);
}

/* ---------------------------------------------------------------- the task */

static void report_task(void *arg) {
  (void)arg;

  ESP_LOGI(TAG, "Reporting task started; dashboard is %s%s", OTA_SERVER_URL,
           "/api/device/heartbeat");
  collect_static_info();

  if (wifi_manager_wait_connected(WIFI_CONNECT_TIMEOUT_MS) != ESP_OK)
    ESP_LOGW(TAG, "Wi-Fi not up yet; heartbeats start once it is");

  TickType_t last = 0;

  for (;;) {
    report_event_t ev;
    while (xQueueReceive(s_events, &ev, 0) == pdTRUE) {
      if (wifi_manager_is_connected()) send_event(&ev);
    }

    if (wifi_manager_is_connected()) {
      /* Report faster while an update is in flight so the dashboard's progress
       * bar tracks the real download rather than lagging behind it. */
      ota_state_t state = ota_manager_state();
      bool busy = (state != OTA_IDLE && state != OTA_FAILED);
      TickType_t interval = pdMS_TO_TICKS(busy ? DEVICE_REPORT_BUSY_INTERVAL_MS
                                               : DEVICE_REPORT_INTERVAL_MS);
      TickType_t now = xTaskGetTickCount();
      if (last == 0 || (now - last) >= interval) {
        send_heartbeat();
        last = xTaskGetTickCount();
      }
    }

    vTaskDelay(pdMS_TO_TICKS(DEVICE_REPORT_TICK_MS));
  }
}

esp_err_t device_report_start(void) {
  s_events = xQueueCreate(8, sizeof(report_event_t));
  if (s_events == NULL) return ESP_ERR_NO_MEM;

  /* 6 KB: an HTTP client and a small cJSON parse, no TLS handshake unless the
   * server is https, in which case mbedTLS also runs on this stack. */
  BaseType_t ok = xTaskCreate(report_task, "report_task", 6144, NULL, 4, NULL);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "Cannot create the reporting task");
    return ESP_ERR_NO_MEM;
  }
  return ESP_OK;
}
