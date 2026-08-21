#include "wifi_manager.h"

#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

static const char *TAG = "WIFI";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAILED_BIT BIT1

static EventGroupHandle_t s_events;
static int s_retries;
static bool s_connected;
static esp_netif_t *s_netif;

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id,
                          void *data) {
  (void)arg;

  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    ESP_LOGI(TAG, "Connecting to SSID \"%s\" ...", WIFI_SSID);
    esp_wifi_connect();
    return;
  }

  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    const wifi_event_sta_disconnected_t *ev =
        (const wifi_event_sta_disconnected_t *)data;
    s_connected = false;
    xEventGroupClearBits(s_events, WIFI_CONNECTED_BIT);

    if (s_retries < WIFI_MAX_RETRY) {
      s_retries++;
      ESP_LOGW(TAG, "Disconnected (reason %d), retry %d/%d",
               ev ? ev->reason : -1, s_retries, WIFI_MAX_RETRY);
      /* Small backoff so a wrong password does not spin the radio flat out. */
      vTaskDelay(pdMS_TO_TICKS(1000));
      esp_wifi_connect();
    } else {
      ESP_LOGE(TAG, "Giving up after %d attempts (last reason %d)",
               WIFI_MAX_RETRY, ev ? ev->reason : -1);
      ESP_LOGE(TAG, "Check WIFI_SSID / WIFI_PASSWORD in main/device_config.h");
      xEventGroupSetBits(s_events, WIFI_FAILED_BIT);
    }
    return;
  }

  if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    const ip_event_got_ip_t *ev = (const ip_event_got_ip_t *)data;
    s_retries = 0;
    s_connected = true;
    ESP_LOGI(TAG, "Connected. IP address " IPSTR, IP2STR(&ev->ip_info.ip));
    xEventGroupClearBits(s_events, WIFI_FAILED_BIT);
    xEventGroupSetBits(s_events, WIFI_CONNECTED_BIT);
  }
}

esp_err_t wifi_manager_init(void) {
  s_events = xEventGroupCreate();
  if (s_events == NULL) {
    ESP_LOGE(TAG, "Cannot create event group (out of memory)");
    return ESP_ERR_NO_MEM;
  }

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  s_netif = esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, NULL, NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_STA_GOT_IP, &on_wifi_event, NULL, NULL));

  wifi_config_t wifi_cfg = {0};
  /* strncpy into fixed SSID/password arrays; both are NUL-terminated by the
   * zero-initialisation above as long as the source fits. */
  strncpy((char *)wifi_cfg.sta.ssid, WIFI_SSID, sizeof wifi_cfg.sta.ssid - 1);
  strncpy((char *)wifi_cfg.sta.password, WIFI_PASSWORD,
          sizeof wifi_cfg.sta.password - 1);
  wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  wifi_cfg.sta.pmf_cfg.capable = true;
  wifi_cfg.sta.pmf_cfg.required = false;

  if (strlen(WIFI_PASSWORD) == 0) {
    /* Open network: allow it, but say so. */
    ESP_LOGW(TAG, "No Wi-Fi password configured; joining an open network");
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
  }

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
  ESP_ERROR_CHECK(esp_wifi_start());

  return ESP_OK;
}

esp_err_t wifi_manager_wait_connected(uint32_t timeout_ms) {
  if (s_events == NULL) return ESP_ERR_INVALID_STATE;

  EventBits_t bits = xEventGroupWaitBits(
      s_events, WIFI_CONNECTED_BIT | WIFI_FAILED_BIT, pdFALSE, pdFALSE,
      pdMS_TO_TICKS(timeout_ms));

  if (bits & WIFI_CONNECTED_BIT) return ESP_OK;
  return ESP_ERR_TIMEOUT;
}

bool wifi_manager_is_connected(void) { return s_connected; }

void wifi_manager_get_ip(char *buf, size_t buflen) {
  if (buf == NULL || buflen == 0) return;
  esp_netif_ip_info_t ip = {0};
  if (s_netif != NULL && s_connected &&
      esp_netif_get_ip_info(s_netif, &ip) == ESP_OK) {
    snprintf(buf, buflen, IPSTR, IP2STR(&ip.ip));
  } else {
    snprintf(buf, buflen, "0.0.0.0");
  }
}
