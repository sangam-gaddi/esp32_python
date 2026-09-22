/* Implementation of the Arduino-compatible layer. See arduino_compat.h. */

#include "arduino_compat.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "driver/gpio.h"
#include "esp_chip_info.h"
#include "esp_clk_tree.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "USER";

/* ----------------------------------------------------------------- pins --- */

void pinMode(int pin, int mode) {
  gpio_config_t cfg = {};
  cfg.pin_bit_mask = 1ULL << pin;
  cfg.intr_type = GPIO_INTR_DISABLE;

  switch (mode) {
    case OUTPUT:
      cfg.mode = GPIO_MODE_OUTPUT;
      cfg.pull_up_en = GPIO_PULLUP_DISABLE;
      cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
      break;
    case INPUT_PULLUP:
      cfg.mode = GPIO_MODE_INPUT;
      cfg.pull_up_en = GPIO_PULLUP_ENABLE;
      cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
      break;
    case INPUT_PULLDOWN:
      cfg.mode = GPIO_MODE_INPUT;
      cfg.pull_up_en = GPIO_PULLUP_DISABLE;
      cfg.pull_down_en = GPIO_PULLDOWN_ENABLE;
      break;
    default:
      cfg.mode = GPIO_MODE_INPUT;
      cfg.pull_up_en = GPIO_PULLUP_DISABLE;
      cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
      break;
  }

  esp_err_t err = gpio_config(&cfg);
  if (err != ESP_OK)
    ESP_LOGW(TAG, "pinMode(%d) failed: %s", pin, esp_err_to_name(err));
}

void digitalWrite(int pin, int value) {
  gpio_set_level(static_cast<gpio_num_t>(pin), value ? 1 : 0);
}

int digitalRead(int pin) {
  return gpio_get_level(static_cast<gpio_num_t>(pin));
}

/* ----------------------------------------------------------------- time --- */

void delay(uint32_t ms) {
  /* Always yield at least one tick, so a delay(0) in a loop cannot starve the
   * scheduler and trip the task watchdog. */
  TickType_t ticks = pdMS_TO_TICKS(ms);
  vTaskDelay(ticks ? ticks : 1);
}

void delayMicroseconds(uint32_t us) {
  if (us >= 1000) {
    delay(us / 1000);
    us %= 1000;
  }
  if (us) {
    int64_t end = esp_timer_get_time() + us;
    while (esp_timer_get_time() < end) { /* busy wait, sub-millisecond only */ }
  }
}

uint32_t millis(void) {
  return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

uint64_t micros(void) {
  return static_cast<uint64_t>(esp_timer_get_time());
}

/* --------------------------------------------------------------- serial --- */

/* One line is assembled here and handed to the log when println() is called,
 * so sketch output keeps the timestamps and tags of the rest of the console. */
static char s_line[256];
static size_t s_len = 0;

static void line_append(const char *text) {
  if (!text) return;
  size_t room = sizeof(s_line) - s_len - 1;
  size_t take = strnlen(text, room);
  memcpy(s_line + s_len, text, take);
  s_len += take;
  s_line[s_len] = '\0';
}

static void line_flush(void) {
  if (s_len == 0) {
    ESP_LOGI(TAG, "%s", "");
    return;
  }
  ESP_LOGI(TAG, "%s", s_line);
  s_len = 0;
  s_line[0] = '\0';
}

SerialShim Serial;
EspShim ESP;

void SerialShim::begin(unsigned long baud) {
  /* The console UART is already configured by ESP-IDF at the rate set in
   * menuconfig, so there is nothing to open here. Reported rather than
   * silently ignored, in case a sketch expects a different rate. */
  ESP_LOGI(TAG, "Serial.begin(%lu) -- console is already running at the "
                "configured rate", baud);
}

void SerialShim::flush(void) {
  if (s_len) line_flush();
}

void SerialShim::print(const char *text) { line_append(text); }

void SerialShim::print(char value) {
  char buf[2] = {value, '\0'};
  line_append(buf);
}

#define PRINT_NUM(type, fmt)                    \
  void SerialShim::print(type value) {          \
    char buf[32];                               \
    snprintf(buf, sizeof buf, fmt, value);      \
    line_append(buf);                           \
  }

PRINT_NUM(int, "%d")
PRINT_NUM(unsigned int, "%u")
PRINT_NUM(long, "%ld")
PRINT_NUM(unsigned long, "%lu")
PRINT_NUM(long long, "%lld")
PRINT_NUM(unsigned long long, "%llu")

void SerialShim::print(double value, int decimals) {
  char buf[40];
  snprintf(buf, sizeof buf, "%.*f", decimals, value);
  line_append(buf);
}

void SerialShim::println(void) { line_flush(); }

void SerialShim::println(const char *text) { print(text); line_flush(); }
void SerialShim::println(char value) { print(value); line_flush(); }
void SerialShim::println(int value) { print(value); line_flush(); }
void SerialShim::println(unsigned int value) { print(value); line_flush(); }
void SerialShim::println(long value) { print(value); line_flush(); }
void SerialShim::println(unsigned long value) { print(value); line_flush(); }
void SerialShim::println(long long value) { print(value); line_flush(); }
void SerialShim::println(unsigned long long value) { print(value); line_flush(); }

void SerialShim::println(double value, int decimals) {
  print(value, decimals);
  line_flush();
}

void SerialShim::printf(const char *format, ...) {
  char buf[224];
  va_list args;
  va_start(args, format);
  vsnprintf(buf, sizeof buf, format, args);
  va_end(args);
  line_append(buf);
  /* Arduino's printf does not imply a newline, but a trailing one means the
   * caller intended to end the line. */
  if (s_len && s_line[s_len - 1] == '\n') {
    s_line[--s_len] = '\0';
    line_flush();
  }
}

/* ------------------------------------------------------------------ ESP --- */

const char *EspShim::getChipModel(void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  switch (chip.model) {
    case CHIP_ESP32:   return "ESP32";
    case CHIP_ESP32S2: return "ESP32-S2";
    case CHIP_ESP32S3: return "ESP32-S3";
    case CHIP_ESP32C3: return "ESP32-C3";
    default:           return "unknown";
  }
}

uint8_t EspShim::getChipRevision(void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  return static_cast<uint8_t>(chip.revision);
}

uint8_t EspShim::getChipCores(void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  return static_cast<uint8_t>(chip.cores);
}

uint32_t EspShim::getCpuFreqMHz(void) {
  uint32_t hz = 0;
  if (esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU,
                                   ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED,
                                   &hz) != ESP_OK)
    return 0;
  return hz / 1000000;
}

uint32_t EspShim::getFlashChipSize(void) {
  uint32_t bytes = 0;
  if (esp_flash_get_size(NULL, &bytes) != ESP_OK) return 0;
  return bytes;
}

const char *EspShim::getSdkVersion(void) { return esp_get_idf_version(); }

uint32_t EspShim::getFreeHeap(void) { return esp_get_free_heap_size(); }

uint32_t EspShim::getMinFreeHeap(void) {
  return esp_get_minimum_free_heap_size();
}

uint32_t EspShim::getHeapSize(void) {
  return static_cast<uint32_t>(heap_caps_get_total_size(MALLOC_CAP_INTERNAL));
}

uint32_t EspShim::getFreePsram(void) {
  return static_cast<uint32_t>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

uint64_t EspShim::getEfuseMac(void) {
  uint64_t mac = 0;
  esp_efuse_mac_get_default(reinterpret_cast<uint8_t *>(&mac));
  return mac;
}

void EspShim::restart(void) { esp_restart(); }
