/*
 * Wi-Fi station bring-up: connect, retry, report status.
 *
 * Nothing security-relevant lives here. The OTA package is verified
 * cryptographically regardless of how it arrived, so the network layer only has
 * to be reliable, not trusted.
 */

#ifndef WIFI_MANAGER_H_
#define WIFI_MANAGER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise netif, the event loop and the Wi-Fi driver, and start connecting.
 * Returns as soon as the connection attempt is under way. Requires NVS to be
 * initialised first (the Wi-Fi driver keeps calibration data there). */
esp_err_t wifi_manager_init(void);

/* Block until connected with an IP address, or until timeout_ms elapses.
 * ESP_OK on success, ESP_ERR_TIMEOUT otherwise. */
esp_err_t wifi_manager_wait_connected(uint32_t timeout_ms);

bool wifi_manager_is_connected(void);

/* Copy the current IPv4 address as text, or "0.0.0.0" when not connected. */
void wifi_manager_get_ip(char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_MANAGER_H_ */
