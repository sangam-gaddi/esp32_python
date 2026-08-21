/*
 * TEMPLATE -- copy to device_config.h and fill in your own values.
 *
 *     cp main/device_config.h.example main/device_config.h     (Linux/macOS)
 *     copy main\device_config.h.example main\device_config.h   (Windows)
 *
 * device_config.h is git-ignored because it holds your Wi-Fi password. This
 * template is tracked; the real file is not. Never put credentials in the
 * template.
 */

#ifndef DEVICE_CONFIG_H_
#define DEVICE_CONFIG_H_

/* =========================================================================
 * WI-FI
 * ========================================================================= */

#define WIFI_SSID "CSE"
#define WIFI_PASSWORD "12345678"

/* =========================================================================
 * OTA SERVER
 * ========================================================================= */

/*
 * Base URL of the update server, no trailing slash. The device appends
 * "/api/firmware/latest" and the package path it is told about.
 *
 * Use the LAN IP address of the machine running server/app.py -- not
 * "localhost", which on the ESP32 means the ESP32 itself. Find it with
 * `ipconfig` (Windows) or `ip addr` (Linux).
 *
 * HTTPS (what a real deployment uses):
 *
 *     #define OTA_SERVER_URL "https://192.168.1.42:8443"
 *
 *   Requires the development certificates:
 *       python tools/make_dev_certs.py --ip 192.168.1.42
 *   which writes server/certs/ and main/server_ca_cert.pem. The device pins
 *   that CA certificate and verifies the server against it. Certificate
 *   verification is never disabled.
 *
 * HTTP (DEVELOPMENT ONLY):
 *
 *     #define OTA_SERVER_URL "http://192.168.1.42:8000"
 *
 *   Plain HTTP is NOT secure. Anyone on the network can read the traffic and
 *   substitute a response. It is acceptable here only because every security
 *   property of this project comes from the package itself -- Ed25519
 *   signature, Ascon-AEAD128 tag, Ascon-Hash256 digest, anti-rollback -- all
 *   of which are still enforced, and all of which still reject a tampered
 *   package delivered over a hostile link. What HTTP does *not* protect is
 *   confidentiality of the metadata and the fact that an update is happening.
 *   Do not describe an HTTP demo as a secure transport.
 */
#define OTA_SERVER_URL "http://10.177.78.146:8000"

/*
 * Set to 1 to allow plain-HTTP OTA URLs. The firmware refuses http:// unless
 * this is set, so shipping an insecure transport has to be a deliberate act
 * rather than an oversight. It logs a prominent warning on every check.
 */
#define OTA_ALLOW_INSECURE_HTTP 1

/* Metadata endpoint, appended to OTA_SERVER_URL. */
#define OTA_METADATA_PATH "/api/firmware/latest"

/*
 * Optional: a device identifier sent as a query parameter, so the server log
 * can distinguish units during a demonstration. Not a security mechanism --
 * it is neither secret nor authenticated.
 */
#define OTA_DEVICE_ID "esp32-demo-01"

#endif /* DEVICE_CONFIG_H_ */
