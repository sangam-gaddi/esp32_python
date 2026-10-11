/*
 * Application configuration: what this firmware *is*, and how it behaves.
 *
 * THE TWO NUMBERS THAT MATTER FOR THE DEMONSTRATION are FIRMWARE_VERSION_* and
 * SECURITY_VERSION, right below. Bump them, rebuild, and package the result --
 * that is how you produce "firmware V2" for the OTA demo. See docs/DEMO.md.
 *
 * Network and server settings live in device_config.h, which is git-ignored
 * because it holds Wi-Fi credentials. Copy device_config.h.example to
 * device_config.h and fill it in.
 */

#ifndef APP_CONFIG_H_
#define APP_CONFIG_H_

#include "device_config.h"

/* =========================================================================
 * VERSIONS
 * ========================================================================= */

/*
 * Firmware version -- the human-facing release number. Encoded into a single
 * 32-bit value as major<<16 | minor<<8 | patch, which makes "is this newer?" a
 * plain integer comparison. Each component must be 0..255.
 *
 * The device installs an update only when the package's firmware_version is
 * strictly greater than this.
 */
#ifndef FIRMWARE_VERSION_MAJOR
#define FIRMWARE_VERSION_MAJOR 38
#endif
#ifndef FIRMWARE_VERSION_MINOR
#define FIRMWARE_VERSION_MINOR 0
#endif
#ifndef FIRMWARE_VERSION_PATCH
#define FIRMWARE_VERSION_PATCH 0
#endif

/*
 * Security version -- a monotonic counter, unrelated to the release number.
 * Raise it whenever a release fixes something that must never be downgraded
 * past. The device rejects any package whose security_version is *lower* than
 * the highest it has already accepted, even when that package is perfectly
 * signed. That is the anti-rollback rule.
 *
 * Equal values are allowed, so routine releases need not touch this.
 */
#ifndef SECURITY_VERSION
#define SECURITY_VERSION 38
#endif

#define FIRMWARE_VERSION_CODE                                     \
  (((uint32_t)(FIRMWARE_VERSION_MAJOR) << 16) |                   \
   ((uint32_t)(FIRMWARE_VERSION_MINOR) << 8) |                    \
   ((uint32_t)(FIRMWARE_VERSION_PATCH)))

#define _SOTA_STR2(x) #x
#define _SOTA_STR(x) _SOTA_STR2(x)
#define FIRMWARE_VERSION_STRING                       \
  _SOTA_STR(FIRMWARE_VERSION_MAJOR)                   \
  "." _SOTA_STR(FIRMWARE_VERSION_MINOR) "." _SOTA_STR(FIRMWARE_VERSION_PATCH)

/* =========================================================================
 * OTA BEHAVIOUR
 * ========================================================================= */

/* How long to wait after boot before the first update check. Long enough for
 * Wi-Fi to settle and for the serial log to be readable during a demo. */
#ifndef OTA_FIRST_CHECK_DELAY_MS
#define OTA_FIRST_CHECK_DELAY_MS (10 * 1000)
#endif

/* Interval between periodic update checks. 60 s suits a live demonstration;
 * a real product would use hours, with jitter to avoid stampeding the server. */
#ifndef OTA_CHECK_INTERVAL_MS
#define OTA_CHECK_INTERVAL_MS (60 * 1000)
#endif

/* Bytes pulled from the socket per read. This is the single largest RAM cost of
 * an update: one buffer of this size for ciphertext and one of
 * (this + 15) for plaintext. 4 KB keeps both comfortably inside the heap while
 * still amortising syscall overhead. Raising it does not make the update more
 * secure, only faster. */
#ifndef OTA_DOWNLOAD_CHUNK_SIZE
#define OTA_DOWNLOAD_CHUNK_SIZE 4096
#endif

/* Per-request network timeout. */
#ifndef OTA_HTTP_TIMEOUT_MS
#define OTA_HTTP_TIMEOUT_MS 15000
#endif

/* Log a progress line every this many bytes, so a demo shows movement without
 * flooding the console. */
#ifndef OTA_PROGRESS_LOG_INTERVAL
#define OTA_PROGRESS_LOG_INTERVAL (32 * 1024)
#endif

/* Reboot delay after a successful install, so the log can be read. */
#ifndef OTA_REBOOT_DELAY_MS
#define OTA_REBOOT_DELAY_MS 3000
#endif

/*
 * ANTI-ROLLBACK POLICY -- read this before changing it.
 *
 *   0 (default, SECURE)  The device installs a package only when its firmware
 *                        version is strictly NEWER, and refuses any package
 *                        whose security version is below the highest it has
 *                        already accepted. This is what stops an attacker
 *                        replaying a genuine older release whose vulnerability
 *                        is publicly known. It is attack scenario 5 in
 *                        docs/DEMO.md and objective 5 of the project.
 *
 *   1 (DEMONSTRATION)    The device installs any published package whose
 *                        version DIFFERS from the one it is running, in either
 *                        direction. This makes it possible to move a board
 *                        back and forth between releases from the web page,
 *                        which is convenient when showing the system off.
 *
 * Turning this on REMOVES a security property. It does not weaken the
 * signature check, the AEAD tag or the hash -- unsigned or tampered firmware
 * is still rejected exactly as before -- but a correctly signed OLD package
 * will now be accepted, which is precisely the rollback attack.
 *
 * The device says which mode it is in, loudly, on every update check, so a
 * demonstration can never silently claim protection it does not have.
 */
#ifndef OTA_ALLOW_DOWNGRADE
#define OTA_ALLOW_DOWNGRADE 0
#endif

/* Blink GPIO2 at a rate derived from the firmware version (main.c). Off by
 * default: GPIO2 is the board LED, and user_code.cpp may want it. */
#ifndef STATUS_LED_ENABLE
#define STATUS_LED_ENABLE 0
#endif

/* Run the on-device crypto microbenchmark (main/crypto_bench.c) once at boot,
 * before Wi-Fi starts. Measurement builds only. */
#ifndef OTA_RUN_CRYPTO_BENCHMARK
#define OTA_RUN_CRYPTO_BENCHMARK 0
#endif

/* Measurement builds only: pretend the post-update self-test failed, so the
 * image is never marked valid and the device restarts. With
 * CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE the bootloader must then return to the
 * previous firmware. Used to measure recovery from a bad update. */
#ifndef OTA_SIMULATE_SELFTEST_FAILURE
#define OTA_SIMULATE_SELFTEST_FAILURE 0
#endif

/* =========================================================================
 * DASHBOARD REPORTING
 *
 * Telemetry only. The device tells the management dashboard what it is doing
 * and picks up at most one of three commands (CHECK_UPDATE, START_OTA, REBOOT).
 * Nothing here can influence how an update is verified: see device_report.h.
 * ========================================================================= */

/* How often a heartbeat is sent while the device is idle. The server treats a
 * device as OFFLINE after ~15 s without one, so keep this comfortably below
 * that (and raise SOTA_HEARTBEAT_TIMEOUT on the server if you raise this). */
#ifndef DEVICE_REPORT_INTERVAL_MS
#define DEVICE_REPORT_INTERVAL_MS 5000
#endif

/* Faster cadence while an OTA cycle is running, so the dashboard's progress
 * bar follows the real download. */
#ifndef DEVICE_REPORT_BUSY_INTERVAL_MS
#define DEVICE_REPORT_BUSY_INTERVAL_MS 1500
#endif

/* How often the reporting task wakes to check its queue. */
#ifndef DEVICE_REPORT_TICK_MS
#define DEVICE_REPORT_TICK_MS 500
#endif

/* Per-request timeout for heartbeats and event reports. Short: if the
 * dashboard is not running, the device should notice quickly and carry on. */
#ifndef DEVICE_REPORT_TIMEOUT_MS
#define DEVICE_REPORT_TIMEOUT_MS 4000
#endif

/* =========================================================================
 * WI-FI BEHAVIOUR
 * ========================================================================= */

#ifndef WIFI_MAX_RETRY
#define WIFI_MAX_RETRY 10
#endif

#ifndef WIFI_CONNECT_TIMEOUT_MS
#define WIFI_CONNECT_TIMEOUT_MS 30000
#endif

/* How often the system monitor prints uptime, heap and PSRAM to the console.
 * Purely a demonstration aid; nothing in the update path reads it. */
#ifndef MONITOR_PERIOD_MS
#define MONITOR_PERIOD_MS 2000
#endif

/* =========================================================================
 * NVS STORAGE
 * ========================================================================= */

/* Namespace holding the provisioned Ascon key. */
#define NVS_NAMESPACE_KEYS "sota_keys"
#define NVS_BLOB_OTA_KEY "ota_key"

/* Namespace holding the accepted-version state used for anti-rollback. */
#define NVS_NAMESPACE_VERSION "sota_ver"
#define NVS_KEY_FIRMWARE_VERSION "fw_ver"
#define NVS_KEY_SECURITY_VERSION "sec_ver"

#endif /* APP_CONFIG_H_ */
