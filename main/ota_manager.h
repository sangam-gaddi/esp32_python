/*
 * Secure OTA state machine.
 *
 * Runs as its own task. Each cycle:
 *
 *   OTA_IDLE
 *      |  timer expires, or ota_manager_trigger_now()
 *      v
 *   OTA_CHECK              GET /api/firmware/latest -- an UNTRUSTED hint about
 *      |                   what exists. Used only to decide whether to bother
 *      |                   downloading. No security decision depends on it.
 *      v
 *   OTA_METADATA           fetch the 160-byte package header
 *      v
 *   OTA_SIGNATURE_VERIFY   Ed25519 over header[0:96]        -> reject
 *      v
 *   OTA_VERSION_VERIFY     anti-rollback and freshness      -> reject
 *      v
 *   OTA_DOWNLOAD           stream the ciphertext in chunks
 *   OTA_DECRYPT            Ascon-AEAD128 decrypt each chunk, write to the
 *      |                   INACTIVE OTA partition, hash as we go
 *      v
 *   OTA_HASH_VERIFY        Ascon-AEAD128 tag, then Ascon-Hash256 vs the signed
 *      |                   digest                           -> reject
 *      v
 *   OTA_INSTALL            esp_ota_end + esp_ota_set_boot_partition
 *      v
 *   OTA_REBOOT             esp_restart
 *
 *   any failure -> OTA_FAILED -> OTA_IDLE, with the running firmware untouched
 *
 * WHY SIGNATURE AND VERSION CHECKS COME BEFORE THE DOWNLOAD
 *
 * The header arrives first and is self-contained, so an unauthorised or
 * downgraded package can be rejected before a single byte of firmware is
 * transferred or written to flash. It saves bandwidth, and more importantly it
 * means unauthenticated payload never reaches flash at all in the common attack
 * cases.
 *
 * WHAT IS UNAVOIDABLY WRITTEN BEFORE AUTHENTICATION
 *
 * The AEAD tag and the hash can only be checked once the whole payload has been
 * seen. Streaming decryption therefore writes not-yet-authenticated plaintext to
 * the inactive OTA partition. That is safe because the partition is inert:
 * esp_ota_set_boot_partition() is called only after every check has passed, so a
 * failed update leaves flash holding bytes that will never be executed, and the
 * bootloader keeps starting the previous image.
 */

#ifndef OTA_MANAGER_H_
#define OTA_MANAGER_H_

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OTA_IDLE = 0,
  OTA_CHECK,
  OTA_METADATA,
  OTA_DOWNLOAD,
  OTA_DECRYPT,
  OTA_HASH_VERIFY,
  OTA_SIGNATURE_VERIFY,
  OTA_VERSION_VERIFY,
  OTA_INSTALL,
  OTA_REBOOT,
  OTA_FAILED,
} ota_state_t;

const char *ota_state_name(ota_state_t s);

/* Start the OTA task. Wi-Fi does not have to be up yet; the task waits. */
esp_err_t ota_manager_start(void);

/* Ask for an update check now instead of waiting for the interval. Safe to call
 * from any task; ignored if a cycle is already running. */
void ota_manager_trigger_now(void);

ota_state_t ota_manager_state(void);

/* Number of update cycles that have completed, and how many were rejected.
 * Useful for a demonstration and for the benchmark harness. */
void ota_manager_get_stats(uint32_t *cycles, uint32_t *rejections);

/* Bytes of the package received so far, and the total the signed header
 * declares. Both are 0 outside a download. Reporting only, for the dashboard:
 * no security decision reads these. */
void ota_manager_get_progress(uint32_t *done, uint32_t *total);

/* Version of the package the current or most recent cycle was working on,
 * encoded as major<<16|minor<<8|patch, plus its security version. Zero when no
 * package has been offered yet. Read from the package header for display; it is
 * only trustworthy once the signature check has passed, which is why an
 * installed-version report is only ever emitted after every check succeeds. */
void ota_manager_get_target(uint32_t *firmware_version,
                            uint32_t *security_version);

/* The last rejection or failure message, or "" if the device has not rejected
 * anything since boot. */
const char *ota_manager_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* OTA_MANAGER_H_ */
