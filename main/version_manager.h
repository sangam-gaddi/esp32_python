/*
 * Version state and anti-rollback bookkeeping.
 *
 * The device keeps two numbers in NVS:
 *
 *   fw_ver    highest firmware version it has ever run
 *   sec_ver   highest security version it has ever accepted
 *
 * Both are raised to the compiled-in constants at start-up and never lowered.
 * That monotonicity is what makes the rollback check meaningful: an attacker who
 * replays a genuinely-signed old package cannot make the device forget it has
 * already moved past that security version.
 *
 * WHY THE STATE IS UPDATED AFTER A REBOOT, NOT BEFORE
 *
 * The obvious design -- record the new version just before rebooting into it --
 * is wrong when combined with rollback protection. If the new image fails to
 * boot, the bootloader reverts to the previous one, but the recorded version
 * would still claim the newer number, and the device would then refuse to
 * install the very update it needs. So nothing is recorded at install time.
 * Instead each image raises the stored state from its *own* compiled-in
 * constants once it has booted and been marked valid. A rolled-back image
 * therefore leaves the stored firmware version where it was, and the update can
 * be retried.
 *
 * The security version is a deliberate exception: it is raised on first
 * successful boot and never lowered again, even after a rollback, because
 * forgetting a security version is exactly what an attacker wants.
 */

#ifndef VERSION_MANAGER_H_
#define VERSION_MANAGER_H_

#include <stdint.h>

#include "esp_err.h"
#include "ota_package.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Load stored state and raise it to this build's FIRMWARE_VERSION_CODE and
 * SECURITY_VERSION. Call after nvs_flash_init(), and only once the running image
 * has been confirmed good. */
esp_err_t version_manager_init(void);

/* Current accepted state, for ota_pkg_check_versions(). */
void version_manager_get(ota_pkg_version_state_t *out);

/* Log the running and accepted versions. */
void version_manager_log_status(void);

#ifdef __cplusplus
}
#endif

#endif /* VERSION_MANAGER_H_ */
