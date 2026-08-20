/*
 * Device reporting and command channel -- the minimum the management dashboard
 * needs to show what this device is doing, and the only way it can ask this
 * device to do anything.
 *
 * TWO DIRECTIONS, BOTH DELIBERATELY DULL
 *
 *   device -> server   a periodic heartbeat of telemetry (versions, partition,
 *                      heap, Wi-Fi, OTA state and byte counters) plus one POST
 *                      per OTA outcome. Everything sent is already printed on
 *                      the serial console; nothing secret is included. Key
 *                      fingerprints are Ascon-Hash256 digests, never keys.
 *
 *   server -> device   the heartbeat response may carry commands. Exactly three
 *                      are understood, and they are compared against a literal
 *                      list here:
 *
 *                          CHECK_UPDATE   ask the OTA task to run a cycle now
 *                          START_OTA      the same thing, named for the UI
 *                          REBOOT         esp_restart()
 *
 *                      Anything else is logged and ignored. There is no
 *                      mechanism -- none -- by which the server can make this
 *                      device execute arbitrary work.
 *
 * WHY THIS CHANGES NOTHING ABOUT SECURITY
 *
 * A command only *triggers* the existing OTA state machine. It supplies no URL,
 * no version, no key and no payload. The update that follows is fetched,
 * verified and installed by exactly the same code as a timer-driven update:
 * Ed25519 signature, then anti-rollback, then Ascon-AEAD128 decryption with tag
 * verification, then Ascon-Hash256 comparison, and only then a partition
 * switch. A hostile server that queues START_OTA a thousand times achieves
 * nothing except a thousand rejected packages.
 */

#ifndef DEVICE_REPORT_H_
#define DEVICE_REPORT_H_

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Start the reporting task. Safe to call before Wi-Fi is up; the task waits. */
esp_err_t device_report_start(void);

/*
 * Queue one OTA outcome for delivery. Returns immediately -- the HTTP POST
 * happens on the reporting task, so this can be called from inside the OTA
 * state machine (including mid-download) without blocking it or borrowing its
 * stack. If the queue is full the event is dropped: reporting must never
 * interfere with an update.
 *
 * `event`  CHECK | START | INSTALL | REJECT | FAIL
 * `stage`  the OTA state where it happened, e.g. SIGNATURE_VERIFY
 * `result` SUCCESS | REJECTED | FAILED
 */
void device_report_ota_event(const char *event, const char *stage,
                             const char *result, const char *reason,
                             const char *from_version, const char *to_version,
                             uint32_t security_version, uint32_t duration_ms);

#ifdef __cplusplus
}
#endif

#endif /* DEVICE_REPORT_H_ */
