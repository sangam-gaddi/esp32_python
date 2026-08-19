/*
 * Device key material: the provisioned Ascon-AEAD128 key and the trusted
 * Ed25519 public key.
 *
 * The two are handled very differently, because they are very different things:
 *
 *   Ed25519 public key -- not secret. Compiled into the image from
 *       crypto_config.h and returned directly. Hard-coding it is the point: it
 *       is the trust anchor, and it must not be replaceable by anything that
 *       arrives over the network.
 *
 *   Ascon-AEAD128 key -- secret, shared with the packaging tool. Read from NVS.
 *       On first boot NVS is empty, so it is provisioned there from the
 *       compiled-in demonstration key and used from NVS thereafter. That models
 *       how a real product works (per-device key in protected storage) while
 *       still being flashable in one step for a demonstration.
 *
 * No function here ever logs key bytes. `device_keys_log_status()` prints a
 * fingerprint -- Ascon-Hash256 of the key, truncated -- which is enough to
 * confirm the host and device agree without disclosing the key.
 */

#ifndef DEVICE_KEYS_H_
#define DEVICE_KEYS_H_

#include <stdint.h>

#include "ascon_aead128.h"
#include "ed25519_verify.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Open NVS storage and, if no key is stored yet, provision the compiled-in
 * demonstration key. Requires nvs_flash_init() to have succeeded. */
esp_err_t device_keys_init(void);

/* Copy the 16-byte Ascon key into `key`. Caller should wipe it after use. */
esp_err_t device_keys_get_ota_key(uint8_t key[ASCON_AEAD128_KEY_BYTES]);

/* The trusted Ed25519 public key. Points at const storage in the image; never
 * NULL, never network-supplied. */
const uint8_t *device_keys_trusted_pubkey(void);

/* Log where the keys came from, plus non-sensitive fingerprints. */
void device_keys_log_status(void);

#ifdef __cplusplus
}
#endif

#endif /* DEVICE_KEYS_H_ */
