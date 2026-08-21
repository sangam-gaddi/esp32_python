/*
 * GENERATED FILE -- do not commit.
 *
 * Written by tools/generate_keys.py from the keys in keys/. Regenerate with:
 *     python tools/generate_keys.py --write-device-config
 *
 * This file holds the device's trust anchors:
 *
 *   OTA_TRUSTED_ED25519_PUBLIC_KEY  public, safe to embed. This is what makes
 *                                   the device reject firmware it was not
 *                                   given by the holder of the private key.
 *
 *   OTA_DEFAULT_ENCRYPTION_KEY      SECRET, and only here because this is a
 *                                   demonstration. It is used once, on first
 *                                   boot, to provision NVS; see
 *                                   main/device_keys.c. A real product would
 *                                   provision this per-device at manufacture
 *                                   into eFuse/NVS-encrypted storage and never
 *                                   compile it into an image at all.
 *
 * The Ed25519 PRIVATE key is deliberately absent and must never appear here.
 */

#ifndef CRYPTO_CONFIG_H_
#define CRYPTO_CONFIG_H_

#include <stdint.h>

/* Ed25519 public key, 32 bytes (raw, not PEM). */
static const uint8_t OTA_TRUSTED_ED25519_PUBLIC_KEY[32] = {
    0x20, 0xAA, 0x4B, 0x83, 0x17, 0x40, 0xBC, 0x8D,
    0xBC, 0x35, 0xBB, 0x62, 0x61, 0x2A, 0x62, 0x86,
    0x9D, 0x3B, 0xF6, 0x67, 0xF3, 0x96, 0x88, 0x7C,
    0xB6, 0x10, 0x26, 0xA0, 0xF6, 0x1F, 0x1B, 0x53,
};

/* Ascon-AEAD128 key, 16 bytes. Demonstration provisioning secret. */
static const uint8_t OTA_DEFAULT_ENCRYPTION_KEY[16] = {
    0x39, 0x1A, 0x54, 0xF4, 0x36, 0x79, 0xD3, 0x08,
    0x3E, 0x90, 0x54, 0x49, 0x15, 0x27, 0x1B, 0x2D,
};

#endif /* CRYPTO_CONFIG_H_ */
