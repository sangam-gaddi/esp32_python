#!/usr/bin/env python3
"""Generate the development keys this project needs.

Three keys, with three different homes:

    keys/ed25519_private.pem   SIGNING HOST ONLY -- never leaves the build machine
    keys/ed25519_public.pem    embedded in the device firmware (trust anchor)
    keys/ota_enc_key.hex       shared by the packaging tool and the device

Usage:
    python tools/generate_keys.py                      # create if absent
    python tools/generate_keys.py --force              # overwrite existing keys
    python tools/generate_keys.py --write-device-config # also emit main/crypto_config.h

`keys/` is git-ignored. These are DEMONSTRATION keys generated on a development
machine, not production key material -- see keys/README.md and docs/SECURITY.md
for what a real deployment would do instead.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sotalib import ascon  # noqa: E402

KEYS = ROOT / "keys"
PRIV = KEYS / "ed25519_private.pem"
PUB = KEYS / "ed25519_public.pem"
ENC = KEYS / "ota_enc_key.hex"
DEVICE_CONFIG = ROOT / "main" / "crypto_config.h"


def c_byte_array(data: bytes, per_line: int = 8, indent: str = "    ") -> str:
    lines = []
    for off in range(0, len(data), per_line):
        chunk = data[off:off + per_line]
        lines.append(indent + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    return "\n".join(lines)


def write_device_config(public_key: bytes, enc_key: bytes) -> None:
    body = f'''/*
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
static const uint8_t OTA_TRUSTED_ED25519_PUBLIC_KEY[32] = {{
{c_byte_array(public_key)}
}};

/* Ascon-AEAD128 key, 16 bytes. Demonstration provisioning secret. */
static const uint8_t OTA_DEFAULT_ENCRYPTION_KEY[16] = {{
{c_byte_array(enc_key)}
}};

#endif /* CRYPTO_CONFIG_H_ */
'''
    DEVICE_CONFIG.write_text(body, encoding="utf-8")
    print(f"  wrote {DEVICE_CONFIG.relative_to(ROOT)}  (git-ignored)")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true",
                    help="overwrite keys that already exist")
    ap.add_argument("--write-device-config", action="store_true",
                    help="also generate main/crypto_config.h for the firmware")
    args = ap.parse_args()

    KEYS.mkdir(parents=True, exist_ok=True)

    existing = [p for p in (PRIV, PUB, ENC) if p.exists()]
    if existing and not args.force:
        print("Keys already exist:")
        for p in existing:
            print(f"  {p.relative_to(ROOT)}")
        print("\nRefusing to overwrite. Re-run with --force if that is really "
              "what you want.")
        print("Overwriting the signing key makes every existing package "
              "unverifiable by devices that already trust the old public key.")
        if args.write_device_config and PRIV.exists() and ENC.exists():
            print("\nRegenerating the device config from the existing keys:")
            pub_raw = serialization.load_pem_public_key(PUB.read_bytes())
            write_device_config(
                pub_raw.public_bytes(serialization.Encoding.Raw,
                                     serialization.PublicFormat.Raw),
                bytes.fromhex(ENC.read_text().split("#")[0].strip()))
            return 0
        return 1

    # ---- Ed25519 signing key pair -------------------------------------------
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    PRIV.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    PUB.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # Best-effort permission tightening. No-op on Windows, which is why the
    # real protection is that keys/ is git-ignored.
    try:
        os.chmod(PRIV, 0o600)
    except OSError:
        pass

    pub_raw = public_key.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)

    # ---- Ascon-AEAD128 symmetric key ----------------------------------------
    enc_key = os.urandom(ascon.ASCON_KEY_BYTES)
    ENC.write_text(
        "# Ascon-AEAD128 OTA encryption key, 128 bits, hex.\n"
        "# Shared secret: the packaging tool encrypts with it, the device\n"
        "# decrypts with it. DEMONSTRATION KEY -- do not reuse in production.\n"
        f"{enc_key.hex()}\n", encoding="utf-8")
    try:
        os.chmod(ENC, 0o600)
    except OSError:
        pass

    print("Generated development keys in keys/\n")
    print(f"  ed25519_private.pem   Ed25519 private key   SIGNING HOST ONLY")
    print(f"  ed25519_public.pem    Ed25519 public key    embed in firmware")
    print(f"    raw public key      {pub_raw.hex()}")
    print(f"  ota_enc_key.hex       Ascon-AEAD128 key     host + device")
    print(f"    fingerprint         {ascon.hash256(enc_key).hex()[:16]}...  "
          f"(hash of the key, not the key)")

    if args.write_device_config:
        print()
        write_device_config(pub_raw, enc_key)
    else:
        print("\nNext: generate the firmware's trust anchors with")
        print("  python tools/generate_keys.py --write-device-config")
        print("or copy main/crypto_config.h.example to main/crypto_config.h and "
              "paste the values in by hand.")

    print("\nkeys/ is git-ignored. Never commit ed25519_private.pem or "
          "ota_enc_key.hex.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
