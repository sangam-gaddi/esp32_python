#!/usr/bin/env python3
"""Build a signed, encrypted `.sota` OTA package from an ESP32 firmware image.

    python tools/create_ota_package.py \
        --firmware build/secure_ota.bin \
        --version 2.0.0 \
        --security-version 2 \
        --output server/packages/firmware_v2.0.0.sota

Order of operations (the device reverses exactly this):

    firmware.bin
       |
       +-- Ascon-Hash256 ------> 32-byte digest of the PLAINTEXT
       |
       +-- Ascon-AEAD128 ------> ciphertext + 16-byte tag, fresh random nonce,
       |                          associated data = header[0:80]
       |
       +-- Ed25519 sign -------> 64-byte signature over header[0:96]
       |
       v
    firmware_vX.sota

The encryption key is *not* placed in the package -- the device already has it.
Only the nonce, which is not secret, travels with the ciphertext.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sotalib import ascon, package  # noqa: E402

DEFAULT_KEYS = ROOT / "keys"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--firmware", required=True, type=pathlib.Path,
                    help="plaintext ESP32 application image (.bin)")
    ap.add_argument("--version", required=True,
                    help="firmware version, major.minor.patch (e.g. 2.0.0)")
    ap.add_argument("--security-version", required=True, type=int,
                    help="monotonic security version; the device rejects "
                         "anything lower than it has already accepted")
    ap.add_argument("--output", required=True, type=pathlib.Path,
                    help="path of the .sota package to write")
    ap.add_argument("--signing-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ed25519_private.pem",
                    help="Ed25519 private key PEM (default: keys/)")
    ap.add_argument("--enc-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ota_enc_key.hex",
                    help="Ascon-AEAD128 key, hex (default: keys/)")
    ap.add_argument("--timestamp", type=int, default=None,
                    help="override the build timestamp (unix seconds); "
                         "use for reproducible output in tests")
    ap.add_argument("--nonce", default=None,
                    help="override the nonce with 32 hex chars. FOR TESTING "
                         "ONLY -- reusing a nonce under the same key breaks "
                         "both confidentiality and authenticity")
    args = ap.parse_args()

    for path, what in ((args.firmware, "firmware image"),
                       (args.signing_key, "signing key"),
                       (args.enc_key, "encryption key")):
        if not path.exists():
            print(f"error: {what} not found: {path}", file=sys.stderr)
            if path in (args.signing_key, args.enc_key):
                print("       run: python tools/generate_keys.py",
                      file=sys.stderr)
            return 1

    try:
        firmware_version = package.encode_version(args.version)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.security_version < 0:
        print("error: --security-version must be >= 0", file=sys.stderr)
        return 1

    firmware = args.firmware.read_bytes()
    signing_key = package.load_private_key(args.signing_key)
    enc_key = package.load_enc_key(args.enc_key)

    nonce = None
    if args.nonce is not None:
        nonce = bytes.fromhex(args.nonce)
        if len(nonce) != ascon.ASCON_NONCE_BYTES:
            print(f"error: --nonce must be {ascon.ASCON_NONCE_BYTES * 2} hex "
                  f"characters", file=sys.stderr)
            return 1
        print("WARNING: using a caller-supplied nonce. Never do this for two "
              "different images under the same key.", file=sys.stderr)

    try:
        blob = package.build_package(
            firmware=firmware,
            firmware_version=firmware_version,
            security_version=args.security_version,
            enc_key=enc_key,
            signing_key=signing_key,
            nonce=nonce,
            build_timestamp=args.timestamp,
        )
    except (ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)

    header, _ = package.parse_package(blob)

    print("OTA package created\n")
    print(f"  firmware          : {args.firmware}")
    print(f"  firmware version  : {args.version} (0x{firmware_version:06X})")
    print(f"  security version  : {args.security_version}")
    print(f"  firmware size     : {len(firmware)} bytes")
    print(f"  Ascon-Hash256     : {header.firmware_hash.hex()}")
    print(f"  Ascon nonce       : {header.nonce.hex()}")
    print(f"  Ascon tag         : {header.auth_tag.hex()}")
    print(f"  Ed25519 signature : {header.signature.hex()[:32]}..."
          f"{header.signature.hex()[-16:]}")
    print(f"  build timestamp   : {header.build_timestamp} "
          f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(header.build_timestamp))})")
    print(f"  package           : {args.output} "
          f"({len(blob)} bytes = {package.HEADER_SIZE} header + "
          f"{len(firmware)} ciphertext)")

    # Self-check: verify what we just wrote, the same way the device will.
    try:
        package.verify_package(blob, enc_key,
                               signing_key.public_key())
        print("\n  self-verification : PASS "
              "(signature, Ascon tag and Ascon-Hash256 all check out)")
    except package.PackageError as exc:
        print(f"\n  self-verification : FAIL -- {exc}", file=sys.stderr)
        print("  The package was written but is not valid. This is a bug.",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
