#!/usr/bin/env python3
"""Inspect and verify a `.sota` OTA package, the same way the device does.

    python tools/verify_package.py server/packages/firmware_v2.0.0.sota

Runs the identical check sequence as the ESP32 and reports each stage, so a
rejection can be attributed to a specific cause rather than "it didn't work":

    1. structure       magic, format version, declared sizes, total length
    2. Ed25519         signature over header[0:96] under the trusted public key
    3. Ascon-AEAD128   tag verification (also proves the key is right)
    4. Ascon-Hash256   digest of the decrypted firmware vs the signed digest
    5. version         optional anti-rollback check against --current-*

Exit status is 0 only if every stage requested passes.
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

PASS = "PASS"
FAIL = "FAIL"


def stage(n: int, name: str, ok: bool, detail: str = "") -> None:
    mark = PASS if ok else FAIL
    print(f"  [{n}] {name:<28} {mark}" + (f"  {detail}" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package", type=pathlib.Path, help="the .sota file")
    ap.add_argument("--public-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ed25519_public.pem",
                    help="trusted Ed25519 public key PEM (default: keys/)")
    ap.add_argument("--enc-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ota_enc_key.hex",
                    help="Ascon-AEAD128 key, hex (default: keys/)")
    ap.add_argument("--current-version", default=None,
                    help="device's installed firmware version, e.g. 1.0.0; "
                         "enables the freshness check")
    ap.add_argument("--current-security-version", type=int, default=None,
                    help="device's accepted security version; enables the "
                         "anti-rollback check")
    ap.add_argument("--extract", type=pathlib.Path, default=None,
                    help="write the decrypted firmware here (only if all "
                         "cryptographic checks pass)")
    ap.add_argument("--header-only", action="store_true",
                    help="parse and print the header, skip cryptography")
    args = ap.parse_args()

    if not args.package.exists():
        print(f"error: package not found: {args.package}", file=sys.stderr)
        return 2

    blob = args.package.read_bytes()
    print(f"Package: {args.package}  ({len(blob)} bytes)\n")

    # ---- 1. structure -------------------------------------------------------
    try:
        header, ciphertext = package.parse_package(blob)
    except package.PackageFormatError as exc:
        stage(1, "structure", False, str(exc))
        print("\nRESULT: REJECTED (malformed package)")
        return 1
    stage(1, "structure", True,
          f"format v{header.format_version}, header {package.HEADER_SIZE} B, "
          f"payload {len(ciphertext)} B")

    print()
    print("  " + header.describe().replace("\n", "\n  "))
    print()

    if args.header_only:
        print("RESULT: header parsed (cryptography skipped, --header-only)")
        return 0

    for path, what in ((args.public_key, "public key"),
                       (args.enc_key, "encryption key")):
        if not path.exists():
            print(f"error: {what} not found: {path}", file=sys.stderr)
            print("       run: python tools/generate_keys.py", file=sys.stderr)
            return 2

    public_key = package.load_public_key(args.public_key)
    enc_key = package.load_enc_key(args.enc_key)

    # ---- 2. Ed25519 ---------------------------------------------------------
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(header.signature, header.signed_region())
        stage(2, "Ed25519 signature", True, "signed header[0:96] is authentic")
    except InvalidSignature:
        stage(2, "Ed25519 signature", False,
              "not signed by the trusted key, or the header was altered")
        print("\nRESULT: REJECTED (INVALID SIGNATURE)")
        return 1

    # ---- 3. Ascon-AEAD128 ---------------------------------------------------
    try:
        firmware = ascon.aead128_decrypt(
            enc_key, header.nonce, ciphertext, header.auth_tag,
            header.associated_data())
        stage(3, "Ascon-AEAD128 tag", True,
              f"decrypted {len(firmware)} bytes")
    except ascon.AsconTagError:
        stage(3, "Ascon-AEAD128 tag", False,
              "wrong encryption key, or the ciphertext was modified")
        print("\nRESULT: REJECTED (ASCON AUTHENTICATION FAILED)")
        return 1

    # ---- 4. Ascon-Hash256 ---------------------------------------------------
    computed = ascon.hash256(firmware)
    if computed != header.firmware_hash:
        stage(4, "Ascon-Hash256", False, f"computed {computed.hex()}")
        print("\nRESULT: REJECTED (HASH MISMATCH)")
        return 1
    stage(4, "Ascon-Hash256", True, "matches the signed digest")

    # ---- 5. versions --------------------------------------------------------
    if args.current_version is not None or args.current_security_version is not None:
        ok = True
        details = []
        if args.current_security_version is not None:
            if header.security_version < args.current_security_version:
                ok = False
                details.append(
                    f"security {header.security_version} < "
                    f"{args.current_security_version}: ROLLBACK")
            else:
                details.append(
                    f"security {header.security_version} >= "
                    f"{args.current_security_version}")
        if args.current_version is not None:
            cur = package.encode_version(args.current_version)
            if header.firmware_version <= cur:
                ok = False
                details.append(
                    f"firmware {package.decode_version(header.firmware_version)}"
                    f" <= {args.current_version}: not an upgrade")
            else:
                details.append(
                    f"firmware {package.decode_version(header.firmware_version)}"
                    f" > {args.current_version}")
        stage(5, "version / anti-rollback", ok, "; ".join(details))
        if not ok:
            print("\nRESULT: REJECTED (version check failed)")
            return 1

    if args.extract:
        args.extract.parent.mkdir(parents=True, exist_ok=True)
        args.extract.write_bytes(firmware)
        print(f"\n  extracted plaintext firmware -> {args.extract} "
              f"({len(firmware)} bytes)")

    print("\nRESULT: ACCEPTED -- this package would install on the device")
    return 0


if __name__ == "__main__":
    sys.exit(main())
