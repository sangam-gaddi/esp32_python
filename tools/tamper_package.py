#!/usr/bin/env python3
"""Produce deliberately bad OTA packages, to prove the device rejects them.

A security claim you have not tried to break is a guess. This tool builds the
attack packages used by the demonstration and by tests/test_negative.py.

    python tools/tamper_package.py --mode flip-ciphertext \
        --input server/packages/firmware_v2.0.0.sota \
        --output server/packages/attack_flip.sota

Modes, and the check each one is designed to trip:

    flip-ciphertext   flip one payload byte          -> Ascon tag fails
    flip-metadata     flip one header byte           -> Ed25519 fails
    bad-signature     randomise the signature        -> Ed25519 fails
    foreign-signer    re-sign with an attacker key   -> Ed25519 fails
    wrong-key         re-encrypt under another key   -> Ascon tag fails
    hash-mismatch     validly sign a wrong digest    -> Ascon-Hash256 fails
    rollback          validly sign an older version  -> anti-rollback fires
    truncate          cut bytes off the end          -> structural / truncated
    bad-magic         corrupt the magic bytes        -> not a .sota package

`wrong-key`, `hash-mismatch` and `rollback` are *correctly signed* with the real
private key. They are not transport attacks -- they model a mistaken or
compromised build server -- and they are the only way to exercise the tag, hash
and rollback checks in isolation, because a plain byte flip trips the earlier
check first.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from sotalib import ascon, package  # noqa: E402

DEFAULT_KEYS = ROOT / "keys"

MODES = ("flip-ciphertext", "flip-metadata", "bad-signature", "foreign-signer",
         "wrong-key", "hash-mismatch", "rollback", "truncate", "bad-magic")

EXPECTED = {
    "flip-ciphertext": "Ascon-AEAD128 tag verification failure",
    "flip-metadata": "Ed25519 signature verification failure",
    "bad-signature": "Ed25519 signature verification failure",
    "foreign-signer": "Ed25519 signature verification failure",
    "wrong-key": "Ascon-AEAD128 tag verification failure",
    "hash-mismatch": "Ascon-Hash256 mismatch",
    "rollback": "anti-rollback rejection",
    "truncate": "structural / truncated-package rejection",
    "bad-magic": "bad magic, not a .sota package",
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", required=True, choices=MODES)
    ap.add_argument("--input", required=True, type=pathlib.Path,
                    help="a valid .sota package to corrupt")
    ap.add_argument("--output", required=True, type=pathlib.Path)
    ap.add_argument("--offset", type=int, default=None,
                    help="byte offset to corrupt (default: middle of the "
                         "relevant region)")
    ap.add_argument("--security-version", type=int, default=1,
                    help="rollback mode: the older security version to claim "
                         "(default 1)")
    ap.add_argument("--version", default=None,
                    help="rollback mode: firmware version string to claim "
                         "(default: keep the original)")
    ap.add_argument("--truncate-bytes", type=int, default=64,
                    help="truncate mode: how many bytes to remove (default 64)")
    ap.add_argument("--signing-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ed25519_private.pem")
    ap.add_argument("--enc-key", type=pathlib.Path,
                    default=DEFAULT_KEYS / "ota_enc_key.hex")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"error: input package not found: {args.input}", file=sys.stderr)
        return 2

    blob = bytearray(args.input.read_bytes())
    mode = args.mode
    note = ""

    needs_rebuild = mode in ("wrong-key", "hash-mismatch", "rollback")
    if needs_rebuild:
        for path, what in ((args.signing_key, "signing key"),
                           (args.enc_key, "encryption key")):
            if not path.exists():
                print(f"error: {what} not found: {path} (mode {mode} needs it)",
                      file=sys.stderr)
                return 2
        signing_key = package.load_private_key(args.signing_key)
        enc_key = package.load_enc_key(args.enc_key)
        header, firmware = package.verify_package(
            bytes(blob), enc_key, signing_key.public_key())

    # ---------------------------------------------------------------- byte flips
    if mode == "flip-ciphertext":
        if len(blob) <= package.HEADER_SIZE:
            print("error: package has no payload to corrupt", file=sys.stderr)
            return 2
        off = args.offset
        if off is None:
            off = package.HEADER_SIZE + (len(blob) - package.HEADER_SIZE) // 2
        if not package.HEADER_SIZE <= off < len(blob):
            print(f"error: offset {off} is not inside the ciphertext "
                  f"[{package.HEADER_SIZE}, {len(blob)})", file=sys.stderr)
            return 2
        blob[off] ^= 0x01
        note = f"flipped bit 0 of ciphertext byte {off}"

    elif mode == "flip-metadata":
        # Default to the security_version field: a meaningful, targeted change.
        off = args.offset if args.offset is not None else 12
        if not 0 <= off < package.AD_LEN:
            print(f"error: offset {off} is not inside the metadata "
                  f"[0, {package.AD_LEN})", file=sys.stderr)
            return 2
        blob[off] ^= 0x01
        note = f"flipped bit 0 of header byte {off} (inside the signed region)"

    elif mode == "bad-signature":
        blob[96:160] = os.urandom(64)
        note = "replaced the 64-byte signature with random bytes"

    elif mode == "bad-magic":
        blob[0:4] = b"XXXX"
        note = 'magic replaced with "XXXX"'

    elif mode == "truncate":
        n = args.truncate_bytes
        if n <= 0 or n >= len(blob):
            print(f"error: --truncate-bytes must be in 1..{len(blob) - 1}",
                  file=sys.stderr)
            return 2
        note = f"removed the last {n} bytes ({len(blob)} -> {len(blob) - n})"
        blob = blob[:-n]

    # ------------------------------------------------------- re-signed attacks
    elif mode == "foreign-signer":
        # An attacker with their own key pair, signing a package the device has
        # never been told to trust.
        attacker = Ed25519PrivateKey.generate()
        hdr = package.PackageHeader.unpack(bytes(blob))
        hdr.signature = attacker.sign(hdr.signed_region())
        blob = bytearray(hdr.pack() + bytes(blob[package.HEADER_SIZE:]))
        note = "re-signed with a freshly generated attacker key"

    elif mode == "wrong-key":
        # Same firmware, encrypted under a different symmetric key, then signed
        # correctly. The device's key cannot authenticate it.
        other = os.urandom(ascon.ASCON_KEY_BYTES)
        blob = bytearray(package.build_package(
            firmware=firmware,
            firmware_version=header.firmware_version,
            security_version=header.security_version,
            enc_key=other,
            signing_key=signing_key,
            build_timestamp=header.build_timestamp))
        note = ("re-encrypted under a different 128-bit Ascon key "
                f"(fingerprint {ascon.hash256(other).hex()[:16]}) and correctly "
                "re-signed")

    elif mode == "hash-mismatch":
        # Correctly signed and correctly encrypted, but the signed digest does
        # not describe the firmware. Isolates the Ascon-Hash256 check.
        real_hash = ascon.hash256(firmware)
        wrong_hash = bytearray(real_hash)
        wrong_hash[0] ^= 0x01
        nonce = os.urandom(ascon.ASCON_NONCE_BYTES)
        hdr = package.PackageHeader(
            firmware_version=header.firmware_version,
            security_version=header.security_version,
            firmware_size=len(firmware),
            ciphertext_size=len(firmware),
            build_timestamp=header.build_timestamp,
            nonce=nonce,
            firmware_hash=bytes(wrong_hash),
            auth_tag=bytes(16),
            signature=bytes(64),
        )
        ct, tag = ascon.aead128_encrypt(enc_key, nonce, firmware,
                                        hdr.associated_data())
        hdr.auth_tag = tag
        hdr.signature = signing_key.sign(hdr.signed_region())
        blob = bytearray(hdr.pack() + ct)
        note = (f"signed digest {bytes(wrong_hash).hex()[:16]}... does not match "
                f"the real digest {real_hash.hex()[:16]}...")

    elif mode == "rollback":
        fw_version = (package.encode_version(args.version)
                      if args.version else header.firmware_version)
        blob = bytearray(package.build_package(
            firmware=firmware,
            firmware_version=fw_version,
            security_version=args.security_version,
            enc_key=enc_key,
            signing_key=signing_key,
            build_timestamp=header.build_timestamp))
        note = (f"valid package claiming security_version="
                f"{args.security_version}, firmware_version="
                f"{package.decode_version(fw_version)}")

    else:  # pragma: no cover - argparse restricts the choices
        print(f"error: unhandled mode {mode}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bytes(blob))

    print(f"Tampered package written: {args.output}  ({len(blob)} bytes)")
    print(f"  mode      : {mode}")
    print(f"  change    : {note}")
    print(f"  expect    : device rejects with {EXPECTED[mode]}")
    print(f"\nConfirm with:\n  python tools/verify_package.py {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
