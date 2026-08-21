#!/usr/bin/env python3
"""Generate package fixtures for the C host test.

Writes a directory of `.sota` packages -- one valid, the rest broken in a
specific way -- plus a manifest naming the exact `ota_pkg_err_t` the C parser
must return for each. `tests/host/test_package_parser.c` then runs the real
device-side parser over them.

This is the cross-validation step: the packages are built by the Python
implementation of Ascon, Ed25519 and the wire format, and verified by the
independent C implementation. If either side drifts, this test fails.

    python tests/host/make_fixtures.py [outdir]

Default outdir is build/host_fixtures/. Uses freshly generated ephemeral keys,
not the ones in keys/, so it neither needs nor touches the project's keys.
"""

from __future__ import annotations

import os
import pathlib
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sotalib import ascon, package  # noqa: E402

# Device state the C test will check the version rules against.
CURRENT_FW = package.encode_version("1.0.0")
CURRENT_SEC = 2

SKIP = "SKIP"  # version check is never reached because crypto already failed


def patch(blob: bytes, offset: int, data: bytes) -> bytes:
    b = bytearray(blob)
    b[offset:offset + len(data)] = data
    return bytes(b)


def main() -> int:
    outdir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "host_fixtures"
    outdir.mkdir(parents=True, exist_ok=True)

    # Ephemeral keys, so this fixture set is self-contained.
    signing_key = Ed25519PrivateKey.generate()
    pub_raw = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    enc_key = os.urandom(ascon.ASCON_KEY_BYTES)

    # A firmware image whose length is deliberately NOT a multiple of the
    # 16-byte AEAD rate or the 8-byte hash rate, so partial-block handling is
    # exercised on both.
    firmware = bytes((i * 37 + 11) & 0xFF for i in range(5003))

    (outdir / "enc_key.bin").write_bytes(enc_key)
    (outdir / "pubkey.bin").write_bytes(pub_raw)
    (outdir / "firmware.bin").write_bytes(firmware)

    good = package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("2.0.0"),
        security_version=2,
        enc_key=enc_key,
        signing_key=signing_key,
        build_timestamp=1700000000)

    cases: list[tuple[str, bytes, str, str]] = []

    # ---------------------------------------------------------------- accepted
    cases.append(("good.sota", good, "OTA_PKG_OK", "OTA_PKG_OK"))

    # firmware whose size IS an exact multiple of both rates (16 and 8)
    fw_aligned = bytes((i * 13) & 0xFF for i in range(4096))
    cases.append(("good_aligned.sota", package.build_package(
        firmware=fw_aligned,
        firmware_version=package.encode_version("2.0.1"),
        security_version=2,
        enc_key=enc_key, signing_key=signing_key,
        build_timestamp=1700000000), "OTA_PKG_OK", "OTA_PKG_OK"))

    # single-byte firmware: the smallest legal payload
    cases.append(("good_tiny.sota", package.build_package(
        firmware=b"\x5a",
        firmware_version=package.encode_version("2.0.2"),
        security_version=2,
        enc_key=enc_key, signing_key=signing_key,
        build_timestamp=1700000000), "OTA_PKG_OK", "OTA_PKG_OK"))

    # ------------------------------------------------------- version rejections
    cases.append(("rollback.sota", package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("2.0.0"),
        security_version=1,                      # below CURRENT_SEC
        enc_key=enc_key, signing_key=signing_key,
        build_timestamp=1700000000),
        "OTA_PKG_OK", "OTA_PKG_ERR_ROLLBACK"))

    cases.append(("not_newer.sota", package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("1.0.0"),  # == CURRENT_FW
        security_version=2,
        enc_key=enc_key, signing_key=signing_key,
        build_timestamp=1700000000),
        "OTA_PKG_OK", "OTA_PKG_ERR_NOT_NEWER"))

    # A downgrade that is also a security downgrade must report ROLLBACK, not
    # NOT_NEWER: the rollback check has to come first.
    cases.append(("rollback_and_older.sota", package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("0.9.0"),
        security_version=0,
        enc_key=enc_key, signing_key=signing_key,
        build_timestamp=1700000000),
        "OTA_PKG_OK", "OTA_PKG_ERR_ROLLBACK"))

    # ---------------------------------------------------- signature rejections
    cases.append(("bad_signature.sota",
                  patch(good, 96, os.urandom(64)),
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    # flip a bit in security_version (offset 12), inside the signed region
    cases.append(("flip_metadata.sota",
                  patch(good, 12, bytes([good[12] ^ 0x01])),
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    # flip a bit in the nonce (offset 32): still inside the signed region
    cases.append(("flip_nonce.sota",
                  patch(good, 32, bytes([good[32] ^ 0x80])),
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    # flip a bit in the declared hash (offset 48): signed, so signature fails
    cases.append(("flip_hash_field.sota",
                  patch(good, 48, bytes([good[48] ^ 0x01])),
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    # flip a bit in the tag (offset 80): also signed
    cases.append(("flip_tag.sota",
                  patch(good, 80, bytes([good[80] ^ 0x01])),
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    attacker = Ed25519PrivateKey.generate()
    hdr = package.PackageHeader.unpack(good)
    hdr.signature = attacker.sign(hdr.signed_region())
    cases.append(("foreign_signer.sota",
                  hdr.pack() + good[package.HEADER_SIZE:],
                  "OTA_PKG_ERR_SIGNATURE", SKIP))

    # ---------------------------------------------------------- tag rejections
    mid = package.HEADER_SIZE + len(firmware) // 2
    cases.append(("flip_ciphertext.sota",
                  patch(good, mid, bytes([good[mid] ^ 0x01])),
                  "OTA_PKG_ERR_TAG", SKIP))

    cases.append(("flip_ciphertext_first.sota",
                  patch(good, package.HEADER_SIZE,
                        bytes([good[package.HEADER_SIZE] ^ 0x01])),
                  "OTA_PKG_ERR_TAG", SKIP))

    cases.append(("flip_ciphertext_last.sota",
                  patch(good, len(good) - 1, bytes([good[-1] ^ 0x01])),
                  "OTA_PKG_ERR_TAG", SKIP))

    # correctly signed, encrypted under a key the device does not have
    cases.append(("wrong_key.sota", package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("2.0.0"),
        security_version=2,
        enc_key=os.urandom(ascon.ASCON_KEY_BYTES),
        signing_key=signing_key,
        build_timestamp=1700000000),
        "OTA_PKG_ERR_TAG", SKIP))

    # ---------------------------------------------------------- hash rejection
    # Correctly signed AND correctly encrypted, but the signed digest is wrong.
    # The only fixture that can reach the Ascon-Hash256 comparison.
    wrong_hash = bytearray(ascon.hash256(firmware))
    wrong_hash[31] ^= 0x01
    nonce = os.urandom(ascon.ASCON_NONCE_BYTES)
    h = package.PackageHeader(
        firmware_version=package.encode_version("2.0.0"),
        security_version=2,
        firmware_size=len(firmware),
        ciphertext_size=len(firmware),
        build_timestamp=1700000000,
        nonce=nonce,
        firmware_hash=bytes(wrong_hash),
        auth_tag=bytes(16),
        signature=bytes(64))
    ct, tag = ascon.aead128_encrypt(enc_key, nonce, firmware, h.associated_data())
    h.auth_tag = tag
    h.signature = signing_key.sign(h.signed_region())
    cases.append(("hash_mismatch.sota", h.pack() + ct,
                  "OTA_PKG_ERR_HASH", SKIP))

    # ------------------------------------------------------ structural rejects
    cases.append(("bad_magic.sota", patch(good, 0, b"XXXX"),
                  "OTA_PKG_ERR_MAGIC", SKIP))

    cases.append(("bad_format_version.sota",
                  patch(good, 4, struct.pack("<H", 99)),
                  "OTA_PKG_ERR_FORMAT_VERSION", SKIP))

    cases.append(("bad_header_size.sota",
                  patch(good, 6, struct.pack("<H", 128)),
                  "OTA_PKG_ERR_HEADER_SIZE", SKIP))

    cases.append(("zero_firmware_size.sota",
                  patch(good, 16, struct.pack("<I", 0)),
                  "OTA_PKG_ERR_SIZE_RANGE", SKIP))

    cases.append(("huge_firmware_size.sota",
                  patch(patch(good, 16, struct.pack("<I", 64 * 1024 * 1024)),
                        20, struct.pack("<I", 64 * 1024 * 1024)),
                  "OTA_PKG_ERR_SIZE_RANGE", SKIP))

    cases.append(("size_mismatch.sota",
                  patch(good, 20, struct.pack("<I", len(firmware) - 1)),
                  "OTA_PKG_ERR_SIZE_MISMATCH", SKIP))

    cases.append(("truncated_payload.sota", good[:-64],
                  "OTA_PKG_ERR_LENGTH", SKIP))

    cases.append(("trailing_garbage.sota", good + b"\xff" * 32,
                  "OTA_PKG_ERR_LENGTH", SKIP))

    cases.append(("short_header.sota", good[:100],
                  "OTA_PKG_ERR_TRUNCATED", SKIP))

    # ------------------------------------------------------------- write it out
    manifest = [
        "# fixtures for tests/host/test_package_parser.c",
        "# generated by tests/host/make_fixtures.py -- do not edit by hand",
        f"current_firmware_version {CURRENT_FW}",
        f"current_security_version {CURRENT_SEC}",
        f"firmware_size {len(firmware)}",
        "#",
        "# file  expected_crypto_result  expected_version_result",
    ]
    for name, blob, crypto_expect, version_expect in cases:
        (outdir / name).write_bytes(blob)
        manifest.append(f"{name} {crypto_expect} {version_expect}")

    (outdir / "manifest.txt").write_text("\n".join(manifest) + "\n",
                                         encoding="utf-8")

    print(f"wrote {len(cases)} fixtures to {outdir}")
    for name, blob, c, v in cases:
        print(f"  {name:<28} {len(blob):>7} bytes  {c}"
              + (f" / {v}" if v != SKIP else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
