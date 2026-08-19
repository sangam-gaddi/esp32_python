"""The `.sota` OTA package format -- build, parse and verify.

This module is the single authority for the wire format on the host side. The
device-side parser in ``components/ota_package`` implements the identical layout,
and ``tests/host/test_package_parser.c`` runs the C parser against packages built
by this module to prove the two agree.

Layout (all integers little-endian, all offsets and sizes fixed):

    off  size  field
      0     4  magic              "SOTA"
      4     2  format_version     = 1
      6     2  header_size        = 160
      8     4  firmware_version   major<<16 | minor<<8 | patch
     12     4  security_version   monotonic counter
     16     4  firmware_size      plaintext length, bytes
     20     4  ciphertext_size    == firmware_size for Ascon-AEAD128
     24     8  build_timestamp    unix seconds, informational
     32    16  nonce              Ascon-AEAD128 nonce, fresh per package
     48    32  firmware_hash      Ascon-Hash256 of the *plaintext* firmware
    ------------ bytes 0..80 are the AEAD associated data ------------
     80    16  auth_tag           Ascon-AEAD128 tag
    ------------ bytes 0..96 are the Ed25519-signed region -----------
     96    64  signature          Ed25519 over header[0:96]
    160     N  ciphertext         firmware_size bytes

Two boundaries matter, and they are the whole design:

* **Associated data = header[0:80].** Everything descriptive is bound into the
  AEAD tag, so a ciphertext cannot be lifted out of one package and replayed
  inside another with different versions or a different declared hash. It stops
  at 80 because the tag itself lives at offset 80 and cannot authenticate itself.

* **Signed region = header[0:96].** The signature covers the associated data
  *and* the tag. This is what makes Ed25519 the root of trust rather than the
  shared symmetric key: someone who steals the encryption key can forge a
  ciphertext and a matching tag, but the tag they produce differs from the signed
  one, so the signature fails. Nothing outside these 96 bytes influences a
  security decision, and the device verifies exactly the bytes that were signed
  -- no re-serialisation in between.

The encryption key is *never* part of the package. See docs/SECURITY.md.
"""

from __future__ import annotations

import hmac
import os
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from . import ascon

__all__ = [
    "MAGIC",
    "FORMAT_VERSION",
    "HEADER_SIZE",
    "AD_LEN",
    "SIGNED_LEN",
    "MAX_FIRMWARE_SIZE",
    "PackageError",
    "PackageFormatError",
    "SignatureError",
    "TagError",
    "HashMismatchError",
    "PackageHeader",
    "build_package",
    "parse_package",
    "verify_package",
    "encode_version",
    "decode_version",
]

MAGIC = b"SOTA"
FORMAT_VERSION = 1
HEADER_SIZE = 160
AD_LEN = 80      # associated data: header[0:80]
SIGNED_LEN = 96  # Ed25519-signed region: header[0:96]

# Sanity bound so a corrupt length field cannot ask the device for a
# multi-gigabyte download. Comfortably larger than any ESP32 app partition.
MAX_FIRMWARE_SIZE = 8 * 1024 * 1024

_HEADER_STRUCT = struct.Struct("<4sHHIIIIQ16s32s16s64s")
assert _HEADER_STRUCT.size == HEADER_SIZE, _HEADER_STRUCT.size


# --------------------------------------------------------------------------- errors

class PackageError(Exception):
    """Base class: any reason to reject a package."""


class PackageFormatError(PackageError):
    """Malformed, truncated, or an unsupported format version."""


class SignatureError(PackageError):
    """Ed25519 signature did not verify against the trusted public key."""


class TagError(PackageError):
    """Ascon-AEAD128 tag did not verify: wrong key, or altered ciphertext."""


class HashMismatchError(PackageError):
    """Decrypted firmware does not match the signed Ascon-Hash256 digest."""


# -------------------------------------------------------------------------- versions

def encode_version(text: str) -> int:
    """"2.1.3" -> 0x00020103. Each component must be 0..255."""
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"version must be major.minor.patch, got {text!r}")
    try:
        major, minor, patch = (int(p) for p in parts)
    except ValueError:
        raise ValueError(f"version components must be integers, got {text!r}") from None
    for name, v in (("major", major), ("minor", minor), ("patch", patch)):
        if not 0 <= v <= 255:
            raise ValueError(f"{name} must be 0..255, got {v}")
    return (major << 16) | (minor << 8) | patch


def decode_version(code: int) -> str:
    """0x00020103 -> "2.1.3"."""
    return f"{(code >> 16) & 0xFF}.{(code >> 8) & 0xFF}.{code & 0xFF}"


# ---------------------------------------------------------------------------- header

@dataclass
class PackageHeader:
    firmware_version: int
    security_version: int
    firmware_size: int
    ciphertext_size: int
    build_timestamp: int
    nonce: bytes
    firmware_hash: bytes
    auth_tag: bytes
    signature: bytes
    format_version: int = FORMAT_VERSION

    def pack(self) -> bytes:
        return _HEADER_STRUCT.pack(
            MAGIC,
            self.format_version,
            HEADER_SIZE,
            self.firmware_version,
            self.security_version,
            self.firmware_size,
            self.ciphertext_size,
            self.build_timestamp,
            self.nonce,
            self.firmware_hash,
            self.auth_tag,
            self.signature,
        )

    @classmethod
    def unpack(cls, blob: bytes) -> "PackageHeader":
        if len(blob) < HEADER_SIZE:
            raise PackageFormatError(
                f"header truncated: {len(blob)} bytes, need {HEADER_SIZE}")
        (magic, format_version, header_size, firmware_version, security_version,
         firmware_size, ciphertext_size, build_timestamp, nonce, firmware_hash,
         auth_tag, signature) = _HEADER_STRUCT.unpack(blob[:HEADER_SIZE])

        if magic != MAGIC:
            raise PackageFormatError(
                f"bad magic {magic!r}, expected {MAGIC!r} -- not a .sota package")
        if format_version != FORMAT_VERSION:
            raise PackageFormatError(
                f"unsupported format_version {format_version}, "
                f"this build understands {FORMAT_VERSION}")
        if header_size != HEADER_SIZE:
            raise PackageFormatError(
                f"header_size {header_size} != {HEADER_SIZE}")

        return cls(
            firmware_version=firmware_version,
            security_version=security_version,
            firmware_size=firmware_size,
            ciphertext_size=ciphertext_size,
            build_timestamp=build_timestamp,
            nonce=nonce,
            firmware_hash=firmware_hash,
            auth_tag=auth_tag,
            signature=signature,
            format_version=format_version,
        )

    # The two authenticated spans. Both are prefixes of the packed header, which
    # is exactly why the device can verify without re-serialising anything.
    def associated_data(self) -> bytes:
        return self.pack()[:AD_LEN]

    def signed_region(self) -> bytes:
        return self.pack()[:SIGNED_LEN]

    def describe(self) -> str:
        return (
            f"format_version   : {self.format_version}\n"
            f"firmware_version : {decode_version(self.firmware_version)} "
            f"(0x{self.firmware_version:06X})\n"
            f"security_version : {self.security_version}\n"
            f"firmware_size    : {self.firmware_size} bytes\n"
            f"ciphertext_size  : {self.ciphertext_size} bytes\n"
            f"build_timestamp  : {self.build_timestamp} "
            f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(self.build_timestamp))})\n"
            f"nonce            : {self.nonce.hex()}\n"
            f"firmware_hash    : {self.firmware_hash.hex()}\n"
            f"auth_tag         : {self.auth_tag.hex()}\n"
            f"signature        : {self.signature.hex()}"
        )


# ----------------------------------------------------------------------------- build

def build_package(firmware: bytes, firmware_version: int, security_version: int,
                  enc_key: bytes, signing_key: Ed25519PrivateKey,
                  nonce: bytes | None = None,
                  build_timestamp: int | None = None) -> bytes:
    """Produce a complete `.sota` package.

    Order of operations, which is the order the device reverses:

        1. Ascon-Hash256 over the *plaintext* firmware
        2. Ascon-AEAD128 encrypt under a fresh nonce, associated data = header[0:80]
        3. Ed25519-sign header[0:96] (the associated data plus the AEAD tag)

    Hashing the plaintext, not the ciphertext, is deliberate: the signature then
    attests to what will actually execute, independently of the transport
    encryption.
    """
    if not firmware:
        raise ValueError("firmware image is empty")
    if len(firmware) > MAX_FIRMWARE_SIZE:
        raise ValueError(
            f"firmware is {len(firmware)} bytes, limit is {MAX_FIRMWARE_SIZE}")
    if len(enc_key) != ascon.ASCON_KEY_BYTES:
        raise ValueError(f"encryption key must be {ascon.ASCON_KEY_BYTES} bytes")
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise TypeError("signing_key must be an Ed25519PrivateKey")
    if security_version < 0 or security_version > 0xFFFFFFFF:
        raise ValueError("security_version must fit in 32 bits")

    if nonce is None:
        # Fresh randomness per package. Reusing a nonce under the same key would
        # leak the XOR of two firmware images and break authenticity outright.
        nonce = os.urandom(ascon.ASCON_NONCE_BYTES)
    elif len(nonce) != ascon.ASCON_NONCE_BYTES:
        raise ValueError(f"nonce must be {ascon.ASCON_NONCE_BYTES} bytes")

    if build_timestamp is None:
        build_timestamp = int(time.time())

    firmware_hash = ascon.hash256(firmware)

    # Build the header with placeholder tag and signature so the associated data
    # -- header[0:80], which contains neither -- is already final.
    header = PackageHeader(
        firmware_version=firmware_version,
        security_version=security_version,
        firmware_size=len(firmware),
        ciphertext_size=len(firmware),
        build_timestamp=build_timestamp,
        nonce=nonce,
        firmware_hash=firmware_hash,
        auth_tag=bytes(16),
        signature=bytes(64),
    )

    ciphertext, tag = ascon.aead128_encrypt(
        enc_key, nonce, firmware, header.associated_data())
    header.auth_tag = tag

    header.signature = signing_key.sign(header.signed_region())

    return header.pack() + ciphertext


# ----------------------------------------------------------------------------- parse

def parse_package(blob: bytes) -> tuple[PackageHeader, bytes]:
    """Structural parse only -- no cryptography. Returns (header, ciphertext).

    Raises PackageFormatError for anything malformed. Nothing this function
    returns has been authenticated yet.
    """
    header = PackageHeader.unpack(blob)

    if header.firmware_size == 0:
        raise PackageFormatError("firmware_size is 0")
    if header.firmware_size > MAX_FIRMWARE_SIZE:
        raise PackageFormatError(
            f"firmware_size {header.firmware_size} exceeds the "
            f"{MAX_FIRMWARE_SIZE}-byte limit")
    if header.ciphertext_size != header.firmware_size:
        raise PackageFormatError(
            f"ciphertext_size {header.ciphertext_size} != firmware_size "
            f"{header.firmware_size} (Ascon-AEAD128 is length-preserving)")

    expected = HEADER_SIZE + header.firmware_size
    if len(blob) != expected:
        raise PackageFormatError(
            f"package is {len(blob)} bytes, header declares {expected} "
            f"({'truncated' if len(blob) < expected else 'trailing garbage'})")

    return header, blob[HEADER_SIZE:]


def verify_package(blob: bytes, enc_key: bytes,
                   public_key: Ed25519PublicKey | bytes) -> tuple[PackageHeader, bytes]:
    """Full verification, in the same order the device uses.

    Returns (header, plaintext firmware). Raises a PackageError subclass on the
    first check that fails:

        PackageFormatError  structure, magic, sizes
        SignatureError      Ed25519 over header[0:96]
        TagError            Ascon-AEAD128 tag
        HashMismatchError   Ascon-Hash256 of the decrypted firmware

    The signature is checked *before* decryption, exactly as the device does it:
    the header arrives first, so an unauthorised package can be rejected before
    a single byte of payload is downloaded.
    """
    if isinstance(public_key, (bytes, bytearray)):
        public_key = Ed25519PublicKey.from_public_bytes(bytes(public_key))

    header, ciphertext = parse_package(blob)

    try:
        public_key.verify(header.signature, header.signed_region())
    except InvalidSignature:
        raise SignatureError(
            "Ed25519 signature is not valid for this header under the trusted "
            "public key") from None

    try:
        firmware = ascon.aead128_decrypt(
            enc_key, header.nonce, ciphertext, header.auth_tag,
            header.associated_data())
    except ascon.AsconTagError:
        raise TagError(
            "Ascon-AEAD128 tag verification failed: wrong encryption key, or "
            "the ciphertext/metadata was altered") from None

    computed = ascon.hash256(firmware)
    if not hmac.compare_digest(computed, header.firmware_hash):
        raise HashMismatchError(
            f"Ascon-Hash256 mismatch: computed {computed.hex()}, "
            f"header says {header.firmware_hash.hex()}")

    return header, firmware


# --------------------------------------------------------------------- key file I/O

def load_private_key(path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(open(path, "rb").read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(open(path, "rb").read())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def load_enc_key(path) -> bytes:
    """Read the 128-bit Ascon key from a hex file, ignoring comments."""
    text = "".join(line.split("#", 1)[0].strip()
                   for line in open(path, "r", encoding="utf-8"))
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"{path} does not contain valid hex") from None
    if len(key) != ascon.ASCON_KEY_BYTES:
        raise ValueError(
            f"{path} holds {len(key)} bytes, need {ascon.ASCON_KEY_BYTES}")
    return key
