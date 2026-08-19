"""Package format tests: layout, round-trip, and structural rejection.

These pin the wire format down. If any offset or size below changes, the C parser
in components/ota_package and this Python implementation would silently disagree,
so the numbers are asserted explicitly rather than derived from the code under
test.
"""

from __future__ import annotations

import os
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from sotalib import ascon, package  # noqa: E402


@pytest.fixture(scope="module")
def keys():
    return {
        "sign": Ed25519PrivateKey.generate(),
        "enc": os.urandom(ascon.ASCON_KEY_BYTES),
    }


@pytest.fixture
def firmware():
    # Length deliberately not a multiple of 16 (AEAD rate) or 8 (hash rate).
    return bytes((i * 31 + 7) & 0xFF for i in range(1234))


@pytest.fixture
def good(keys, firmware):
    return package.build_package(
        firmware=firmware,
        firmware_version=package.encode_version("2.1.0"),
        security_version=3,
        enc_key=keys["enc"],
        signing_key=keys["sign"],
        build_timestamp=1700000000)


# --------------------------------------------------------------- format constants

def test_format_constants_are_frozen():
    """The C implementation hard-codes these. They must not drift."""
    assert package.MAGIC == b"SOTA"
    assert package.FORMAT_VERSION == 1
    assert package.HEADER_SIZE == 160
    assert package.AD_LEN == 80
    assert package.SIGNED_LEN == 96


def test_field_offsets_match_the_specification(good):
    """Every field must sit at the documented offset, little-endian."""
    assert good[0:4] == b"SOTA"
    assert struct.unpack_from("<H", good, 4)[0] == 1          # format_version
    assert struct.unpack_from("<H", good, 6)[0] == 160        # header_size
    assert struct.unpack_from("<I", good, 8)[0] == 0x020100   # firmware_version
    assert struct.unpack_from("<I", good, 12)[0] == 3         # security_version
    assert struct.unpack_from("<I", good, 16)[0] == 1234      # firmware_size
    assert struct.unpack_from("<I", good, 20)[0] == 1234      # ciphertext_size
    assert struct.unpack_from("<Q", good, 24)[0] == 1700000000
    assert len(good[32:48]) == 16    # nonce
    assert len(good[48:80]) == 32    # firmware_hash
    assert len(good[80:96]) == 16    # auth_tag
    assert len(good[96:160]) == 64   # signature
    assert len(good) == 160 + 1234


def test_authenticated_spans_are_prefixes_of_the_header(good):
    """AD and the signed region must be literal prefixes of the received bytes.

    This is what lets the device verify the exact bytes it received instead of
    re-serialising parsed fields and hoping the result matches.
    """
    header, _ = package.parse_package(good)
    assert header.associated_data() == good[:80]
    assert header.signed_region() == good[:96]


def test_associated_data_stops_before_the_tag(good):
    """The tag cannot authenticate itself, so AD must end at offset 80."""
    header, _ = package.parse_package(good)
    assert header.auth_tag not in header.associated_data()
    assert len(header.associated_data()) == 80


def test_signed_region_covers_the_tag(good):
    """The signature must cover the AEAD tag.

    Without this, someone holding the symmetric key could substitute their own
    ciphertext and tag while reusing a genuine signature.
    """
    header, _ = package.parse_package(good)
    assert header.auth_tag in header.signed_region()


# ------------------------------------------------------------------- versions

@pytest.mark.parametrize("text,code", [
    ("0.0.0", 0x000000),
    ("1.0.0", 0x010000),
    ("1.2.3", 0x010203),
    ("2.0.0", 0x020000),
    ("255.255.255", 0xFFFFFF),
])
def test_version_encoding_round_trip(text, code):
    assert package.encode_version(text) == code
    assert package.decode_version(code) == text


def test_version_ordering_is_numeric():
    v = [package.encode_version(s)
         for s in ("0.9.9", "1.0.0", "1.0.1", "1.1.0", "2.0.0")]
    assert v == sorted(v), "encoded versions must sort like semantic versions"


@pytest.mark.parametrize("bad", ["1.0", "1.0.0.0", "x.y.z", "", "256.0.0",
                                 "-1.0.0", "1.0.256"])
def test_version_encoding_rejects_malformed_input(bad):
    with pytest.raises(ValueError):
        package.encode_version(bad)


# ---------------------------------------------------------------- round trip

def test_verify_accepts_a_good_package(keys, good, firmware):
    header, recovered = package.verify_package(
        good, keys["enc"], keys["sign"].public_key())
    assert recovered == firmware
    assert header.firmware_version == package.encode_version("2.1.0")
    assert header.security_version == 3
    assert header.firmware_size == len(firmware)


@pytest.mark.parametrize("size", [1, 15, 16, 17, 255, 256, 4096, 65537])
def test_round_trip_at_awkward_sizes(keys, size):
    fw = os.urandom(size)
    blob = package.build_package(
        firmware=fw, firmware_version=package.encode_version("1.0.1"),
        security_version=1, enc_key=keys["enc"], signing_key=keys["sign"])
    _, recovered = package.verify_package(blob, keys["enc"],
                                          keys["sign"].public_key())
    assert recovered == fw
    assert len(blob) == package.HEADER_SIZE + size


def test_hash_is_over_plaintext_not_ciphertext(keys, good, firmware):
    """The signed digest must describe what will execute, not the ciphertext."""
    header, ciphertext = package.parse_package(good)
    assert header.firmware_hash == ascon.hash256(firmware)
    assert header.firmware_hash != ascon.hash256(ciphertext)


def test_ciphertext_is_not_the_plaintext(keys, good, firmware):
    """Sanity: the payload really is encrypted."""
    _, ciphertext = package.parse_package(good)
    assert len(ciphertext) == len(firmware)
    assert ciphertext != firmware
    # And it should not leak long runs of plaintext either.
    assert firmware[:64] not in ciphertext


def test_nonce_is_fresh_for_every_package(keys, firmware):
    nonces = set()
    for _ in range(25):
        blob = package.build_package(
            firmware=firmware, firmware_version=1, security_version=1,
            enc_key=keys["enc"], signing_key=keys["sign"])
        header, _ = package.parse_package(blob)
        nonces.add(header.nonce)
    assert len(nonces) == 25, "nonce must never repeat under the same key"


def test_encryption_key_does_not_appear_in_the_package(keys, firmware):
    """The whole point of the design: the key is never transmitted."""
    blob = package.build_package(
        firmware=firmware, firmware_version=1, security_version=1,
        enc_key=keys["enc"], signing_key=keys["sign"])
    assert keys["enc"] not in blob
    # nor should the Ed25519 private key
    from cryptography.hazmat.primitives import serialization
    priv_raw = keys["sign"].private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    assert priv_raw not in blob


def test_same_firmware_twice_gives_different_ciphertext(keys, firmware):
    """Fresh nonces mean identical input must not produce identical output."""
    a = package.build_package(firmware=firmware, firmware_version=1,
                              security_version=1, enc_key=keys["enc"],
                              signing_key=keys["sign"], build_timestamp=1)
    b = package.build_package(firmware=firmware, firmware_version=1,
                              security_version=1, enc_key=keys["enc"],
                              signing_key=keys["sign"], build_timestamp=1)
    assert a != b
    assert a[package.HEADER_SIZE:] != b[package.HEADER_SIZE:]


# ------------------------------------------------------------ structural rejects

def test_parse_rejects_bad_magic(good):
    with pytest.raises(package.PackageFormatError, match="magic"):
        package.parse_package(b"XXXX" + good[4:])


def test_parse_rejects_unknown_format_version(good):
    bad = bytearray(good)
    struct.pack_into("<H", bad, 4, 99)
    with pytest.raises(package.PackageFormatError, match="format_version"):
        package.parse_package(bytes(bad))


def test_parse_rejects_bad_header_size(good):
    bad = bytearray(good)
    struct.pack_into("<H", bad, 6, 128)
    with pytest.raises(package.PackageFormatError, match="header_size"):
        package.parse_package(bytes(bad))


def test_parse_rejects_zero_firmware_size(good):
    bad = bytearray(good)
    struct.pack_into("<I", bad, 16, 0)
    with pytest.raises(package.PackageFormatError, match="firmware_size is 0"):
        package.parse_package(bytes(bad))


def test_parse_rejects_oversized_firmware(good):
    bad = bytearray(good)
    struct.pack_into("<I", bad, 16, package.MAX_FIRMWARE_SIZE + 1)
    struct.pack_into("<I", bad, 20, package.MAX_FIRMWARE_SIZE + 1)
    with pytest.raises(package.PackageFormatError, match="exceeds"):
        package.parse_package(bytes(bad))


def test_parse_rejects_size_disagreement(good):
    bad = bytearray(good)
    struct.pack_into("<I", bad, 20, 1233)
    with pytest.raises(package.PackageFormatError, match="ciphertext_size"):
        package.parse_package(bytes(bad))


def test_parse_rejects_truncation(good):
    with pytest.raises(package.PackageFormatError, match="truncated"):
        package.parse_package(good[:-1])
    with pytest.raises(package.PackageFormatError, match="header truncated"):
        package.parse_package(good[:100])


def test_parse_rejects_trailing_garbage(good):
    with pytest.raises(package.PackageFormatError, match="trailing garbage"):
        package.parse_package(good + b"\x00")


def test_build_rejects_bad_inputs(keys, firmware):
    with pytest.raises(ValueError, match="empty"):
        package.build_package(b"", 1, 1, keys["enc"], keys["sign"])
    with pytest.raises(ValueError, match="key must be"):
        package.build_package(firmware, 1, 1, b"short", keys["sign"])
    with pytest.raises(ValueError, match="nonce must be"):
        package.build_package(firmware, 1, 1, keys["enc"], keys["sign"],
                              nonce=b"short")
    with pytest.raises(TypeError):
        package.build_package(firmware, 1, 1, keys["enc"], "not-a-key")
    with pytest.raises(ValueError, match="32 bits"):
        package.build_package(firmware, 1, 1 << 33, keys["enc"], keys["sign"])
