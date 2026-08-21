"""Ed25519 signature tests.

Two things are being checked, and the second matters more than the first:

 1. The signature primitive works and rejects tampering (RFC 8032 vectors).
 2. The signature is *bound to the right bytes*. A signature scheme applied to
    the wrong span, or verified against a key the attacker supplies, provides no
    security at all -- and both mistakes look fine in a happy-path test.
"""

from __future__ import annotations

import os
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sotalib import ascon, package  # noqa: E402

# RFC 8032 section 7.1, vectors 1-3. Cross-checked against OpenSSL.
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
     "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac1"
     "8ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.fixture(scope="module")
def keys():
    return {"sign": Ed25519PrivateKey.generate(),
            "enc": os.urandom(ascon.ASCON_KEY_BYTES)}


@pytest.fixture
def good(keys):
    return package.build_package(
        firmware=os.urandom(2000),
        firmware_version=package.encode_version("2.0.0"),
        security_version=2, enc_key=keys["enc"], signing_key=keys["sign"])


# ------------------------------------------------------------- the primitive

@pytest.mark.parametrize("sk_hex,pk_hex,msg_hex,sig_hex", RFC8032)
def test_rfc8032_vectors(sk_hex, pk_hex, msg_hex, sig_hex):
    """The RFC 8032 vectors must reproduce exactly, key and signature both."""
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex))
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    assert pk.hex() == pk_hex
    msg = bytes.fromhex(msg_hex)
    assert sk.sign(msg).hex() == sig_hex
    # and it verifies
    Ed25519PublicKey.from_public_bytes(pk).verify(bytes.fromhex(sig_hex), msg)


@pytest.mark.parametrize("sk_hex,pk_hex,msg_hex,sig_hex", RFC8032)
def test_rfc8032_vectors_reject_bit_flips(sk_hex, pk_hex, msg_hex, sig_hex):
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    msg = bytes.fromhex(msg_hex)
    sig = bytes.fromhex(sig_hex)
    for i in range(0, 64, 5):
        bad = bytearray(sig)
        bad[i] ^= 0x01
        with pytest.raises(InvalidSignature):
            pk.verify(bytes(bad), msg)


def test_signature_is_64_bytes(keys, good):
    header, _ = package.parse_package(good)
    assert len(header.signature) == 64


# --------------------------------------------------- bound to the right bytes

def test_signature_covers_every_byte_of_the_signed_region(keys, good):
    """Flipping ANY bit in header[0:96] must invalidate the signature.

    Iterating the whole span is the only way to be sure nothing was accidentally
    left outside the signed bytes.
    """
    pub = keys["sign"].public_key()
    for offset in range(package.SIGNED_LEN):
        bad = bytearray(good)
        bad[offset] ^= 0x01
        try:
            header = package.PackageHeader.unpack(bytes(bad))
        except package.PackageFormatError:
            # magic / format_version / header_size are rejected even earlier,
            # which is a stronger outcome than a signature failure.
            continue
        with pytest.raises(InvalidSignature):
            pub.verify(header.signature, header.signed_region())


def test_full_verify_rejects_any_signed_byte_change(keys, good):
    """The same sweep, through the top-level verify entry point."""
    for offset in range(package.SIGNED_LEN):
        bad = bytearray(good)
        bad[offset] ^= 0x80
        with pytest.raises(package.PackageError):
            package.verify_package(bytes(bad), keys["enc"],
                                   keys["sign"].public_key())


def test_version_fields_are_authenticated(keys, good):
    """An attacker must not be able to relabel a package's versions.

    Anti-rollback is worthless if the version numbers are unsigned.
    """
    for offset, field in ((8, "firmware_version"), (12, "security_version")):
        bad = bytearray(good)
        struct.pack_into("<I", bad, offset, 0)
        with pytest.raises(package.SignatureError):
            package.verify_package(bytes(bad), keys["enc"],
                                   keys["sign"].public_key())


def test_nonce_is_authenticated(keys, good):
    bad = bytearray(good)
    bad[32:48] = os.urandom(16)
    with pytest.raises(package.SignatureError):
        package.verify_package(bytes(bad), keys["enc"],
                               keys["sign"].public_key())


def test_declared_hash_is_authenticated(keys, good):
    bad = bytearray(good)
    bad[48] ^= 0x01
    with pytest.raises(package.SignatureError):
        package.verify_package(bytes(bad), keys["enc"],
                               keys["sign"].public_key())


def test_aead_tag_is_authenticated(keys, good):
    """The tag is inside the signed region, so it cannot be swapped."""
    bad = bytearray(good)
    bad[80] ^= 0x01
    with pytest.raises(package.SignatureError):
        package.verify_package(bytes(bad), keys["enc"],
                               keys["sign"].public_key())


# ------------------------------------------------------- wrong / hostile keys

def test_another_key_cannot_sign_an_acceptable_package(keys):
    """Unauthorised firmware: correctly built, signed by the wrong key."""
    attacker = Ed25519PrivateKey.generate()
    blob = package.build_package(
        firmware=os.urandom(500),
        firmware_version=package.encode_version("9.9.9"),
        security_version=99, enc_key=keys["enc"], signing_key=attacker)

    # The device's trusted key must reject it...
    with pytest.raises(package.SignatureError):
        package.verify_package(blob, keys["enc"], keys["sign"].public_key())
    # ...even though it is internally perfectly consistent.
    package.verify_package(blob, keys["enc"], attacker.public_key())


def test_signature_from_a_different_package_is_not_transferable(keys):
    """A genuine signature must not validate a different header."""
    a = package.build_package(
        firmware=os.urandom(300), firmware_version=package.encode_version("2.0.0"),
        security_version=2, enc_key=keys["enc"], signing_key=keys["sign"])
    b = package.build_package(
        firmware=os.urandom(300), firmware_version=package.encode_version("3.0.0"),
        security_version=3, enc_key=keys["enc"], signing_key=keys["sign"])

    grafted = bytearray(b)
    grafted[96:160] = a[96:160]          # A's signature onto B's header
    with pytest.raises(package.SignatureError):
        package.verify_package(bytes(grafted), keys["enc"],
                               keys["sign"].public_key())


def test_stealing_the_symmetric_key_does_not_allow_forgery(keys):
    """The point of signing the tag.

    An attacker who learns the shared Ascon key can encrypt whatever they like
    and compute a valid tag -- but the tag is covered by the signature, so
    reusing a genuine signature no longer matches. Ed25519 remains the root of
    trust.
    """
    genuine = package.build_package(
        firmware=b"legitimate firmware image" * 40,
        firmware_version=package.encode_version("2.0.0"),
        security_version=2, enc_key=keys["enc"], signing_key=keys["sign"])
    header, _ = package.parse_package(genuine)

    # Attacker knows keys["enc"] and builds their own payload + valid tag.
    malicious = b"MALICIOUS PAYLOAD" * 60
    nonce = os.urandom(ascon.ASCON_NONCE_BYTES)
    forged = package.PackageHeader(
        firmware_version=header.firmware_version,
        security_version=header.security_version,
        firmware_size=len(malicious), ciphertext_size=len(malicious),
        build_timestamp=header.build_timestamp, nonce=nonce,
        firmware_hash=ascon.hash256(malicious),
        auth_tag=bytes(16), signature=bytes(64))
    ct, tag = ascon.aead128_encrypt(keys["enc"], nonce, malicious,
                                    forged.associated_data())
    forged.auth_tag = tag
    # Best they can do is replay the real signature.
    forged.signature = header.signature

    with pytest.raises(package.SignatureError):
        package.verify_package(forged.pack() + ct, keys["enc"],
                               keys["sign"].public_key())


def test_public_key_from_the_package_is_never_used(keys, good):
    """There is nowhere in the format to put a public key -- by design.

    A package-supplied trust anchor would reduce the signature to a checksum.
    This test documents the property: the header struct has no key field, and
    verification takes the key as a separate argument the caller controls.
    """
    header, _ = package.parse_package(good)
    assert not hasattr(header, "public_key")
    fields = set(header.__dataclass_fields__)
    assert not any("public" in f or "pubkey" in f for f in fields)
    # verify_package requires the caller to pass the key explicitly
    with pytest.raises(TypeError):
        package.verify_package(good, keys["enc"])  # type: ignore[call-arg]
