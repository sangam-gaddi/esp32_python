"""The attack tests: every rejection path the project claims, exercised.

Each test here corresponds to one of the numbered scenarios in docs/DEMO.md and
one row of the acceptance criteria. They run through the real command-line tools
(`create_ota_package.py`, `tamper_package.py`, `verify_package.py`) in a
subprocess, so what is being tested is the pipeline a demonstrator actually
types -- not just the library underneath it.

    TEST 1  valid update            accepted
    TEST 2  modified firmware       rejected (Ascon-AEAD128 tag)
    TEST 3  invalid signature       rejected (Ed25519)
    TEST 4  wrong encryption key    rejected (Ascon-AEAD128 tag)
    TEST 5  rollback                rejected (anti-rollback)
    TEST 6  corrupted package       rejected (structure)
    TEST 7  interrupted transfer    rejected, no partial acceptance
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from sotalib import ascon, package  # noqa: E402


def run(*args: str) -> subprocess.CompletedProcess:
    """Run one of the project's tools and capture the result."""
    return subprocess.run([sys.executable, *args], cwd=ROOT,
                          capture_output=True, text=True)


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    """A self-contained key set, firmware image and valid package.

    Uses its own keys in a temp directory so the test suite neither needs nor
    disturbs the project's real keys/.
    """
    d = tmp_path_factory.mktemp("negative")

    signing_key = Ed25519PrivateKey.generate()
    priv = d / "ed25519_private.pem"
    priv.write_bytes(signing_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pub = d / "ed25519_public.pem"
    pub.write_bytes(signing_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))

    enc_key = os.urandom(ascon.ASCON_KEY_BYTES)
    enc = d / "ota_enc_key.hex"
    enc.write_text(enc_key.hex() + "\n", encoding="utf-8")

    firmware = d / "firmware_v2.bin"
    firmware.write_bytes(bytes((i * 17 + 3) & 0xFF for i in range(9001)))

    good = d / "good.sota"
    r = run("tools/create_ota_package.py",
            "--firmware", str(firmware), "--version", "2.0.0",
            "--security-version", "2", "--output", str(good),
            "--signing-key", str(priv), "--enc-key", str(enc))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "self-verification : PASS" in r.stdout

    return {"dir": d, "priv": priv, "pub": pub, "enc": enc,
            "enc_key": enc_key, "signing_key": signing_key,
            "firmware": firmware, "good": good}


def verify(ws, pkg: pathlib.Path, *extra: str) -> subprocess.CompletedProcess:
    return run("tools/verify_package.py", str(pkg),
               "--public-key", str(ws["pub"]), "--enc-key", str(ws["enc"]),
               *extra)


def tamper(ws, mode: str, out_name: str, *extra: str) -> pathlib.Path:
    out = ws["dir"] / out_name
    r = run("tools/tamper_package.py", "--mode", mode,
            "--input", str(ws["good"]), "--output", str(out),
            "--signing-key", str(ws["priv"]), "--enc-key", str(ws["enc"]),
            *extra)
    assert r.returncode == 0, r.stdout + r.stderr
    assert out.exists()
    return out


# ============================================================ TEST 1: valid

def test_1_valid_update_is_accepted(workspace):
    r = verify(workspace, workspace["good"],
               "--current-version", "1.0.0", "--current-security-version", "1")
    assert r.returncode == 0, r.stdout
    assert "RESULT: ACCEPTED" in r.stdout
    for stage in ("structure", "Ed25519 signature", "Ascon-AEAD128 tag",
                  "Ascon-Hash256", "version / anti-rollback"):
        assert f"{stage}" in r.stdout
    assert "FAIL" not in r.stdout


def test_1_decrypted_firmware_is_byte_identical(workspace):
    out = workspace["dir"] / "extracted.bin"
    r = verify(workspace, workspace["good"], "--extract", str(out))
    assert r.returncode == 0, r.stdout
    assert out.read_bytes() == workspace["firmware"].read_bytes()


# ================================================= TEST 2: modified firmware

@pytest.mark.parametrize("where,offset", [
    ("first byte", package.HEADER_SIZE),
    ("middle", package.HEADER_SIZE + 4500),
])
def test_2_modified_firmware_is_rejected(workspace, where, offset):
    pkg = tamper(workspace, "flip-ciphertext", f"t2_{offset}.sota",
                 "--offset", str(offset))
    r = verify(workspace, pkg)
    assert r.returncode == 1
    assert "ASCON AUTHENTICATION FAILED" in r.stdout, where
    assert "Ed25519 signature            PASS" in r.stdout, \
        "the header is untouched, so the signature should still be good"


def test_2_every_byte_of_the_payload_is_protected(workspace):
    """Library-level sweep: no region of the ciphertext is unauthenticated."""
    blob = workspace["good"].read_bytes()
    payload_len = len(blob) - package.HEADER_SIZE
    for off in range(package.HEADER_SIZE, len(blob), max(1, payload_len // 40)):
        bad = bytearray(blob)
        bad[off] ^= 0x01
        with pytest.raises(package.TagError):
            package.verify_package(bytes(bad), workspace["enc_key"],
                                   workspace["signing_key"].public_key())


# ================================================== TEST 3: invalid signature

@pytest.mark.parametrize("mode", ["bad-signature", "foreign-signer",
                                  "flip-metadata"])
def test_3_invalid_signature_is_rejected(workspace, mode):
    pkg = tamper(workspace, mode, f"t3_{mode}.sota")
    r = verify(workspace, pkg)
    assert r.returncode == 1
    assert "REJECTED (INVALID SIGNATURE)" in r.stdout
    # Rejected before decryption is even attempted.
    assert "Ascon-AEAD128 tag" not in r.stdout


def test_3_unauthorised_firmware_cannot_claim_a_high_version(workspace):
    """An attacker's own build, signed with their own key, must not install."""
    attacker = Ed25519PrivateKey.generate()
    priv = workspace["dir"] / "attacker.pem"
    priv.write_bytes(attacker.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    out = workspace["dir"] / "t3_attacker.sota"
    r = run("tools/create_ota_package.py",
            "--firmware", str(workspace["firmware"]),
            "--version", "9.9.9", "--security-version", "99",
            "--output", str(out), "--signing-key", str(priv),
            "--enc-key", str(workspace["enc"]))
    assert r.returncode == 0, r.stdout + r.stderr

    r = verify(workspace, out)
    assert r.returncode == 1
    assert "REJECTED (INVALID SIGNATURE)" in r.stdout


# ================================================ TEST 4: wrong encryption key

def test_4_wrong_encryption_key_is_rejected(workspace):
    pkg = tamper(workspace, "wrong-key", "t4.sota")
    r = verify(workspace, pkg)
    assert r.returncode == 1
    assert "REJECTED (ASCON AUTHENTICATION FAILED)" in r.stdout
    # Correctly signed, so the signature stage passes: the failure is the key.
    assert "Ed25519 signature            PASS" in r.stdout


def test_4_device_with_the_wrong_key_rejects_a_good_package(workspace):
    """Same thing from the other side: a valid package, a mismatched device."""
    other = workspace["dir"] / "other_key.hex"
    other.write_text(os.urandom(ascon.ASCON_KEY_BYTES).hex() + "\n",
                     encoding="utf-8")
    r = run("tools/verify_package.py", str(workspace["good"]),
            "--public-key", str(workspace["pub"]), "--enc-key", str(other))
    assert r.returncode == 1
    assert "ASCON AUTHENTICATION FAILED" in r.stdout


# =========================================================== TEST 5: rollback

def test_5_rollback_is_rejected(workspace):
    pkg = tamper(workspace, "rollback", "t5.sota", "--security-version", "1")
    # Every cryptographic check passes -- it is a genuinely signed package.
    r = verify(workspace, pkg)
    assert r.returncode == 0, "no version state given, so nothing to compare"

    # Against a device that has already accepted security version 2, it must be
    # refused.
    r = verify(workspace, pkg, "--current-security-version", "2")
    assert r.returncode == 1
    assert "ROLLBACK" in r.stdout
    assert "REJECTED (version check failed)" in r.stdout


def test_5_equal_security_version_is_allowed(workspace):
    """Anti-rollback blocks downgrades, not ordinary same-tier releases."""
    r = verify(workspace, workspace["good"], "--current-security-version", "2")
    assert r.returncode == 0
    assert "security 2 >= 2" in r.stdout


def test_5_reinstalling_the_same_firmware_version_is_not_an_update(workspace):
    r = verify(workspace, workspace["good"], "--current-version", "2.0.0")
    assert r.returncode == 1
    assert "not an upgrade" in r.stdout


def test_5_rollback_wins_over_freshness_in_reporting(workspace):
    """A package that is both older and less secure reports the rollback."""
    pkg = tamper(workspace, "rollback", "t5b.sota",
                 "--security-version", "0", "--version", "1.0.0")
    r = verify(workspace, pkg, "--current-version", "2.0.0",
               "--current-security-version", "2")
    assert r.returncode == 1
    assert "ROLLBACK" in r.stdout


# ================================================== TEST 6: corrupted package

@pytest.mark.parametrize("mode,expect", [
    ("bad-magic", "bad magic"),
    ("truncate", "truncated"),
])
def test_6_corrupted_package_is_rejected(workspace, mode, expect):
    pkg = tamper(workspace, mode, f"t6_{mode}.sota")
    r = verify(workspace, pkg)
    assert r.returncode == 1
    assert "REJECTED (malformed package)" in r.stdout
    assert expect in r.stdout


def test_6_random_bytes_are_not_a_package(workspace):
    junk = workspace["dir"] / "t6_junk.sota"
    junk.write_bytes(os.urandom(5000))
    r = verify(workspace, junk)
    assert r.returncode == 1
    assert "REJECTED (malformed package)" in r.stdout


def test_6_empty_file_is_rejected(workspace):
    empty = workspace["dir"] / "t6_empty.sota"
    empty.write_bytes(b"")
    r = verify(workspace, empty)
    assert r.returncode == 1


def test_6_header_only_file_is_rejected(workspace):
    """A package whose payload never arrived at all."""
    part = workspace["dir"] / "t6_headeronly.sota"
    part.write_bytes(workspace["good"].read_bytes()[:package.HEADER_SIZE])
    r = verify(workspace, part)
    assert r.returncode == 1
    assert "REJECTED (malformed package)" in r.stdout


# ================================================ TEST 7: interrupted transfer

@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9, 0.999])
def test_7_interrupted_download_is_never_accepted(workspace, fraction):
    """Any prefix of a valid package must be refused.

    On the device this is the "connection dropped mid-update" case. Because the
    boot partition is only switched after the final tag and hash check, a partial
    transfer leaves the running firmware selected and untouched.
    """
    blob = workspace["good"].read_bytes()
    cut = int(len(blob) * fraction)
    part = workspace["dir"] / f"t7_{int(fraction * 1000)}.sota"
    part.write_bytes(blob[:cut])

    r = verify(workspace, part)
    assert r.returncode == 1, f"prefix of {cut}/{len(blob)} bytes was accepted"


def test_7_truncated_payload_fails_at_the_library_level(workspace):
    blob = workspace["good"].read_bytes()
    with pytest.raises(package.PackageFormatError, match="truncated"):
        package.verify_package(blob[:-1], workspace["enc_key"],
                               workspace["signing_key"].public_key())


# ============================================ isolated hash-mismatch rejection

def test_hash_mismatch_is_detected_independently(workspace):
    """The only way to reach the Ascon-Hash256 check as the *first* failure.

    Correctly encrypted and correctly signed, but the signed digest does not
    describe the firmware -- i.e. a broken or malicious build server. It proves
    the hash comparison is genuinely enforced rather than implied by the tag.
    """
    pkg = tamper(workspace, "hash-mismatch", "t8.sota")
    r = verify(workspace, pkg)
    assert r.returncode == 1
    assert "REJECTED (HASH MISMATCH)" in r.stdout
    assert "Ed25519 signature            PASS" in r.stdout
    assert "Ascon-AEAD128 tag            PASS" in r.stdout


# ================================================================ tool hygiene

def test_tamper_tool_covers_every_documented_mode(workspace):
    """Each advertised attack mode must actually produce a rejected package."""
    import tools.tamper_package as tp  # noqa: PLC0415
    for mode in tp.MODES:
        extra = ["--security-version", "1"] if mode == "rollback" else []
        pkg = tamper(workspace, mode, f"all_{mode}.sota", *extra)
        r = verify(workspace, pkg, "--current-version", "1.0.0",
                   "--current-security-version", "2")
        assert r.returncode == 1, f"mode {mode} produced an ACCEPTED package"
        assert "REJECTED" in r.stdout, f"mode {mode}"
