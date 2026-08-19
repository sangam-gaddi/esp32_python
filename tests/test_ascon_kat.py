"""Validate the host Ascon implementation against the official NIST SP 800-232
Known-Answer-Test vectors.

The vector files in ``tests/vectors/`` are taken verbatim from the Ascon
reference repository (``github.com/ascon/ascon-c``, branch ``main``, the
SP 800-232 code drop):

* ``LWC_HASH_KAT_128_256.txt`` -- ``crypto_hash/asconhash256/``  (1025 vectors)
* ``LWC_AEAD_KAT_128_128.txt`` -- ``crypto_aead/asconaead128/``  (1089 vectors)

These are the same files the C implementation is tested against in
``tests/host/``, which is what pins the host packager and the device firmware to
the same algorithm.

Run with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sotalib import ascon  # noqa: E402

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors"


def _parse_kat(path: pathlib.Path) -> list[dict[str, bytes]]:
    """Parse a NIST LWC KAT file into a list of {field: bytes} records."""
    records: list[dict[str, bytes]] = []
    current: dict[str, bytes] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "Count":
            if current:
                records.append(current)
            current = {"Count": value}
        else:
            current[key] = bytes.fromhex(value)
    if current:
        records.append(current)
    return records


HASH_VECTORS = _parse_kat(VECTORS / "LWC_HASH_KAT_128_256.txt")
AEAD_VECTORS = _parse_kat(VECTORS / "LWC_AEAD_KAT_128_128.txt")


def test_vector_files_are_present_and_complete():
    assert len(HASH_VECTORS) == 1025, "unexpected hash KAT count"
    assert len(AEAD_VECTORS) == 1089, "unexpected AEAD KAT count"


# ---------------------------------------------------------------- Ascon-Hash256

def test_hash256_all_official_vectors():
    """All 1025 official Ascon-Hash256 vectors, one-shot API."""
    failures = []
    for rec in HASH_VECTORS:
        got = ascon.hash256(rec["Msg"])
        if got != rec["MD"]:
            failures.append((rec["Count"], rec["MD"].hex(), got.hex()))
    assert not failures, f"{len(failures)} hash mismatches, first: {failures[0]}"


@pytest.mark.parametrize("chunk", [1, 3, 7, 8, 9, 16, 31, 64])
def test_hash256_incremental_matches_one_shot(chunk):
    """Streaming in awkward chunk sizes must equal the one-shot digest.

    This is the property the device depends on: it hashes the firmware in
    network-sized pieces that do not align to the 8-byte Ascon rate.
    """
    for rec in HASH_VECTORS[:120]:
        msg = rec["Msg"]
        h = ascon.AsconHash256()
        for off in range(0, len(msg), chunk):
            h.update(msg[off:off + chunk])
        assert h.digest() == rec["MD"], f"count {rec['Count']} chunk {chunk}"


def test_hash256_digest_is_stable_and_repeatable():
    h = ascon.AsconHash256(b"secure ota")
    assert h.digest() == h.digest()
    assert h.hexdigest() == h.digest().hex()
    with pytest.raises(RuntimeError):
        h.update(b"more")


# ---------------------------------------------------------------- Ascon-AEAD128

def test_aead128_encrypt_all_official_vectors():
    """All 1089 official Ascon-AEAD128 vectors. CT in the file is ciphertext||tag."""
    failures = []
    for rec in AEAD_VECTORS:
        ct, tag = ascon.aead128_encrypt(rec["Key"], rec["Nonce"], rec["PT"], rec["AD"])
        if ct + tag != rec["CT"]:
            failures.append((rec["Count"], rec["CT"].hex(), (ct + tag).hex()))
    assert not failures, f"{len(failures)} AEAD mismatches, first: {failures[0]}"


def test_aead128_decrypt_all_official_vectors():
    """Decryption must recover the plaintext and accept the official tag."""
    for rec in AEAD_VECTORS:
        ct, tag = rec["CT"][:-16], rec["CT"][-16:]
        pt = ascon.aead128_decrypt(rec["Key"], rec["Nonce"], ct, tag, rec["AD"])
        assert pt == rec["PT"], f"count {rec['Count']}"


def test_aead128_rejects_tampered_ciphertext():
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    pt = b"firmware payload that is longer than one 16-byte rate block"
    ct, tag = ascon.aead128_encrypt(key, nonce, pt, b"metadata")

    for pos in (0, 5, 16, 17, len(ct) - 1):
        bad = bytearray(ct)
        bad[pos] ^= 0x01
        with pytest.raises(ascon.AsconTagError):
            ascon.aead128_decrypt(key, nonce, bytes(bad), tag, b"metadata")


def test_aead128_rejects_wrong_key_nonce_ad_and_tag():
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    pt, ad = b"firmware payload", b"metadata"
    ct, tag = ascon.aead128_encrypt(key, nonce, pt, ad)

    wrong_key = bytearray(key)
    wrong_key[0] ^= 0x01
    wrong_nonce = bytearray(nonce)
    wrong_nonce[15] ^= 0x80
    bad_tag = bytearray(tag)
    bad_tag[8] ^= 0x01

    cases = {
        "wrong key": (bytes(wrong_key), nonce, ct, tag, ad),
        "wrong nonce": (key, bytes(wrong_nonce), ct, tag, ad),
        "wrong ad": (key, nonce, ct, tag, b"metadatA"),
        "bad tag": (key, nonce, ct, bytes(bad_tag), ad),
    }
    for name, args in cases.items():
        with pytest.raises(ascon.AsconTagError, match="tag verification failed"):
            ascon.aead128_decrypt(*args)
        assert name  # names kept so a failure reports which case broke


@pytest.mark.parametrize("length", [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 1000])
def test_aead128_roundtrip_at_block_boundaries(length):
    """Partial-block padding is where AEAD implementations usually break."""
    key, nonce = b"\xa5" * 16, b"\x5a" * 16
    pt = bytes((i * 7) & 0xFF for i in range(length))
    for ad in (b"", b"\x01", b"\x02" * 16, b"\x03" * 23):
        ct, tag = ascon.aead128_encrypt(key, nonce, pt, ad)
        assert len(ct) == length
        assert len(tag) == 16
        assert ascon.aead128_decrypt(key, nonce, ct, tag, ad) == pt


def test_aead128_rejects_bad_parameter_sizes():
    with pytest.raises(ValueError):
        ascon.aead128_encrypt(b"short", b"\x00" * 16, b"")
    with pytest.raises(ValueError):
        ascon.aead128_encrypt(b"\x00" * 16, b"short", b"")
    with pytest.raises(ValueError):
        ascon.aead128_decrypt(b"\x00" * 16, b"\x00" * 16, b"", b"shorttag")
