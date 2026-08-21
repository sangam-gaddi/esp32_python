"""OTA server tests.

Exercised through Flask's test client, so no port is bound and no background
process is needed.

The important properties, beyond "the endpoints return 200":

* the server needs no keys at all, and holds none;
* it refuses to serve a package it cannot parse, rather than handing a device
  something broken;
* what it serves is byte-identical to what the packager produced.
"""

from __future__ import annotations

import importlib
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from sotalib import ascon, package  # noqa: E402


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A server instance whose packages directory is a temp dir."""
    import server.app as server_app
    importlib.reload(server_app)

    pkgdir = tmp_path / "packages"
    pkgdir.mkdir()
    monkeypatch.setattr(server_app, "PACKAGES_DIR", pkgdir)

    signing_key = Ed25519PrivateKey.generate()
    enc_key = os.urandom(ascon.ASCON_KEY_BYTES)

    def add(version: str, security: int, size: int = 800) -> bytes:
        fw = os.urandom(size)
        blob = package.build_package(
            firmware=fw, firmware_version=package.encode_version(version),
            security_version=security, enc_key=enc_key,
            signing_key=signing_key, build_timestamp=1700000000)
        (pkgdir / f"firmware_v{version}.sota").write_bytes(blob)
        return blob

    server_app.app.config["TESTING"] = True
    return {"app": server_app, "client": server_app.app.test_client(),
            "dir": pkgdir, "add": add, "enc_key": enc_key,
            "signing_key": signing_key}


# ------------------------------------------------------------------ basics

def test_health_reports_package_counts(server):
    r = server["client"].get("/health")
    assert r.status_code == 200
    assert r.get_json()["packages"] == 0

    server["add"]("1.0.0", 1)
    r = server["client"].get("/health")
    assert r.get_json() == {"status": "ok", "packages": 1,
                            "invalid_packages": 0, "scheme": "http"}


def test_latest_returns_404_when_nothing_is_published(server):
    r = server["client"].get("/api/firmware/latest")
    assert r.status_code == 404
    assert "no firmware packages" in r.get_json()["error"]


def test_latest_picks_the_highest_firmware_version(server):
    for v, s in (("1.0.0", 1), ("2.0.0", 2), ("1.5.0", 1), ("10.0.0", 3)):
        server["add"](v, s)

    meta = server["client"].get("/api/firmware/latest").get_json()
    assert meta["firmware_version"] == "10.0.0"
    assert meta["security_version"] == 3
    # 10.0.0 must beat 2.0.0 -- i.e. comparison is numeric, not lexicographic
    assert meta["firmware_version_code"] == package.encode_version("10.0.0")


def test_metadata_contains_the_fields_the_device_parses(server):
    server["add"]("2.0.0", 2)
    meta = server["client"].get("/api/firmware/latest").get_json()
    for field in ("firmware_version_code", "security_version", "package_size",
                  "package_url", "firmware_size", "format_version"):
        assert field in meta, f"device reads {field}"
    assert meta["package_url"].startswith("/api/firmware/")


def test_list_reports_every_package(server):
    for v, s in (("1.0.0", 1), ("2.0.0", 2), ("3.0.0", 2)):
        server["add"](v, s)
    body = server["client"].get("/api/firmware/list").get_json()
    assert body["count"] == 3
    # newest first, so a device reading the list needs no sorting of its own
    assert [p["firmware_version"] for p in body["packages"]] == \
        ["3.0.0", "2.0.0", "1.0.0"]


def test_index_page_renders(server):
    server["add"]("2.0.0", 2)
    r = server["client"].get("/")
    assert r.status_code == 200
    assert b"Secure OTA update server" in r.data
    assert b"2.0.0" in r.data
    # the HTTP-transport caveat must be visible, not buried
    assert b"development only" in r.data.lower()
    assert b"holds no cryptographic keys" in r.data.lower()


# --------------------------------------------------------------- downloads

def test_download_is_byte_identical(server):
    blob = server["add"]("2.0.0", 2, size=3000)
    r = server["client"].get("/api/firmware/2.0.0/package")
    assert r.status_code == 200
    assert r.data == blob
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert int(r.headers["Content-Length"]) == len(blob)
    assert r.headers["X-Firmware-Version"] == "2.0.0"


def test_downloaded_package_still_verifies(server):
    server["add"]("2.0.0", 2, size=3000)
    r = server["client"].get("/api/firmware/latest/package")
    header, firmware = package.verify_package(
        r.data, server["enc_key"], server["signing_key"].public_key())
    assert header.firmware_version == package.encode_version("2.0.0")
    assert len(firmware) == 3000


def test_download_by_filename_also_works(server):
    server["add"]("2.0.0", 2)
    r = server["client"].get("/api/firmware/firmware_v2.0.0.sota/package")
    assert r.status_code == 200


def test_unknown_version_is_404(server):
    server["add"]("1.0.0", 1)
    r = server["client"].get("/api/firmware/9.9.9/package")
    assert r.status_code == 404
    assert "9.9.9" in r.get_json()["error"]


# ------------------------------------------------------- corrupt packages

def test_corrupt_package_is_excluded_not_served(server):
    server["add"]("1.0.0", 1)
    (server["dir"] / "broken.sota").write_bytes(b"not a package at all")

    health = server["client"].get("/health").get_json()
    assert health["packages"] == 1
    assert health["invalid_packages"] == 1

    body = server["client"].get("/api/firmware/list").get_json()
    assert body["count"] == 1
    assert len(body["invalid"]) == 1
    assert body["invalid"][0]["file"] == "broken.sota"


def test_truncated_package_is_not_offered(server):
    blob = server["add"]("2.0.0", 2)
    (server["dir"] / "cut.sota").write_bytes(blob[:-100])

    meta = server["client"].get("/api/firmware/latest").get_json()
    assert meta["package_name"] == "firmware_v2.0.0.sota"

    invalid = server["client"].get("/api/firmware/list").get_json()["invalid"]
    assert any(e["file"] == "cut.sota" for e in invalid)


def test_only_corrupt_packages_means_nothing_is_offered(server):
    (server["dir"] / "junk.sota").write_bytes(os.urandom(500))
    r = server["client"].get("/api/firmware/latest")
    assert r.status_code == 404


def test_package_corrupted_after_the_scan_is_refused(server):
    """The re-check on the way out.

    A package can be replaced between the directory scan and the read. The
    server validates again before sending, so a device is never handed bytes the
    server already knows are broken.
    """
    server["add"]("2.0.0", 2)
    app = server["app"]
    real_scan = app.scan_packages

    def scan_then_break():
        valid, invalid = real_scan()
        for entry in valid:
            entry["path"].write_bytes(b"corrupted after scanning")
        return valid, invalid

    app.scan_packages = scan_then_break
    try:
        r = server["client"].get("/api/firmware/latest/package")
        assert r.status_code == 500
        assert "failed validation" in r.get_json()["error"]
    finally:
        app.scan_packages = real_scan


# --------------------------------------------------------------- key hygiene

def test_server_module_holds_no_key_material(server):
    """The server must not import, load or reference private key material."""
    source = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    for forbidden in ("load_private_key", "load_enc_key", "ed25519_private",
                      "ota_enc_key", "sign("):
        assert forbidden not in source, \
            f"server/app.py references {forbidden!r}; it must hold no keys"


def test_metadata_never_contains_secrets(server):
    server["add"]("2.0.0", 2)
    meta = server["client"].get("/api/firmware/latest").get_json()
    blob = json.dumps(meta)
    assert server["enc_key"].hex() not in blob
    # the digest and versions are public; a key never is
    assert "key" not in {k.lower() for k in meta}
