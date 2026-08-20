"""Tests for the management dashboard layer.

Two things are being checked here, and the second matters more than the first:

  1. the dashboard does what it claims -- online/offline detection, the command
     allowlist, publishing, the version-mismatch report;

  2. the dashboard did not change the OTA server. The endpoints the ESP32 uses
     are exercised alongside the new ones, because a management UI that breaks
     device updates is worse than no UI at all.

Everything runs against a temporary database and temporary package directories,
so the developer's own server/ota.db and server/packages/ are untouched.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from sotalib import ascon, package  # noqa: E402


@pytest.fixture
def dash(tmp_path, monkeypatch):
    import server.app as server_app
    from server.dashboard import db, inventory

    packages = tmp_path / "packages"
    staging = tmp_path / "staging"
    uploads = tmp_path / "uploads"
    for d in (packages, staging, uploads):
        d.mkdir()

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "ota.db")
    monkeypatch.setattr(inventory, "PACKAGES_DIR", packages)
    monkeypatch.setattr(inventory, "STAGING_DIR", staging)
    monkeypatch.setattr(inventory, "UPLOADS_DIR", uploads)
    monkeypatch.setattr(server_app, "PACKAGES_DIR", packages)
    db.init()

    signing_key = Ed25519PrivateKey.generate()
    enc_key = os.urandom(ascon.ASCON_KEY_BYTES)

    def add_package(version: str, security: int, published: bool = True,
                    size: int = 512) -> pathlib.Path:
        blob = package.build_package(
            firmware=os.urandom(size),
            firmware_version=package.encode_version(version),
            security_version=security, enc_key=enc_key,
            signing_key=signing_key, build_timestamp=1700000000)
        target = (packages if published else staging) / f"firmware_v{version}.sota"
        target.write_bytes(blob)
        return target

    server_app.app.config["TESTING"] = True
    return {"client": server_app.app.test_client(), "db": db,
            "add_package": add_package, "packages": packages,
            "staging": staging, "uploads": uploads, "app": server_app}


def beat(client, device="esp32-test-01", **overrides):
    payload = {
        "device_id": device, "ip": "10.0.0.9",
        "firmware_version": "1.0.0", "firmware_version_code": 0x010000,
        "security_version": 1, "partition": "ota_0", "free_heap": 200000,
        "uptime_s": 100, "ota_state": "IDLE", "idf_version": "v5.3.1",
    }
    payload.update(overrides)
    return client.post("/api/device/heartbeat", json=payload)


# ------------------------------------------- the device-facing API is intact

def test_existing_ota_endpoints_still_work(dash):
    c = dash["client"]
    dash["add_package"]("2.0.0", 2)

    assert c.get("/health").status_code == 200

    meta = c.get("/api/firmware/latest?device=esp32-demo-01").get_json()
    assert meta["firmware_version"] == "2.0.0"
    assert meta["security_version"] == 2
    assert meta["package_url"] == "/api/firmware/2.0.0/package"

    r = c.get("/api/firmware/2.0.0/package")
    assert r.status_code == 200
    assert r.headers["X-Firmware-Version"] == "2.0.0"
    header, _ = package.parse_package(r.data)
    assert header.firmware_version == package.encode_version("2.0.0")

    assert c.get("/api/firmware/list").get_json()["count"] == 1
    assert c.get("/api/firmware/latest/package").status_code == 200


def test_dashboard_never_serves_staged_packages_to_devices(dash):
    """A package that has not been published must be invisible to the device."""
    c = dash["client"]
    dash["add_package"]("3.0.0", 3, published=False)

    assert c.get("/api/firmware/latest").status_code == 404
    assert c.get("/api/firmware/3.0.0/package").status_code == 404
    # but the dashboard can see it
    files = [p["file"] for p in c.get("/api/firmware").get_json()["packages"]]
    assert "firmware_v3.0.0.sota" in files


# ------------------------------------------------------------------- pages

@pytest.mark.parametrize("path", ["/dashboard", "/firmware", "/history",
                                  "/security", "/logs"])
def test_pages_render(dash, path):
    r = dash["client"].get(path)
    assert r.status_code == 200
    assert b"SECURE OTA" in r.data


# --------------------------------------------------------------- heartbeats

def test_heartbeat_creates_a_device_and_reports_online(dash):
    c = dash["client"]
    assert c.get("/api/dashboard/summary").get_json()["device"] is None

    assert beat(c).status_code == 200
    summary = c.get("/api/dashboard/summary").get_json()
    assert summary["device"]["status"] == "ONLINE"
    assert summary["device"]["firmware_version"] == "1.0.0"
    assert summary["device"]["free_heap"] == 200000


def test_heartbeat_requires_a_sane_device_id(dash):
    c = dash["client"]
    for bad in ("", "  ", "a" * 65, "../../etc/passwd", "dev;rm -rf /"):
        r = c.post("/api/device/heartbeat", json={"device_id": bad})
        assert r.status_code == 400


def test_device_goes_offline_after_the_timeout(dash):
    c = dash["client"]
    beat(c)
    dash["db"]._exec("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                     (time.time() - 3600, "esp32-test-01"))
    assert c.get("/api/devices/esp32-test-01").get_json()["status"] == "OFFLINE"


def test_device_is_rebooting_not_offline_right_after_install(dash):
    c = dash["client"]
    beat(c, ota_state="REBOOT")
    dash["db"]._exec("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                     (time.time() - 30, "esp32-test-01"))
    assert c.get("/api/devices/esp32-test-01").get_json()["status"] == "REBOOTING"


def test_progress_is_only_reported_when_the_device_reports_it(dash):
    c = dash["client"]
    beat(c)
    dev = c.get("/api/dashboard/summary").get_json()["device"]
    assert dev["ota_percent"] is None
    assert dev["ota_active"] is False

    beat(c, ota_state="DECRYPT", ota_done=463344, ota_total=926688)
    dev = c.get("/api/dashboard/summary").get_json()["device"]
    assert dev["ota_percent"] == 50.0
    assert dev["ota_active"] is True


def test_pipeline_follows_the_reported_state(dash):
    c = dash["client"]
    beat(c, ota_state="DOWNLOAD")
    stages = {s["key"]: s["state"]
              for s in c.get("/api/dashboard/summary").get_json()["pipeline"]}
    assert stages["CHECK"] == "done"
    assert stages["SIGNATURE_VERIFY"] == "done"
    assert stages["DOWNLOAD"] == "active"
    assert stages["INSTALL"] == "pending"


def test_no_pipeline_progress_is_shown_for_an_offline_device(dash):
    c = dash["client"]
    beat(c, ota_state="DOWNLOAD")
    dash["db"]._exec("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                     (time.time() - 3600, "esp32-test-01"))
    stages = {s["state"]
              for s in c.get("/api/dashboard/summary").get_json()["pipeline"]}
    assert stages == {"pending"}


# ----------------------------------------------------------------- commands

def test_only_allowlisted_commands_are_accepted(dash):
    c = dash["client"]
    beat(c)
    for cmd in ("CHECK_UPDATE", "START_OTA", "REBOOT"):
        assert c.post("/api/devices/esp32-test-01/command",
                      json={"command": cmd}).status_code == 202

    for bad in ("REFLASH", "rm -rf /", "", "START_OTA; REBOOT", "../REBOOT",
                "eval", None):
        r = c.post("/api/devices/esp32-test-01/command", json={"command": bad})
        assert r.status_code == 400, f"{bad!r} was accepted"


def test_commands_are_delivered_once(dash):
    c = dash["client"]
    beat(c)
    c.post("/api/devices/esp32-test-01/command", json={"command": "START_OTA"})

    first = c.get("/api/device/esp32-test-01/commands").get_json()["commands"]
    assert [x["command"] for x in first] == ["START_OTA"]
    assert c.get("/api/device/esp32-test-01/commands").get_json()["commands"] == []


def test_commands_also_ride_on_the_heartbeat_response(dash):
    c = dash["client"]
    beat(c)
    c.post("/api/devices/esp32-test-01/command", json={"command": "REBOOT"})
    assert beat(c).get_json()["commands"] == ["REBOOT"]
    assert beat(c).get_json()["commands"] == []


def test_command_for_an_unknown_device_is_refused(dash):
    r = dash["client"].post("/api/devices/ghost/command",
                            json={"command": "REBOOT"})
    assert r.status_code == 404


# ---------------------------------------------------------------- firmware

def test_upload_package_publish_flow(dash):
    c = dash["client"]

    r = c.post("/api/firmware/upload",
               data={"file": (io.BytesIO(b"\xe9" + os.urandom(2047)), "app.bin")},
               content_type="multipart/form-data")
    assert r.status_code == 201
    name = r.get_json()["file"]

    r = c.post("/api/firmware/package",
               json={"file": name, "version": "4.1.0", "security_version": 4})
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["ok"] is True
    assert all(s["ok"] for s in body["stages"])
    assert len(body["firmware_hash"]) == 64
    assert (dash["staging"] / "firmware_v4.1.0.sota").exists()

    # staged, so the device is still offered nothing
    assert c.get("/api/firmware/latest").status_code == 404

    staged_bytes = (dash["staging"] / "firmware_v4.1.0.sota").read_bytes()
    assert c.post("/api/firmware/firmware_v4.1.0.sota/publish").status_code == 201

    published = dash["packages"] / "firmware_v4.1.0.sota"
    assert published.read_bytes() == staged_bytes, \
        "publishing must copy the signed bytes unchanged"
    assert c.get("/api/firmware/latest").get_json()["firmware_version"] == "4.1.0"


def test_packages_are_never_overwritten(dash):
    c = dash["client"]
    c.post("/api/firmware/upload",
           data={"file": (io.BytesIO(b"\xe9" + os.urandom(511)), "app.bin")},
           content_type="multipart/form-data")
    first = c.post("/api/firmware/package",
                   json={"file": "app.bin", "version": "5.0.0",
                         "security_version": 5})
    assert first.status_code == 201
    again = c.post("/api/firmware/package",
                   json={"file": "app.bin", "version": "5.0.0",
                         "security_version": 5})
    assert again.status_code == 409


def test_upload_rejects_non_bin_and_traversal(dash):
    c = dash["client"]
    r = c.post("/api/firmware/upload",
               data={"file": (io.BytesIO(b"x"), "evil.exe")},
               content_type="multipart/form-data")
    assert r.status_code == 400

    r = c.post("/api/firmware/upload",
               data={"file": (io.BytesIO(b"x"), "../../../../etc/passwd.bin")},
               content_type="multipart/form-data")
    # the name is reduced to its basename, so nothing escapes the uploads dir
    if r.status_code == 201:
        assert r.get_json()["file"] == "passwd.bin"
        assert (dash["uploads"] / "passwd.bin").exists()


def test_package_creation_validates_versions(dash):
    c = dash["client"]
    c.post("/api/firmware/upload",
           data={"file": (io.BytesIO(b"\xe9" + os.urandom(255)), "app.bin")},
           content_type="multipart/form-data")
    for version in ("1.0", "300.0.0", "abc", "1.0.0.0", ""):
        r = c.post("/api/firmware/package",
                   json={"file": "app.bin", "version": version,
                         "security_version": 1})
        assert r.status_code == 400, version
    r = c.post("/api/firmware/package",
               json={"file": "app.bin", "version": "1.2.3",
                     "security_version": "not a number"})
    assert r.status_code == 400


def test_unknown_upload_is_not_packaged(dash):
    r = dash["client"].post("/api/firmware/package",
                            json={"file": "nope.bin", "version": "1.0.0",
                                  "security_version": 1})
    assert r.status_code == 404


# ------------------------------------------------------- events and history

def test_device_events_become_history_and_security_events(dash):
    c = dash["client"]
    beat(c)
    c.post("/api/device/esp32-test-01/event", json={
        "event": "REJECT", "stage": "VERSION_VERIFY", "result": "REJECTED",
        "from_version": "2.0.0", "to_version": "1.0.0",
        "reason": "package security version 1 is below the accepted floor 2"})

    history = c.get("/api/ota/history").get_json()["events"]
    assert history[0]["result"] == "REJECTED"
    assert history[0]["stage"] == "VERSION_VERIFY"

    events = c.get("/api/security/events").get_json()["events"]
    assert events[0]["kind"] == "ROLLBACK_ATTEMPT"
    assert events[0]["severity"] == "warn"


def test_successful_install_is_recorded_as_a_verified_update(dash):
    c = dash["client"]
    beat(c)
    c.post("/api/device/esp32-test-01/event", json={
        "event": "INSTALL", "stage": "INSTALL", "result": "SUCCESS",
        "from_version": "1.0.0", "to_version": "2.0.0",
        "security_version": 2, "duration_ms": 13800})
    events = c.get("/api/security/events").get_json()["events"]
    assert events[0]["kind"] == "UPDATE_VERIFIED"
    assert events[0]["severity"] == "ok"


def test_reboot_into_the_new_version_is_recorded(dash):
    c = dash["client"]
    beat(c, uptime_s=300)
    beat(c, uptime_s=4, firmware_version="2.0.0",
         firmware_version_code=0x020000, security_version=2)

    boots = [e for e in c.get("/api/ota/history").get_json()["events"]
             if e["event"] == "BOOT"]
    assert boots and boots[0]["from_version"] == "1.0.0"
    assert boots[0]["to_version"] == "2.0.0"


def test_version_mismatch_is_reported_not_hidden(dash):
    """The exact failure seen on real hardware: package says 2.0.0, device
    still reports 1.0.0 after rebooting."""
    c = dash["client"]
    beat(c, uptime_s=300, ota_state="INSTALL")
    c.post("/api/device/esp32-test-01/event", json={
        "event": "INSTALL", "stage": "INSTALL", "result": "SUCCESS",
        "from_version": "1.0.0", "to_version": "2.0.0", "security_version": 2})

    # reboot, but the running image still reports the old version
    dash["db"]._exec(
        "UPDATE ota_events SET ts = ? WHERE event = 'INSTALL'",
        (time.time() - 60,))
    beat(c, uptime_s=5, ota_state="IDLE")

    summary = c.get("/api/dashboard/summary").get_json()
    mismatch = summary["version_mismatch"]
    assert mismatch is not None
    assert mismatch["installed_version"] == "2.0.0"
    assert mismatch["running_version"] == "1.0.0"

    kinds = [e["kind"] for e in c.get("/api/security/events").get_json()["events"]]
    assert "VERSION_MISMATCH" in kinds


def test_no_mismatch_when_the_versions_agree(dash):
    c = dash["client"]
    beat(c, uptime_s=300)
    c.post("/api/device/esp32-test-01/event", json={
        "event": "INSTALL", "stage": "INSTALL", "result": "SUCCESS",
        "from_version": "1.0.0", "to_version": "2.0.0", "security_version": 2})
    dash["db"]._exec("UPDATE ota_events SET ts = ? WHERE event = 'INSTALL'",
                     (time.time() - 60,))
    beat(c, uptime_s=5, firmware_version="2.0.0",
         firmware_version_code=0x020000, security_version=2)
    assert c.get("/api/dashboard/summary").get_json()["version_mismatch"] is None


# ---------------------------------------------------------------- security

def test_lab_detects_every_attack(dash):
    """The lab must report PROTECTED for tampering and VERIFIED for a good
    package. This runs the project's real tamper/verify tools."""
    from server.dashboard import sectest
    if not sectest.keys_present():
        pytest.skip("keys/ not generated on this machine")

    c = dash["client"]
    dash["add_package"]("2.0.0", 2)  # gives the lab a base package to corrupt

    expected = {"valid": "VERIFIED"}
    for key in sectest.TESTS:
        r = c.post(f"/api/security/lab/{key}")
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["status"] == expected.get(key, "PROTECTED"), \
            f"{key}: {body['status']} -- {body['result_line']}"


def test_lab_rejects_an_unknown_test(dash):
    assert dash["client"].post("/api/security/lab/../../etc").status_code in (400, 404)


def test_crypto_status_never_exposes_key_material(dash):
    c = dash["client"]
    beat(c, key_fingerprint="1e66187f5ecb349b",
         signer_fingerprint="38dfcd5967abc244")
    blob = json.dumps(c.get("/api/dashboard/summary").get_json())

    keys_dir = ROOT / "keys"
    if (keys_dir / "ota_enc_key.hex").exists():
        enc = "".join(
            line.split("#", 1)[0].strip()
            for line in (keys_dir / "ota_enc_key.hex").read_text(
                encoding="utf-8").splitlines())
        assert enc and enc not in blob
    if (keys_dir / "ed25519_private.pem").exists():
        pem = (keys_dir / "ed25519_private.pem").read_text(encoding="utf-8")
        body = "".join(line for line in pem.splitlines()
                       if "-----" not in line).strip()
        assert body and body not in blob

    assert "BEGIN PRIVATE KEY" not in blob
    assert "1e66187f5ecb349b" in blob  # the fingerprint itself is fine


def test_no_endpoint_returns_a_private_key(dash):
    c = dash["client"]
    beat(c)
    for path in ("/api/dashboard/summary", "/api/firmware", "/api/devices",
                 "/api/security/events", "/api/logs", "/api/ota/history",
                 "/api/devices/esp32-test-01"):
        text = c.get(path).get_data(as_text=True)
        for forbidden in ("BEGIN PRIVATE KEY", "ed25519_private", "PRIVATE KEY"):
            assert forbidden not in text, f"{path} leaked {forbidden}"


def test_dashboard_holds_no_key_material_in_its_own_responses(dash):
    """packaging.py may reference key *paths* -- it runs the signing tool -- but
    no route may return their contents."""
    c = dash["client"]
    r = c.post("/api/firmware/upload",
               data={"file": (io.BytesIO(b"\xe9" + os.urandom(255)), "k.bin")},
               content_type="multipart/form-data")
    assert r.status_code == 201
    body = c.post("/api/firmware/package",
                  json={"file": "k.bin", "version": "6.0.0",
                        "security_version": 6}).get_data(as_text=True)
    assert "PRIVATE KEY" not in body
    assert "ed25519_private.pem" not in body or "keys" not in body.split("ed25519_private.pem")[0][-40:]


# -------------------------------------------------------------------- logs

def test_logs_capture_server_activity(dash):
    c = dash["client"]
    dash["add_package"]("2.0.0", 2)
    c.get("/api/firmware/latest?device=esp32-test-01")

    lines = c.get("/api/logs").get_json()["lines"]
    assert any("update check" in ln["message"] for ln in lines)


def test_device_can_push_a_log_line(dash):
    c = dash["client"]
    assert c.post("/api/device/log", json={"device_id": "esp32-test-01",
                                           "message": "hello"}).status_code == 200
    assert c.post("/api/device/log", json={"device_id": "x"}).status_code == 400
    lines = c.get("/api/logs").get_json()["lines"]
    assert any("hello" in ln["message"] for ln in lines)
