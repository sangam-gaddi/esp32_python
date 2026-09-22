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

@pytest.mark.parametrize("path", ["/", "/dashboard", "/firmware"])
def test_the_one_page_renders(dash, path):
    """One page, reachable at "/" and at the two old URLs."""
    r = dash["client"].get(path)
    assert r.status_code == 200
    assert b"Secure OTA" in r.data


def test_the_page_explains_how_to_use_it(dash):
    body = dash["client"].get("/").get_data(as_text=True)
    assert 'id="how-to-use"' in body
    for expected in ("tools/generate_keys.py", "idf.py build",
                     "python server/app.py", "device_config.h"):
        assert expected in body, f"the how-to-use section never mentions {expected}"


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


def test_a_package_in_both_directories_is_listed_once_as_published(dash):
    """Publishing keeps the staged copy, so a file can be in both places.

    That is still one package, and it is published. Listing it twice -- once
    with a Publish button that can only answer 409 -- misrepresents the state
    of the server.
    """
    c = dash["client"]
    dash["add_package"]("7.0.0", 7, published=True)
    dash["add_package"]("7.0.0", 7, published=False)
    assert (dash["packages"] / "firmware_v7.0.0.sota").exists()
    assert (dash["staging"] / "firmware_v7.0.0.sota").exists()

    rows = [p for p in c.get("/api/firmware").get_json()["packages"]
            if p["file"] == "firmware_v7.0.0.sota"]
    assert len(rows) == 1, f"listed {len(rows)} times, expected once"
    assert rows[0]["published"] is True


def test_packages_are_never_overwritten(dash):
    c = dash["client"]
    c.post("/api/firmware/upload",
           data={"file": (io.BytesIO(b"\xe9" + os.urandom(2047)), "app.bin")},
           content_type="multipart/form-data")
    first = c.post("/api/firmware/package",
                   json={"file": "app.bin", "version": "5.0.0",
                         "security_version": 5})
    assert first.status_code == 201
    again = c.post("/api/firmware/package",
                   json={"file": "app.bin", "version": "5.0.0",
                         "security_version": 5})
    assert again.status_code == 409


def test_the_next_version_is_always_one_a_device_will_accept(dash):
    """Choosing the version by hand is where updates silently stop working.

    A package numbered at or below what a device already runs is perfectly
    valid and completely ignored, which looks like a broken update rather than
    the version rule doing its job. So the page is told what to offer.
    """
    c = dash["client"]

    # Nothing anywhere yet: still ahead of the source tree's own version.
    first = c.get("/api/firmware").get_json()["next"]
    assert first["version"].endswith(".0.0")

    # A device reporting a high version pushes the suggestion above it.
    beat(c, firmware_version="40.0.0",
         firmware_version_code=40 << 16, security_version=41)
    nxt = c.get("/api/firmware").get_json()["next"]
    assert nxt["version"] == "41.0.0"
    assert nxt["security_version"] == 42

    # So does a package on disk, even an unpublished one.
    dash["add_package"]("60.0.0", 7, published=False)
    nxt = c.get("/api/firmware").get_json()["next"]
    assert nxt["version"] == "61.0.0"
    assert nxt["security_version"] == 42, "security follows the highest seen"


# ------------------------------------------------------------------- build

def test_build_writes_the_versions_it_was_given(tmp_path, monkeypatch):
    """The version typed on the page must end up in the source that is built.

    If these drift, the package declares one version and the image reports
    another, and an update "succeeds" while leaving the device on the old
    number.
    """
    from server.dashboard import builder

    header = tmp_path / "app_config.h"
    header.write_text(
        "#ifndef FIRMWARE_VERSION_MAJOR\n#define FIRMWARE_VERSION_MAJOR 2\n#endif\n"
        "#ifndef FIRMWARE_VERSION_MINOR\n#define FIRMWARE_VERSION_MINOR 1\n#endif\n"
        "#ifndef FIRMWARE_VERSION_PATCH\n#define FIRMWARE_VERSION_PATCH 0\n#endif\n"
        "#ifndef SECURITY_VERSION\n#define SECURITY_VERSION 2\n#endif\n"
        "#define NVS_KEY_SECURITY_VERSION \"sec_ver\"\n", encoding="utf-8")
    monkeypatch.setattr(builder, "APP_CONFIG", header)

    builder.write_versions("9.3.1", 11)
    text = header.read_text(encoding="utf-8")
    assert "#define FIRMWARE_VERSION_MAJOR 9" in text
    assert "#define FIRMWARE_VERSION_MINOR 3" in text
    assert "#define FIRMWARE_VERSION_PATCH 1" in text
    assert "#define SECURITY_VERSION 11" in text
    # The guards and unrelated lines survive untouched.
    assert text.count("#ifndef") == 4
    assert 'NVS_KEY_SECURITY_VERSION "sec_ver"' in text


def test_build_refuses_a_version_it_cannot_write_safely(tmp_path, monkeypatch):
    from server.dashboard import builder

    header = tmp_path / "app_config.h"
    monkeypatch.setattr(builder, "APP_CONFIG", header)

    header.write_text("#define FIRMWARE_VERSION_MAJOR 1\n", encoding="utf-8")
    for bad in ("1.0", "300.0.0", "abc", "", "1.0.0.0"):
        with pytest.raises(builder.BuildError):
            builder.write_versions(bad, 1)

    # A header missing a constant is left alone rather than guessed at.
    before = header.read_text(encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.write_versions("2.0.0", 2)
    assert header.read_text(encoding="utf-8") == before


def test_build_endpoint_reports_whether_it_can_run(dash):
    body = dash["client"].get("/api/firmware/build").get_json()
    assert "available" in body and "running" in body
    assert isinstance(body["note"], str)


def test_build_endpoint_validates_before_touching_anything(dash, monkeypatch):
    """A bad request must not edit the header or start a subprocess."""
    from server.dashboard import builder

    def explode(*a, **kw):
        raise AssertionError("a build must not start for an invalid request")

    monkeypatch.setattr(builder, "_run_build", explode)
    c = dash["client"]
    assert c.post("/api/firmware/build",
                  json={"version": "1.0", "security_version": 1}
                  ).status_code == 400
    assert c.post("/api/firmware/build",
                  json={"version": "1.0.0", "security_version": "nope"}
                  ).status_code == 400


# --------------------------------------------------------- upload security

def send(client, data: bytes, name: str):
    return client.post("/api/firmware/upload",
                       data={"file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data")


def image(size: int = 2048) -> bytes:
    """Bytes that pass the ESP32 image magic check."""
    return b"\xe9" + os.urandom(size - 1)


def test_upload_accepts_any_bin_however_it_is_named(dash):
    """'Any .bin' means any .bin. Awkward names are cleaned, never refused."""
    c = dash["client"]
    cases = {
        "My Firmware (v2).BIN": "My_Firmware_v2.bin",
        "../../../../etc/passwd.bin": "passwd.bin",
        r"C:\Users\me\build\secure_ota.bin": "secure_ota.bin",
        "  spaced name .bin": "spaced_name.bin",
        "firmware\u00e9\u00e9.bin": "firmware.bin",
        ".bin": "firmware.bin",
        "NUL.bin": "_NUL.bin",
    }
    for sent, expected in cases.items():
        r = send(c, image(), sent)
        assert r.status_code == 201, (sent, r.get_json())
        stored = r.get_json()["file"]
        # A repeat name gets a suffix, so compare the stem that was derived.
        assert stored.startswith(expected[:-4]), (sent, stored, expected)
        assert stored.endswith(".bin")
        # Everything landed in the uploads directory and nowhere else.
        assert (dash["uploads"] / stored).exists()

    for child in dash["uploads"].iterdir():
        assert child.parent == dash["uploads"]
        assert child.suffix == ".bin"


def test_upload_refuses_anything_that_is_not_a_bin(dash):
    for name in ("evil.exe", "app.bin.exe", "notes.txt", "app", ""):
        r = send(dash["client"], image(), name)
        assert r.status_code == 400, name
    assert not list(dash["uploads"].iterdir())


def test_upload_accepts_a_small_bin_and_says_what_it_is(dash):
    """"Any .bin" includes a tiny one.

    A file too small to be firmware is stored and reported as not being an
    ESP32 image. Refusing it would be this layer second-guessing the user about
    a file it has no authority over -- the device is what decides whether an
    image boots.
    """
    c = dash["client"]
    r = send(c, b"void setup() {}\nvoid loop() {}\n", "blink.ino.bin")
    assert r.status_code == 201, r.get_json()

    body = r.get_json()
    assert body["looks_like_esp32_image"] is False
    assert (dash["uploads"] / body["file"]).exists()


def test_upload_refuses_an_empty_file_and_an_oversized_one(dash):
    from server.dashboard import uploads

    c = dash["client"]
    assert send(c, b"", "empty.bin").status_code == 400

    too_big = uploads.MAX_UPLOAD_BYTES + 1
    r = c.post("/api/firmware/upload",
               data={"file": (io.BytesIO(b"\xe9" * too_big), "huge.bin")},
               content_type="multipart/form-data")
    assert r.status_code == 413

    # Neither attempt left a file or a fragment behind.
    assert not list(dash["uploads"].iterdir())


def test_upload_leaves_no_partial_file_when_the_stream_dies(dash):
    """An upload that fails mid-stream must not be packageable."""
    from server.dashboard import uploads

    class Dying:
        def __init__(self):
            self.sent = 0

        def read(self, n):
            if self.sent >= 4096:
                raise OSError("connection reset")
            self.sent += n
            return b"\xe9" * n

    with pytest.raises(uploads.UploadError):
        uploads.save_stream(Dying(), dash["uploads"], "half.bin")
    assert not list(dash["uploads"].iterdir())


def test_upload_identifies_the_file_by_its_contents(dash):
    c = dash["client"]
    blob = image()

    first = send(c, blob, "app.bin").get_json()
    assert len(first["sha256"]) == 64
    assert first["duplicate"] is False

    # Same bytes, different name: one copy, and the site says why.
    again = send(c, blob, "renamed.bin").get_json()
    assert again["duplicate"] is True
    assert again["file"] == first["file"]
    assert len(list(dash["uploads"].iterdir())) == 1

    different = send(c, image(), "app.bin").get_json()
    assert different["duplicate"] is False
    assert different["sha256"] != first["sha256"]
    assert different["file"] != first["file"], "an upload must never overwrite"
    assert len(list(dash["uploads"].iterdir())) == 2


def test_upload_reports_what_the_image_says_about_itself(dash):
    """The esp_app_desc structure is read back, so a wrong .bin is obvious."""
    import struct

    blob = bytearray(image(512))
    struct.pack_into("<H", blob, 12, 0)                      # chip id: ESP32
    blob[0x20:0xB0] = bytes(0x90)                            # clear esp_app_desc
    struct.pack_into("<I", blob, 0x20, 0xABCD5432)           # app desc magic
    blob[0x30:0x35] = b"9.9.9"                               # version[32]
    blob[0x50:0x5A] = b"secure_ota"                          # project_name[32]
    blob[0x90:0x96] = b"v5.3.1"                              # idf_ver[32]
    blob = bytes(blob) + os.urandom(1536)

    facts = send(dash["client"], blob, "good.bin").get_json()["image"]
    assert facts["magic_ok"] is True
    assert facts["chip"] == "ESP32"
    assert facts["app_name"] == "secure_ota"
    assert facts["app_version"] == "9.9.9"
    assert facts["idf_version"] == "v5.3.1"


def test_source_code_is_named_as_source_not_just_rejected_as_wrong(dash):
    """Uploading the sketch instead of the build output is the common mistake.

    Saying "not an ESP32 image" leaves someone re-uploading the same file.
    Saying "this is source code, it has to be compiled" does not.
    """
    sketch = (b"#define LED_PIN 2\n"
              b"void setup() { pinMode(LED_PIN, OUTPUT); }\n"
              b"void loop() { digitalWrite(LED_PIN, HIGH); delay(500); }\n")
    body = send(dash["client"], sketch, "blink.ino.bin").get_json()

    assert body["looks_like_esp32_image"] is False
    assert body["image"]["looks_like_source"] is True
    assert "compiled" in body["image"]["verdict"]

    # A real image must never be mistaken for source.
    real = send(dash["client"], image(4096), "app.bin").get_json()
    assert real["image"]["looks_like_source"] is False


def test_a_file_that_is_not_an_esp32_image_is_flagged_but_kept(dash):
    """Any .bin is accepted -- but the site must not pretend it is firmware."""
    c = dash["client"]
    r = send(c, b"MZ" + os.urandom(2046), "windows.bin")
    assert r.status_code == 201

    body = r.get_json()
    assert body["looks_like_esp32_image"] is False
    assert body["image"]["first_byte"] == "0x4D"
    assert (dash["uploads"] / body["file"]).exists()

    kinds = [e["kind"] for e in c.get("/api/security/events").get_json()["events"]]
    assert "UPLOAD_NOT_AN_IMAGE" in kinds


def test_the_uploads_directory_is_never_served(dash):
    """An upload is input, not content. Nothing may read it back over HTTP."""
    c = dash["client"]
    name = send(c, image(), "app.bin").get_json()["file"]
    for path in (f"/api/firmware/{name}/package",
                 f"/dashboard/static/../../firmware/uploads/{name}",
                 f"/uploads/{name}", f"/firmware/uploads/{name}"):
        assert c.get(path).status_code in (400, 404, 405), path


def test_the_upload_record_says_which_file_arrived(dash):
    c = dash["client"]
    body = send(c, image(), "My Build.bin").get_json()

    row = next(r for r in c.get("/api/firmware").get_json()["uploads"]
               if r["file"] == body["file"])
    assert row["sha256"] == body["sha256"]
    assert row["original_name"] == "My Build.bin"
    assert row["looks_like_esp32_image"] is True


def test_package_creation_validates_versions(dash):
    c = dash["client"]
    c.post("/api/firmware/upload",
           data={"file": (io.BytesIO(b"\xe9" + os.urandom(2047)), "app.bin")},
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


def esp_image(project: str, size: int = 4096) -> bytes:
    """A .bin whose esp_app_desc names `project`."""
    import struct
    blob = bytearray(b"\xe9" + os.urandom(size - 1))
    struct.pack_into("<H", blob, 12, 0)
    blob[0x20:0xB0] = bytes(0x90)
    struct.pack_into("<I", blob, 0x20, 0xABCD5432)
    blob[0x30:0x35] = b"1.0.0"
    name = project.encode()[:31]
    blob[0x50:0x50 + len(name)] = name
    blob[0x90:0x96] = b"v5.3.1"
    return bytes(blob)


def test_an_image_from_another_project_is_not_signed(dash, monkeypatch):
    """Signing is the point of no return -- a foreign image must stop here.

    A package built from another project's firmware installs perfectly, because
    the signature is genuine and every device-side check passes. It then runs
    without an OTA client, and the device can never be updated again.
    """
    import server.dashboard as dashboard
    monkeypatch.setattr(dashboard, "_project_name", lambda: "secure_ota")

    c = dash["client"]
    send(c, esp_image("arduino-lib-builder"), "sketch.bin")

    r = c.post("/api/firmware/package",
               json={"file": "sketch.bin", "version": "3.0.0",
                     "security_version": 3})
    assert r.status_code == 409, r.get_json()
    body = r.get_json()
    assert "arduino-lib-builder" in body["error"]
    assert "secure_ota" in body["error"]
    assert body["hint"]

    # Nothing was signed, staged or published.
    assert not list(dash["staging"].glob("*.sota"))
    assert not list(dash["packages"].glob("*.sota"))


def test_this_projects_own_image_still_packages(dash, monkeypatch):
    import server.dashboard as dashboard
    monkeypatch.setattr(dashboard, "_project_name", lambda: "secure_ota")

    c = dash["client"]
    send(c, esp_image("secure_ota"), "ours.bin")
    r = c.post("/api/firmware/package",
               json={"file": "ours.bin", "version": "3.1.0",
                     "security_version": 3})
    assert r.status_code == 201, r.get_json()


def test_a_file_that_is_not_an_image_at_all_is_not_signed(dash):
    c = dash["client"]
    send(c, b"#define LED 2\nvoid setup(){}\nvoid loop(){}\n", "sketch.bin")
    r = c.post("/api/firmware/package",
               json={"file": "sketch.bin", "version": "3.2.0",
                     "security_version": 3})
    assert r.status_code == 400
    assert "not an ESP32 application image" in r.get_json()["error"]
    assert not list(dash["staging"].glob("*.sota"))


def test_the_project_check_can_be_overridden_deliberately(dash, monkeypatch):
    """The guard protects against a slip, not against a decision."""
    import server.dashboard as dashboard
    monkeypatch.setattr(dashboard, "_project_name", lambda: "secure_ota")

    c = dash["client"]
    send(c, esp_image("something-else"), "other.bin")
    r = c.post("/api/firmware/package",
               json={"file": "other.bin", "version": "3.3.0",
                     "security_version": 3, "force": True})
    assert r.status_code == 201, r.get_json()


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


def test_reinstall_loop_is_detected(dash):
    """The failure that hides from the mismatch check.

    Observed on hardware: a package labelled 2.0.0 containing an older build.
    The device installs it, reboots into an image that does not report at all,
    sees 2.0.0 offered again, and loops. No heartbeat ever arrives after the
    install, so only the device-facing endpoints show it is still alive.
    """
    c = dash["client"]
    beat(c)
    c.post("/api/device/esp32-test-01/event", json={
        "event": "INSTALL", "stage": "INSTALL", "result": "SUCCESS",
        "from_version": "1.0.0", "to_version": "2.0.0", "security_version": 2})

    # the device keeps pulling the same package; no BOOT is ever reported
    for _ in range(3):
        dash["db"].add_ota_event(device_id="", event="DOWNLOAD",
                                 stage="DOWNLOAD", to_version="2.0.0",
                                 result="STARTED")

    summary = c.get("/api/dashboard/summary").get_json()
    loop = summary["reinstall_loop"]
    assert loop is not None
    assert loop["version"] == "2.0.0"
    assert loop["downloads_since_install"] == 3

    kinds = [e["kind"] for e in c.get("/api/security/events").get_json()["events"]]
    assert "STALE_PACKAGE" in kinds

    # and it is recorded once, not once per poll
    for _ in range(3):
        c.get("/api/dashboard/summary")
    kinds = [e["kind"] for e in c.get("/api/security/events").get_json()["events"]]
    assert kinds.count("STALE_PACKAGE") == 1


def test_reinstall_loop_clears_once_the_device_boots_the_new_image(dash):
    c = dash["client"]
    beat(c, uptime_s=300)
    c.post("/api/device/esp32-test-01/event", json={
        "event": "INSTALL", "stage": "INSTALL", "result": "SUCCESS",
        "from_version": "1.0.0", "to_version": "2.0.0", "security_version": 2})
    for _ in range(3):
        dash["db"].add_ota_event(device_id="", event="DOWNLOAD",
                                 stage="DOWNLOAD", to_version="2.0.0",
                                 result="STARTED")
    assert c.get("/api/dashboard/summary").get_json()["reinstall_loop"]

    # the device reboots into the new version and reports it
    beat(c, uptime_s=5, firmware_version="2.0.0",
         firmware_version_code=0x020000, security_version=2)
    assert c.get("/api/dashboard/summary").get_json()["reinstall_loop"] is None


def test_offline_device_still_using_the_ota_endpoints_is_reported(dash):
    """OFFLINE means 'not reporting', which is not the same as 'not alive'."""
    c = dash["client"]
    dash["add_package"]("2.0.0", 2)
    beat(c)
    dash["db"]._exec("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                     (time.time() - 3600, "esp32-test-01"))

    summary = c.get("/api/dashboard/summary").get_json()
    assert summary["device"]["status"] == "OFFLINE"
    assert summary["device_http_activity"] is None

    c.get("/api/firmware/latest?device=esp32-test-01")
    summary = c.get("/api/dashboard/summary").get_json()
    assert summary["device_http_activity"]["requests"] >= 1


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
               data={"file": (io.BytesIO(b"\xe9" + os.urandom(2047)), "k.bin")},
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
