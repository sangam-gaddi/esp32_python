"""Secure OTA web interface -- a Flask blueprint bolted onto the OTA server.

THE PAGE

One page at "/", with one job: upload a firmware .bin, turn it into a signed and
encrypted package, publish it to devices, and explain how to do all three. Every
check applied to an upload lives in uploads.py and is described there.

WHAT THIS LAYER IS ALLOWED TO DO

    * accept, measure and store an uploaded .bin
    * remember what devices report (heartbeats, OTA outcomes)
    * queue one of three commands for a device to pick up
    * run the project's existing packaging and attack tooling in a subprocess
    * copy a signed package from server/staging/ into server/packages/

WHAT IT DOES NOT DO

    * it does not verify, sign, encrypt, decrypt or hash anything itself
    * it does not modify a package after signing -- publishing is a byte copy
    * it does not touch the existing device-facing routes in server/app.py
    * it does not hold, read back or return key material of any kind
    * it does not serve anything back out of the uploads directory

Several JSON endpoints here outlive the pages that used to draw them -- the
device telemetry APIs, the OTA history, the security events and the attack lab.
They are the device protocol and the project's test surface, and they cost the
page nothing, so they stayed when the pages went. Only "/" has a UI.

Nothing is invented. When a device has reported no value, the answer is null.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import time

from flask import (Blueprint, Response, jsonify, render_template, request,
                   stream_with_context)

from . import builder, db, inventory, logbus, packaging, sectest, uploads

ROOT = pathlib.Path(__file__).resolve().parents[2]

# A device counts as ONLINE if a heartbeat arrived this recently.
HEARTBEAT_TIMEOUT_S = int(os.environ.get("SOTA_HEARTBEAT_TIMEOUT", "15"))
# After INSTALL/REBOOT a device is expected to vanish for a while. Within this
# window it is reported as REBOOTING rather than OFFLINE.
REBOOT_GRACE_S = int(os.environ.get("SOTA_REBOOT_GRACE", "120"))

ALLOWED_COMMANDS = ("CHECK_UPDATE", "START_OTA", "REBOOT")

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# The OTA state machine in main/ota_manager.c, in execution order.
PIPELINE = [
    ("CHECK", "Check"),
    ("METADATA", "Metadata"),
    ("SIGNATURE_VERIFY", "Signature Verification"),
    ("VERSION_VERIFY", "Version Verification"),
    ("DOWNLOAD", "Download"),
    ("DECRYPT", "Decrypt"),
    ("HASH_VERIFY", "Hash Verification"),
    ("INSTALL", "Install"),
    ("REBOOT", "Reboot"),
]

bp = Blueprint("dashboard", __name__,
               template_folder="templates",
               static_folder="static",
               static_url_path="/dashboard/static")


# --------------------------------------------------------------------- helpers

def _valid_device_id(device_id: str) -> bool:
    return bool(device_id) and bool(DEVICE_ID_RE.match(device_id))


def _num(value, default=None):
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _device_status(row: dict | None) -> tuple[str, float | None]:
    """(ONLINE | REBOOTING | OFFLINE | UNKNOWN, seconds since last heartbeat)."""
    if row is None or not row.get("last_seen"):
        return "UNKNOWN", None
    age = time.time() - row["last_seen"]
    if age <= HEARTBEAT_TIMEOUT_S:
        return "ONLINE", age
    if row.get("ota_state") in ("INSTALL", "REBOOT") and age <= REBOOT_GRACE_S:
        return "REBOOTING", age
    return "OFFLINE", age


def _pipeline_view(state: str | None, status: str) -> list[dict]:
    """Mark each stage done / active / pending from the reported OTA state.

    Nothing is inferred beyond the state the device last reported. If the device
    is IDLE or offline every stage is pending -- no invented progress.
    """
    names = [s[0] for s in PIPELINE]
    idx = names.index(state) if state in names else -1
    out = []
    for i, (key, label) in enumerate(PIPELINE):
        if state == "FAILED":
            # The device reports FAILED without saying where; the stage that
            # failed comes from the OTA event, not from a guess here.
            mark = "pending"
        elif idx < 0 or status not in ("ONLINE", "REBOOTING"):
            mark = "pending"
        elif i < idx:
            mark = "done"
        elif i == idx:
            mark = "active"
        else:
            mark = "pending"
        out.append({"key": key, "label": label, "state": mark})
    return out


def _device_json(row: dict | None) -> dict | None:
    if row is None:
        return None
    status, age = _device_status(row)
    d = dict(row)
    d.pop("raw", None)
    d["status"] = status
    d["seconds_since_heartbeat"] = round(age, 1) if age is not None else None
    d["pending_commands"] = db.pending_count(row["device_id"])
    total = row.get("ota_total") or 0
    done = row.get("ota_done") or 0
    d["ota_percent"] = round(done * 100 / total, 1) if total else None
    d["ota_active"] = (status == "ONLINE" and
                       row.get("ota_state") not in (None, "", "IDLE", "FAILED"))
    return d


def _version_mismatch(device: dict | None) -> dict | None:
    """Did the last successful install actually produce the version it claimed?

    The device reports 'installed version X' when it writes the OTA partition,
    and reports its running version on every heartbeat after the reboot. If the
    two disagree the update did *not* deliver what the package said it would --
    typically because the .bin that was packaged still carries the old
    FIRMWARE_VERSION_* constants from main/app_config.h. The dashboard reports
    that plainly instead of assuming success.
    """
    if not device or not device.get("firmware_version"):
        return None
    rows = db.query(
        "SELECT * FROM ota_events WHERE device_id = ? AND event = 'INSTALL' "
        "AND result = 'SUCCESS' ORDER BY ts DESC LIMIT 1",
        (device["device_id"],))
    if not rows:
        return None
    ev = rows[0]
    installed = ev.get("to_version")
    running = device.get("firmware_version")
    if not installed or installed == running:
        return None

    # Only meaningful once the device has actually rebooted into the new image.
    # The device reports uptime, so its boot time is last_seen - uptime; if that
    # is earlier than the install, the reboot has not happened yet.
    if device.get("uptime_s") is not None and device.get("last_seen") and \
            ev.get("ts"):
        boot_time = device["last_seen"] - device["uptime_s"]
        if boot_time < ev["ts"]:
            return None
    return {
        "installed_version": installed,
        "running_version": running,
        "installed_security": ev.get("security_version"),
        "running_security": device.get("security_version"),
        "at": ev.get("ts"),
        "explanation":
            f"The package installed at {time.strftime('%H:%M:%S', time.localtime(ev['ts']))} "
            f"declared firmware {installed}, but the device reports {running} "
            f"after rebooting. The update itself was cryptographically "
            f"verified -- signature, AEAD tag and hash all passed on the device "
            f"-- so what disagrees is the version metadata, not the firmware. "
            f"The packaged .bin was almost certainly built with the old "
            f"FIRMWARE_VERSION_* / SECURITY_VERSION values in "
            f"main/app_config.h. Fix: edit those constants, rebuild with "
            f"idf.py build, and package the new build/secure_ota.bin.",
    }


def _reinstall_loop() -> dict | None:
    """Detect a device reinstalling a version it has already installed.

    This is the failure that hides from _version_mismatch(). That check compares
    an install against the next heartbeat -- but if the image inside the package
    is an *older build*, the device that boots it may not report at all, so no
    heartbeat ever arrives and the mismatch is never noticed. The device is not
    dead; it is looping, and the only evidence is on the device-facing endpoints:
    it keeps downloading the same version it supposedly just installed.

    So the rule is: a successful install of version V, no BOOT event since, and
    two or more downloads of V afterwards. That combination has one cause -- the
    packaged .bin does not identify itself as V.
    """
    rows = db.query(
        "SELECT * FROM ota_events WHERE event = 'INSTALL' AND result = 'SUCCESS' "
        "ORDER BY ts DESC LIMIT 1")
    if not rows:
        return None
    ev = rows[0]
    version = ev.get("to_version")
    if not version or not ev.get("ts"):
        return None

    booted = db.query_one(
        "SELECT COUNT(*) AS n FROM ota_events WHERE event = 'BOOT' AND ts > ?",
        (ev["ts"],))
    if booted and booted["n"]:
        return None  # the device came back and reported; nothing to warn about

    again = db.query_one(
        "SELECT COUNT(*) AS n, MAX(ts) AS last FROM ota_events WHERE "
        "event = 'DOWNLOAD' AND to_version = ? AND ts > ?", (version, ev["ts"]))
    if not again or again["n"] < 2:
        return None

    detail = (
        f"The device installed {version} at "
        f"{time.strftime('%H:%M:%S', time.localtime(ev['ts']))} and has "
        f"downloaded {version} {again['n']} more times since, without ever "
        f"reporting that it booted it. The package is cryptographically valid "
        f"-- the .bin inside it simply is not build {version}. The device "
        f"installs it, reboots, still reports its old version, sees "
        f"{version} offered again, and repeats. Fix: rebuild after setting "
        f"FIRMWARE_VERSION_* / SECURITY_VERSION in main/app_config.h, then "
        f"package that build/secure_ota.bin.")

    # Record it once per install, not once per poll.
    seen = db.query_one(
        "SELECT COUNT(*) AS n FROM security_events WHERE kind = 'STALE_PACKAGE' "
        "AND ts > ?", (ev["ts"],))
    if not seen or not seen["n"]:
        db.add_security_event(
            "warn", "STALE_PACKAGE",
            f"Device is reinstalling {version} repeatedly -- the packaged image "
            f"is not build {version}", detail, ev.get("device_id") or "", "server")
        logbus.push("SERVER", "WARNING",
                    f"stale package: {version} has been installed and "
                    f"re-downloaded {again['n']} times without a boot report")

    return {
        "version": version,
        "downloads_since_install": again["n"],
        "installed_at": ev["ts"],
        "last_download": again["last"],
        "device_id": ev.get("device_id"),
        "explanation": detail,
    }


def _recent_device_http(window_s: int = 120) -> dict | None:
    """Has *something* used the device-facing OTA endpoints recently?

    A device shown as OFFLINE may still be perfectly alive -- running an image
    that predates the reporting task, for instance. The OTA endpoints see that
    traffic even when no heartbeat arrives, and saying so is a good deal more
    useful than a bare OFFLINE.
    """
    row = db.query_one(
        "SELECT COUNT(*) AS n, MAX(ts) AS last FROM ota_events WHERE "
        "event IN ('CHECK', 'DOWNLOAD') AND ts > ?", (time.time() - window_s,))
    if not row or not row["n"]:
        return None
    return {"requests": row["n"], "last": row["last"], "window_s": window_s}


def _crypto_status(device: dict | None) -> list[dict]:
    """Status only. Key material is never read, stored or displayed here.

    The fingerprints, when present, are the ones the firmware already prints on
    boot: Ascon-Hash256 of the key, truncated. They are not key material.
    """
    keys_ok, keys_note = packaging.keys_present()
    return [
        {"name": "Ascon-Hash256", "state": "ACTIVE",
         "detail": "NIST SP 800-232, digest of the plaintext firmware"},
        {"name": "Ascon-AEAD128", "state": "ACTIVE",
         "detail": "NIST SP 800-232, streaming decrypt + tag"},
        {"name": "Ed25519", "state": "ACTIVE",
         "detail": "signature over header[0:96], root of trust"},
        {"name": "Signature verification", "state": "ENFORCED",
         "detail": "device-side, before any payload is downloaded"},
        {"name": "AEAD authentication", "state": "ENFORCED",
         "detail": "tag checked before the boot partition is switched"},
        {"name": "Hash verification", "state": "ENFORCED",
         "detail": "decrypted image compared against the signed digest"},
        {"name": "Anti-rollback", "state": "ENFORCED",
         "detail": "monotonic security version stored in NVS"},
        {"name": "Signing keys on this host",
         "state": "PRESENT" if keys_ok else "MISSING",
         "detail": keys_note},
        {"name": "Device Ascon key fingerprint",
         "state": "REPORTED" if (device or {}).get("key_fingerprint") else "-",
         "detail": (device or {}).get("key_fingerprint") or
                   "not reported by the device yet"},
        {"name": "Device trusted signer fingerprint",
         "state": "REPORTED" if (device or {}).get("signer_fingerprint") else "-",
         "detail": (device or {}).get("signer_fingerprint") or
                   "not reported by the device yet"},
    ]


def _primary_device() -> dict | None:
    devices = db.list_devices()
    return devices[0] if devices else None


# ------------------------------------------------------------ heartbeat intake

def _record_transitions(prev: dict | None, payload: dict, device_id: str) -> None:
    """Notice reboots and version changes between two heartbeats."""
    if prev is None:
        logbus.push("DEVICE", "INFO",
                    f"{device_id}: first heartbeat, firmware "
                    f"{payload.get('firmware_version')}")
        return

    prev_uptime = prev.get("uptime_s")
    new_uptime = payload.get("uptime_s")
    rebooted = (prev_uptime is not None and new_uptime is not None and
                new_uptime < prev_uptime)

    if rebooted:
        old_v = prev.get("firmware_version")
        new_v = payload.get("firmware_version")
        logbus.push("DEVICE", "INFO",
                    f"{device_id}: rebooted (uptime {prev_uptime}s -> "
                    f"{new_uptime}s), firmware {new_v}")
        if old_v != new_v:
            db.add_ota_event(device_id=device_id, event="BOOT",
                             stage="REBOOT", from_version=old_v,
                             to_version=new_v,
                             security_version=payload.get("security_version"),
                             result="SUCCESS",
                             reason="device booted the newly installed image")
            db.add_security_event(
                "ok", "VERSION_TRANSITION",
                f"Firmware transition confirmed: {old_v} -> {new_v}",
                f"Device rebooted and now reports firmware {new_v}, "
                f"security version {payload.get('security_version')}.",
                device_id, "server")
        else:
            pending = db.query(
                "SELECT * FROM ota_events WHERE device_id = ? AND "
                "event = 'INSTALL' AND result = 'SUCCESS' AND ts > ? "
                "ORDER BY ts DESC LIMIT 1", (device_id, time.time() - 600))
            if pending and pending[0].get("to_version") not in (None, new_v):
                db.add_security_event(
                    "warn", "VERSION_MISMATCH",
                    f"Version mismatch after update: package said "
                    f"{pending[0]['to_version']}, device reports {new_v}",
                    "The package was cryptographically verified and installed, "
                    "but the image inside it reports a different version. The "
                    "packaged .bin was probably not rebuilt with the new "
                    "FIRMWARE_VERSION_* values.",
                    device_id, "server")

    if prev.get("ota_state") != payload.get("ota_state") and \
            payload.get("ota_state"):
        logbus.push("DEVICE", "INFO",
                    f"{device_id}: OTA state -> {payload.get('ota_state')}")


@bp.route("/api/device/heartbeat", methods=["POST"])
def device_heartbeat():
    """Called by the ESP32. Payload is telemetry only -- never a security input."""
    payload = request.get_json(silent=True) or {}
    device_id = str(payload.get("device_id") or "").strip()
    if not _valid_device_id(device_id):
        return jsonify({"error": "missing or malformed device_id"}), 400

    payload["ip"] = payload.get("ip") or request.remote_addr

    for key in ("free_heap", "min_free_heap", "uptime_s", "ota_done",
                "ota_total", "security_version", "firmware_version_code",
                "wifi_rssi", "flash_size", "chip_cores", "ota_checks",
                "ota_rejections"):
        if key in payload:
            payload[key] = _num(payload[key])

    prev = db.get_device(device_id)
    _record_transitions(prev, payload, device_id)
    db.upsert_device(device_id, payload)

    commands = [c["command"] for c in db.take_pending_commands(device_id)]
    if commands:
        logbus.push("SERVER", "INFO",
                    f"delivering {', '.join(commands)} to {device_id}")

    return jsonify({
        "ok": True,
        "server_time": int(time.time()),
        "commands": commands,
        "heartbeat_timeout_s": HEARTBEAT_TIMEOUT_S,
    })


@bp.route("/api/device/<device_id>/commands", methods=["GET"])
def device_poll_commands(device_id: str):
    """Called by the ESP32. Returns and clears the pending command queue."""
    if not _valid_device_id(device_id):
        return jsonify({"error": "malformed device_id"}), 400
    rows = db.take_pending_commands(device_id)
    return jsonify({"commands": [{"id": r["id"], "command": r["command"]}
                                 for r in rows]})


@bp.route("/api/device/<device_id>/event", methods=["POST"])
def device_event(device_id: str):
    """Called by the ESP32 to report an OTA outcome or a rejection.

    Accepted events: CHECK, START, INSTALL, REJECT, FAIL. Anything else is
    stored as an OTA event with result UNKNOWN -- it is a log, not a command.
    """
    if not _valid_device_id(device_id):
        return jsonify({"error": "malformed device_id"}), 400

    payload = request.get_json(silent=True) or {}
    event = str(payload.get("event") or "UNKNOWN")[:32]
    stage = str(payload.get("stage") or "")[:32]
    result = str(payload.get("result") or "UNKNOWN")[:16]
    reason = str(payload.get("reason") or "")[:500]

    db.add_ota_event(
        device_id=device_id, event=event, stage=stage,
        from_version=str(payload.get("from_version") or "")[:16],
        to_version=str(payload.get("to_version") or "")[:16],
        security_version=_num(payload.get("security_version")),
        result=result, reason=reason,
        duration_ms=_num(payload.get("duration_ms")))

    logbus.push("DEVICE", "ERROR" if result in ("REJECTED", "FAILED") else "INFO",
                f"{device_id}: {event}" + (f" [{stage}]" if stage else "") +
                f" {result}" + (f" -- {reason}" if reason else ""))

    if result in ("REJECTED", "FAILED"):
        kind = {
            "SIGNATURE_VERIFY": "INVALID_SIGNATURE",
            "VERSION_VERIFY": "ROLLBACK_ATTEMPT",
            "HASH_VERIFY": "HASH_MISMATCH",
            "DECRYPT": "DECRYPTION_FAILURE",
        }.get(stage, "UPDATE_REJECTED")
        db.add_security_event(
            "warn", kind,
            f"Update rejected at {stage or 'OTA'}: {reason or 'no reason given'}",
            "The device refused the package and kept running its current "
            "firmware. Reported by the device itself.",
            device_id, "device")
    elif event == "INSTALL" and result == "SUCCESS":
        db.add_security_event(
            "ok", "UPDATE_VERIFIED",
            f"Package accepted: signature, AEAD tag and hash all verified "
            f"({payload.get('to_version')})",
            "Ed25519 signature, Ascon-AEAD128 tag and Ascon-Hash256 digest "
            "all passed on the device before the boot partition was switched.",
            device_id, "device")

    return jsonify({"ok": True})


@bp.route("/api/device/log", methods=["POST"])
def device_log():
    """Optional: a device pushing a log line into the live viewer."""
    payload = request.get_json(silent=True) or {}
    device_id = str(payload.get("device_id") or "device")[:64]
    message = str(payload.get("message") or "")[:500]
    level = str(payload.get("level") or "INFO")[:8]
    if not message:
        return jsonify({"error": "empty message"}), 400
    logbus.push("DEVICE", level, f"{device_id}: {message}")
    return jsonify({"ok": True})


# ------------------------------------------------------------- dashboard APIs

@bp.route("/api/dashboard/summary")
def summary():
    device_row = _primary_device()
    device = _device_json(device_row)
    latest = inventory.latest_published()
    packages = inventory.all_packages()

    update = None
    if latest and device:
        dev_code = device.get("firmware_version_code") or 0
        if latest["firmware_version_code"] > dev_code:
            update = {
                "current": device.get("firmware_version"),
                "available": latest["firmware_version"],
                "security_version": latest["security_version"],
                "package_size": latest["package_size"],
                "firmware_size": latest["firmware_size"],
                "file": latest["file"],
                "firmware_hash": latest["firmware_hash"],
                "built": latest["built"],
            }

    status = device["status"] if device else "UNKNOWN"
    return jsonify({
        "server": {
            "status": "ONLINE",
            "scheme": request.scheme,
            "published_packages": sum(1 for p in packages
                                      if p["published"] and p["valid"]),
            "staged_packages": sum(1 for p in packages if not p["published"]),
            "invalid_packages": sum(1 for p in packages if not p["valid"]),
            "latest_version": latest["firmware_version"] if latest else None,
            "heartbeat_timeout_s": HEARTBEAT_TIMEOUT_S,
            "time": time.time(),
        },
        "device": device,
        "update": update,
        "pipeline": _pipeline_view(device.get("ota_state") if device else None,
                                   status),
        "crypto": _crypto_status(device_row),
        "version_mismatch": _version_mismatch(device),
        "reinstall_loop": _reinstall_loop(),
        "device_http_activity": _recent_device_http(),
        "history": db.list_ota_events(8),
        "security_events": db.list_security_events(8),
        "commands": db.list_commands(device["device_id"] if device else None, 8),
    })


@bp.route("/api/devices")
def api_devices():
    return jsonify({"devices": [_device_json(r) for r in db.list_devices()],
                    "heartbeat_timeout_s": HEARTBEAT_TIMEOUT_S})


@bp.route("/api/devices/<device_id>")
def api_device(device_id: str):
    row = db.get_device(device_id)
    if row is None:
        return jsonify({"error": f"unknown device {device_id}"}), 404
    return jsonify(_device_json(row))


@bp.route("/api/devices/<device_id>/heartbeat")
def api_device_heartbeat(device_id: str):
    row = db.get_device(device_id)
    if row is None:
        return jsonify({"error": f"unknown device {device_id}"}), 404
    status, age = _device_status(row)
    raw = {}
    try:
        raw = json.loads(row.get("raw") or "{}")
    except ValueError:
        raw = {}
    return jsonify({"device_id": device_id, "status": status,
                    "last_seen": row["last_seen"],
                    "seconds_since_heartbeat": round(age, 1) if age else None,
                    "payload": raw})


@bp.route("/api/devices/<device_id>/command", methods=["POST"])
def api_device_command(device_id: str):
    """Queue one of exactly three commands. There is no generic execution path."""
    if not _valid_device_id(device_id):
        return jsonify({"error": "malformed device_id"}), 400

    payload = request.get_json(silent=True) or {}
    command = str(payload.get("command") or "").strip().upper()
    if command not in ALLOWED_COMMANDS:
        return jsonify({
            "error": f"command must be one of {', '.join(ALLOWED_COMMANDS)}",
            "received": command[:32],
        }), 400

    if db.get_device(device_id) is None:
        return jsonify({
            "error": f"device {device_id} has never reported in; nothing would "
                     f"collect this command"}), 404

    cmd_id = db.queue_command(device_id, command)
    logbus.push("SERVER", "INFO",
                f"queued {command} for {device_id} (id {cmd_id})")
    row = db.get_device(device_id)
    status, _ = _device_status(row)
    return jsonify({
        "ok": True, "id": cmd_id, "command": command, "status": "PENDING",
        "device_status": status,
        "note": ("The device collects commands on its next heartbeat."
                 if status == "ONLINE" else
                 "Device is not online; the command waits in the queue."),
    }), 202


@bp.route("/api/devices/<device_id>/commands")
def api_device_command_list(device_id: str):
    return jsonify({"commands": db.list_commands(device_id, 25)})


# ------------------------------------------------------------- firmware APIs

def _next_version() -> dict:
    """The next version number that every device will actually accept.

    A device installs a package only when it is strictly newer than what it is
    running, and refuses a security version lower than the highest it has ever
    accepted. Choosing that number by hand is where this goes wrong -- reusing
    or lowering it produces a package that is perfectly valid and silently
    ignored, which reads like a broken update rather than a working rule.

    So it is computed instead, from the highest of everything that exists: what
    each device reports, every package on disk, and what the source is set to.
    """
    major = 0
    security = 0

    for row in db.list_devices():
        code = row.get("firmware_version_code") or 0
        major = max(major, code >> 16)
        security = max(security, row.get("security_version") or 0)

    for pkg in inventory.all_packages():
        if not pkg.get("valid"):
            continue
        major = max(major, (pkg.get("firmware_version_code") or 0) >> 16)
        security = max(security, pkg.get("security_version") or 0)

    try:
        text = (ROOT / "main" / "app_config.h").read_text(encoding="utf-8")
        m = re.search(r"#define\s+FIRMWARE_VERSION_MAJOR\s+(\d+)", text)
        if m:
            major = max(major, int(m.group(1)))
        m = re.search(r"#define\s+SECURITY_VERSION\s+(\d+)", text)
        if m:
            security = max(security, int(m.group(1)))
    except OSError:
        pass

    return {"version": f"{min(major + 1, 255)}.0.0",
            "security_version": min(security + 1, 0xFFFFFFFF)}


def _uploads_view() -> list[dict]:
    """Files on disk, annotated with what was recorded when they arrived.

    The filesystem is the source of truth for what exists; the database only
    adds the hash and the image facts. A file that predates the database, or
    that was copied in by hand, still appears -- it is simply unannotated.
    """
    recorded = {row["filename"]: row for row in db.list_uploads(500)}
    rows = []
    for entry in inventory.uploads():
        row = dict(entry)
        info = recorded.get(entry["file"])
        if info:
            row.update({
                "sha256": info["sha256"],
                "original_name": info["original_name"],
                "looks_like_esp32_image": bool(info["image_ok"]),
                "chip": info["chip"], "app_name": info["app_name"],
                "app_version": info["app_version"],
                "idf_version": info["idf_version"],
                "compiled": info["compiled"], "verdict": info["verdict"],
            })
        else:
            # Copied in by hand, or uploaded before there was a record. Read
            # the header now rather than shrugging: "not inspected" next to a
            # file from an entirely different project is how the wrong image
            # gets signed.
            try:
                with open(inventory.UPLOADS_DIR / entry["file"], "rb") as fh:
                    image = uploads.inspect_image(fh.read(512))
            except OSError as exc:
                row["verdict"] = f"unreadable: {exc}"
                rows.append(row)
                continue
            row.update({
                "sha256": "",
                "original_name": "",
                "looks_like_esp32_image": image["magic_ok"],
                "chip": image["chip"], "app_name": image["app_name"],
                "app_version": image["app_version"],
                "idf_version": image["idf_version"],
                "compiled": image["compiled"], "verdict": image["verdict"],
                "recorded": False,
            })
        rows.append(row)
    return rows


@bp.route("/api/firmware")
def api_firmware():
    return jsonify({
        "packages": inventory.all_packages(),
        "uploads": _uploads_view(),
        "releases": db.list_releases(),
        "keys_present": packaging.keys_present()[0],
        "keys_note": packaging.keys_present()[1],
        "max_upload_bytes": uploads.MAX_UPLOAD_BYTES,
        "next": _next_version(),
    })


@bp.route("/api/firmware/build", methods=["GET"])
def api_build_state():
    ok, note = builder.available()
    state = builder.state()
    state["available"] = ok
    state["note"] = note
    return jsonify(state)


def _build_finished(ok: bool, artifact: str, version: str,
                    security_version: int, seconds: float) -> None:
    """Record the built image as an upload so step 3 can package it."""
    if not ok or not artifact:
        logbus.push("BUILD", "ERROR",
                    f"build of {version} failed after {seconds:.0f} s")
        return

    path = inventory.UPLOADS_DIR / artifact
    try:
        image = uploads.inspect_image(path.read_bytes()[:512])
        size = path.stat().st_size
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:  # pragma: no cover - defensive
        logbus.push("BUILD", "ERROR", f"built image unreadable: {exc}")
        return

    db.forget_upload(artifact)
    db.add_upload(
        filename=artifact, original_name=f"built on this PC ({version})",
        size=size, sha256=sha, remote_addr="localhost",
        image_ok=1 if image["magic_ok"] else 0, chip=image["chip"],
        app_name=image["app_name"], app_version=image["app_version"],
        idf_version=image["idf_version"], compiled=image["compiled"],
        verdict=image["verdict"])
    logbus.push("BUILD", "INFO",
                f"built {version} (security {security_version}) in "
                f"{seconds:.0f} s -> {artifact} ({size} bytes)")


@bp.route("/api/firmware/build", methods=["POST"])
def api_build_start():
    """Run `idf.py build` on this machine with the versions from the page."""
    payload = request.get_json(silent=True) or request.form or {}
    version = str(payload.get("version") or "")
    security_version = payload.get("security_version")

    try:
        security_version = packaging.validate_security_version(security_version)
    except packaging.PackagingError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        builder.start(version, security_version, inventory.UPLOADS_DIR,
                      _build_finished)
    except builder.BuildError as exc:
        return jsonify({"error": str(exc)}), 400

    logbus.push("BUILD", "INFO",
                f"building firmware {version} (security {security_version})")
    return jsonify(builder.state()), 202


@bp.route("/api/firmware/upload", methods=["POST"])
def api_firmware_upload():
    """Accept a plaintext .bin. Nothing cryptographic happens here.

    Every check lives in server/dashboard/uploads.py, which streams the body to
    a temporary file, caps its size as it arrives, hashes it, and only then
    moves it into the uploads directory under a sanitised name. Any .bin is
    accepted; what the file turns out to be is reported rather than guessed at.
    """
    if "file" not in request.files:
        return jsonify({"error": "no file part in the request"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "no file selected"}), 400

    try:
        stored = uploads.save_stream(f.stream, inventory.UPLOADS_DIR, f.filename)
    except uploads.UploadError as exc:
        logbus.push("SERVER", "WARNING",
                    f"upload refused ({f.filename!r}): {exc}")
        return jsonify({"error": str(exc)}), exc.status

    image = stored["image"]

    # Identified by content, not by name: the same bytes under a new name are
    # the same firmware, and there is no reason to keep a second copy.
    previous = db.get_upload_by_sha(stored["sha256"])
    if previous and (inventory.UPLOADS_DIR / previous["filename"]).exists():
        (inventory.UPLOADS_DIR / stored["file"]).unlink(missing_ok=True)
        logbus.push("SERVER", "INFO",
                    f"upload {f.filename!r} is byte-identical to "
                    f"{previous['filename']}; kept the existing copy")
        return jsonify({
            "ok": True, "duplicate": True, "file": previous["filename"],
            "size": previous["size"], "sha256": previous["sha256"],
            "image": image,
            "note": f"identical bytes were already uploaded as "
                    f"{previous['filename']}; that copy is being reused",
        }), 200

    if previous:
        # The recorded file is gone from disk; the row is stale.
        db.forget_upload(previous["filename"])

    db.add_upload(
        filename=stored["file"], original_name=stored["original_name"],
        size=stored["size"], sha256=stored["sha256"],
        remote_addr=request.remote_addr or "",
        image_ok=1 if image["magic_ok"] else 0,
        chip=image["chip"], app_name=image["app_name"],
        app_version=image["app_version"], idf_version=image["idf_version"],
        compiled=image["compiled"], verdict=image["verdict"])

    logbus.push("SERVER", "INFO" if image["magic_ok"] else "WARNING",
                f"firmware uploaded: {stored['file']} ({stored['size']} bytes, "
                f"sha256 {stored['sha256'][:16]}...) -- {image['verdict']}")
    if not image["magic_ok"]:
        db.add_security_event(
            "warn", "UPLOAD_NOT_AN_IMAGE",
            f"{stored['file']} does not look like an ESP32 application image",
            f"First byte is {image['first_byte']}, expected 0xE9. The file was "
            f"stored anyway; a device would refuse to boot it.",
            "", "server")

    return jsonify({
        "ok": True, "duplicate": False, "file": stored["file"],
        "original_name": stored["original_name"], "renamed": stored["renamed"],
        "size": stored["size"], "sha256": stored["sha256"],
        "image": image,
        "looks_like_esp32_image": image["magic_ok"],
    }), 201


def _project_name() -> str:
    """The project this firmware belongs to, from the last build."""
    try:
        desc = json.loads(
            (ROOT / "build" / "project_description.json").read_text())
        return str(desc.get("project_name") or "")
    except (OSError, ValueError):
        return ""


def _foreign_image_refusal(path: pathlib.Path, payload: dict):
    """None if this image may be signed, otherwise the response refusing it."""
    if str(payload.get("force") or "").lower() in ("1", "true", "yes"):
        logbus.push("PKG", "WARNING",
                    f"signing {path.name} despite the project check (force)")
        return None

    try:
        with open(path, "rb") as fh:
            image = uploads.inspect_image(fh.read(512))
    except OSError as exc:
        return jsonify({"error": f"cannot read {path.name}: {exc}"}), 400

    expected = _project_name()

    if not image["magic_ok"]:
        what = ("This is source code, not compiled firmware."
                if image.get("looks_like_source")
                else f"Its first byte is {image['first_byte']}, not 0xE9.")
        logbus.push("PKG", "WARNING",
                    f"refused to sign {path.name}: not an ESP32 image")
        return jsonify({
            "error": f"{path.name} is not an ESP32 application image. {what} "
                     f"Signing it would produce a package your device installs "
                     f"and then fails to boot.",
            "hint": "Use step 1, Build the firmware, which compiles this "
                    "project and passes the result straight to this step.",
            "image": image,
        }), 400

    if expected and image["app_name"] and image["app_name"] != expected:
        logbus.push("PKG", "WARNING",
                    f"refused to sign {path.name}: built from project "
                    f"{image['app_name']!r}, not {expected!r}")
        db.add_security_event(
            "warn", "FOREIGN_IMAGE_REFUSED",
            f"Refused to sign {path.name}: it is {image['app_name']}, "
            f"not {expected}",
            "An image from another project installs correctly and then runs "
            "without an OTA client, leaving the device unable to be updated "
            "again. Refused before signing.",
            "", "server")
        return jsonify({
            "error": f"{path.name} was built from the project "
                     f"'{image['app_name']}', not '{expected}'. Refusing to "
                     f"sign it.",
            "why": "It would install correctly -- the signature would be "
                   "genuine and every check would pass -- and then run without "
                   "an OTA client. Your device could never be updated over the "
                   "air again; it would need a USB cable to recover.",
            "hint": f"Use step 1, Build the firmware, to compile "
                    f"'{expected}'. To add new code, put it in main/main.c as "
                    f"a task rather than flashing a separate sketch.",
            "image": image,
        }), 409

    return None


@bp.route("/api/firmware/package", methods=["POST"])
def api_firmware_package():
    """Create a signed, encrypted package by running the existing tool."""
    payload = request.get_json(silent=True) or request.form or {}
    source = str(payload.get("file") or "")
    version = str(payload.get("version") or "")
    security_version = payload.get("security_version")

    try:
        source = packaging.safe_filename(source)
        version = packaging.validate_version(version)
        security_version = packaging.validate_security_version(security_version)
    except packaging.PackagingError as exc:
        return jsonify({"error": str(exc)}), 400

    firmware_path = inventory.UPLOADS_DIR / source
    if not firmware_path.exists():
        return jsonify({"error": f"no uploaded firmware named {source}"}), 404

    # Refuse to sign an image that is not this project's firmware.
    #
    # Signing is the moment a file becomes something a device will install, and
    # every check downstream will pass because the signature is genuine. An
    # image from another project installs perfectly and then runs without an
    # OTA client, so the device can never be updated again -- a brick that only
    # a USB cable recovers. The signature cannot tell you that; the image
    # header can, so it is checked here, once, at the point of no return.
    refusal = _foreign_image_refusal(firmware_path, payload)
    if refusal is not None:
        return refusal

    out_name = f"firmware_v{version}.sota"
    published = inventory.PACKAGES_DIR / out_name
    staged = inventory.STAGING_DIR / out_name
    if published.exists() or staged.exists():
        return jsonify({
            "error": f"{out_name} already exists -- packages are never "
                     f"overwritten. Delete it or pick another version."}), 409

    logbus.push("PKG", "INFO",
                f"creating package {out_name} from {source} "
                f"(security version {security_version})")
    try:
        result = packaging.create_package(firmware_path, version,
                                          security_version, staged)
    except packaging.PackagingError as exc:
        logbus.push("PKG", "ERROR", f"package creation failed: {exc}")
        return jsonify({"error": str(exc)}), 400

    if not result["ok"]:
        logbus.push("PKG", "ERROR",
                    f"package creation failed: {result.get('error')}")
        return jsonify(result), 500

    row = inventory.describe(staged, published=False)
    db.add_release(filename=out_name, version=version,
                   version_code=row.get("firmware_version_code"),
                   security_version=security_version,
                   firmware_size=row.get("firmware_size"),
                   package_size=row.get("package_size"),
                   firmware_hash=row.get("firmware_hash"),
                   built_at=row.get("build_timestamp"),
                   published=0, source_bin=source,
                   notes="created from the dashboard")
    logbus.push("PKG", "INFO",
                f"package ready: {out_name} ({row.get('package_size')} bytes), "
                f"self-verification PASS")
    result["package"] = row
    return jsonify(result), 201


@bp.route("/api/firmware/<path:name>/publish", methods=["POST"])
def api_firmware_publish(name: str):
    """Make a staged package available to the existing OTA server.

    A byte-for-byte copy into server/packages/. The package is not re-signed,
    re-encrypted or modified in any way -- doing so would invalidate the
    signature, which is exactly the property that matters.
    """
    try:
        name = packaging.safe_filename(name if name.endswith(".sota")
                                       else f"firmware_v{name}.sota")
    except packaging.PackagingError as exc:
        return jsonify({"error": str(exc)}), 400

    src = inventory.STAGING_DIR / name
    dst = inventory.PACKAGES_DIR / name
    if not src.exists():
        return jsonify({"error": f"no staged package named {name}"}), 404
    if dst.exists():
        return jsonify({"error": f"{name} is already published"}), 409

    row = inventory.describe(src, published=False)
    if not row["valid"]:
        return jsonify({"error": f"refusing to publish an unparsable package: "
                                 f"{row['error']}"}), 400

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    if dst.stat().st_size != src.stat().st_size:
        dst.unlink(missing_ok=True)
        return jsonify({"error": "copy failed: size mismatch"}), 500

    db.set_published(name, True)
    logbus.push("SERVER", "INFO",
                f"published {name} -- firmware {row['firmware_version']}, "
                f"security {row['security_version']} is now offered to devices")
    db.add_security_event(
        "ok", "PACKAGE_PUBLISHED",
        f"Package published: {name} (firmware {row['firmware_version']}, "
        f"security {row['security_version']})",
        "Copied byte-for-byte from server/staging/ into server/packages/. "
        "The signature covers the header, so publishing cannot alter it.",
        "", "server")
    return jsonify({"ok": True, "package": inventory.describe(dst, True)}), 201


@bp.route("/api/firmware/<path:name>/unpublish", methods=["POST"])
def api_firmware_unpublish(name: str):
    """Withdraw a published package (demo reset). The staged copy is kept."""
    try:
        name = packaging.safe_filename(name if name.endswith(".sota")
                                       else f"firmware_v{name}.sota")
    except packaging.PackagingError as exc:
        return jsonify({"error": str(exc)}), 400

    src = inventory.PACKAGES_DIR / name
    if not src.exists():
        return jsonify({"error": f"{name} is not published"}), 404

    staged = inventory.STAGING_DIR / name
    if not staged.exists():
        inventory.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, staged)
    src.unlink()
    db.set_published(name, False)
    logbus.push("SERVER", "WARNING",
                f"unpublished {name} -- devices are no longer offered it")
    return jsonify({"ok": True})


# ------------------------------------------------------- history / events APIs

@bp.route("/api/ota/history")
def api_history():
    limit = min(_num(request.args.get("limit"), 100) or 100, 500)
    return jsonify({"events": db.list_ota_events(limit)})


@bp.route("/api/security/events")
def api_security_events():
    limit = min(_num(request.args.get("limit"), 100) or 100, 500)
    return jsonify({"events": db.list_security_events(limit),
                    "crypto": _crypto_status(_primary_device())})


@bp.route("/api/security/lab")
def api_lab_list():
    return jsonify({
        "keys_present": sectest.keys_present(),
        "tests": [{"key": k, "label": v[0], "mode": v[1] or "none",
                   "defended_by": v[2]} for k, v in sectest.TESTS.items()],
    })


@bp.route("/api/security/lab/<test_key>", methods=["POST"])
def api_lab_run(test_key: str):
    # ?base=published tampers with the real .sota on disk instead of a small
    # one built for the test. Same keys, same tools, same rejection paths.
    use_published = request.args.get("base") == "published"
    logbus.push("LAB", "INFO", f"running security test: {test_key}")
    try:
        result = sectest.run_test(test_key, use_published=use_published)
    except sectest.LabError as exc:
        logbus.push("LAB", "ERROR", f"{test_key}: {exc}")
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # tooling blew up; report rather than 500 silently
        logbus.push("LAB", "ERROR", f"{test_key}: {exc}")
        return jsonify({"error": f"lab failure: {exc}"}), 500

    severity = "ok" if result["passed"] else "alert"
    if result["mode"] != "none" and result["passed"]:
        severity = "warn"  # an attack was detected: worth showing in red/amber
    db.add_security_event(
        severity, f"LAB_{result['test'].upper().replace('-', '_')}",
        f"{result['label']}: {result['status']}",
        f"{result['headline']} ({result['result_line']})",
        "", "lab")
    logbus.push("LAB", "INFO" if result["passed"] else "ERROR",
                f"{result['label']}: {result['status']} -- {result['headline']}")
    return jsonify(result)


# ----------------------------------------------------------------- logs APIs

@bp.route("/api/logs")
def api_logs():
    after = _num(request.args.get("after"), 0) or 0
    return jsonify({"lines": logbus.since(after), "last_id": logbus.last_id()})


@bp.route("/api/logs/stream")
def api_logs_stream():
    """Server-Sent Events feed of the same ring buffer."""
    after = _num(request.args.get("after"), 0) or 0

    @stream_with_context
    def generate():
        cursor = after
        idle = 0
        while idle < 600:  # ~10 minutes, then the browser reconnects
            lines = logbus.since(cursor)
            if lines:
                cursor = lines[-1]["id"]
                idle = 0
                yield "data: " + json.dumps(lines) + "\n\n"
            else:
                idle += 1
                yield ": keep-alive\n\n"
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------- page

# One page, one job: get a .bin onto the device safely. `/dashboard` and
# `/firmware` are kept as aliases so older links and docs still land somewhere.

def _asset_version() -> str:
    """A token that changes whenever the stylesheet or the script changes.

    Appended to the asset URLs so a browser can never pair a cached script with
    a newer page. That mismatch is not hypothetical -- it presents as the
    script failing on elements the old HTML does not contain, which looks like
    a server fault and is not one.
    """
    static = pathlib.Path(__file__).resolve().parent / "static"
    newest = 0.0
    for name in ("css/site.css", "js/site.js"):
        try:
            newest = max(newest, (static / name).stat().st_mtime)
        except OSError:
            pass
    return str(int(newest))


@bp.route("/")
@bp.route("/dashboard")
@bp.route("/firmware")
def page_index():
    return render_template(
        "index.html",
        asset_version=_asset_version(),
        max_upload_mb=uploads.MAX_UPLOAD_BYTES // (1024 * 1024),
        min_upload_bytes=uploads.MIN_UPLOAD_BYTES)


# ------------------------------------------------------------------ register

def _observe_existing_routes(app) -> None:
    """Record device-facing traffic without touching the existing handlers.

    An after_request hook, so /api/firmware/latest and the package download
    endpoint keep behaving exactly as they did -- this only watches.
    """

    @app.after_request
    def _watch(response):
        try:
            endpoint = request.endpoint or ""
            device = request.args.get("device")
            if endpoint == "latest" and device and _valid_device_id(device):
                db.add_ota_event(device_id=device, event="CHECK",
                                 stage="CHECK", result="OK" if
                                 response.status_code == 200 else "NO_PACKAGE",
                                 reason="" if response.status_code == 200 else
                                        "server has no valid package to offer")
            elif endpoint in ("versioned_package", "latest_package") and \
                    response.status_code == 200:
                version = response.headers.get("X-Firmware-Version", "")
                dev = device if device and _valid_device_id(device) else ""
                db.add_ota_event(device_id=dev, event="DOWNLOAD",
                                 stage="DOWNLOAD", to_version=version,
                                 result="STARTED",
                                 reason=f"{request.remote_addr} began "
                                        f"downloading the package")
        except Exception:
            pass  # observation must never affect the device-facing response
        return response


def register(app) -> None:
    """Attach the dashboard to an existing Flask app."""
    db.init()
    logbus.attach_to_logging()
    inventory.STAGING_DIR.mkdir(parents=True, exist_ok=True)
    inventory.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    app.register_blueprint(bp)
    _observe_existing_routes(app)
    logbus.push("SERVER", "INFO", "web interface ready at /")
