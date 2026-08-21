"""SQLite persistence for the management dashboard.

This database is *only* a record of what happened. Nothing here is trusted by
the device and nothing here participates in a security decision -- the Ed25519
signature, the Ascon-AEAD128 tag, the Ascon-Hash256 digest and the anti-rollback
rule all live in sotalib/ and on the ESP32, exactly where they were before.

Tables:

    devices           latest heartbeat per device (one row per device)
    firmware_releases packages created or uploaded through the dashboard
    ota_events        one row per OTA attempt/outcome reported by a device
    security_events   verification failures, rollback attempts, lab results
    device_commands   the CHECK_UPDATE / START_OTA / REBOOT queue

NO SECRETS ARE STORED HERE. Not the Ascon key, not the Ed25519 private key, not
the Wi-Fi password. Only fingerprints and public metadata.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
import threading
import time

DB_PATH = pathlib.Path(__file__).resolve().parents[1] / "ota.db"

_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id            TEXT PRIMARY KEY,
    first_seen           REAL,
    last_seen            REAL,
    ip                   TEXT,
    firmware_version     TEXT,
    firmware_version_code INTEGER,
    security_version     INTEGER,
    partition            TEXT,
    partition_addr       TEXT,
    free_heap            INTEGER,
    min_free_heap        INTEGER,
    uptime_s             INTEGER,
    ota_state            TEXT,
    ota_done             INTEGER,
    ota_total            INTEGER,
    ota_checks           INTEGER,
    ota_rejections       INTEGER,
    wifi_rssi            INTEGER,
    wifi_ssid            TEXT,
    chip_model           TEXT,
    chip_revision        TEXT,
    chip_cores           INTEGER,
    flash_size           INTEGER,
    mac                  TEXT,
    idf_version          TEXT,
    build_time           TEXT,
    app_version          TEXT,
    key_fingerprint      TEXT,
    signer_fingerprint   TEXT,
    last_error           TEXT,
    raw                  TEXT
);

CREATE TABLE IF NOT EXISTS firmware_releases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       REAL,
    filename         TEXT,
    version          TEXT,
    version_code     INTEGER,
    security_version INTEGER,
    firmware_size    INTEGER,
    package_size     INTEGER,
    firmware_hash    TEXT,
    built_at         INTEGER,
    published        INTEGER DEFAULT 0,
    published_at     REAL,
    source_bin       TEXT,
    notes            TEXT
);

CREATE TABLE IF NOT EXISTS ota_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               REAL,
    device_id        TEXT,
    event            TEXT,
    stage            TEXT,
    from_version     TEXT,
    to_version       TEXT,
    security_version INTEGER,
    result           TEXT,
    reason           TEXT,
    duration_ms      INTEGER
);

CREATE TABLE IF NOT EXISTS security_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL,
    device_id TEXT,
    severity  TEXT,
    kind      TEXT,
    title     TEXT,
    detail    TEXT,
    source    TEXT
);

CREATE TABLE IF NOT EXISTS device_commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL,
    device_id    TEXT,
    command      TEXT,
    status       TEXT,
    delivered_at REAL,
    detail       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ota_events_ts ON ota_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_commands_pending ON device_commands(device_id, status);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init() -> None:
    with _write_lock:
        conn = connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


def _exec(sql: str, params: tuple = ()) -> int:
    with _write_lock:
        conn = connect()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def query(sql: str, params: tuple = ()) -> list[dict]:
    conn = connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


# ------------------------------------------------------------------- devices

DEVICE_FIELDS = (
    "ip", "firmware_version", "firmware_version_code", "security_version",
    "partition", "partition_addr", "free_heap", "min_free_heap", "uptime_s",
    "ota_state", "ota_done", "ota_total", "ota_checks", "ota_rejections",
    "wifi_rssi", "wifi_ssid", "chip_model", "chip_revision", "chip_cores",
    "flash_size", "mac", "idf_version", "build_time", "app_version",
    "key_fingerprint", "signer_fingerprint", "last_error",
)


def upsert_device(device_id: str, payload: dict) -> None:
    """Record the newest heartbeat. Unknown keys in the payload are ignored."""
    now = time.time()
    values = {k: payload.get(k) for k in DEVICE_FIELDS}
    existing = query_one("SELECT device_id FROM devices WHERE device_id = ?",
                         (device_id,))
    raw = json.dumps(payload)[:4000]

    if existing is None:
        cols = ", ".join(("device_id", "first_seen", "last_seen", "raw",
                          *DEVICE_FIELDS))
        marks = ", ".join(["?"] * (4 + len(DEVICE_FIELDS)))
        _exec(f"INSERT INTO devices ({cols}) VALUES ({marks})",
              (device_id, now, now, raw,
               *[values[k] for k in DEVICE_FIELDS]))
    else:
        sets = ", ".join(f"{k} = ?" for k in DEVICE_FIELDS)
        _exec(f"UPDATE devices SET last_seen = ?, raw = ?, {sets} "
              f"WHERE device_id = ?",
              (now, raw, *[values[k] for k in DEVICE_FIELDS], device_id))


def get_device(device_id: str) -> dict | None:
    return query_one("SELECT * FROM devices WHERE device_id = ?", (device_id,))


def list_devices() -> list[dict]:
    return query("SELECT * FROM devices ORDER BY last_seen DESC")


# ------------------------------------------------------------------ releases

def add_release(**kw) -> int:
    kw.setdefault("created_at", time.time())
    cols = ", ".join(kw)
    marks = ", ".join(["?"] * len(kw))
    return _exec(f"INSERT INTO firmware_releases ({cols}) VALUES ({marks})",
                 tuple(kw.values()))


def set_published(filename: str, published: bool) -> None:
    _exec("UPDATE firmware_releases SET published = ?, published_at = ? "
          "WHERE filename = ?",
          (1 if published else 0, time.time() if published else None, filename))


def get_release(filename: str) -> dict | None:
    return query_one("SELECT * FROM firmware_releases WHERE filename = ?",
                     (filename,))


def list_releases() -> list[dict]:
    return query("SELECT * FROM firmware_releases ORDER BY created_at DESC")


# -------------------------------------------------------------------- events

def add_ota_event(**kw) -> int:
    kw.setdefault("ts", time.time())
    cols = ", ".join(kw)
    marks = ", ".join(["?"] * len(kw))
    return _exec(f"INSERT INTO ota_events ({cols}) VALUES ({marks})",
                 tuple(kw.values()))


def list_ota_events(limit: int = 100) -> list[dict]:
    return query("SELECT * FROM ota_events ORDER BY ts DESC LIMIT ?", (limit,))


def add_security_event(severity: str, kind: str, title: str,
                       detail: str = "", device_id: str = "",
                       source: str = "device") -> int:
    return _exec(
        "INSERT INTO security_events (ts, device_id, severity, kind, title, "
        "detail, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (time.time(), device_id, severity, kind, title, detail[:2000], source))


def list_security_events(limit: int = 100) -> list[dict]:
    return query("SELECT * FROM security_events ORDER BY ts DESC LIMIT ?",
                 (limit,))


# ------------------------------------------------------------------ commands

def queue_command(device_id: str, command: str, detail: str = "") -> int:
    return _exec(
        "INSERT INTO device_commands (ts, device_id, command, status, detail) "
        "VALUES (?, ?, ?, 'PENDING', ?)",
        (time.time(), device_id, command, detail))


def take_pending_commands(device_id: str) -> list[dict]:
    """Return pending commands and mark them delivered in one transaction."""
    with _write_lock:
        conn = connect()
        try:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM device_commands WHERE device_id = ? AND "
                "status = 'PENDING' ORDER BY id", (device_id,)).fetchall()]
            if rows:
                conn.execute(
                    "UPDATE device_commands SET status = 'DELIVERED', "
                    "delivered_at = ? WHERE device_id = ? AND status = 'PENDING'",
                    (time.time(), device_id))
                conn.commit()
            return rows
        finally:
            conn.close()


def list_commands(device_id: str | None = None, limit: int = 50) -> list[dict]:
    if device_id:
        return query("SELECT * FROM device_commands WHERE device_id = ? "
                     "ORDER BY id DESC LIMIT ?", (device_id, limit))
    return query("SELECT * FROM device_commands ORDER BY id DESC LIMIT ?",
                 (limit,))


def pending_count(device_id: str) -> int:
    row = query_one("SELECT COUNT(*) AS n FROM device_commands WHERE "
                    "device_id = ? AND status = 'PENDING'", (device_id,))
    return row["n"] if row else 0
