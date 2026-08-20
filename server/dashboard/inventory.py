"""Read-only inventory of .sota packages on disk.

Two directories matter:

    server/packages/   PUBLISHED -- the existing OTA server serves these, and
                       the device can download them. Untouched by the dashboard
                       except when publishing copies a file in.

    server/staging/    CREATED BUT NOT PUBLISHED -- a package built through the
                       dashboard waits here. The device never sees this
                       directory; no existing route reads it.

Parsing is structural only, via sotalib.package.parse_package -- the same
parser the rest of the project uses. No keys are needed and none are held.
"""

from __future__ import annotations

import datetime
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sotalib import package  # noqa: E402

PACKAGES_DIR = ROOT / "server" / "packages"
STAGING_DIR = ROOT / "server" / "staging"
UPLOADS_DIR = ROOT / "server" / "firmware" / "uploads"


def describe(path: pathlib.Path, published: bool) -> dict:
    """Parse one package file into a dashboard row, valid or not."""
    row = {
        "file": path.name,
        "published": published,
        "location": "packages" if published else "staging",
        "package_size": 0,
        "valid": False,
        "error": "",
        "modified": path.stat().st_mtime if path.exists() else 0,
    }
    try:
        blob = path.read_bytes()
    except OSError as exc:
        row["error"] = f"unreadable: {exc}"
        return row

    row["package_size"] = len(blob)
    try:
        header, _ = package.parse_package(blob)
    except package.PackageError as exc:
        row["error"] = str(exc)
        return row

    row.update({
        "valid": True,
        "format_version": header.format_version,
        "firmware_version": package.decode_version(header.firmware_version),
        "firmware_version_code": header.firmware_version,
        "security_version": header.security_version,
        "firmware_size": header.firmware_size,
        "build_timestamp": header.build_timestamp,
        "built": datetime.datetime.fromtimestamp(
            header.build_timestamp, datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC"),
        "firmware_hash": header.firmware_hash.hex(),
        "nonce": header.nonce.hex(),
        "auth_tag": header.auth_tag.hex(),
        "signature_head": header.signature.hex()[:32],
        # Structural presence of the two authenticated fields. A full
        # cryptographic verification needs the keys and is what the DEVICE does;
        # the server holds no keys and must not claim more than it can check.
        "has_signature": header.signature != bytes(64),
        "has_auth_tag": header.auth_tag != bytes(16),
    })
    return row


def scan_dir(directory: pathlib.Path, published: bool) -> list[dict]:
    if not directory.is_dir():
        return []
    return [describe(p, published) for p in sorted(directory.glob("*.sota"))]


def all_packages() -> list[dict]:
    """Published first, then staged, newest firmware version first."""
    rows = scan_dir(PACKAGES_DIR, True) + scan_dir(STAGING_DIR, False)
    rows.sort(key=lambda r: (r["published"],
                             r.get("firmware_version_code", 0),
                             r["modified"]), reverse=True)
    return rows


def latest_published() -> dict | None:
    valid = [r for r in scan_dir(PACKAGES_DIR, True) if r["valid"]]
    if not valid:
        return None
    return max(valid, key=lambda r: r["firmware_version_code"])


def uploads() -> list[dict]:
    if not UPLOADS_DIR.is_dir():
        return []
    rows = []
    for p in sorted(UPLOADS_DIR.glob("*.bin")):
        st = p.stat()
        rows.append({"file": p.name, "size": st.st_size,
                     "modified": st.st_mtime})
    rows.sort(key=lambda r: r["modified"], reverse=True)
    return rows
