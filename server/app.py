#!/usr/bin/env python3
"""OTA update server for the Secure OTA project.

    python server/app.py                        # HTTP on 0.0.0.0:8000
    python server/app.py --https --port 8443    # HTTPS, needs server/certs/

Serves pre-built `.sota` packages from server/packages/ and answers a metadata
query so the device can decide whether to download.

THE SERVER HOLDS NO KEYS. Not the Ed25519 private key, not the Ascon encryption
key, nothing. It reads only the public header fields of packages that were built
and signed elsewhere, and copies bytes to whoever asks. This is deliberate and it
is the main structural reason a compromised server cannot push malicious
firmware: an attacker who owns this machine can delete packages, serve stale
ones, or lie in the JSON metadata, but cannot produce a package the device will
accept, because the device verifies the Ed25519 signature against a key this
machine has never seen.

That also means the metadata this server returns is UNTRUSTED input as far as
the device is concerned. It is a hint used to avoid pointless downloads; every
value that matters is re-read from the signed package header on the device.

Endpoints:

    GET /health                           liveness probe
    GET /api/firmware/latest              metadata for the newest package
    GET /api/firmware/list                metadata for every package
    GET /api/firmware/<version>/package   download a specific package
    GET /api/firmware/latest/package      download the newest package

The web interface (server/dashboard/) registers itself on this app at import
time and owns "/" plus its own /api/... routes. It does not touch the endpoints
above, which are the ones the ESP32 uses. If it fails to load for any reason the
OTA server still starts and still serves devices, and "/" falls back to a plain
status page.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import pathlib
import sys

from flask import Flask, Response, abort, jsonify, request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sotalib import package  # noqa: E402

PACKAGES_DIR = ROOT / "server" / "packages"
CERTS_DIR = ROOT / "server" / "certs"

# The largest ESP32 flash is 16 MB, so no legitimate firmware image is bigger.
# Werkzeug enforces this before a handler runs, which means an oversized body is
# refused at the door rather than buffered. Upload handling caps the stream a
# second time as it is written -- see server/dashboard/uploads.py.
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# Jinja caches templates unless told otherwise, which means an edited page keeps
# serving the old HTML until the process is restarted. On a development server
# that is a trap: the stale page pairs with a fresh stylesheet or script and the
# result looks like a server fault. Python changes still need a restart.
app.config["TEMPLATES_AUTO_RELOAD"] = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ota-server")

# Silence Flask's per-request line; the handlers log something more useful.
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ------------------------------------------------------------------ dashboard
#
# The management layer is optional and additive. It is wrapped so that a missing
# dependency or a broken dashboard module can never stop the OTA server from
# serving devices -- the device-facing routes below are the ones that matter.
DASHBOARD_ENABLED = False
try:
    from server import dashboard as _dashboard  # noqa: E402

    _dashboard.register(app)
    DASHBOARD_ENABLED = True
except Exception as _exc:  # pragma: no cover - defensive
    log.warning("web interface not available (%s); OTA endpoints unaffected",
                _exc)


# --------------------------------------------------------------------------- scan

def scan_packages() -> tuple[list[dict], list[dict]]:
    """Parse every .sota in the packages directory.

    Returns (valid, invalid). Parsing is structural only -- no keys are needed
    or held. A package that will not parse is excluded and reported rather than
    served, so a half-written file cannot be handed to a device.
    """
    valid: list[dict] = []
    invalid: list[dict] = []

    if not PACKAGES_DIR.is_dir():
        return valid, invalid

    for path in sorted(PACKAGES_DIR.glob("*.sota")):
        try:
            blob = path.read_bytes()
            header, _ = package.parse_package(blob)
        except package.PackageError as exc:
            invalid.append({"file": path.name, "reason": str(exc)})
            continue
        except OSError as exc:
            invalid.append({"file": path.name, "reason": f"unreadable: {exc}"})
            continue

        valid.append({
            "file": path.name,
            "path": path,
            "format_version": header.format_version,
            "firmware_version": package.decode_version(header.firmware_version),
            "firmware_version_code": header.firmware_version,
            "security_version": header.security_version,
            "firmware_size": header.firmware_size,
            "package_size": len(blob),
            "build_timestamp": header.build_timestamp,
            "built": datetime.datetime.fromtimestamp(
                header.build_timestamp, datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "firmware_hash": header.firmware_hash.hex(),
            "nonce": header.nonce.hex(),
        })

    valid.sort(key=lambda e: e["firmware_version_code"], reverse=True)
    return valid, invalid


def metadata_json(entry: dict) -> dict:
    """The subset the device consumes. Kept small and stable."""
    return {
        "format_version": entry["format_version"],
        "firmware_version": entry["firmware_version"],
        "firmware_version_code": entry["firmware_version_code"],
        "security_version": entry["security_version"],
        "firmware_size": entry["firmware_size"],
        "package_size": entry["package_size"],
        "package_name": entry["file"],
        "package_url": f"/api/firmware/{entry['firmware_version']}/package",
        "firmware_hash": entry["firmware_hash"],
        "built": entry["built"],
    }


def client_desc() -> str:
    device = request.args.get("device", "-")
    return f"{request.remote_addr} device={device}"


# ------------------------------------------------------------------------ routes

@app.route("/health")
def health():
    valid, invalid = scan_packages()
    return jsonify({
        "status": "ok",
        "packages": len(valid),
        "invalid_packages": len(invalid),
        "scheme": request.scheme,
    })


@app.route("/api/firmware/latest")
def latest():
    valid, invalid = scan_packages()
    for bad in invalid:
        log.warning("ignoring unusable package %s: %s", bad["file"], bad["reason"])

    if not valid:
        log.warning("update check from %s -- no valid packages available",
                    client_desc())
        return jsonify({
            "error": "no firmware packages available",
            "hint": "build one with tools/create_ota_package.py into server/packages/",
        }), 404

    entry = valid[0]
    current = request.args.get("current")
    log.info("update check from %s -- offering %s (security %d, %d bytes)%s",
             client_desc(), entry["firmware_version"], entry["security_version"],
             entry["package_size"],
             f", device reports {current}" if current else "")
    return jsonify(metadata_json(entry))


@app.route("/api/firmware/list")
def list_all():
    valid, invalid = scan_packages()
    log.info("package list requested by %s (%d valid, %d invalid)",
             client_desc(), len(valid), len(invalid))
    return jsonify({
        "count": len(valid),
        "packages": [metadata_json(e) for e in valid],
        "invalid": invalid,
    })


def _send_package(entry: dict) -> Response:
    path: pathlib.Path = entry["path"]
    try:
        blob = path.read_bytes()
    except OSError as exc:
        log.error("cannot read %s: %s", path.name, exc)
        abort(500, description="package unreadable")

    # Re-check on the way out. The file may have changed since the scan, and a
    # device should never be handed a package the server knows is broken.
    try:
        package.parse_package(blob)
    except package.PackageError as exc:
        log.error("refusing to serve corrupt package %s: %s", path.name, exc)
        abort(500, description=f"package failed validation: {exc}")

    log.info("serving %s (%d bytes) to %s", path.name, len(blob), client_desc())
    return Response(
        blob,
        mimetype="application/octet-stream",
        headers={
            "Content-Length": str(len(blob)),
            "Content-Disposition": f'attachment; filename="{path.name}"',
            "X-Firmware-Version": entry["firmware_version"],
            "X-Security-Version": str(entry["security_version"]),
            "Cache-Control": "no-store",
        },
    )


@app.route("/api/firmware/latest/package")
def latest_package():
    valid, _ = scan_packages()
    if not valid:
        log.warning("download request from %s but no packages exist", client_desc())
        abort(404, description="no firmware packages available")
    return _send_package(valid[0])


@app.route("/api/firmware/<version>/package")
def versioned_package(version: str):
    valid, _ = scan_packages()
    for entry in valid:
        if entry["firmware_version"] == version or entry["file"] == version:
            return _send_package(entry)
    log.warning("download request from %s for unknown version %r",
                client_desc(), version)
    abort(404, description=f"no package for version {version}")


# The web interface owns "/". It is registered by server/dashboard/ above, so a
# route is only defined here when the interface failed to load -- in which case
# the device-facing endpoints still work and the page says so.
if not DASHBOARD_ENABLED:

    @app.route("/")
    def index():
        valid, invalid = scan_packages()
        rows = "".join(
            f"<li><code>{e['file']}</code> &mdash; firmware "
            f"{e['firmware_version']}, security {e['security_version']}, "
            f"{e['package_size']:,} bytes</li>" for e in valid) or (
            "<li><em>No packages yet.</em></li>")
        return f"""<!doctype html>
<title>Secure OTA update server</title>
<style>body {{ font-family: system-ui, sans-serif; margin: 2rem auto;
  max-width: 44rem; padding: 0 1rem; line-height: 1.6; }}</style>
<h1>Secure OTA update server</h1>
<p><strong>The web interface did not load</strong>, so this is the bare server.
Devices are unaffected &mdash; the update endpoints below are working. Check the
console for the reason (usually a missing dependency from
<code>server/requirements.txt</code>).</p>
<h2>Packages ({len(valid)} valid, {len(invalid)} rejected)</h2>
<ul>{rows}</ul>
<h2>API</h2>
<ul>
  <li><code><a href="/api/firmware/latest">/api/firmware/latest</a></code></li>
  <li><code><a href="/api/firmware/list">/api/firmware/list</a></code></li>
  <li><code>/api/firmware/&lt;version&gt;/package</code></li>
  <li><code><a href="/health">/health</a></code></li>
</ul>
"""


@app.errorhandler(413)
def too_large(err):
    return jsonify({
        "error": f"the upload is larger than the "
                 f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit; no ESP32 "
                 f"firmware image is that big",
    }), 413


@app.errorhandler(404)
def not_found(err):
    return jsonify({"error": str(getattr(err, "description", "not found"))}), 404


@app.errorhandler(500)
def server_error(err):
    return jsonify({"error": str(getattr(err, "description", "server error"))}), 500


# -------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0",
                    help="bind address (default 0.0.0.0, i.e. reachable on the LAN)")
    ap.add_argument("--port", type=int, default=None,
                    help="port (default 8000 for HTTP, 8443 for HTTPS)")
    ap.add_argument("--https", action="store_true",
                    help="serve TLS using server/certs/server_cert.pem and "
                         "server_key.pem (create them with tools/make_dev_certs.py)")
    args = ap.parse_args()

    port = args.port if args.port else (8443 if args.https else 8000)

    ssl_context = None
    if args.https:
        cert = CERTS_DIR / "server_cert.pem"
        key = CERTS_DIR / "server_key.pem"
        if not cert.exists() or not key.exists():
            log.error("TLS requested but %s / %s are missing", cert.name, key.name)
            log.error("create them with: python tools/make_dev_certs.py --ip <server-ip>")
            return 2
        ssl_context = (str(cert), str(key))

    valid, invalid = scan_packages()
    scheme = "https" if args.https else "http"

    log.info("=" * 64)
    log.info("Secure OTA update server")
    log.info("=" * 64)
    log.info("packages directory : %s", PACKAGES_DIR)
    log.info("packages available : %d valid, %d rejected", len(valid), len(invalid))
    for e in valid:
        log.info("   %-34s firmware %-8s security %d",
                 e["file"], e["firmware_version"], e["security_version"])
    for b in invalid:
        log.warning("   %-34s REJECTED: %s", b["file"], b["reason"])
    if not valid:
        log.warning("No packages yet. Build one:")
        log.warning("  python tools/create_ota_package.py --firmware build/secure_ota.bin \\")
        log.warning("      --version 2.0.0 --security-version 2 \\")
        log.warning("      --output server/packages/firmware_v2.0.0.sota")

    log.info("listening on       : %s://%s:%d", scheme, args.host, port)
    if DASHBOARD_ENABLED:
        log.info("open in a browser  : %s://localhost:%d/", scheme, port)
    else:
        log.warning("web interface      : NOT LOADED (see the warning above)")
    if not args.https:
        log.warning("transport          : plain HTTP -- DEVELOPMENT ONLY, not secure")
        log.warning("                     package-level crypto is still fully enforced")
    log.info("this server holds NO keys")
    log.info("=" * 64)

    # threaded=True so a slow device download does not block metadata checks.
    app.run(host=args.host, port=port, ssl_context=ssl_context, threaded=True,
            debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
