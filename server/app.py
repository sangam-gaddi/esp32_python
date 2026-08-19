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

    GET /                                 human-readable status page
    GET /health                           liveness probe
    GET /api/firmware/latest              metadata for the newest package
    GET /api/firmware/list                metadata for every package
    GET /api/firmware/<version>/package   download a specific package
    GET /api/firmware/latest/package      download the newest package
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

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ota-server")

# Silence Flask's per-request line; the handlers log something more useful.
logging.getLogger("werkzeug").setLevel(logging.WARNING)


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


@app.route("/")
def index():
    valid, invalid = scan_packages()
    scheme = request.scheme
    banner = ("" if scheme == "https" else
              '<p class="warn"><strong>Transport: plain HTTP &mdash; '
              'development only.</strong> Not secure. The device still enforces '
              'the Ed25519 signature, the Ascon-AEAD128 tag and the '
              'Ascon-Hash256 digest on every package, so tampered firmware is '
              'still rejected &mdash; but the transport itself protects '
              'nothing.</p>')

    rows = "".join(
        f"<tr><td><code>{e['file']}</code></td><td>{e['firmware_version']}</td>"
        f"<td>{e['security_version']}</td><td>{e['firmware_size']:,}</td>"
        f"<td>{e['built']}</td>"
        f"<td><code>{e['firmware_hash'][:16]}&hellip;</code></td>"
        f"<td><a href=\"/api/firmware/{e['firmware_version']}/package\">download</a></td></tr>"
        for e in valid) or (
        '<tr><td colspan="7"><em>No packages. Build one with '
        '<code>tools/create_ota_package.py</code>.</em></td></tr>')

    bad = "".join(
        f"<li><code>{b['file']}</code>: {b['reason']}</li>" for b in invalid)
    bad_block = (f"<h2>Rejected files</h2><ul>{bad}</ul>" if bad else "")

    return f"""<!doctype html>
<title>Secure OTA update server</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
         padding: 0 1rem; line-height: 1.5; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #ddd;
            font-size: .9rem; }}
  code {{ font-size: .85rem; }}
  .warn {{ background: #fff4e5; border-left: 4px solid #e8a33d; padding: .8rem; }}
  .note {{ color: #555; font-size: .9rem; }}
</style>
<h1>Secure OTA update server</h1>
{banner}
<p class="note">This server holds no cryptographic keys. Packages are signed and
encrypted on the build host; the server only stores and serves the bytes.</p>
<h2>Available packages ({len(valid)})</h2>
<table>
  <tr><th>File</th><th>Firmware</th><th>Security</th><th>Size</th><th>Built</th>
      <th>Ascon-Hash256</th><th></th></tr>
  {rows}
</table>
{bad_block}
<h2>API</h2>
<ul>
  <li><code><a href="/api/firmware/latest">/api/firmware/latest</a></code></li>
  <li><code><a href="/api/firmware/list">/api/firmware/list</a></code></li>
  <li><code>/api/firmware/&lt;version&gt;/package</code></li>
  <li><code><a href="/health">/health</a></code></li>
</ul>
"""


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
