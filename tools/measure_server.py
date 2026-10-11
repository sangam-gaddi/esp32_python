#!/usr/bin/env python3
"""
Measurement OTA server -- for the evaluation campaign only.

Speaks the same two device-facing endpoints as server/app.py, but serves
whichever package the campaign script selects, with whatever metadata it
chooses, and can cut the connection part-way through. That is exactly what a
compromised or failing update server can do, which is the point: every attack
is delivered to the real device over the real network.

    GET  /api/firmware/latest           metadata hint (untrusted by the device)
    GET  /api/firmware/latest/package   the selected package bytes
    POST /bench/select                  JSON {file, version_code, security,
                                              cut_after} -- set what to serve
    POST /bench/none                    serve nothing (metadata returns 404)

Like server/app.py it holds no keys. Run:

    python tools/measure_server.py --port 8000
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_lock = threading.Lock()
_sel: dict | None = None
_log_path: pathlib.Path | None = None


def log(event: dict) -> None:
    event["t"] = time.time()
    line = json.dumps(event)
    print(line, flush=True)
    if _log_path:
        with _log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence the default access log
        pass

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global _sel
        n = int(self.headers.get("Content-Length") or 0)
        data = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/bench/select":
            with _lock:
                _sel = data
            log({"ev": "select", **data})
            return self._json(200, {"ok": True})
        if self.path == "/bench/none":
            with _lock:
                _sel = None
            log({"ev": "select_none"})
            return self._json(200, {"ok": True})
        self._json(404, {"error": "not found"})

    def do_GET(self):
        path = self.path.split("?")[0]
        with _lock:
            sel = dict(_sel) if _sel else None

        if path == "/api/firmware/latest":
            if sel is None:
                return self._json(404, {"error": "no package"})
            size = pathlib.Path(sel["file"]).stat().st_size
            log({"ev": "metadata", "client": self.client_address[0],
                 "file": sel["file"]})
            return self._json(200, {
                "firmware_version_code": sel["version_code"],
                "security_version": sel["security"],
                "package_size": size,
                "package_url": "/api/firmware/latest/package",
            })

        if path == "/api/firmware/latest/package":
            if sel is None:
                return self._json(404, {"error": "no package"})
            blob = pathlib.Path(sel["file"]).read_bytes()
            cut = sel.get("cut_after")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            t0 = time.time()
            limit = len(blob) if cut is None else min(cut, len(blob))
            sent = 0
            try:
                while sent < limit:
                    n = min(16384, limit - sent)
                    self.wfile.write(blob[sent:sent + n])
                    sent += n
                self.wfile.flush()
            except OSError:
                pass
            log({"ev": "package", "file": sel["file"], "sent": sent,
                 "total": len(blob), "cut": cut is not None,
                 "secs": round(time.time() - t0, 3)})
            if cut is not None:
                self.close_connection = True
            return

        self._json(404, {"error": "not found"})


def main() -> int:
    global _log_path
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", type=pathlib.Path, default=None)
    args = ap.parse_args()
    _log_path = args.log
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    log({"ev": "listening", "port": args.port})
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
