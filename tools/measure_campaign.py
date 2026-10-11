#!/usr/bin/env python3
"""
Drive the on-hardware evaluation campaign against a real ESP32.

Needs tools/measure_server.py running on the port in OTA_SERVER_URL, the board
on --port running a measurement build, and the packages made by
build/measure/make_packages.py. Every serial line is written to
build/measure/serial.log with a host timestamp; the results are computed from
that log afterwards by tools/measure_report.py.

Phases
  A  N valid updates in a row                      -> success rate, timings, RAM
  B  attacks delivered over the network            -> rejection rate
  C  power cut part-way through a download         -> recovery
  D  signed image that fails its self-test         -> bootloader rollback
"""
from __future__ import annotations

import argparse
import json
import pathlib
import queue
import re
import sys
import threading
import time
import urllib.request

import serial  # pyserial

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "measure"
PK = OUT / "pkgs"

ANSI = re.compile(r"\x1b\[[0-9;]*m")
lines: "queue.Queue[tuple[float, str]]" = queue.Queue()
events_path = OUT / "campaign_events.jsonl"


def vcode(major: int) -> int:
    return major << 16


def event(**kw) -> None:
    kw["t"] = time.time()
    print("EVENT", json.dumps(kw), flush=True)
    with events_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(kw) + "\n")


def reader(ser: serial.Serial, logf) -> None:
    buf = b""
    while True:
        try:
            d = ser.read(4096)
        except serial.SerialException:
            return
        if not d:
            continue
        buf += d
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            text = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip("\r")
            t = time.time()
            logf.write(f"{t:.3f} {text}\n")
            logf.flush()
            lines.put((t, text))


def drain() -> None:
    while not lines.empty():
        lines.get_nowait()


def wait_for(patterns: dict[str, str], timeout: float, on_line=None):
    """Return (key, t, line) for the first serial line matching a pattern."""
    comp = {k: re.compile(p) for k, p in patterns.items()}
    end = time.time() + timeout
    while time.time() < end:
        try:
            t, text = lines.get(timeout=0.5)
        except queue.Empty:
            continue
        if on_line and on_line(t, text):
            return "callback", t, text
        for k, rx in comp.items():
            if rx.search(text):
                return k, t, text
    return "timeout", time.time(), ""


def select(server: str, file: pathlib.Path | None, version: int = 0,
           security: int = 24, cut_after: int | None = None) -> None:
    if file is None:
        req = urllib.request.Request(server + "/bench/none", data=b"{}",
                                     method="POST")
    else:
        body = {"file": str(file), "version_code": vcode(version),
                "security": security}
        if cut_after is not None:
            body["cut_after"] = cut_after
        req = urllib.request.Request(server + "/bench/select",
                                     data=json.dumps(body).encode(),
                                     method="POST",
                                     headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


def reset_board(ser: serial.Serial) -> None:
    """Pull EN low through the auto-reset circuit: a hard power-style reset."""
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False


# --------------------------------------------------------------------- phases

def phase_a(server: str, first: int, last: int) -> None:
    for v in range(first, last + 1):
        drain()
        select(server, PK / f"v{v}.sota", v)
        event(phase="A", run=v, action="offer", version=v)
        k, t_check, _ = wait_for({"check": r"OTA: state -> CHECK"}, 60)
        k, t_done, line = wait_for({
            "ok": r"OTA update successful",
            "rej": r"UPDATE REJECTED",
            "idle": r"Already up to date"}, 180)
        if k != "ok":
            event(phase="A", run=v, result="FAIL", why=k, line=line)
            continue
        k2, t_valid, line2 = wait_for({
            "valid": r"Self-test passed -- image marked valid",
            "boot": r"Current Firmware Version"}, 120)
        if k2 == "boot":
            k2, t_valid, line2 = wait_for(
                {"valid": r"Self-test passed -- image marked valid"}, 90)
        k3, _, banner = (k2, t_valid, line2)
        event(phase="A", run=v, result="SUCCESS" if k2 == "valid" else "FAIL",
              check_to_installed_s=round(t_done - t_check, 3),
              check_to_running_valid_s=round(t_valid - t_check, 3)
              if k2 == "valid" else None)


ATTACKS = [
    # (name, package file, hint version, hint security, cut_after, expect)
    ("flip-ciphertext", "atk_flip-ciphertext.sota", 50, 24, None, "rej"),
    ("flip-metadata", "atk_flip-metadata.sota", 50, 24, None, "rej"),
    ("bad-signature", "atk_bad-signature.sota", 50, 24, None, "rej"),
    ("foreign-signer", "atk_foreign-signer.sota", 50, 24, None, "rej"),
    ("wrong-key", "atk_wrong-key.sota", 50, 24, None, "rej"),
    ("hash-mismatch", "atk_hash-mismatch.sota", 50, 24, None, "rej"),
    ("truncate", "atk_truncate.sota", 50, 24, None, "rej"),
    ("bad-magic", "atk_bad-magic.sota", 50, 24, None, "rej"),
    ("rollback-security", "atk_rollback.sota", 50, 24, None, "rej"),
    ("replay-old-lying-hint", "v30.sota", 50, 24, None, "rej"),
    ("replay-old-honest-hint", "v30.sota", 30, 24, None, "idle"),
    ("interrupted-transfer", "base50.sota", 50, 24, "half", "rej"),
]


def phase_b(server: str, reps: int, expect_running: int) -> None:
    for rep in range(1, reps + 1):
        for name, fname, hv, hs, cut, expect in ATTACKS:
            f = PK / fname
            cut_after = f.stat().st_size // 2 if cut == "half" else None
            drain()
            select(server, f, hv, hs, cut_after)
            event(phase="B", attack=name, rep=rep, action="offer")
            k, t_check, _ = wait_for({"check": r"OTA: state -> CHECK"}, 60)
            k, t, line = wait_for({
                "rej": r"UPDATE REJECTED at (\w+)",
                "idle": r"Already up to date",
                "ok": r"OTA update successful"}, 120)
            stage = re.search(r"UPDATE REJECTED at (\w+)", line)
            # the device must still be on the same firmware afterwards
            k2, _, alive = wait_for({"alive": r"BOOT: alive: firmware"}, 30)
            still = f"firmware {expect_running}.0.0" in alive
            event(phase="B", attack=name, rep=rep, outcome=k,
                  stage=stage.group(1) if stage else None,
                  blocked=(k == expect), firmware_unchanged=still,
                  detect_s=round(t - t_check, 3))
            select(server, None)


def phase_c(ser: serial.Serial, server: str, cuts: int, running: int) -> None:
    """Hard-reset the board part-way through a download, `cuts` times."""
    f = PK / "v36bad.sota"
    for n in range(1, cuts + 1):
        drain()
        select(server, f, 36)
        event(phase="C", run=n, action="offer")
        k, t, line = wait_for({"half": r"OTA: +\d+ / \d+ bytes \((4\d|5\d)%\)"},
                              120)
        if k != "half":
            event(phase="C", run=n, result="FAIL", why="no progress")
            continue
        select(server, None)  # so the reboot does not immediately retry
        reset_board(ser)
        t_cut = time.time()
        event(phase="C", run=n, action="power_cut", at=line)
        k, t_boot, banner = wait_for({"boot": r"Current Firmware Version: (\S+)"},
                                     60)
        k2, t_net, _ = wait_for({"net": r"Network ready at"}, 60)
        ver = re.search(r"Version: (\S+)", banner)
        ok = bool(ver) and ver.group(1) == f"{running}.0.0"
        event(phase="C", run=n, result="RECOVERED" if ok else "FAIL",
              booted=ver.group(1) if ver else None,
              cut_to_boot_s=round(t_boot - t_cut, 3),
              cut_to_network_s=round(t_net - t_cut, 3) if k2 == "net" else None)
        time.sleep(2)


def phase_d(server: str, reps: int, running: int) -> None:
    """Install a correctly signed image whose self-test fails."""
    f = PK / "v36bad.sota"
    for n in range(1, reps + 1):
        drain()
        select(server, f, 36)
        event(phase="D", run=n, action="offer")
        k, t_ok, _ = wait_for({"ok": r"OTA update successful",
                               "rej": r"UPDATE REJECTED"}, 180)
        select(server, None)
        if k != "ok":
            event(phase="D", run=n, result="FAIL", why=k)
            continue
        k, _, _ = wait_for({"bad": r"SELFTEST FAILED"}, 90)
        t_fail = time.time()
        k2, t_boot, banner = wait_for(
            {"boot": r"Current Firmware Version: (\S+)"}, 60)
        ver = re.search(r"Version: (\S+)", banner)
        k3, t_net, _ = wait_for({"net": r"Network ready at"}, 60)
        ok = k == "bad" and bool(ver) and ver.group(1) == f"{running}.0.0"
        event(phase="D", run=n, result="ROLLED_BACK" if ok else "FAIL",
              selftest_failed=(k == "bad"),
              booted_after=ver.group(1) if ver else None,
              install_to_recovered_s=round(t_net - t_ok, 3)
              if k3 == "net" else None)
        time.sleep(5)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM10")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--phases", default="ABCD")
    ap.add_argument("--first", type=int, default=26)
    ap.add_argument("--last", type=int, default=35)
    ap.add_argument("--reps", type=int, default=3)
    args = ap.parse_args()

    ser = serial.Serial()
    ser.port = args.port
    ser.baudrate = 115200
    ser.timeout = 0.2
    ser.dtr = False
    ser.rts = False
    ser.open()
    logf = (OUT / "serial.log").open("a", encoding="utf-8")
    threading.Thread(target=reader, args=(ser, logf), daemon=True).start()

    event(action="campaign_start", phases=args.phases)
    if "A" in args.phases:
        phase_a(args.server, args.first, args.last)
    running = args.last
    if "B" in args.phases:
        phase_b(args.server, args.reps, running)
    if "C" in args.phases:
        phase_c(ser, args.server, args.reps, running)
    if "D" in args.phases:
        phase_d(args.server, args.reps, running)
    select(args.server, None)
    event(action="campaign_end")
    time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
