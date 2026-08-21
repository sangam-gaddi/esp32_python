#!/usr/bin/env python3
"""SIMULATED ESP32 -- for testing the dashboard without hardware.

    python tools/simulate_device.py                       # idle heartbeats
    python tools/simulate_device.py --ota                 # also fake one OTA run
    python tools/simulate_device.py --device esp32-sim-01

THIS IS NOT A DEVICE. It speaks the same heartbeat/command protocol as
main/device_report.c so the dashboard can be exercised on a laptop, and it is
useful for checking the UI before a demonstration. It performs no cryptography,
downloads nothing, and installs nothing.

Everything it reports is made up. It defaults to the device id `esp32-sim-01`
precisely so it can never be mistaken for the real `esp32-demo-01` on the
dashboard. Do not use it to demonstrate that the OTA pipeline works -- only the
ESP32 can do that.
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time

import requests

STAGES = [
    ("CHECK", 1), ("METADATA", 1), ("SIGNATURE_VERIFY", 1),
    ("VERSION_VERIFY", 1), ("DOWNLOAD", 1), ("DECRYPT", 12),
    ("HASH_VERIFY", 1), ("INSTALL", 2), ("REBOOT", 2),
]

TOTAL_BYTES = 926688


def heartbeat(server: str, payload: dict) -> list[str]:
    r = requests.post(f"{server}/api/device/heartbeat", json=payload, timeout=5)
    r.raise_for_status()
    return r.json().get("commands", [])


def event(server: str, device: str, **kw) -> None:
    requests.post(f"{server}/api/device/{device}/event", json=kw, timeout=5)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--device", default="esp32-sim-01")
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--security-version", type=int, default=1)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--ota", action="store_true",
                    help="run one simulated OTA cycle, then keep idling")
    args = ap.parse_args()

    print("=" * 68)
    print(" SIMULATED DEVICE -- no hardware, no cryptography, invented values")
    print(f" device_id {args.device}   server {args.server}")
    print("=" * 68)

    major, minor, patch = (int(p) for p in args.version.split("."))
    boot = time.time()

    base = {
        "device_id": args.device,
        "ip": "127.0.0.1",
        "firmware_version": args.version,
        "firmware_version_code": (major << 16) | (minor << 8) | patch,
        "security_version": args.security_version,
        "partition": "ota_0", "partition_addr": "0x00160000",
        "free_heap": 201336, "min_free_heap": 189440,
        "ota_state": "IDLE", "ota_done": 0, "ota_total": 0,
        "ota_checks": 0, "ota_rejections": 0,
        "wifi_rssi": -54, "wifi_ssid": "SIMULATED",
        "chip_model": "ESP32", "chip_revision": "v3.1", "chip_cores": 2,
        "flash_size": 4 * 1024 * 1024, "mac": "00:00:00:00:00:00",
        "idf_version": "v5.3.1", "build_time": "simulated",
        "app_version": "simulator",
        "key_fingerprint": "simulated", "signer_fingerprint": "simulated",
        "last_error": "",
    }

    ota_queue: list = []
    if args.ota:
        ota_queue = list(STAGES)

    for tick in itertools.count():
        payload = dict(base, uptime_s=int(time.time() - boot))

        if ota_queue:
            stage, ticks = ota_queue[0]
            payload["ota_state"] = stage
            if stage in ("DECRYPT", "DOWNLOAD"):
                done = int(TOTAL_BYTES * (1 - ticks / 12))
                payload.update(ota_done=max(done, 0), ota_total=TOTAL_BYTES)
            ota_queue[0] = (stage, ticks - 1)
            if ticks - 1 <= 0:
                ota_queue.pop(0)
                if stage == "INSTALL":
                    event(args.server, args.device, event="INSTALL",
                          stage="INSTALL", result="SUCCESS",
                          from_version=args.version, to_version="2.0.0",
                          security_version=2, duration_ms=13800)
                if stage == "REBOOT":
                    boot = time.time()
                    base.update(firmware_version="2.0.0",
                                firmware_version_code=0x020000,
                                security_version=2, partition="ota_1")
                    print("  [sim] rebooted into 2.0.0")

        try:
            commands = heartbeat(args.server, payload)
        except Exception as exc:
            print(f"  [sim] dashboard unreachable: {exc}")
            time.sleep(args.interval)
            continue

        for cmd in commands:
            print(f"  [sim] received command {cmd}")
            if cmd in ("CHECK_UPDATE", "START_OTA"):
                base["ota_checks"] = base["ota_checks"] + 1
                if not ota_queue:
                    ota_queue = list(STAGES)
            elif cmd == "REBOOT":
                boot = time.time()
                print("  [sim] restarting")

        if tick % 10 == 0:
            print(f"  [sim] heartbeat {tick}: state={payload['ota_state']} "
                  f"fw={payload['firmware_version']}")
        time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nstopped")
