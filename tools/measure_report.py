#!/usr/bin/env python3
"""
Turn the raw logs of a measurement campaign into the results table.

Inputs (all under build/measure/):
  bench_run*.log          on-device crypto microbenchmark (BENCH lines)
  serial.log              campaign serial capture, host-timestamped
  campaign_events.jsonl   what the campaign did and what it observed
  host_timing.json        host-side packaging timings and package sizes
  size_components.txt     `idf.py size-components` output

Output: build/measure/results.json and results.md. Every figure is computed from
those files; nothing is typed in by hand.
"""
from __future__ import annotations

import json
import pathlib
import re
import statistics as st

ROOT = pathlib.Path(__file__).resolve().parent.parent
M = ROOT / "build" / "measure"


def stats(xs):
    xs = [float(x) for x in xs]
    if not xs:
        return None
    return {"n": len(xs), "mean": st.mean(xs),
            "sd": st.stdev(xs) if len(xs) > 1 else 0.0,
            "min": min(xs), "max": max(xs)}


def fmt(s, scale=1.0, nd=1):
    if s is None:
        return "n/a"
    return (f"{s['mean'] * scale:.{nd}f} ± {s['sd'] * scale:.{nd}f} "
            f"(min {s['min'] * scale:.{nd}f}, max {s['max'] * scale:.{nd}f}, n={s['n']})")


def main() -> int:
    R: dict = {}

    # ---------------------------------------------------- device microbenchmark
    bench = {"aead_encrypt": [], "aead_decrypt": [], "hash256": [],
             "ed25519_verify": []}
    fw_bytes = None
    for p in sorted(M.glob("bench_run*.log")):
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"BENCH: (\w+) run=\d+ (?:bytes=(\d+) )?us=(\d+)", line)
            if m and m.group(1) in bench:
                bench[m.group(1)].append(int(m.group(3)) / 1000.0)  # ms
                if m.group(2):
                    fw_bytes = int(m.group(2))
    R["device_bench_ms"] = {k: stats(v) for k, v in bench.items()}
    R["device_bench_bytes"] = fw_bytes

    # ------------------------------------------------------------------ events
    events = [json.loads(l) for l in
              (M / "campaign_events.jsonl").read_text().splitlines() if l.strip()]
    serial = []
    for l in (M / "serial.log").read_text(encoding="utf-8",
                                          errors="replace").splitlines():
        t, _, text = l.partition(" ")
        try:
            serial.append((float(t), text))
        except ValueError:
            pass

    def window(phase):
        ts = [e["t"] for e in events if e.get("phase") == phase]
        return (min(ts), max(ts)) if ts else (0, 0)

    def metrics_in(phase, key_rx):
        a, b = window(phase)
        out = []
        for t, text in serial:
            if a - 1 <= t <= b + 1:
                m = re.search(key_rx, text)
                if m:
                    out.append(m)
        return out

    # Phase A: valid updates
    A = [e for e in events if e.get("phase") == "A" and "result" in e]
    succ = [e for e in A if e["result"] == "SUCCESS"]
    R["updates_attempted"] = len(A)
    R["updates_succeeded"] = len(succ)

    rx_s = (r"METRICS success bytes=(\d+) fw=(\d+) payload_ms=(\d+) net_ms=(\d+) "
            r"crypto_ms=(\d+) flash_ms=(\d+) ota_end_ms=(\d+) cycle_ms=(\d+)")
    ms = metrics_in("A", rx_s)
    cols = ["bytes", "fw", "payload_ms", "net_ms", "crypto_ms", "flash_ms",
            "ota_end_ms", "cycle_ms"]
    rows = [dict(zip(cols, map(int, m.groups()))) for m in ms]
    R["ota_rows"] = rows
    R["ota"] = {c: stats([r[c] for r in rows]) for c in cols[2:]}
    R["throughput_net_kBps"] = stats([r["bytes"] / 1024 / (r["net_ms"] / 1000)
                                      for r in rows])
    R["throughput_effective_kBps"] = stats(
        [r["bytes"] / 1024 / (r["payload_ms"] / 1000) for r in rows])
    R["sig_ms_ota"] = stats([int(m.group(1)) / 1000
                             for m in metrics_in("A", r"METRICS sig_us=(\d+)")])
    R["ota_begin_ms"] = stats([int(m.group(1)) for m in
                               metrics_in("A", r"METRICS ota_begin_ms=(\d+)")])
    hm = metrics_in("A", r"METRICS heap heap_base=(\d+) heap_min=(\d+) "
                         r"heap_peak_used=(\d+) heap_min_ever=(\d+) "
                         r"ota_stack_free=(\d+)")
    R["heap_base"] = stats([int(m.group(1)) for m in hm])
    R["heap_min"] = stats([int(m.group(2)) for m in hm])
    R["heap_peak_used"] = stats([int(m.group(3)) for m in hm])
    R["ota_stack_free_words"] = stats([int(m.group(5)) for m in hm])
    R["total_check_to_installed_s"] = stats(
        [e["check_to_installed_s"] for e in succ])
    R["total_check_to_running_valid_s"] = stats(
        [e["check_to_running_valid_s"] for e in succ
         if e.get("check_to_running_valid_s") is not None])

    # Phase B: attacks
    B = [e for e in events if e.get("phase") == "B" and "outcome" in e]
    R["attacks"] = {}
    for e in B:
        a = R["attacks"].setdefault(e["attack"], {"n": 0, "blocked": 0,
                                                  "unchanged": 0, "stages": set(),
                                                  "detect_s": []})
        a["n"] += 1
        a["blocked"] += bool(e["blocked"])
        a["unchanged"] += bool(e["firmware_unchanged"])
        a["stages"].add(e["stage"] or e["outcome"])
        a["detect_s"].append(e["detect_s"])
    for a in R["attacks"].values():
        a["stages"] = sorted(a["stages"])
        a["detect_s"] = stats(a["detect_s"])
    R["attacks_total"] = len(B)
    R["attacks_blocked"] = sum(bool(e["blocked"]) for e in B)
    R["attacks_fw_unchanged"] = sum(bool(e["firmware_unchanged"]) for e in B)

    # Phase C / D: recovery
    C = [e for e in events if e.get("phase") == "C" and "result" in e]
    D = [e for e in events if e.get("phase") == "D" and "result" in e]
    R["powercut_total"] = len(C)
    R["powercut_recovered"] = sum(e["result"] == "RECOVERED" for e in C)
    R["powercut_to_network_s"] = stats([e["cut_to_network_s"] for e in C
                                        if e.get("cut_to_network_s")])
    R["selftest_total"] = len(D)
    R["selftest_rolled_back"] = sum(e["result"] == "ROLLED_BACK" for e in D)
    R["selftest_recover_s"] = stats([e["install_to_recovered_s"] for e in D
                                     if e.get("install_to_recovered_s")])

    # ---------------------------------------------------------------- host side
    H = json.loads((M / "host_timing.json").read_text())
    R["host"] = {k: stats([r[k] for r in H["runs"]]) for k in H["runs"][0]}
    R["package_sizes"] = H["sizes"]

    # ------------------------------------------------------------------ flash
    sz = (M / "size_components.txt").read_text(errors="replace")
    comp = {}
    for line in sz.splitlines():
        cells = [c.strip() for c in line.split("│") if c.strip()]
        if cells and cells[0] in ("libascon.a", "libed25519.a",
                                  "libota_package.a", "libmain.a",
                                  "libapp_update.a"):
            n = [int(c) for c in cells[1:]]
            comp[cells[0]] = {"total": n[0], "dram": n[1], "flash_code": n[7],
                              "flash_data": n[9]}
    R["flash"] = comp

    (M / "results.json").write_text(json.dumps(R, indent=1, default=list))
    print(json.dumps(R, indent=1, default=list))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
