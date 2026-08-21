#!/usr/bin/env python3
"""Compile and run the host-side C tests.

The point of these tests is that they build the *same* C sources the ESP32
firmware links against, on the development machine, where they can actually be
executed. Everything in ``components/ascon``, ``components/ed25519`` and
``components/ota_package`` is deliberately free of ESP-IDF dependencies so this
is possible.

Usage:
    python tests/host/build_and_run.py            # build and run everything
    python tests/host/build_and_run.py ascon      # one target only
    python tests/host/build_and_run.py --keep     # leave binaries in build/

Compiler: uses gcc or clang if either is on PATH, otherwise falls back to MSVC
(Visual Studio Build Tools) by locating vcvars64.bat. Exits non-zero if no
compiler is available, or if any test fails.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "tests" / "host"

INCLUDES = [
    ROOT / "components" / "ascon" / "include",
    ROOT / "components" / "ed25519" / "include",
    ROOT / "components" / "ota_package" / "include",
    HOST,
]

ASCON_SRC = [
    ROOT / "components" / "ascon" / "src" / "hash.c",
    ROOT / "components" / "ascon" / "src" / "permutations.c",
    ROOT / "components" / "ascon" / "src" / "ascon_hash256.c",
    ROOT / "components" / "ascon" / "src" / "ascon_aead128.c",
]

ED25519_SRC = [
    ROOT / "components" / "ed25519" / "src" / "tweetnacl.c",
    ROOT / "components" / "ed25519" / "src" / "ed25519_verify.c",
]

PACKAGE_SRC = [
    ROOT / "components" / "ota_package" / "src" / "ota_package.c",
]

TARGETS: dict[str, dict] = {
    "ascon": {
        "main": HOST / "test_ascon_kat.c",
        "sources": ASCON_SRC,
        "args": [
            str(ROOT / "tests" / "vectors" / "LWC_HASH_KAT_128_256.txt"),
            str(ROOT / "tests" / "vectors" / "LWC_AEAD_KAT_128_128.txt"),
        ],
    },
    "package": {
        "main": HOST / "test_package_parser.c",
        "sources": ASCON_SRC + ED25519_SRC + PACKAGE_SRC,
        # directory of fixtures produced by tests/host/make_fixtures.py
        "args": [str(ROOT / "build" / "host_fixtures")],
    },
}


# ------------------------------------------------------------------- compiler discovery

def find_vcvars() -> str | None:
    roots = [
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
    ]
    for r in roots:
        hits = sorted(glob.glob(os.path.join(
            r, "Microsoft Visual Studio", "*", "*", "VC", "Auxiliary", "Build",
            "vcvars64.bat")))
        if hits:
            return hits[-1]
    return None


class Compiler:
    def __init__(self, kind: str, path: str | None = None):
        self.kind = kind
        self.path = path

    def describe(self) -> str:
        return self.kind + (f" ({self.path})" if self.path else "")

    def build(self, out_exe: Path, main: Path, sources: list[Path],
              workdir: Path) -> tuple[bool, str]:
        inc = [str(i) for i in INCLUDES]
        files = [str(main)] + [str(s) for s in sources]

        if self.kind in ("gcc", "clang"):
            cmd = [self.kind, "-std=c11", "-O2", "-Wall", "-Wextra",
                   "-Wno-unused-parameter"]
            for i in inc:
                cmd += ["-I", i]
            cmd += files + ["-o", str(out_exe)]
            p = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True)
            return p.returncode == 0, p.stdout + p.stderr

        # MSVC, driven through a generated .bat file. Handing cmd /c a single
        # quoted 'call vcvars && cl ...' string gets mangled by the Windows
        # argument-quoting rules, so write the script out instead.
        # /W3 rather than /W4: MSVC's noise about portable C is not useful here.
        incflags = " ".join(f'/I "{i}"' for i in inc)
        filelist = " ".join(f'"{f}"' for f in files)
        # No /Fo: a trailing backslash inside a quoted path escapes the quote,
        # and the .bat already runs with workdir as its current directory, so
        # object files land there anyway.
        cl_line = (f'cl /nologo /std:c11 /O2 /W3 /D_CRT_SECURE_NO_WARNINGS '
                   f'{incflags} {filelist} /Fe:"{out_exe}"')
        bat = workdir / f"build_{out_exe.stem}.bat"
        bat.write_text("\r\n".join([
            "@echo off",
            f'call "{self.path}" >nul',
            cl_line,
            "exit /b %ERRORLEVEL%",
        ]) + "\r\n", encoding="ascii")

        p = subprocess.run(["cmd", "/c", str(bat)], cwd=workdir,
                           capture_output=True, text=True)
        return p.returncode == 0, p.stdout + p.stderr


def detect_compiler() -> Compiler:
    for kind in ("gcc", "clang"):
        found = shutil.which(kind)
        if found:
            return Compiler(kind, found)
    vcvars = find_vcvars()
    if vcvars:
        return Compiler("msvc", vcvars)
    print("ERROR: no C compiler found. Install one of:")
    print("  - MinGW-w64 (gcc) or clang, on PATH")
    print("  - Visual Studio Build Tools with the C/C++ workload")
    sys.exit(2)


# -------------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help=f"subset of: {', '.join(TARGETS)}")
    ap.add_argument("--keep", action="store_true",
                    help="build into build/host_tests instead of a temp dir")
    args = ap.parse_args()

    wanted = args.targets or list(TARGETS)
    unknown = [t for t in wanted if t not in TARGETS]
    if unknown:
        print(f"unknown target(s): {unknown}; available: {list(TARGETS)}")
        return 2

    cc = detect_compiler()
    print(f"compiler: {cc.describe()}\n")

    tmp = None
    if args.keep:
        workdir = ROOT / "build" / "host_tests"
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory(prefix="sota_hosttest_")
        workdir = Path(tmp.name)

    failures: list[str] = []
    skipped: list[str] = []
    try:
        for name in wanted:
            spec = TARGETS[name]
            main_c = Path(spec["main"])
            if not main_c.exists():
                print(f"--- {name}: SKIPPED ({main_c.name} not present)\n")
                skipped.append(name)
                continue

            missing = [Path(s).name for s in spec["sources"] if not Path(s).exists()]
            if missing:
                print(f"--- {name}: SKIPPED (missing sources: {missing})\n")
                skipped.append(name)
                continue

            exe = workdir / f"test_{name}.exe"
            print(f"--- {name}: compiling {len(spec['sources']) + 1} files")
            ok, log = cc.build(exe, main_c, [Path(s) for s in spec["sources"]],
                               workdir)
            noteworthy = [ln for ln in log.splitlines()
                          if "error" in ln.lower() or "warning" in ln.lower()]
            for ln in noteworthy[:40]:
                print(f"    {ln}")
            if not ok:
                if not noteworthy:  # show something rather than failing silently
                    for ln in log.splitlines()[-20:]:
                        print(f"    {ln}")
                print(f"--- {name}: BUILD FAILED\n")
                failures.append(name)
                continue

            print(f"--- {name}: running")
            p = subprocess.run([str(exe)] + list(spec["args"]), cwd=ROOT,
                               capture_output=True, text=True)
            for ln in (p.stdout + p.stderr).splitlines():
                print(f"    {ln}")
            if p.returncode != 0:
                failures.append(name)
            print()
    finally:
        if tmp is not None:
            tmp.cleanup()

    if failures:
        print(f"HOST TESTS FAILED: {failures}")
        return 1
    if skipped:
        print(f"HOST TESTS PASSED (skipped: {skipped})")
    else:
        print("HOST TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
