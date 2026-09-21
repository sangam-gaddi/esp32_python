"""Build the firmware from the web page, by driving ESP-IDF on this machine.

This only works because the server runs on the same PC as the toolchain. It is
a convenience for a demonstration, not a build service: there is no sandbox, no
queue and no isolation, and it runs `idf.py build` with the privileges of
whoever started the server. See docs/WEB_INTERFACE.md for why that is
acceptable on a private lab network and nowhere else.

WHAT IT CHANGES

  main/app_config.h   The two version constants are rewritten to the numbers
                      typed on the page, so the source always says what was
                      built. Nothing else in the file is touched, and the edit
                      is refused unless both constants are found exactly once.

WHAT IT RUNS

  idf.py build        In a subprocess, through the ESP-IDF activation profile,
                      in the project directory. No flags beyond `build`; the
                      target and configuration come from the project itself.

Building takes a minute or two, which is far too long to hold an HTTP request
open, so a build runs on a background thread and the page polls for its state.
Exactly one build runs at a time.
"""

from __future__ import annotations

import glob
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP_CONFIG = ROOT / "main" / "app_config.h"
BUILD_DIR = ROOT / "build"
APP_BIN = BUILD_DIR / "secure_ota.bin"

BUILD_TIMEOUT_S = int(os.environ.get("SOTA_BUILD_TIMEOUT", "900"))

# The stages the page ticks off. Each is matched against the build output.
STAGES = [
    ("versions", "Version constants written", None),
    ("configure", "Project configured", "Building ESP-IDF components"),
    ("compile", "Sources compiled", "Generating binary image"),
    ("image", "Application image generated", "Project build complete"),
    ("collect", "Image handed to the packaging step", None),
]

_lock = threading.Lock()
_state: dict = {"running": False, "started_at": 0.0, "finished_at": 0.0,
                "ok": None, "error": "", "log": "", "version": "",
                "security_version": None, "artifact": "", "stages": []}


class BuildError(Exception):
    """The build could not be started, or the toolchain is not usable."""


# ------------------------------------------------------------- the toolchain

def _profile() -> pathlib.Path | None:
    """The ESP-IDF PowerShell activation profile to source before building.

    `idf.py` is not on PATH on a normal Windows install; the Espressif
    installer writes a profile that puts the toolchain, the ninja build and the
    IDF python environment there. SOTA_IDF_PROFILE overrides the search.
    """
    override = os.environ.get("SOTA_IDF_PROFILE")
    if override:
        path = pathlib.Path(override)
        return path if path.exists() else None

    found = sorted(glob.glob(r"C:\Espressif\tools\Microsoft.v*.PowerShell_profile.ps1"))
    if not found:
        return None

    # Prefer the release the project already built against, so a second
    # installed version cannot silently change the toolchain under it.
    wanted = ""
    try:
        import json
        desc = json.loads((BUILD_DIR / "project_description.json").read_text())
        wanted = str(desc.get("idf_version") or "")
    except Exception:
        wanted = ""
    if not wanted:
        wanted = os.environ.get("ESP_IDF_VERSION", "")
    if not wanted and (idf_path := os.environ.get("IDF_PATH")):
        m = re.search(r"v\d+\.\d+(?:\.\d+)?", idf_path)
        wanted = m.group(0) if m else ""

    if wanted:
        for path in found:
            if wanted.lstrip("v") in path:
                return pathlib.Path(path)
    return pathlib.Path(found[0])


def _command() -> list[str]:
    """How to invoke `idf.py build` on this machine."""
    override = os.environ.get("SOTA_BUILD_CMD")
    if override:
        return ["cmd", "/c", override] if os.name == "nt" else \
            ["/bin/sh", "-c", override]

    if shutil.which("idf.py"):
        return [sys.executable, shutil.which("idf.py"), "build"] \
            if shutil.which("idf.py").endswith(".py") else ["idf.py", "build"]

    if os.name == "nt":
        profile = _profile()
        if profile:
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-Command",
                    f". '{profile}' | Out-Null; idf.py build"]

    export = os.environ.get("IDF_PATH", "")
    if export and pathlib.Path(export, "export.sh").exists():
        return ["/bin/sh", "-c",
                f". '{export}/export.sh' >/dev/null 2>&1 && idf.py build"]

    raise BuildError(
        "ESP-IDF was not found on this machine. Build with `idf.py build` in "
        "the ESP-IDF terminal and upload build/secure_ota.bin instead, or set "
        "SOTA_IDF_PROFILE / SOTA_BUILD_CMD.")


def available() -> tuple[bool, str]:
    try:
        _command()
    except BuildError as exc:
        return False, str(exc)
    profile = _profile()
    return True, (f"ESP-IDF via {profile.name}" if profile
                  else "ESP-IDF on PATH")


# --------------------------------------------------------------- the version

VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")


def write_versions(version: str, security_version: int) -> None:
    """Put the numbers typed on the page into main/app_config.h.

    The constants are rewritten rather than overridden on the command line, so
    the file on disk always matches the image that was built. If a constant is
    not found exactly once the edit is abandoned -- guessing at a header this
    project's security depends on is not worth the convenience.
    """
    if not VERSION_RE.match(version or ""):
        raise BuildError(f"version must be major.minor.patch, got {version!r}")
    major, minor, patch = (int(p) for p in version.split("."))
    if max(major, minor, patch) > 255:
        raise BuildError("each version component must be 0-255")
    if not 0 <= int(security_version) <= 0xFFFFFFFF:
        raise BuildError("security version must fit in 32 bits")

    text = APP_CONFIG.read_text(encoding="utf-8")
    edits = {
        "FIRMWARE_VERSION_MAJOR": major,
        "FIRMWARE_VERSION_MINOR": minor,
        "FIRMWARE_VERSION_PATCH": patch,
        "SECURITY_VERSION": int(security_version),
    }
    for name, value in edits.items():
        pattern = re.compile(r"^(#define\s+%s\s+)(\d+)\s*$" % name, re.M)
        if len(pattern.findall(text)) != 1:
            raise BuildError(
                f"expected exactly one '#define {name}' in app_config.h; "
                f"refusing to edit it automatically")
        text = pattern.sub(lambda m, v=value: f"{m.group(1)}{v}", text)

    APP_CONFIG.write_text(text, encoding="utf-8")


# ----------------------------------------------------------------- the build

def state() -> dict:
    with _lock:
        return dict(_state)


def _set(**kw) -> None:
    with _lock:
        _state.update(kw)


def _stages_from(log: str, reached: str | None = None) -> list[dict]:
    out = []
    for key, label, probe in STAGES:
        if probe is None:
            ok = reached == "done" or (key == "versions")
        else:
            ok = probe in log
        out.append({"key": key, "label": label, "ok": bool(ok)})
    if reached != "done":
        # "collect" only happens after a successful build.
        out[-1]["ok"] = False
    return out


def _run_build(version: str, security_version: int, uploads_dir: pathlib.Path,
               on_done) -> None:
    started = time.time()
    log = ""
    try:
        cmd = _command()
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              timeout=BUILD_TIMEOUT_S)
        log = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        ok = proc.returncode == 0 and "Project build complete" in log

        artifact = ""
        if ok:
            if not APP_BIN.exists():
                ok = False
                log += f"\nbuild reported success but {APP_BIN.name} is missing"
            else:
                uploads_dir.mkdir(parents=True, exist_ok=True)
                artifact = f"secure_ota_v{version.replace('.', '_')}.bin"
                target = uploads_dir / artifact
                # A rebuild of the same version replaces its own artifact;
                # that is the one case where overwriting is what the user
                # means. Packages are still never overwritten.
                shutil.copy2(APP_BIN, target)

        _set(running=False, ok=ok, finished_at=time.time(),
             log=log[-8000:], artifact=artifact,
             stages=_stages_from(log, "done" if ok else None),
             error="" if ok else (
                 proc.stderr.strip().splitlines()[-1][:300] if proc.stderr.strip()
                 else "the build did not complete -- see the log below"))
        on_done(ok, artifact, version, security_version, time.time() - started)
    except subprocess.TimeoutExpired:
        _set(running=False, ok=False, finished_at=time.time(),
             error=f"the build did not finish within {BUILD_TIMEOUT_S} s",
             log=log[-8000:], stages=_stages_from(log))
        on_done(False, "", version, security_version, time.time() - started)
    except Exception as exc:  # pragma: no cover - defensive
        _set(running=False, ok=False, finished_at=time.time(),
             error=str(exc)[:300], log=log[-8000:], stages=_stages_from(log))
        on_done(False, "", version, security_version, time.time() - started)


def start(version: str, security_version: int, uploads_dir: pathlib.Path,
          on_done) -> None:
    """Rewrite the versions and start a build. Raises BuildError if it cannot."""
    with _lock:
        if _state["running"]:
            raise BuildError("a build is already running")
    _command()  # fail fast if the toolchain is unusable
    write_versions(version, security_version)

    _set(running=True, ok=None, error="", log="", artifact="",
         started_at=time.time(), finished_at=0.0, version=version,
         security_version=int(security_version), stages=_stages_from(""))

    thread = threading.Thread(
        target=_run_build,
        args=(version, int(security_version), uploads_dir, on_done),
        daemon=True, name="sota-build")
    thread.start()
