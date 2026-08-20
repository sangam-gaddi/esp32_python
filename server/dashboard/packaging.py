"""Dashboard wrapper around the existing packaging tool.

There is deliberately NO cryptography in this file. Creating a package means
running `tools/create_ota_package.py` in a subprocess -- the same command a
demonstrator types by hand -- and reporting what it printed. The Ascon-Hash256,
Ascon-AEAD128 and Ed25519 work all happens inside sotalib/, unchanged.

KEY HANDLING. The private key never leaves this machine and never enters an
HTTP response. The browser sends only a firmware file, a version and a security
version; the paths to keys/ed25519_private.pem and keys/ota_enc_key.hex are
resolved here, server-side, and the tool reads them itself. Nothing in this
module returns key bytes, and the parser below extracts only the public header
fields the tool prints (hash, nonce, tag, signature prefix), never the keys.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT / "keys"
TOOL = ROOT / "tools" / "create_ota_package.py"

SIGNING_KEY = KEYS_DIR / "ed25519_private.pem"
ENC_KEY = KEYS_DIR / "ota_enc_key.hex"

VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class PackagingError(Exception):
    """Package creation could not even be attempted, or the tool failed."""


def keys_present() -> tuple[bool, str]:
    missing = [p.name for p in (SIGNING_KEY, ENC_KEY) if not p.exists()]
    if missing:
        return False, ("missing " + ", ".join(missing) +
                       " -- run: python tools/generate_keys.py")
    return True, "keys/ present on the build host"


def validate_version(text: str) -> str:
    text = (text or "").strip()
    if not VERSION_RE.match(text):
        raise PackagingError(
            f"firmware version must be major.minor.patch with each part 0-255, "
            f"got {text!r}")
    if any(int(p) > 255 for p in text.split(".")):
        raise PackagingError("each version component must be 0-255")
    return text


def validate_security_version(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise PackagingError(
            f"security version must be an integer, got {value!r}") from None
    if n < 0 or n > 0xFFFFFFFF:
        raise PackagingError("security version must fit in 32 bits")
    return n


def safe_filename(name: str) -> str:
    name = pathlib.Path(name or "").name
    if not name or not SAFE_NAME_RE.match(name):
        raise PackagingError(f"unsafe or empty file name: {name!r}")
    return name


# The stage list the dashboard animates. Each entry is (key, label); the tool's
# output is matched against `probe` to decide whether the stage really ran.
STAGES = [
    ("load", "Firmware loaded", "firmware size"),
    ("hash", "Ascon-Hash256 generated", "Ascon-Hash256"),
    ("encrypt", "Ascon-AEAD128 encryption", "Ascon tag"),
    ("sign", "Ed25519 signature generated", "Ed25519 signature"),
    ("write", "OTA package generated", "package"),
    ("verify", "Self-verification (signature + tag + hash)",
     "self-verification : PASS"),
]


def _parse_field(stdout: str, label: str) -> str:
    m = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", stdout, re.M)
    return m.group(1).strip() if m else ""


def create_package(firmware_path: pathlib.Path, version: str,
                   security_version: int, output_path: pathlib.Path,
                   timeout: int = 300) -> dict:
    """Run the packaging tool. Returns a result dict for the dashboard.

    Raises PackagingError before touching anything if the inputs are bad or the
    keys are absent. Never overwrites an existing package.
    """
    version = validate_version(version)
    security_version = validate_security_version(security_version)

    ok, why = keys_present()
    if not ok:
        raise PackagingError(why)
    if not firmware_path.exists():
        raise PackagingError(f"firmware image not found: {firmware_path.name}")
    if output_path.exists():
        raise PackagingError(
            f"{output_path.name} already exists -- packages are never "
            f"overwritten; delete it first or choose another version")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(TOOL),
           "--firmware", str(firmware_path),
           "--version", version,
           "--security-version", str(security_version),
           "--output", str(output_path),
           "--signing-key", str(SIGNING_KEY),
           "--enc-key", str(ENC_KEY)]

    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise PackagingError("packaging tool timed out") from None
    except OSError as exc:
        raise PackagingError(f"cannot run the packaging tool: {exc}") from None

    stdout, stderr = proc.stdout, proc.stderr
    success = proc.returncode == 0 and "self-verification : PASS" in stdout

    stages = [{"key": k, "label": label, "ok": (probe in stdout) and success}
              for k, label, probe in STAGES]

    result = {
        "ok": success,
        "version": version,
        "security_version": security_version,
        "filename": output_path.name,
        "path": str(output_path),
        "stages": stages,
        "duration_ms": int((time.time() - started) * 1000),
        # Public header material only. No key bytes are ever parsed or returned.
        "firmware_hash": _parse_field(stdout, "Ascon-Hash256"),
        "nonce": _parse_field(stdout, "Ascon nonce"),
        "auth_tag": _parse_field(stdout, "Ascon tag"),
        "signature": _parse_field(stdout, "Ed25519 signature"),
        "firmware_size": _parse_field(stdout, "firmware size"),
        "output": (stdout + ("\n" + stderr if stderr else ""))[-4000:],
    }

    if not success:
        # Do not leave a half-written package where the server might serve it.
        if output_path.exists() and proc.returncode != 0:
            try:
                output_path.unlink()
            except OSError:
                pass
        reason = (stderr.strip() or stdout.strip() or
                  f"tool exited with code {proc.returncode}")
        result["error"] = reason.splitlines()[-1][:300]

    return result
