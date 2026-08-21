"""Security Test Lab: drive the project's existing attack tooling.

Every test here is `tools/tamper_package.py` producing a hostile package and
`tools/verify_package.py` refusing it -- the exact commands documented in
docs/DEMO.md, run in a subprocess. No cryptography is reimplemented, and no
second verification path exists: the lab uses sotalib, which is the same code
`tools/create_ota_package.py` uses and the mirror of the C implementation the
ESP32 runs.

What the lab proves is a property of the *package format*, verified on the host.
It does not push anything at the device: a hostile package is never published,
never placed in server/packages/, and never offered over the OTA API. It is
built in a scratch directory and deleted.

Colour convention for the UI: PROTECTED (green) means the attack was detected
and the package rejected. VULNERABLE (red) would mean a tampered package was
accepted -- which must never happen.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS = ROOT / "keys"
PACKAGES_DIR = ROOT / "server" / "packages"
STAGING_DIR = ROOT / "server" / "staging"

TAMPER_TOOL = ROOT / "tools" / "tamper_package.py"
VERIFY_TOOL = ROOT / "tools" / "verify_package.py"
CREATE_TOOL = ROOT / "tools" / "create_ota_package.py"

PRIV = KEYS / "ed25519_private.pem"
PUB = KEYS / "ed25519_public.pem"
ENC = KEYS / "ota_enc_key.hex"


class LabError(Exception):
    """The lab could not run -- missing keys, no base package, tooling error."""


# key            label shown in the UI                  tamper mode      what should stop it
TESTS = {
    "valid": ("Valid Package", None,
              "Ed25519 + Ascon-AEAD128 + Ascon-Hash256 all pass"),
    "firmware-tamper": ("Firmware Tampering", "flip-ciphertext",
                        "Ascon-AEAD128 tag"),
    "hash-tamper": ("Hash Tampering", "hash-mismatch", "Ascon-Hash256 digest"),
    "bad-signature": ("Invalid Signature", "bad-signature", "Ed25519 signature"),
    "foreign-signer": ("Attacker's Signing Key", "foreign-signer",
                       "Ed25519 signature"),
    "wrong-key": ("Wrong Encryption Key", "wrong-key", "Ascon-AEAD128 tag"),
    "metadata-tamper": ("Metadata Tampering", "flip-metadata",
                        "Ed25519 signature over header[0:96]"),
    "rollback": ("Rollback Attack", "rollback", "anti-rollback rule"),
    "truncate": ("Interrupted Transfer", "truncate", "structural check"),
}


def _run(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=timeout)


def keys_present() -> bool:
    return PRIV.exists() and PUB.exists() and ENC.exists()


def _newest_package() -> pathlib.Path | None:
    candidates = sorted(PACKAGES_DIR.glob("*.sota")) + \
        sorted(STAGING_DIR.glob("*.sota"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _make_base_package(workdir: pathlib.Path) -> pathlib.Path:
    """Fall back to a small synthetic image when no real package exists yet.

    Built with the project's own packaging tool and the project's own keys, so
    it is a genuine .sota package -- just not a bootable ESP32 image, which the
    lab never installs anyway.
    """
    fw = workdir / "lab_firmware.bin"
    fw.write_bytes(bytes((i * 31 + 7) & 0xFF for i in range(16 * 1024)))
    out = workdir / "lab_base.sota"
    r = _run([str(CREATE_TOOL), "--firmware", str(fw), "--version", "2.0.0",
              "--security-version", "2", "--output", str(out),
              "--signing-key", str(PRIV), "--enc-key", str(ENC)])
    if r.returncode != 0 or not out.exists():
        raise LabError("could not build a lab base package: " +
                       (r.stderr.strip() or r.stdout.strip())[:300])
    return out


def run_test(test_key: str) -> dict:
    """Run one lab test end to end. Returns a result dict for the dashboard."""
    if test_key not in TESTS:
        raise LabError(f"unknown test {test_key!r}")
    if not keys_present():
        raise LabError("keys/ is incomplete -- run: python tools/generate_keys.py")

    label, mode, defended_by = TESTS[test_key]
    started = time.time()
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="sota_lab_"))

    try:
        base = _newest_package()
        base_note = f"base package: {base.name}" if base else \
            "base package: generated for the lab (no .sota published yet)"
        if base is None:
            base = _make_base_package(workdir)
        else:
            shutil.copy2(base, workdir / base.name)
            base = workdir / base.name

        if mode is None:
            target = base
            tamper_note = "untouched, exactly as signed"
        else:
            target = workdir / f"{test_key}.sota"
            args = [str(TAMPER_TOOL), "--mode", mode,
                    "--input", str(base), "--output", str(target),
                    "--signing-key", str(PRIV), "--enc-key", str(ENC)]
            if mode == "rollback":
                args += ["--security-version", "1"]
            r = _run(args)
            if r.returncode != 0 or not target.exists():
                raise LabError(
                    f"tamper tool failed for mode {mode}: " +
                    (r.stderr.strip() or r.stdout.strip())[:300])
            tamper_note = r.stdout.strip().splitlines()[-1][:200] if r.stdout \
                else f"mode {mode}"

        vargs = [str(VERIFY_TOOL), str(target),
                 "--public-key", str(PUB), "--enc-key", str(ENC)]
        if mode == "rollback":
            # The device would be at security version 2; the package claims 1.
            vargs += ["--current-version", "1.0.0",
                      "--current-security-version", "2"]
        v = _run(vargs)
        out = v.stdout

        accepted = "RESULT: ACCEPTED" in out
        expected_accept = mode is None
        passed = accepted == expected_accept

        if expected_accept:
            verdict = "PASS" if passed else "FAIL"
            headline = ("Valid package accepted -- the pipeline is not simply "
                        "rejecting everything") if passed else \
                       "A valid, correctly signed package was REJECTED"
            status = "VERIFIED" if passed else "BROKEN"
        else:
            verdict = "PASS" if passed else "FAIL"
            headline = (f"Attack detected and update rejected ({defended_by})"
                        if passed else
                        "ATTACK WAS NOT DETECTED -- the tampered package was "
                        "accepted")
            status = "PROTECTED" if passed else "VULNERABLE"

        rejection = ""
        for line in out.splitlines():
            if line.startswith("RESULT:"):
                rejection = line.strip()

        return {
            "test": test_key,
            "label": label,
            "mode": mode or "none",
            "verdict": verdict,
            "status": status,
            "passed": passed,
            "accepted": accepted,
            "headline": headline,
            "defended_by": defended_by,
            "result_line": rejection,
            "base_note": base_note,
            "tamper_note": tamper_note,
            "duration_ms": int((time.time() - started) * 1000),
            "output": out[-4000:],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
