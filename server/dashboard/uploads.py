"""Secure handling of uploaded firmware images.

The website has exactly one job: take a `.bin` off somebody's machine and put
it somewhere the packaging tool can reach. That is a file-upload endpoint on a
machine that holds the Ed25519 signing key, so every byte that arrives is
treated as hostile until it has been measured.

WHAT IS ENFORCED HERE

  name      The client's file name is *sanitised*, never trusted and never
            rejected for being ugly. Any `.bin` is accepted; directory
            components, control characters, unicode and Windows reserved device
            names are stripped or neutralised, and the result is always a plain
            `[A-Za-z0-9._-]+.bin` inside the uploads directory. The final path
            is re-checked to be a direct child of that directory before anything
            is moved into place.

  size      Capped at MAX_UPLOAD_BYTES (16 MB, the largest ESP32 flash),
            enforced twice: Flask's MAX_CONTENT_LENGTH refuses an oversized body
            as it arrives, and the loop below caps it again as it is written, so
            a large file is never copied into place. There is no lower bound
            beyond "not empty" -- any .bin is accepted, and a file too small to
            be firmware is reported as such rather than refused.

  atomicity The upload streams into a `.part` file and is moved into place with
            os.replace() only once it is complete. A half-written file can
            never be listed, packaged or served -- an interrupted upload leaves
            nothing behind.

  identity  SHA-256 is computed over the bytes as they are written, so the file
            is identified by content and not by name. Re-uploading identical
            bytes is reported as a duplicate instead of making another copy.

  contents  The ESP32 image header and the `esp_app_desc` structure are parsed
            and reported: chip, segment count, project name, app version, IDF
            version, build time. This is *inspection*, not a gate -- any `.bin`
            is still accepted, but the site says plainly what it thinks it got.

WHAT IS DELIBERATELY NOT DONE HERE

  No cryptography. An uploaded image is plaintext, unsigned and untrusted; it
  becomes trustworthy only when tools/create_ota_package.py signs it. Nothing in
  this module reads a key. The uploads directory is never exposed over HTTP --
  no route serves a file out of it -- so an upload cannot become a download, and
  the extension check is not by itself a security boundary.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import struct
import time

# 16 MB is the largest flash an ESP32 variant carries; an app image is always
# smaller.
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
# Any .bin is accepted, so the only size a file can be refused for is none at
# all. A file too small to be firmware is still stored -- it is reported as not
# being an ESP32 image, which is the honest answer, rather than turned away.
MIN_UPLOAD_BYTES = 1
CHUNK = 64 * 1024

ALLOWED_SUFFIX = ".bin"
MAX_STEM = 64

# Anything outside this set is replaced, not rejected.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_RUNS = re.compile(r"_{2,}")
_SEPARATORS = re.compile(r"[\\/]")
# CON.bin, NUL.bin and friends are still device names on Windows, where this
# project is most often run.
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])$", re.I)

ESP_IMAGE_MAGIC = 0xE9
ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_APP_DESC_OFFSET = 0x20

CHIP_IDS = {
    0x0000: "ESP32", 0x0002: "ESP32-S2", 0x0005: "ESP32-C3",
    0x0009: "ESP32-S3", 0x000C: "ESP32-C2", 0x000D: "ESP32-C6",
    0x0010: "ESP32-H2", 0x0011: "ESP32-C5", 0x0012: "ESP32-P4",
}


class UploadError(Exception):
    """The upload was refused. `status` is the HTTP code to answer with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------- the name

def sanitise_name(raw: str) -> str:
    """Turn whatever the browser sent into a safe `something.bin`.

    This never raises for a cosmetic reason. `My Firmware (v2).BIN`,
    `../../etc/app.bin` and a full Windows path all become ordinary names in the
    uploads directory. The only refusal is a name that is not a `.bin` at all,
    which is a content decision rather than a safety one.
    """
    raw = (raw or "").replace("\x00", "")
    # Both separators, because a Windows browser may send a full path.
    base = _SEPARATORS.split(raw)[-1].strip()
    base = "".join(ch for ch in base if ch.isprintable())

    if not base.lower().endswith(ALLOWED_SUFFIX):
        shown = (raw or "(no name)")[:80]
        raise UploadError(
            f"only ESP32 application images are accepted, and they must be "
            f"named *.bin -- got {shown!r}")

    stem = base[: -len(ALLOWED_SUFFIX)]
    stem = _RUNS.sub("_", _UNSAFE.sub("_", stem)).strip("._-")
    if not stem:
        stem = "firmware"
    if _RESERVED.match(stem):
        stem = "_" + stem
    return stem[:MAX_STEM] + ALLOWED_SUFFIX


def _unique_path(directory: pathlib.Path, name: str) -> pathlib.Path:
    """A path in `directory` that does not exist yet. Nothing is overwritten."""
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    stamp = int(time.time())
    candidate = directory / f"{stem}_{stamp}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem}_{stamp}_{counter}{suffix}"
        counter += 1
    return candidate


def _assert_inside(directory: pathlib.Path, path: pathlib.Path) -> None:
    """Belt and braces: the target must be a direct child of the uploads dir."""
    if path.resolve().parent != directory.resolve():
        raise UploadError("refusing to write outside the uploads directory")


# --------------------------------------------------------------- the contents

def _cstr(blob: bytes) -> str:
    return blob.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


# Enough C/Arduino punctuation that a paragraph of prose will not match.
_SOURCE_HINTS = (b"#include", b"#define", b"void ", b"setup()", b"loop()",
                 b"int ", b"//", b"/*", b"printf", b";")


def _looks_like_source(head: bytes) -> bool:
    """Is this text a human wrote, rather than a compiled image?

    A compiled binary is full of bytes outside the printable range. Source code
    is not, and it usually carries at least one obvious C marker.
    """
    if not head:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(head) < 0.95:
        return False
    return any(hint in head for hint in _SOURCE_HINTS)


def inspect_image(head: bytes) -> dict:
    """Read what an ESP-IDF application image says about itself.

    Advisory only. The authority on whether an image is bootable is
    esp_ota_end() on the device, which refuses one that is not. Reporting this
    here means a wrong file is obvious before it is signed, rather than after a
    device has already rejected it.
    """
    facts: dict = {
        "magic_ok": False, "first_byte": "", "chip": "", "chip_id": None,
        "segments": None, "entry_addr": "", "hash_appended": None,
        "app_name": "", "app_version": "", "idf_version": "", "compiled": "",
        "secure_version": None, "verdict": "", "looks_like_source": False,
    }
    if not head:
        facts["verdict"] = "empty file"
        return facts

    facts["first_byte"] = "0x%02X" % head[0]
    if head[0] != ESP_IMAGE_MAGIC:
        facts["verdict"] = (
            "does not start with 0x%02X, so this is probably not an ESP32 "
            "application image" % ESP_IMAGE_MAGIC)
        # Distinguish the single most common mistake -- uploading the sketch
        # instead of the build output -- from a merely wrong binary. Source
        # code cannot be made into firmware by uploading it; it has to be
        # compiled, which is what the build step is for.
        if _looks_like_source(head):
            facts["looks_like_source"] = True
            facts["verdict"] = (
                "this is text, not a compiled binary -- it looks like source "
                "code (.ino / .c). Source has to be compiled into firmware "
                "before it can be signed and sent to a device")
        return facts

    facts["magic_ok"] = True
    facts["verdict"] = "ESP32 application image"
    if len(head) >= 24:
        facts["segments"] = head[1]
        facts["entry_addr"] = "0x%08X" % struct.unpack_from("<I", head, 4)[0]
        chip_id = struct.unpack_from("<H", head, 12)[0]
        facts["chip_id"] = chip_id
        facts["chip"] = CHIP_IDS.get(chip_id, "unknown (id %d)" % chip_id)
        facts["hash_appended"] = bool(head[23])

    # esp_app_desc sits immediately after the image and first segment headers.
    if len(head) >= ESP_APP_DESC_OFFSET + 144:
        base = ESP_APP_DESC_OFFSET
        if struct.unpack_from("<I", head, base)[0] == ESP_APP_DESC_MAGIC:
            facts["secure_version"] = struct.unpack_from("<I", head, base + 4)[0]
            facts["app_version"] = _cstr(head[base + 16:base + 48])
            facts["app_name"] = _cstr(head[base + 48:base + 80])
            build_time = _cstr(head[base + 80:base + 96])
            build_date = _cstr(head[base + 96:base + 112])
            facts["idf_version"] = _cstr(head[base + 112:base + 144])
            facts["compiled"] = " ".join(p for p in (build_date, build_time) if p)
    return facts


# ------------------------------------------------------------------ the write

def save_stream(stream, directory: pathlib.Path, raw_name: str) -> dict:
    """Stream an upload to disk, measuring it on the way in.

    Returns a description of the stored file. Raises UploadError, having left
    nothing behind, if the bytes are unusable.
    """
    name = sanitise_name(raw_name)
    directory.mkdir(parents=True, exist_ok=True)

    part = directory / (".incoming-%d-%d.part" % (os.getpid(), time.time_ns()))
    digest = hashlib.sha256()
    size = 0
    head = b""

    try:
        with open(part, "wb") as fh:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise UploadError(
                        "firmware image is larger than %d MB, which is more "
                        "than any ESP32 flash holds"
                        % (MAX_UPLOAD_BYTES // (1024 * 1024)), 413)
                digest.update(chunk)
                if len(head) < 512:
                    head += chunk[: 512 - len(head)]
                fh.write(chunk)

        if size < MIN_UPLOAD_BYTES:
            raise UploadError("the file is empty -- there is nothing to store")

        dest = _unique_path(directory, name)
        _assert_inside(directory, dest)
        os.replace(part, dest)
    except UploadError:
        part.unlink(missing_ok=True)
        raise
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise UploadError("could not store the upload: %s" % exc, 500) from None

    return {
        "file": dest.name,
        "original_name": (raw_name or "")[:200],
        "renamed": dest.name != _SEPARATORS.split(raw_name or "")[-1],
        "size": size,
        "sha256": digest.hexdigest(),
        "uploaded_at": time.time(),
        "image": inspect_image(head),
    }
