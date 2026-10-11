"""
The user's Arduino sketch: where it comes from, and where the build reads it.

An Arduino IDE .bin is a complete firmware -- it has no Wi-Fi client and no
OTA client, so it can never be sent to the board as it is. What the user means
by uploading it is "run this code". So the code is fetched instead: the .ino
source that produced the .bin is found and copied to SKETCH_FILE, which
main/CMakeLists.txt compiles into the OTA firmware.

Finding the source for `NAME.ino.bin`:
  1. The Arduino IDE's build cache (%LOCALAPPDATA%/arduino/sketches/*/
     build.options.json) records the folder of every sketch it compiled.
     The newest entry whose folder is called NAME wins.
  2. Otherwise the usual sketch folders are searched for NAME/NAME.ino.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SKETCH_DIR = ROOT / "main" / "user_sketch"
SKETCH_FILE = SKETCH_DIR / "sketch.ino"
ORIGIN_FILE = SKETCH_DIR / "ORIGIN.txt"
MAX_SKETCH_BYTES = 256 * 1024


class SketchError(Exception):
    pass


def sketch_name(filename: str) -> str | None:
    """`LOL.ino.bin`, `LOL.ino_1791718277.bin` -> `LOL`; anything else None."""
    m = re.match(r"^(.+?)\.ino(?:_\d+)?\.bin$", pathlib.Path(filename).name,
                 re.IGNORECASE)
    return m.group(1) if m else None


def _search_roots() -> list[pathlib.Path]:
    home = pathlib.Path(os.environ.get("USERPROFILE") or pathlib.Path.home())
    roots = [home / "OneDrive" / "Desktop", home / "Desktop",
             home / "OneDrive" / "Documents" / "Arduino",
             home / "Documents" / "Arduino"]
    return [r for r in roots if r.is_dir()]


def find_source(name: str) -> pathlib.Path | None:
    """Locate NAME.ino for a sketch compiled by the Arduino IDE."""
    local = os.environ.get("LOCALAPPDATA")
    if local:
        cache = pathlib.Path(local) / "arduino" / "sketches"
        entries = []
        for opts in cache.glob("*/build.options.json"):
            try:
                loc = json.loads(opts.read_text(encoding="utf-8"))["sketchLocation"]
                entries.append((opts.stat().st_mtime, pathlib.Path(loc)))
            except (OSError, ValueError, KeyError):
                continue
        for _, folder in sorted(entries, reverse=True):
            candidate = folder / f"{name}.ino"
            if folder.name.lower() == name.lower() and candidate.is_file():
                return candidate

    for root in _search_roots():
        for candidate in (root / name / f"{name}.ino", root / f"{name}.ino"):
            if candidate.is_file():
                return candidate
    return None


def install_text(text: str, origin: str) -> dict:
    """Make `text` the sketch the next build compiles."""
    if not text.strip():
        raise SketchError("the sketch is empty")
    if "loop" not in text or "setup" not in text:
        raise SketchError("this does not look like an Arduino sketch: it needs "
                          "both setup() and loop()")
    SKETCH_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SKETCH_FILE.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, SKETCH_FILE)
    ORIGIN_FILE.write_text(
        f"{origin}\ninstalled {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        encoding="utf-8")
    return current()


def install_file(path: pathlib.Path) -> dict:
    data = path.read_bytes()
    if len(data) > MAX_SKETCH_BYTES:
        raise SketchError(f"{path.name} is larger than {MAX_SKETCH_BYTES} bytes")
    return install_text(data.decode("utf-8", "replace"), str(path))


def current() -> dict:
    if not SKETCH_FILE.is_file():
        return {"present": False}
    origin = ""
    if ORIGIN_FILE.is_file():
        origin = ORIGIN_FILE.read_text(encoding="utf-8").splitlines()[0]
    text = SKETCH_FILE.read_text(encoding="utf-8", errors="replace")
    return {"present": True, "origin": origin, "text": text,
            "modified": SKETCH_FILE.stat().st_mtime}
