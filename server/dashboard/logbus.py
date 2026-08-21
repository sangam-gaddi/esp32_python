"""In-memory log bus feeding the dashboard's live log viewer.

Two sources land in the same ring buffer:

  * the OTA server's own `logging` output, captured with a Handler that is
    attached to the root logger -- so every existing log line the server already
    produced ("update check from ...", "serving firmware_v2.0.0.sota ...")
    appears in the dashboard without changing a single existing log call;

  * lines pushed by the ESP32 through POST /api/device/log and the heartbeat /
    event endpoints.

Deliberately tiny: a deque, a lock, a monotonically increasing id. No files, no
external logging infrastructure. Anything older than the buffer is simply gone,
which is the right trade for a live view.
"""

from __future__ import annotations

import threading
import time
from collections import deque

MAX_LINES = 1000

_lock = threading.Lock()
_lines: deque = deque(maxlen=MAX_LINES)
_next_id = 1


def push(source: str, level: str, message: str) -> None:
    """Append one line. `source` is SERVER, DEVICE, PKG, LAB, ..."""
    global _next_id
    with _lock:
        _lines.append({
            "id": _next_id,
            "ts": time.time(),
            "source": source,
            "level": level.upper(),
            "message": str(message)[:1000],
        })
        _next_id += 1


def since(after_id: int = 0, limit: int = 300) -> list[dict]:
    with _lock:
        rows = [ln for ln in _lines if ln["id"] > after_id]
    return rows[-limit:]


def last_id() -> int:
    with _lock:
        return _lines[-1]["id"] if _lines else 0


def attach_to_logging(logger_names: tuple = ("ota-server", "werkzeug")) -> None:
    """Mirror the named loggers' records into the ring buffer.

    Idempotent: loggers outlive a module reload, so a second call must not
    attach a second handler and double every line.
    """
    import logging

    class _Handler(logging.Handler):
        sota_logbus = True

        def emit(self, record: logging.LogRecord) -> None:
            try:
                push("SERVER", record.levelname, record.getMessage())
            except Exception:  # never let logging break a request
                pass

    for name in logger_names:
        logger = logging.getLogger(name)
        if any(getattr(h, "sota_logbus", False) for h in logger.handlers):
            continue
        handler = _Handler()
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
