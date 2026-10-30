"""Approvals and fix results in one small JSON file (data/fix/state.json).

The website, the command line and the scheduled run all read and write it, so every change goes through
`edit()`, which holds a lock file while it reads, changes and atomically replaces the file. The website never
opens the database; this file is how it shares fix decisions with the pipeline.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from threat_intel.store import utcnow

STALE_LOCK_S = 60
MAX_EVENTS = 400


def empty() -> dict:
    return {"fixes": {}, "probes": {}, "events": []}


class FixState:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(".lock")
        self._local = threading.Lock()

    def read(self) -> dict:
        for _ in range(5):
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return {**empty(), **data}
            except FileNotFoundError:
                return empty()
            except (OSError, ValueError):
                time.sleep(0.1)                      # being replaced right now
        return empty()

    def _acquire(self, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return
            except FileExistsError:
                try:
                    if time.time() - self.lock_path.stat().st_mtime > STALE_LOCK_S:
                        self.lock_path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Fix state is locked ({self.lock_path}); try again")
                time.sleep(0.05)

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, default=str, ensure_ascii=False, indent=1), encoding="utf-8")
        for attempt in range(20):
            try:
                os.replace(tmp, self.path)
                return
            except PermissionError:                  # Windows: a reader has it open for a moment
                time.sleep(0.05 * (attempt + 1))
        os.replace(tmp, self.path)

    @contextmanager
    def edit(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._local:
            self._acquire()
            try:
                data = self.read()
                yield data
                self._write(data)
            finally:
                self.lock_path.unlink(missing_ok=True)


def event(data: dict, text: str, fix_id: str | None = None) -> None:
    data.setdefault("events", []).append({"at": utcnow().isoformat(), "fix_id": fix_id, "text": text[:300]})
    del data["events"][:-MAX_EVENTS]
