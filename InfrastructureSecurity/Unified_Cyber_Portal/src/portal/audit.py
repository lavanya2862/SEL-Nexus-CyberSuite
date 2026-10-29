"""Activity trail: who did what in the portal, and when; the Activity log page lists it (activity.py).

One line per action in data/audit/audit.jsonl, only ever appended. Recorded: pipeline runs started (or refused) and
how they finished, every Remediation action (approve, withdraw, save, run, check), Alert Triage agree / disagree and
Reopen.

Tamper evidence: every line carries the SHA-256 of its own content plus the hash of the line before it (a hash chain).
Editing, removing or reordering any line breaks the chain from that line on, and verify() says where.

Two processes write here: the portal, and the run wrapper (portal.runner) when a pipeline ends. A lock file keeps
their writes one at a time, so the chain stays in order.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

GENESIS = "0" * 64

# action key -> what the Activity log page shows
ACTIONS = {
    "run.start": "Started a pipeline run",
    "run.refused": "Pipeline run refused",
    "run.finish": "Pipeline run completed",
    "fix.approve": "Approved remediation",
    "fix.unapprove": "Withdrew remediation approval",
    "fix.save": "Saved remediation for later",
    "fix.unsave": "Moved remediation back to the queue",
    "fix.run": "Ran remediation",
    "fix.probe": "Checked remediation result",
    "triage.agree": "Agreed with triage verdict",
    "triage.disagree": "Disagreed with triage verdict",
    "triage.reopen": "Reopened incident",
    "triage.decide": "Classified incident in Defender",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def _file_lock(path: Path, wait_s: float = 10) -> Iterator[None]:
    """Cross-process lock: a byte-range lock on <path> (msvcrt on Windows, fcntl elsewhere)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            deadline = time.monotonic() + wait_s
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.05)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
    finally:
        fh.close()


def _last_line(path: Path) -> str | None:
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return None
    return lines[-1].decode("utf-8", errors="replace") if lines else None


def who(user: dict | None) -> dict:
    """The parts of a signed-in user (auth.current_user) the log keeps."""
    user = user or {}
    return {"email": str(user.get("email") or "unknown"), "name": str(user.get("name") or user.get("email") or "Unknown")}


class AuditLog:
    def __init__(self, folder: Path):
        self.folder = folder
        self.path = folder / "audit.jsonl"

    def record(self, user: dict | None, action: str, *, agent: str = "", target: str = "", outcome: str = "success",
               detail: str = "", ip: str | None = None, ref: str | None = None) -> dict | None:
        """Append one line. Never raises: a full disk must not stop a pipeline or a fix."""
        person = who(user)
        try:
            with _file_lock(self.folder / "audit.lock"):
                last = _last_line(self.path)
                prev = json.loads(last) if last else None
                entry = {"seq": (prev["seq"] + 1) if prev else 1, "at": _now(),
                         "user_email": person["email"], "user_name": person["name"], "ip": ip,
                         "action": action, "agent": agent, "target": target[:500], "outcome": outcome,
                         "detail": detail[:1000], "ref": ref, "prev": prev["hash"] if prev else GENESIS}
                entry["hash"] = _digest(entry)
                with self.path.open("a", encoding="utf-8", newline="\n") as f:
                    f.write(json.dumps(entry) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                return entry
        except (OSError, ValueError, KeyError):
            return None

    def entries(self) -> list[dict]:
        rows: list[dict] = []
        try:
            with self.path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        try:
                            rows.append(json.loads(line))
                        except ValueError:
                            rows.append({"_broken": line.strip()[:200]})
        except OSError:
            pass
        return rows

    def verify(self, rows: list[dict] | None = None) -> dict:
        """Walk the chain. ok=False names the first line that was changed, removed or put out of order."""
        rows = self.entries() if rows is None else rows
        prev, seq = GENESIS, 0
        for i, row in enumerate(rows, start=1):
            seq += 1
            if "_broken" in row or row.get("prev") != prev or row.get("seq") != seq or row.get("hash") != _digest(row):
                return {"ok": False, "count": len(rows), "broken_at": i,
                        "message": f"Line {i} of the audit log was changed, removed or reordered after it was written"}
            prev = row["hash"]
        return {"ok": True, "count": len(rows), "broken_at": None, "last_hash": prev if rows else None,
                "message": f"All {len(rows)} recorded actions are intact"}
