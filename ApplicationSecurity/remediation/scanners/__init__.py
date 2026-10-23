"""Scanner registry. Every scanner degrades gracefully when its tool is missing."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from ..config import get_settings
from ..models import Finding, ScannerRun
from ..parsers import deduplicate
from .base import Scanner, ScannerUnavailable
from .builtin_sast import BuiltinSastScanner
from .builtin_secrets import BuiltinSecretsScanner
from .external import BanditScanner, CodeQLScanner, SemgrepScanner, TrivyScanner
from .osv import OsvScanner

log = logging.getLogger(__name__)


def all_scanners() -> list[Scanner]:
    return [TrivyScanner(), SemgrepScanner(), BanditScanner(), CodeQLScanner(), OsvScanner(),
            BuiltinSastScanner(), BuiltinSecretsScanner()]


def capabilities() -> dict[str, dict]:
    out = {}
    for scanner in all_scanners():
        out[scanner.name] = {"enabled": scanner.enabled(), "available": scanner.available(),
                             "kind": scanner.kind, "description": scanner.description, "primary": scanner.primary}
    return out


def run_scanners(root: Path, workdir: Path, languages: dict[str, int], only: list[str] | None = None,
                 log_fn: Callable[[str], None] | None = None,
                 cancel_check: Callable[[], None] | None = None) -> tuple[list[Finding], list[ScannerRun]]:
    """Run every applicable scanner in parallel; failures are recorded, never fatal."""
    log_fn = log_fn or log.info
    selected = [s for s in all_scanners() if not only or s.name in only]
    runs: list[ScannerRun] = []
    tasks = []
    active_names = {s.name for s in selected if s.enabled() and s.available()}
    for scanner in selected:
        if not scanner.enabled():
            runs.append(ScannerRun(name=scanner.name, status="disabled"))
        elif not scanner.available():
            runs.append(ScannerRun(name=scanner.name, status="unavailable", message="tool not installed"))
        elif scanner.redundant_with & active_names:
            runs.append(ScannerRun(name=scanner.name, status="skipped",
                                   message=f"covered by {', '.join(sorted(scanner.redundant_with & active_names))}"))
        elif not scanner.applies_to(languages):
            runs.append(ScannerRun(name=scanner.name, status="skipped", message="no matching languages"))
        else:
            tasks.append(scanner)

    def execute(scanner: Scanner):
        start = time.monotonic()
        try:
            out = scanner.scan(root, workdir / scanner.name)
            return scanner, out, None, time.monotonic() - start
        except ScannerUnavailable as exc:
            return scanner, [], ("unavailable", str(exc)), time.monotonic() - start
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            log.exception("scanner %s failed", scanner.name)
            return scanner, [], ("failed", f"{type(exc).__name__}: {exc}"[:800]), time.monotonic() - start

    findings: list[Finding] = []
    if tasks:
        log_fn(f"Running scanners: {', '.join(s.name for s in tasks)}")
        with ThreadPoolExecutor(max_workers=min(4, len(tasks)), thread_name_prefix="scan") as pool:
            for scanner, out, err, duration in pool.map(execute, tasks):
                if cancel_check:
                    cancel_check()
                if err:
                    runs.append(ScannerRun(name=scanner.name, status=err[0], message=err[1], duration_seconds=round(duration, 2)))
                    log_fn(f"Scanner {scanner.name} {err[0]}: {err[1][:300]}")
                else:
                    runs.append(ScannerRun(name=scanner.name, status="ok", findings=len(out), duration_seconds=round(duration, 2),
                                           message=getattr(scanner, "last_message", "")))
                    log_fn(f"Scanner {scanner.name}: {len(out)} finding(s) in {duration:.1f}s")
                    findings.extend(out)
    order = [s.name for s in all_scanners()]
    runs.sort(key=lambda r: order.index(r.name) if r.name in order else 99)
    return deduplicate(findings), runs


__all__ = ["run_scanners", "capabilities", "all_scanners", "get_settings"]
