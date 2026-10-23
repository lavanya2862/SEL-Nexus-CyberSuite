"""Shared run state and the stage timeline that every agent reports into."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from ..config import get_settings
from ..github import RepoRef
from ..models import Finding, FixRecord, JobOptions, PipelineStage, RemediationReport, StageStep

log = logging.getLogger("remediation.agents")


class JobCancelled(Exception):
    pass


class JobTimedOut(Exception):
    pass


class Reporter(Protocol):
    def log(self, message: str, level: str = "info") -> None: ...
    def stage(self, name: str, progress: int) -> None: ...
    def check_cancelled(self) -> bool: ...


class ConsoleReporter:
    def __init__(self, stream: Callable[[str], None] = print):
        self._out = stream
        self._stage = None

    def log(self, message: str, level: str = "info") -> None:
        self._out(f"[{level.upper():5}] {message}")

    def stage(self, name: str, progress: int) -> None:
        if name != self._stage:
            self._stage = name
            self._out(f"==> {name} ({progress}%)")

    def check_cancelled(self) -> bool:
        return False

    def timeline(self, stages: list[dict]) -> None:  # console output already covers transitions
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunContext:
    """Everything the agents share for one repository run."""

    MAX_STEPS = 80

    def __init__(self, repo: RepoRef, options: JobOptions, reporter: Reporter, run_id: str,
                 imported: dict | None = None):
        self.s = get_settings()
        self.repo = repo
        self.options = options
        self.reporter = reporter
        self.run_id = run_id
        self.imported = imported or {}
        self.workspace: Path = self.s.workspaces_dir / run_id
        self.src: Path = self.workspace / "src"
        self.deadline = time.monotonic() + self.s.job_timeout_seconds
        self.report = RemediationReport(run_id=run_id, repo=repo.full_name, repo_url=repo.html_url,
                                        llm_enabled=self.s.llm_enabled and options.use_llm,
                                        llm_model=self.s.llm_model if self.s.llm_enabled and options.use_llm else None)
        self.findings: list[Finding] = []
        self.selected: list[Finding] = []
        self.info = None
        self.scanner_names: list[str] | None = None
        self.fix_commits: list[tuple[str, FixRecord]] = []
        self.can_push: bool | None = None
        self.default_branch: str | None = None
        self._stage_t0: dict[str, float] = {}

    # -- logging / control -----------------------------------------------------------------
    def log(self, msg: str, level: str = "info") -> None:
        log.debug("[%s] %s: %s", self.run_id, level, msg)
        self.reporter.log(msg, level)

    def checkpoint(self) -> None:
        if self.reporter.check_cancelled():
            raise JobCancelled("Cancelled by user.")
        if time.monotonic() > self.deadline:
            raise JobTimedOut(f"Job exceeded JOB_TIMEOUT_SECONDS={self.s.job_timeout_seconds}.")

    def progress(self, name: str, pct: int) -> None:
        self.checkpoint()
        self.reporter.stage(name, pct)

    # -- timeline --------------------------------------------------------------------------
    def stage(self, stage_id: str) -> PipelineStage:
        return next(s for s in self.report.stages if s.id == stage_id)

    def emit(self) -> None:
        timeline = getattr(self.reporter, "timeline", None)
        if timeline:
            try:
                timeline([s.model_dump() for s in self.report.stages])
            except Exception:  # noqa: BLE001 - UI updates must never break a run
                log.exception("timeline update failed")

    def start_stage(self, stage_id: str, summary: str = "") -> None:
        st = self.stage(stage_id)
        st.status, st.started_at, st.summary = "running", _now(), summary
        self._stage_t0[stage_id] = time.monotonic()
        label = f"{st.agent}: {st.name}" if st.agent else st.name
        self.log(f"▶ {label} started")
        self.emit()

    def step(self, stage_id: str, name: str, status: str = "completed", detail: str = "") -> None:
        st = self.stage(stage_id)
        if len(st.steps) < self.MAX_STEPS:
            st.steps.append(StageStep(name=name[:200], status=status, detail=detail[:1500]))
        elif len(st.steps) == self.MAX_STEPS:
            st.steps.append(StageStep(name="…more steps in the job log", status="completed"))
        self.emit()

    def finish_stage(self, stage_id: str, status: str = "completed", summary: str | None = None,
                     **metrics) -> None:
        st = self.stage(stage_id)
        st.status, st.finished_at = status, _now()
        if summary is not None:
            st.summary = summary
        if stage_id in self._stage_t0:
            st.duration_seconds = round(time.monotonic() - self._stage_t0[stage_id], 2)
        st.metrics.update({k: v for k, v in metrics.items() if v is not None})
        self.log(f"■ {st.name}: {status}" + (f" — {st.summary}" if st.summary else ""),
                 "warning" if status in ("failed", "warning") else "info")
        self.emit()

    def skip_stage(self, stage_id: str, reason: str) -> None:
        st = self.stage(stage_id)
        st.status, st.summary = "skipped", reason
        self.emit()

    def fail_running_stages(self, reason: str) -> None:
        for st in self.report.stages:
            if st.status == "running":
                st.status, st.finished_at, st.summary = "failed", _now(), reason[:300]
        self.emit()
