"""Job worker. Run standalone (``python -m remediation.worker``) or embedded in the API process."""
from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import threading
import time
import traceback

from . import jobqueue
from .config import get_settings
from .db import Job
from .github import RepoAccessError, RepoURLError, parse_repo_url, resolve_remote_ref
from .logging_setup import setup_logging
from .models import JobOptions
from .pipeline import JobCancelled, JobTimedOut, RepositoryPipeline

log = logging.getLogger(__name__)


class DbReporter:
    """Bridges pipeline progress to the database, throttling cancellation polls."""

    def __init__(self, job_id: str, lost: threading.Event):
        self.job_id = job_id
        self.lost = lost
        self._last_check = 0.0
        self._cancelled = False

    def log(self, message: str, level: str = "info") -> None:
        try:
            jobqueue.add_event(self.job_id, message, level)
        except Exception:  # noqa: BLE001 - progress logging must never kill a job
            log.exception("could not record event")

    def stage(self, name: str, progress: int) -> None:
        try:
            jobqueue.set_progress(self.job_id, name, progress)
        except Exception:  # noqa: BLE001
            log.exception("could not record progress")

    def timeline(self, stages: list[dict]) -> None:
        try:
            jobqueue.set_stages(self.job_id, stages)
        except Exception:  # noqa: BLE001
            log.exception("could not record stage timeline")

    def check_cancelled(self) -> bool:
        if self._cancelled or self.lost.is_set():
            return True
        now = time.monotonic()
        if now - self._last_check > 3:
            self._last_check = now
            try:
                self._cancelled = jobqueue.is_cancel_requested(self.job_id)
            except Exception:  # noqa: BLE001
                return False
        return self._cancelled


def _after_run(job_id: str, options: JobOptions) -> None:
    """The "Run tests on GitHub" scan option: start the Test & Fix loop as soon as the run has completed."""
    if options.github_tests:
        from . import testloop
        try:
            testloop.start(job_id)
        except Exception:  # noqa: BLE001 - the run itself succeeded; the loop reports its own problems
            log.exception("could not start the test loop for %s", job_id)


class Worker:
    def __init__(self, concurrency: int | None = None, worker_id: str | None = None):
        s = get_settings()
        self.concurrency = max(1, concurrency or s.worker_concurrency)
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}"
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.active: dict[str, str] = {}

    def start(self) -> None:
        log.info("worker %s starting with concurrency %d", self.worker_id, self.concurrency)
        for i in range(self.concurrency):
            t = threading.Thread(target=self._loop, name=f"job-worker-{i}", args=(f"{self.worker_id}/{i}",), daemon=True)
            t.start()
            self.threads.append(t)
        m = threading.Thread(target=self._maintenance, name="job-maintenance", daemon=True)
        m.start()
        self.threads.append(m)

    def stop(self, timeout: float = 10) -> None:
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=timeout)

    def run_forever(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        finally:
            self.stop()

    # -------------------------------------------------------------------------------------
    def _maintenance(self) -> None:
        while not self.stop_event.wait(30):
            try:
                n = jobqueue.recover_stale()
                if n:
                    log.warning("recovered %d stale job(s)", n)
            except Exception:  # noqa: BLE001
                log.exception("stale job recovery failed")

    def _loop(self, slot_id: str) -> None:
        s = get_settings()
        try:
            jobqueue.recover_stale()
        except Exception:  # noqa: BLE001
            log.exception("initial recovery failed")
        while not self.stop_event.is_set():
            try:
                job = jobqueue.claim_next(slot_id)
            except Exception:  # noqa: BLE001 - e.g. database briefly unavailable
                log.exception("claim failed")
                self.stop_event.wait(5)
                continue
            if job is None:
                self.stop_event.wait(s.poll_interval_seconds)
                continue
            self.active[slot_id] = job.id
            try:
                self.process(job, slot_id)
            finally:
                self.active.pop(slot_id, None)

    def process(self, job: Job, slot_id: str) -> None:
        s = get_settings()
        lost = threading.Event()
        done = threading.Event()

        def beat():
            while not done.wait(max(5, s.lease_seconds // 3)):
                try:
                    if not jobqueue.heartbeat(job.id, slot_id):
                        lost.set()
                        return
                except Exception:  # noqa: BLE001
                    log.exception("heartbeat failed")

        hb = threading.Thread(target=beat, name=f"heartbeat-{job.id[:8]}", daemon=True)
        hb.start()
        reporter = DbReporter(job.id, lost)
        try:
            options = JobOptions(**(job.options or {}))
            if options.use_cache and not options.create_pr:
                repo = parse_repo_url(job.repo_url, options.ref)
                sha = resolve_remote_ref(repo, options.ref)
                cached = jobqueue.find_cached_result(job, sha) if sha else None
                if cached:
                    reporter.log(f"Commit {sha[:12]} was analysed by job {cached.id} with identical options; "
                                 "reusing its results.")
                    jobqueue.complete(job.id, slot_id, cached.summary or {}, jobqueue.copy_artifacts(cached.id), sha,
                                      cached_from=cached.id)
                    _after_run(job.id, options)
                    return
            pipeline = RepositoryPipeline(job.repo_url, options, reporter, run_id=job.id)
            result = pipeline.run()
            jobqueue.complete(job.id, slot_id, result.summary(), result.artifacts, result.report.commit)
            _after_run(job.id, options)
        except JobCancelled as exc:
            jobqueue.fail(job.id, slot_id, "Lost lease to another worker." if lost.is_set() else str(exc),
                          status="cancelled")
        except (JobTimedOut, RepoURLError, RepoAccessError) as exc:
            jobqueue.fail(job.id, slot_id, str(exc))
        except Exception as exc:  # noqa: BLE001
            log.error("job %s crashed: %s", job.id, traceback.format_exc())
            jobqueue.fail(job.id, slot_id, f"{type(exc).__name__}: {exc}", retry=True)
        finally:
            done.set()
            hb.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run remediation job workers.")
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--worker-id", default=None)
    args = parser.parse_args()
    setup_logging()
    worker = Worker(args.concurrency, args.worker_id)

    def _graceful(signum, _frame):
        log.info("signal %s received; finishing current jobs", signum)
        worker.stop_event.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _graceful)
        except (ValueError, OSError):  # pragma: no cover
            pass
    worker.run_forever()


if __name__ == "__main__":
    main()
