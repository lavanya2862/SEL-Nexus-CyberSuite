"""Vulnerability Analysis & Prioritization Agent.

Collects findings from CodeQL (primary SAST) and Trivy (dependencies, secrets, misconfigurations)
plus supporting scanners, normalises them into one schema, de-duplicates across scanners,
risk-ranks them and attaches the surrounding source code for review and remediation.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..detect import is_vendored
from ..models import SEVERITY_ORDER, Finding, ScannerRun
from ..parsers import deduplicate, parse_codeql, parse_trivy_data
from ..prioritize import prioritize
from ..scanners import all_scanners, run_scanners
from ..scanners.builtin_secrets import redact
from .base import RunContext

STEP_STATUS = {"ok": "completed", "failed": "failed", "unavailable": "skipped", "disabled": "skipped",
               "skipped": "skipped"}
CONTEXT_RADIUS = 6
MAX_CONTEXT_FINDINGS = 600


def passes_threshold(f: Finding, threshold: str) -> bool:
    if f.severity == "unknown":
        return SEVERITY_ORDER[threshold] >= SEVERITY_ORDER["low"]
    return SEVERITY_ORDER.get(f.severity, 5) <= SEVERITY_ORDER[threshold]


class AnalysisAgent:
    stage_id = "analysis"

    def __init__(self, ctx: RunContext):
        self.ctx = ctx

    # -- scanning ----------------------------------------------------------------------------
    def _load_imported(self) -> tuple[list[Finding], list[ScannerRun]]:
        """Reports produced elsewhere (e.g. the CodeQL GitHub Action) are ingested instead of re-running."""
        ctx = self.ctx
        findings, runs = [], []
        for path in ctx.imported.get("codeql", []) or []:
            items = parse_codeql(path, "CodeQL", ctx.src)
            findings += items
            runs.append(ScannerRun(name="codeql", status="ok", findings=len(items), message=f"imported {Path(path).name}"))
        if ctx.imported.get("trivy"):
            items = parse_trivy_data(json.loads(Path(ctx.imported["trivy"]).read_text(encoding="utf-8")))
            findings += items
            runs.append(ScannerRun(name="trivy", status="ok", findings=len(items), message="imported report"))
        return findings, runs

    def scan(self, label: str, only: list[str] | None) -> tuple[list[Finding], list[ScannerRun]]:
        ctx = self.ctx
        return run_scanners(ctx.src, ctx.workspace / f"scan-{label}", ctx.report.languages, only,
                            log_fn=ctx.log, cancel_check=ctx.checkpoint)

    def rescan(self) -> tuple[list[Finding], list[ScannerRun]]:
        only = [n for n in (self.ctx.scanner_names or []) if n not in self._imported_names()]
        if not only:
            return [], []
        findings, runs = self.scan("rescan", only)
        # Identify findings exactly as in the first scan, so "still present" / "new" comparisons are like-for-like.
        self.attach_snippets(findings)
        return findings, runs

    def _imported_names(self) -> set[str]:
        names = set()
        if self.ctx.imported.get("codeql"):
            names.add("codeql")
        if self.ctx.imported.get("trivy"):
            names.add("trivy")
        return names

    # -- enrichment --------------------------------------------------------------------------
    def _lines(self, cache: dict, rel: str) -> list[str] | None:
        if rel not in cache:
            root = self.ctx.src.resolve()
            path = (root / rel).resolve()
            try:
                ok = root in path.parents and path.is_file() and path.stat().st_size < 2_000_000
                cache[rel] = path.read_text(encoding="utf-8", errors="replace").splitlines() if ok else None
            except OSError:
                cache[rel] = None
        return cache[rel]

    def attach_snippets(self, findings: list[Finding]) -> None:
        """Fill in the flagged line's text where the scanner did not (e.g. CodeQL SARIF).

        The line text is part of a finding's identity, so this must run identically on the first
        scan and on the verification rescan.
        """
        cache: dict[str, list[str] | None] = {}
        for f in findings:
            if f.snippet or not f.file_path or not f.line or f.category == "exposed_secret":
                continue
            lines = self._lines(cache, f.file_path)
            if lines and f.line <= len(lines):
                f.snippet = lines[f.line - 1].strip()[:300]

    def attach_context(self, findings: list[Finding]) -> int:
        cache: dict[str, list[str] | None] = {}
        attached = 0
        for f in findings[:MAX_CONTEXT_FINDINGS]:
            if not f.file_path or not f.line:
                continue
            lines = self._lines(cache, f.file_path)
            if not lines or f.line > len(lines):
                continue
            start = max(1, f.line - CONTEXT_RADIUS)
            end = min(len(lines), (f.end_line or f.line) + CONTEXT_RADIUS)
            f.context_start_line = start
            f.code_context = redact("\n".join(lines[start - 1:end]))[:6000]
            attached += 1
        return attached

    @staticmethod
    def mark_vendored(findings: list[Finding]) -> int:
        n = 0
        for f in findings:
            if not f.is_dependency and f.file_path and is_vendored(f.file_path):
                f.raw = {**(f.raw or {}), "vendored": True}
                n += 1
        return n

    # -- main --------------------------------------------------------------------------------
    def run(self) -> list[Finding]:
        ctx = self.ctx
        ctx.start_stage(self.stage_id, "Collecting findings from CodeQL, Trivy and supporting scanners")
        ctx.progress("analysis", 20)
        imported, imported_runs = self._load_imported()
        imported_names = self._imported_names()
        requested = ctx.options.scanners or [s.name for s in all_scanners()]
        only = [n for n in requested if n not in imported_names]
        findings, runs = self.scan("scanning", only)
        runs = imported_runs + [r for r in runs if r.name not in imported_names]
        order = [s.name for s in all_scanners()]
        runs.sort(key=lambda r: order.index(r.name) if r.name in order else 99)
        ctx.report.scanners = runs
        ctx.scanner_names = [r.name for r in runs if r.status == "ok"]

        for r in runs:
            status, detail = STEP_STATUS.get(r.status, "skipped"), r.message
            if r.status == "ok":
                detail = f"{r.findings} result(s) in {r.duration_seconds:.1f}s" + (f" — {r.message}" if r.message else "")
            if r.name == "codeql" and r.status == "failed":
                status = "warning"
                ctx.report.notes.append(f"CodeQL failed: {r.message[:300]}")
            elif r.name == "codeql" and r.status == "unavailable":
                status = "warning"
                detail = ("CodeQL (primary SAST) is not installed on this worker — falling back to Semgrep/Bandit/"
                          "built-in rules. Run scripts/install-codeql.ps1 (or .sh), set CODEQL_PATH, or use the "
                          "Docker image / GitHub Actions workflow which include CodeQL.")
                ctx.report.notes.append("CodeQL was not available; source-code coverage relied on fallback SAST.")
            label = {"codeql": "CodeQL (primary SAST)", "trivy": "Trivy (deps, secrets, IaC)"}.get(r.name, r.name)
            ctx.step(self.stage_id, label, status, detail)
        if not ctx.scanner_names:
            ctx.report.notes.append("No scanner completed successfully.")

        raw_total = sum(r.findings for r in runs if r.status == "ok")
        merged = deduplicate(findings + imported) if imported else findings
        ctx.step(self.stage_id, "Normalise & de-duplicate",
                 detail=f"{raw_total} raw results → {len(merged)} unique findings (CVE/GHSA aliases, CWE categories, "
                        "file/line merged across scanners)")
        self.attach_snippets(merged)
        vendored = self.mark_vendored(merged)
        if vendored:
            ctx.step(self.stage_id, "Recognise third-party library code",
                     detail=f"{vendored} finding(s) are inside bundled third-party libraries; ranked lower — the fix is "
                            "to update the library, not to patch it")
        ranked = prioritize(merged)
        top = ranked[0] if ranked else None
        ctx.step(self.stage_id, "Risk-based prioritisation",
                 detail=(f"Top risk: {top.title[:90]} (score {top.priority_score})" if top else "No findings"))
        attached = self.attach_context(ranked)
        ctx.step(self.stage_id, "Attach code context", detail=f"Source context captured for {attached} findings")

        ctx.findings = ranked
        rep = ctx.report
        rep.findings_input = len(ranked)
        rep.severity_counts, rep.category_counts, rep.scanner_counts = {}, {}, {}
        for f in ranked:
            rep.severity_counts[f.severity] = rep.severity_counts.get(f.severity, 0) + 1
            rep.category_counts[f.category] = rep.category_counts.get(f.category, 0) + 1
            for sc in [f.scanner, *f.also_reported_by]:
                rep.scanner_counts[sc] = rep.scanner_counts.get(sc, 0) + 1
        ctx.selected = [f for f in ranked if passes_threshold(f, ctx.options.min_severity)]
        rep.findings_selected = len(ctx.selected)
        sev = ", ".join(f"{rep.severity_counts[s]} {s}" for s in ("critical", "high", "medium", "low")
                        if rep.severity_counts.get(s))
        ctx.finish_stage(self.stage_id, "completed",
                         f"{len(ranked)} unique findings ({sev or 'none'}); {len(ctx.selected)} selected for remediation",
                         raw_results=raw_total, unique=len(ranked), selected=len(ctx.selected),
                         critical=rep.severity_counts.get("critical", 0), high=rep.severity_counts.get("high", 0))
        return ranked
