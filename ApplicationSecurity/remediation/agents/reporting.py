"""Reporting Component: turns the run into reviewable artifacts."""
from __future__ import annotations

from ..report import build_artifacts
from .base import RunContext


class ReportingAgent:
    stage_id = "reporting"

    def __init__(self, ctx: RunContext):
        self.ctx = ctx

    def build(self, patch: str, mbox: str) -> dict[str, tuple[str, str]]:
        ctx = self.ctx
        artifacts = build_artifacts(ctx.report, ctx.findings, patch)
        artifacts["fixes.mbox"] = (mbox, "application/mbox")
        limit = ctx.s.max_artifact_bytes
        for name, (content, ctype) in list(artifacts.items()):
            if len(content.encode("utf-8")) > limit:
                if name == "fixes.mbox":
                    artifacts[name] = ("", ctype)  # a truncated mbox cannot be replayed safely
                    ctx.report.notes.append("fixes.mbox exceeded MAX_ARTIFACT_BYTES; approval-based PRs are disabled "
                                            "for this run.")
                else:
                    artifacts[name] = (content[: limit // 2] + "\n\n[truncated: artifact exceeded MAX_ARTIFACT_BYTES]\n",
                                       ctype)
        return artifacts

    def run(self, patch: str, mbox: str) -> dict[str, tuple[str, str]]:
        ctx = self.ctx
        ctx.start_stage(self.stage_id, "Compiling report, SARIF and patch")
        ctx.progress("reporting", 92)
        artifacts = self.build(patch, mbox)
        for name in ("report.md", "report.json", "findings.sarif", "fixes.patch"):
            size = len(artifacts[name][0].encode("utf-8"))
            ctx.step(self.stage_id, name, detail=f"{size / 1024:.1f} KB")
        ctx.finish_stage(self.stage_id, "completed",
                         f"Validation status: {ctx.report.validation_status.upper()} · "
                         f"{ctx.report.findings_input} findings · {ctx.report.patches_applied} fixes",
                         artifacts=len(artifacts))
        return artifacts
