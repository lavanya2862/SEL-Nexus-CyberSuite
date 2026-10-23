"""Domain models shared by scanners, fixers, the pipeline, the API and the worker."""
from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}

FixStatus = Literal["not_attempted", "fixed", "verified", "failed", "manual", "skipped"]


def normalize_severity(value: Any) -> str:
    raw = str(value or "unknown").strip().lower()
    aliases = {"moderate": "medium", "important": "high", "warning": "medium", "error": "high",
               "note": "low", "none": "info", "negligible": "info", "informational": "info"}
    raw = aliases.get(raw, raw)
    return raw if raw in SEVERITY_ORDER else "unknown"


class Finding(BaseModel):
    finding_id: str
    scanner: str
    category: str = "unknown"
    severity: str = "unknown"
    title: str
    description: str = ""
    file_path: str | None = None
    line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    rule_id: str | None = None
    cwe: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    package_name: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    advisory_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    remediation_type: str = "investigate"
    references: list[str] = Field(default_factory=list)
    also_reported_by: list[str] = Field(default_factory=list)
    fix_status: FixStatus = "not_attempted"
    fix_note: str | None = None
    priority_score: float = 0.0
    priority_rank: int | None = None
    priority_reasons: list[str] = Field(default_factory=list)
    code_context: str | None = None
    context_start_line: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, value):
        return normalize_severity(value)

    @field_validator("file_path", mode="before")
    @classmethod
    def _path(cls, value):
        if value is None:
            return None
        value = str(value).replace("\\", "/")
        while value.startswith("./"):
            value = value[2:]
        return value or None

    @property
    def is_dependency(self) -> bool:
        return self.remediation_type == "dependency_upgrade" and bool(self.package_name)

    def fingerprint(self) -> str:
        """Stable identity used for deduplication and verification rescans.

        Line numbers move when code is edited, so source findings are keyed on the
        flagged line's content instead of its number.
        """
        if self.is_dependency:
            ids = sorted({a.upper() for a in [self.advisory_id or "", *self.aliases] if a})
            key = f"dep|{(self.ecosystem or '').lower()}|{(self.package_name or '').lower()}|" \
                  f"{self.installed_version}|{(self.file_path or '').lower()}|{ids[0] if ids else self.title.lower()}"
        else:
            content = " ".join((self.snippet or "").split()) or str(self.line)
            key = f"code|{self.category.lower()}|{self.rule_id or self.title.lower()}|{(self.file_path or '').lower()}|{content}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

    def public_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data = self.model_dump()
        if not include_raw:
            data.pop("raw", None)
        data["fingerprint"] = self.fingerprint()
        return data


class ValidationResult(BaseModel):
    name: str
    command: str
    exit_code: int
    passed: bool
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    skipped: bool = False


class ScannerRun(BaseModel):
    name: str
    status: Literal["ok", "failed", "unavailable", "disabled", "skipped"]
    findings: int = 0
    duration_seconds: float = 0.0
    message: str = ""


class ValidationCheck(BaseModel):
    name: str
    category: Literal["static", "security-regression", "security-rescan", "functional", "policy"]
    status: Literal["passed", "failed", "warning", "skipped"]
    detail: str = ""
    fix_index: int | None = None


class FixRecord(BaseModel):
    finding_ids: list[str]
    method: Literal["dependency", "rule", "llm"]
    summary: str
    files: list[str] = Field(default_factory=list)
    commit: str | None = None
    status: Literal["applied", "reverted", "failed"] = "applied"
    verified: bool | None = None
    detail: str = ""
    explanation: str = ""
    diff: str = ""
    risk: Literal["low", "medium", "high"] = "low"
    validation_status: Literal["pending", "passed", "flagged"] = "pending"


StageStatus = Literal["pending", "running", "completed", "failed", "skipped", "warning"]


class StageStep(BaseModel):
    name: str
    status: StageStatus = "completed"
    detail: str = ""


class PipelineStage(BaseModel):
    id: str
    name: str
    agent: str | None = None
    description: str = ""
    status: StageStatus = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    summary: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    steps: list[StageStep] = Field(default_factory=list)


PIPELINE_STAGES: list[tuple[str, str, str | None, str]] = [
    ("ingest", "Repository Ingestion", None, "Validate the GitHub link, shallow-clone the requested ref, detect languages "
     "and dependency manifests."),
    ("analysis", "Vulnerability Analysis & Prioritization", "Analysis Agent",
     "Run CodeQL (primary SAST) and Trivy (dependencies, secrets, misconfigurations) plus supporting scanners; "
     "normalise, de-duplicate and risk-rank every finding."),
    ("remediation", "Remediation", "Remediation Agent",
     "Generate targeted patches (deterministic upgrades/rewrites first, LLM patches for code) and commit each one "
     "on an isolated Git branch."),
    ("validation", "Testing & Validation", "Validation Agent",
     "Syntax checks, security-regression guard, functional tests in a sandbox and a security rescan of every fix."),
    ("reporting", "Reporting", "Reporting Agent",
     "Produce the report, SARIF, per-fix diffs and the final validation status."),
    ("approval", "Human Approval & Pull Request", None,
     "Push the branch and open a pull request for human review. Flagged runs become draft PRs; nothing is merged "
     "automatically."),
]


def new_stages() -> list[PipelineStage]:
    return [PipelineStage(id=i, name=n, agent=a, description=d) for i, n, a, d in PIPELINE_STAGES]


class JobOptions(BaseModel):
    """Optional knobs; every field has a safe default so a repo URL alone is enough."""
    ref: str | None = Field(default=None, description="Branch, tag or commit SHA. Defaults to the default branch.")
    max_findings: int | None = Field(default=None, ge=1, le=200)
    min_severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "low"
    scanners: list[str] | None = Field(default=None, description="Restrict to these scanners.")
    auto_fix: bool = True
    use_llm: bool = True
    fix_dependencies: bool = True
    run_tests: bool | None = Field(default=None, description="Run the test suite in the sandbox (needs SANDBOX_MODE).")
    test_command: str | None = Field(default=None, max_length=500)
    install_command: str | None = Field(default=None, max_length=500)
    verify_with_rescan: bool = True
    create_pr: bool = False
    github_tests: bool = Field(default=False, description="After the run, test the fix branch on GitHub Actions and let "
                                                          "the Remediation Agent fix failing tests (testloop.py).")
    pr_on_flagged: Literal["draft", "skip"] = "draft"
    use_cache: bool = True

    @field_validator("scanners")
    @classmethod
    def _scanners(cls, value):
        if value is None:
            return None
        return sorted({v.strip().lower() for v in value if v and v.strip()}) or None

    def cache_key_material(self) -> dict[str, Any]:
        data = self.model_dump(exclude={"use_cache", "create_pr", "github_tests"})
        return data


class RemediationReport(BaseModel):
    run_id: str
    repo: str
    repo_url: str | None = None
    ref: str | None = None
    commit: str | None = None
    branch: str | None = None
    status: str = "created"
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float = 0.0
    languages: dict[str, int] = Field(default_factory=dict)
    scanners: list[ScannerRun] = Field(default_factory=list)
    findings_input: int = 0
    findings_selected: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    patches_proposed: int = 0
    patches_applied: int = 0
    fixes: list[FixRecord] = Field(default_factory=list)
    verified_fixed: int = 0
    validation: list[ValidationResult] = Field(default_factory=list)
    validation_checks: list[ValidationCheck] = Field(default_factory=list)
    validation_status: Literal["not_run", "passed", "flagged", "failed"] = "not_run"
    stages: list[PipelineStage] = Field(default_factory=new_stages)
    category_counts: dict[str, int] = Field(default_factory=dict)
    scanner_counts: dict[str, int] = Field(default_factory=dict)
    base_commit: str | None = None
    pull_request_url: str | None = None
    pull_request_draft: bool | None = None
    approval_status: Literal["not_required", "awaiting_approval", "pr_opened", "failed"] = "not_required"
    llm_enabled: bool = False
    llm_model: str | None = None
    notes: list[str] = Field(default_factory=list)
