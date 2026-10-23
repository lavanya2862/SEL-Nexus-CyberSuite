"""Built-in secret detection, used when Trivy (which has a richer secret engine) is unavailable."""
from __future__ import annotations

import math
import re
from pathlib import Path

from ..detect import iter_files
from ..models import Finding
from .base import Scanner

SECRET_PATTERNS = [
    ("aws-access-key-id", "AWS access key ID", "critical", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", "GitHub token", "critical", r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ("gitlab-token", "GitLab token", "critical", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("slack-token", "Slack token", "high", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ("slack-webhook", "Slack webhook URL", "medium", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("private-key", "Private key", "critical", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"),
    ("google-api-key", "Google API key", "high", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("stripe-secret", "Stripe secret key", "critical", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    ("openai-key", "OpenAI API key", "critical", r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b"),
    ("anthropic-key", "Anthropic API key", "critical", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
    ("twilio-key", "Twilio API key", "high", r"\bSK[0-9a-fA-F]{32}\b"),
    ("sendgrid-key", "SendGrid API key", "high", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("jwt", "JSON Web Token", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("db-url-password", "Database URL with embedded password", "high",
     r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{3,}@[^\s'\"]+"),
]
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(password|passwd|pwd|secret|api_?key|access_?key|auth_?token|client_?secret)[A-Za-z0-9_]*)"
    r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")
PLACEHOLDER = re.compile(r"(?i)(change.?me|example|placeholder|your[_-]|xxx+|dummy|sample|test|fake|redacted|\*{3,}|"
                         r"<[^>]+>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|none|null|password\d*$)")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".jar", ".woff", ".woff2", ".ttf",
                 ".lock", ".svg", ".mp4", ".exe", ".dll", ".so", ".pyc", ".class", ".min.js", ".map"}
_COMPILED = [(i, t, s, re.compile(p)) for i, t, s, p in SECRET_PATTERNS]
ALL_SECRET_RES = [p for _, _, _, p in _COMPILED]


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def redact(text: str) -> str:
    """Mask anything that looks like a credential before it leaves the worker (e.g. LLM prompts)."""
    for pattern in ALL_SECRET_RES:
        text = pattern.sub(lambda m: m.group(0)[:4] + "****REDACTED****", text)
    return GENERIC_ASSIGNMENT.sub(lambda m: m.group(0).replace(m.group(3), "****REDACTED****")
                                 if not PLACEHOLDER.search(m.group(3)) else m.group(0), text)


class BuiltinSecretsScanner(Scanner):
    name, kind, setting = "builtin-secrets", "secrets", "enable_builtin_secrets"
    description = "Built-in credential patterns + entropy check (fallback when Trivy is absent)"
    redundant_with = {"trivy"}

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        findings = []
        for path in iter_files(root, max_bytes=2_000_000):
            if any(path.name.lower().endswith(s) for s in SKIP_SUFFIXES):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except (UnicodeDecodeError, OSError):
                continue
            for no, line in enumerate(text.splitlines(), 1):
                if len(line) > 5000:
                    continue
                hit = None
                for rule_id, title, severity, pattern in _COMPILED:
                    if pattern.search(line):
                        hit = (rule_id, title, severity)
                        break
                if not hit:
                    m = GENERIC_ASSIGNMENT.search(line)
                    if m and not PLACEHOLDER.search(m.group(3)) and _entropy(m.group(3)) >= 3.0:
                        hit = ("generic-credential", f"Hard-coded credential in '{m.group(1)}'", "high")
                if hit:
                    findings.append(Finding(
                        finding_id=f"SECRET-{hit[0]}-{len(findings) + 1}", scanner="Builtin-Secrets",
                        category="exposed_secret", severity=hit[2], title=hit[1],
                        description="Potential hard-coded credential (value redacted). Remove it from source, "
                                    "rotate the credential, and load it from the environment or a secret manager.",
                        file_path=rel, line=no, snippet=f"{hit[0]}:{redact(line.strip())[:120]}", rule_id=hit[0],
                        cwe=["798"], remediation_type="secret_removal", confidence="medium"))
        return findings
