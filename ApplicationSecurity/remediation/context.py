"""Builds the code context sent to the LLM for one finding."""
from __future__ import annotations

from pathlib import Path

from .scanners.builtin_secrets import redact

TEXT_SUFFIXES = {".py", ".txt", ".toml", ".ini", ".yaml", ".yml", ".json", ".md", ".cfg", ".sh", ".js", ".ts", ".tsx",
                 ".jsx", ".sql", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".tf", ".xml", ".gradle", ".mjs",
                 ".cjs", ".html", ".vue", ".svelte", ".conf", ".env.example"}
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", "worktrees", "runs", "dist", "build"}


def resolve_in_repo(repo: Path, file_path: str | None) -> Path | None:
    if not file_path:
        return None
    raw = Path(file_path)
    repo = repo.resolve()
    def candidates():
        yield raw if raw.is_absolute() else repo / raw
        if not raw.is_absolute():
            # Scanner paths are sometimes relative to a sub-directory; fall back to a suffix match.
            for p in repo.rglob(raw.name):
                if p.as_posix().endswith(raw.as_posix()):
                    yield p

    for cand in candidates():
        try:
            target = cand.resolve()
        except OSError:
            continue
        if target.is_file() and repo in target.parents and not cand.is_symlink():
            return target
    return None


def _numbered(lines: list[str], start: int, end: int) -> str:
    return "\n".join(f"{i + 1:>5}| {lines[i]}" for i in range(start, end))


def collect_context(repo: Path, finding, max_chars: int = 18000, window: int = 40) -> str:
    repo = repo.resolve()
    parts: list[str] = []
    target = resolve_in_repo(repo, finding.file_path)
    if target:
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        rel = target.relative_to(repo).as_posix()
        if lines:
            if len(lines) <= window * 3:
                parts.append(f"FILE: {rel} (entire file, {len(lines)} lines)\n" + _numbered(lines, 0, len(lines)))
            else:
                line = max(1, min(finding.line or 1, len(lines)))
                head_end = min(25, len(lines))
                start, end = max(0, line - 1 - window), min(len(lines), line + window)
                if start > head_end:
                    parts.append(f"FILE: {rel} lines 1-{head_end} (imports/header)\n" + _numbered(lines, 0, head_end))
                    parts.append(f"FILE: {rel} lines {start + 1}-{end} (around the finding)\n" + _numbered(lines, start, end))
                else:
                    parts.append(f"FILE: {rel} lines 1-{end}\n" + _numbered(lines, 0, end))
    if not parts:
        budget = max_chars
        for path in sorted(repo.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
                continue
            try:
                snippet = path.read_text(encoding="utf-8", errors="replace")[:2500]
            except OSError:
                continue
            parts.append(f"FILE: {path.relative_to(repo).as_posix()}\n{snippet}")
            budget -= len(parts[-1])
            if budget <= 0:
                break
    return redact("\n\n".join(parts))[:max_chars]
