"""Remediation strategies, from cheapest/most reliable to most flexible:

1. dependency  - deterministic manifest version bumps (no LLM)
2. rule        - deterministic rewrites for built-in rules with a known-safe autofix
3. llm         - model-proposed search/replace edits, self-corrected on failure
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import get_settings, scrubbed_env
from .context import collect_context, resolve_in_repo
from .edits import EditError, apply_edits, parse_edits
from .gitops import apply_patch, changed_files, discard_changes, run_cmd
from .llm import SYSTEM_PROMPT, LLMError, LLMQuotaExhausted, chat, extract_diff, extract_json, finding_prompt
from .manifests import bump_dependency, is_major_upgrade, max_version, stable_version
from .models import Finding
from .scanners.builtin_sast import RULES
from .validate import static_check


@dataclass
class FixAttempt:
    ok: bool
    files: list[str] = field(default_factory=list)
    summary: str = ""
    detail: str = ""
    manual: bool = False  # the issue needs a human (not a failure of the tooling)


# --- 1. dependencies ------------------------------------------------------------------------

def group_dependency_findings(findings: list[Finding]) -> dict[tuple[str, str], list[Finding]]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.is_dependency and f.file_path:
            groups.setdefault((f.file_path, f.package_name or ""), []).append(f)
    return groups


def fix_dependency_group(root: Path, manifest: str, package: str, group: list[Finding]) -> FixAttempt:
    eco = group[0].ecosystem
    fixed = [f.fixed_version for f in group if f.fixed_version]
    installed = group[0].installed_version
    if not fixed:
        return FixAttempt(False, manual=True, detail="No patched version has been published for these advisories; "
                                                        "consider replacing the package or applying mitigations.")
    target = stable_version(max_version(fixed, eco), eco)
    unfixed = [f.advisory_id for f in group if not f.fixed_version]
    files, message = bump_dependency(root, manifest, package, target)
    if not files:
        return FixAttempt(False, manual=True, detail=message)
    ok, problem = static_check(root, files)
    if not ok:
        discard_changes(root)
        return FixAttempt(False, detail=f"Manifest became invalid: {problem}")
    advisories = ", ".join(sorted({f.advisory_id or f.title for f in group}))
    detail = message + (f"; still unfixed upstream: {', '.join(filter(None, unfixed))}" if unfixed else "")
    summary = f"Upgrade {package} {installed} -> {target} ({advisories})"
    if is_major_upgrade(installed, target):
        summary = "[MAJOR] " + summary
        detail = "Major-version upgrade: expect breaking API changes; run the test suite. " + detail
    return FixAttempt(True, files, summary, detail)


def npm_lockfile_dirs(root: Path, findings: list[Finding]) -> list[str]:
    """Directories (repo-relative) holding an npm lockfile that has vulnerable entries."""
    dirs = set()
    for f in findings:
        if f.is_dependency and f.ecosystem == "npm" and f.file_path:
            d = Path(f.file_path).parent.as_posix()
            d = "" if d == "." else d
            if (root / d / "package-lock.json").is_file() and (root / d / "package.json").is_file():
                dirs.add(d)
    return sorted(dirs)


def refresh_npm_lockfile(root: Path, rel_dir: str) -> FixAttempt:
    """Re-resolve package-lock.json after manifest bumps and apply ``npm audit fix`` for transitive
    advisories. ``--package-lock-only --ignore-scripts`` means nothing is installed and no
    repository code (lifecycle scripts) is executed."""
    npm = shutil.which("npm")
    if not npm or not get_settings().enable_lockfile_refresh:
        return FixAttempt(False, manual=True, detail="npm is not available on the worker (or lockfile refresh is "
                                                     "disabled); run `npm audit fix` and commit package-lock.json.")
    workdir = (root / rel_dir).resolve()
    if root.resolve() not in workdir.parents and workdir != root.resolve():
        return FixAttempt(False, detail="lockfile directory escapes repository")
    lock = workdir / "package-lock.json"
    before = lock.read_bytes()
    env = scrubbed_env({"npm_config_update_notifier": "false", "npm_config_fund": "false", "CI": "true"})
    timeout = min(600, get_settings().scanner_timeout_seconds)
    common = ["--package-lock-only", "--ignore-scripts", "--no-fund"]
    log_lines = []
    for args in ([npm, "install", *common, "--no-audit"], [npm, "audit", "fix", *common]):
        res = run_cmd(args, cwd=workdir, timeout=timeout, env=env)
        if not res.ok and "ERESOLVE" in (res.stderr + res.stdout):
            res = run_cmd(args + ["--legacy-peer-deps"], cwd=workdir, timeout=timeout, env=env)
        log_lines.append(f"`npm {' '.join(args[1:3])}` exit {res.returncode}")
    after = lock.read_bytes() if lock.exists() else b""
    if not after or after == before:
        discard_changes(root)
        return FixAttempt(False, manual=True, detail="npm could not update the lockfile automatically (" +
                          "; ".join(log_lines) + "); a major upgrade may be required (`npm audit fix --force`).")
    try:
        json.loads(after.decode("utf-8"))
    except ValueError:
        discard_changes(root)
        return FixAttempt(False, detail="npm produced an invalid package-lock.json")
    rel = (Path(rel_dir) / "package-lock.json").as_posix()
    files = [rel] + ([(Path(rel_dir) / "package.json").as_posix()]
                     if (Path(rel_dir) / "package.json").as_posix() in changed_files(root) else [])
    return FixAttempt(True, files, f"Regenerate {rel} and apply `npm audit fix` (non-breaking upgrades)",
                      "; ".join(log_lines))


# --- 2. deterministic rule fixes --------------------------------------------------------------

_POST_FIX = {"PY-YAML-LOAD": [(re.compile(r",\s*Loader\s*=\s*[\w.]+"), "")]}
_NEEDS_PY_IMPORT = {"PY-FLASK-DEBUG": "os"}
_PY_IMPORT_RE = re.compile(r"^(import|from)\s+\S+")


def ensure_python_import(lines: list[str], module: str) -> int:
    """Insert ``import <module>`` at module level if missing. Returns the number of lines inserted."""
    pattern = re.compile(rf"^\s*(import\s+([\w.]+\s*,\s*)*{re.escape(module)}\b|from\s+{re.escape(module)}\s+import\b)")
    if any(pattern.match(line) for line in lines):
        return 0
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    insert_at = 0
    # Skip shebang/encoding comments and a module docstring.
    while insert_at < len(lines) and lines[insert_at].startswith("#"):
        insert_at += 1
    if insert_at < len(lines) and lines[insert_at].lstrip().startswith(('"""', "'''")):
        quote = lines[insert_at].lstrip()[:3]
        end = insert_at if lines[insert_at].count(quote) >= 2 else next(
            (i for i in range(insert_at + 1, len(lines)) if quote in lines[i]), insert_at)
        insert_at = end + 1
    future = [i for i, line in enumerate(lines) if line.startswith("from __future__")]
    if future:
        insert_at = future[-1] + 1
    else:
        first_import = next((i for i, line in enumerate(lines) if _PY_IMPORT_RE.match(line)), None)
        if first_import is not None and first_import >= insert_at:
            insert_at = first_import
    lines.insert(insert_at, f"import {module}{newline}")
    return 1


_SECRET_ASSIGN = {
    ".py": re.compile(r"^(?P<indent>\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<ann>\s*:\s*str)?\s*=\s*"
                      r"(?P<q>[rbuRBU]?['\"])(?P<val>[^'\"\n]{6,})['\"]\s*(?P<comment>#.*)?$"),
    ".js": re.compile(r"^(?P<indent>\s*)(?P<kw>const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
                      r"(?P<q>['\"`])(?P<val>[^'\"`\n]{6,})['\"`]\s*;?\s*(?P<comment>//.*)?$"),
}
_SECRET_ASSIGN[".ts"] = _SECRET_ASSIGN[".mjs"] = _SECRET_ASSIGN[".cjs"] = _SECRET_ASSIGN[".js"]


def fix_secret_to_env(root: Path, finding: Finding) -> FixAttempt | None:
    """Replace a hard-coded credential assignment with an environment-variable lookup."""
    target = resolve_in_repo(root, finding.file_path)
    if not target or not finding.line:
        return None
    regex = _SECRET_ASSIGN.get(target.suffix.lower())
    if regex is None:
        return None
    with open(target, encoding="utf-8", errors="strict", newline="") as fh:
        lines = fh.read().splitlines(keepends=True)
    if finding.line > len(lines):
        return None
    original = lines[finding.line - 1]
    eol = "\r\n" if original.endswith("\r\n") else ("\n" if original.endswith("\n") else "")
    m = regex.match(original.rstrip("\r\n"))
    if not m:
        return None
    name = m.group("name")
    env_name = re.sub(r"(?<!^)(?=[A-Z][a-z])", "_", name).upper()
    comment = f"  {m.group('comment')}" if m.group("comment") else ""
    if target.suffix.lower() == ".py":
        ann = m.group("ann") or ""
        lines[finding.line - 1] = f'{m.group("indent")}{name}{ann} = os.environ.get("{env_name}", ""){comment}{eol}'
        ensure_python_import(lines, "os")
    else:
        lines[finding.line - 1] = (f'{m.group("indent")}{m.group("kw")} {name} = process.env.{env_name} || "";'
                                   f'{comment}{eol}')
    with open(target, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(lines))
    rel = target.relative_to(root.resolve()).as_posix()
    ok, problem = static_check(root, [rel])
    if not ok:
        discard_changes(root)
        return FixAttempt(False, detail=f"Secret rewrite produced invalid code: {problem}")
    return FixAttempt(True, [rel], f"Move hard-coded credential `{name}` to environment variable {env_name} "
                                   f"({rel}:{finding.line})",
                      f"The literal value was removed from source; the application now reads {env_name} from the "
                      "environment. ROTATE the exposed credential — it remains in Git history.")


def fix_with_rule(root: Path, finding: Finding) -> FixAttempt | None:
    target = resolve_in_repo(root, finding.file_path)
    if not target or not finding.line:
        return None
    suffix = target.suffix.lower()
    with open(target, encoding="utf-8", errors="strict", newline="") as fh:
        lines = fh.read().splitlines(keepends=True)
    if finding.line > len(lines):
        return None
    original = lines[finding.line - 1]
    for rule in RULES:
        if not rule.autofix or suffix not in rule.suffixes or rule.category != finding.category:
            continue
        if not rule.pattern.search(original) or (rule.unless and rule.unless.search(original)):
            continue
        pattern, replacement = rule.autofix
        new = pattern.sub(replacement, original, count=1)
        for post_pattern, post_repl in _POST_FIX.get(rule.id, []):
            new = post_pattern.sub(post_repl, new)
        if new == original:
            continue
        lines[finding.line - 1] = new
        if rule.id in _NEEDS_PY_IMPORT:
            ensure_python_import(lines, _NEEDS_PY_IMPORT[rule.id])
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write("".join(lines))
        rel = target.relative_to(root.resolve()).as_posix()
        ok, problem = static_check(root, [rel])
        if not ok:
            discard_changes(root)
            return FixAttempt(False, detail=f"Rule autofix produced invalid code: {problem}")
        return FixAttempt(True, [rel], f"{rule.title}: deterministic rewrite in {rel}:{finding.line}",
                          f"`{original.strip()}` -> `{new.strip()}`")
    return None


# --- 3. LLM ----------------------------------------------------------------------------------

def fix_with_llm(root: Path, finding: Finding, attempts: int = 2,
                 log: Callable[[str], None] | None = None) -> FixAttempt:
    context = collect_context(root, finding)
    messages = [{"role": "user", "content": finding_prompt(finding, context)}]
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            reply = chat(SYSTEM_PROMPT, messages)
        except LLMQuotaExhausted:
            raise  # the caller stops using the LLM for the rest of the run
        except LLMError as exc:
            return FixAttempt(False, detail=str(exc))
        data = extract_json(reply)
        try:
            if data is None:
                diff = extract_diff(reply)
                if not diff:
                    raise EditError("Response was neither the requested JSON object nor a unified diff.")
                ok, message = apply_patch(root, diff)
                if not ok:
                    raise EditError(f"Unified diff did not apply: {message[:500]}")
                files, explanation = changed_files(root), "Applied unified diff from model."
            else:
                if str(data.get("status", "")).lower() == "cannot_fix":
                    return FixAttempt(False, manual=True,
                                      detail=f"Model declined: {str(data.get('explanation', ''))[:500]}")
                files = apply_edits(root, parse_edits(data))
                explanation = str(data.get("explanation", ""))[:1000]
            ok, problem = static_check(root, files)
            if not ok:
                raise EditError(f"Edit introduced a syntax error: {problem}")
            return FixAttempt(True, files, f"{finding.title} in {finding.file_path}:{finding.line or '?'}",
                              explanation)
        except (EditError, OSError, UnicodeDecodeError) as exc:
            discard_changes(root)
            last_error = str(exc)
            if log:
                log(f"{finding.finding_id}: attempt {attempt} rejected: {last_error[:200]}")
            messages += [{"role": "assistant", "content": reply[:8000]},
                         {"role": "user", "content": f"That response could not be applied: {last_error}\n"
                                                     "Copy the search text verbatim from the context (without the "
                                                     "line-number prefix) and return the corrected JSON object only."}]
    return FixAttempt(False, detail=f"Could not produce an applicable fix: {last_error}")
