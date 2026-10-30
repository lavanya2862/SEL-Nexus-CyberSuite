"""Subprocess and Git helpers. Commands are always passed as argument lists (no shell)."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import get_settings, scrubbed_env


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_cmd(args: list[str], cwd: str | Path | None = None, timeout: int = 600,
            env: dict[str, str] | None = None, input_text: str | None = None) -> CmdResult:
    # Binary I/O on purpose: text mode on Windows rewrites "\n" -> "\r\n" in stdin and drops "\r"
    # from stdout, which corrupts patches/mboxes and diffs of CRLF files.
    try:
        proc = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, timeout=timeout,
                              check=False, env=env if env is not None else scrubbed_env(),
                              input=input_text.encode("utf-8") if input_text is not None else None)
        return CmdResult(proc.returncode, (proc.stdout or b"").decode("utf-8", "replace"),
                         (proc.stderr or b"").decode("utf-8", "replace"))
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return CmdResult(124, out, f"Timed out after {timeout}s: {' '.join(args[:3])}", timed_out=True)
    except FileNotFoundError as exc:
        return CmdResult(127, "", f"Executable not found: {exc}")


def git_base_args() -> list[str]:
    """Hardened Git invocation: no hooks, no prompts, no CRLF rewriting, no local-file transports."""
    hooks = "NUL" if os.name == "nt" else "/dev/null"
    return ["git", "-c", f"core.hooksPath={hooks}", "-c", "core.autocrlf=false", "-c", "core.longpaths=true",
            "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
            "-c", "submodule.recurse=false", "-c", "advice.detachedHead=false"]


def git(args: list[str], cwd: Path, timeout: int = 300, extra_config: list[str] | None = None) -> CmdResult:
    cmd = git_base_args()
    for item in extra_config or []:
        cmd += ["-c", item]
    return run_cmd(cmd + args, cwd=cwd, timeout=timeout)


def git_identity() -> list[str]:
    s = get_settings()
    return [f"user.name={s.git_author_name}", f"user.email={s.git_author_email}", "commit.gpgsign=false"]


def git_root(repo: str | Path) -> Path:
    result = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=repo)
    if not result.ok:
        raise RuntimeError(f"Not a Git repository: {repo}\n{result.stderr}")
    return Path(result.stdout.strip()).resolve()


def head_sha(repo: Path) -> str:
    res = git(["rev-parse", "HEAD"], repo)
    if not res.ok:
        raise RuntimeError(f"Could not read HEAD: {res.stderr.strip()}")
    return res.stdout.strip()


def create_branch(repo: Path, branch: str) -> None:
    res = git(["checkout", "-q", "-B", branch], repo)
    if not res.ok:
        raise RuntimeError(f"Could not create branch {branch}: {res.stderr.strip()}")


def commit_all(repo: Path, message: str, paths: list[str] | None = None) -> str | None:
    add = git(["add", "--", *(paths or ["."])], repo)
    if not add.ok:
        raise RuntimeError(f"git add failed: {add.stderr.strip()}")
    staged = git(["diff", "--cached", "--quiet"], repo)
    if staged.returncode == 0:
        return None  # nothing to commit
    res = git(["commit", "-q", "--no-verify", "-m", message], repo, extra_config=git_identity())
    if not res.ok:
        raise RuntimeError(f"git commit failed: {res.stderr.strip()}")
    return head_sha(repo)


def revert_commit(repo: Path, sha: str, message: str) -> str | None:
    """Undo one commit with a new commit on top (history stays reviewable). None when it does not revert cleanly."""
    res = git(["revert", "--no-edit", "--no-commit", sha], repo, extra_config=git_identity())
    if not res.ok:
        git(["revert", "--abort"], repo)
        discard_changes(repo)
        return None
    res = git(["commit", "-q", "--no-verify", "-m", message], repo, extra_config=git_identity())
    if not res.ok:
        discard_changes(repo)
        return None
    return head_sha(repo)


def discard_changes(repo: Path) -> None:
    git(["reset", "-q", "--hard", "HEAD"], repo)
    git(["clean", "-q", "-fd"], repo)


def diff_since(repo: Path, base: str) -> str:
    res = git(["diff", "--no-color", "--no-ext-diff", base, "HEAD"], repo, timeout=120)
    return res.stdout if res.ok else ""


def commit_diff(repo: Path, sha: str, limit: int = 40000) -> str:
    res = git(["show", "--no-color", "--no-ext-diff", "--format=", sha], repo, timeout=60)
    out = res.stdout if res.ok else ""
    return out if len(out) <= limit else out[:limit] + "\n[diff truncated]\n"


def format_patch(repo: Path, base: str) -> str:
    """All commits since ``base`` as an mbox, so they can be replayed with ``git am`` later."""
    res = git(["format-patch", "--stdout", "--no-color", "--no-signature", f"{base}..HEAD"], repo, timeout=120)
    return res.stdout if res.ok else ""


def apply_mbox(repo: Path, mbox: str) -> tuple[bool, str]:
    cmd = git_base_args()
    for item in git_identity():
        cmd += ["-c", item]
    res = run_cmd(cmd + ["am", "--3way", "--keep-cr", "--committer-date-is-author-date"], cwd=repo,
                  input_text=mbox, timeout=300)
    if not res.ok:
        run_cmd(git_base_args() + ["am", "--abort"], cwd=repo)
        return False, (res.stderr or res.stdout)[-1500:]
    return True, "applied"


def changed_files(repo: Path) -> list[str]:
    res = git(["status", "--porcelain", "--untracked-files=all"], repo)
    files = []
    for line in res.stdout.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        files.append(path.strip('"'))
    return files


def apply_patch(worktree: Path, patch: str) -> tuple[bool, str]:
    """Apply a unified diff, trying progressively more tolerant strategies."""
    if not patch.endswith("\n"):
        patch += "\n"
    strategies = [["apply", "--whitespace=nowarn"],
                  ["apply", "--whitespace=nowarn", "--recount"],
                  ["apply", "--whitespace=nowarn", "--recount", "--ignore-whitespace", "-C1"]]
    last = ""
    for strategy in strategies:
        check = run_cmd(git_base_args() + strategy + ["--check", "-"], cwd=worktree, input_text=patch)
        if check.ok:
            applied = run_cmd(git_base_args() + strategy + ["-"], cwd=worktree, input_text=patch)
            if applied.ok:
                return True, "Patch applied."
            last = applied.stderr or applied.stdout
        else:
            last = check.stderr or check.stdout
    return False, last.strip()


def _on_rm_error(func, path, _exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onexc=_on_rm_error) if _supports_onexc() else shutil.rmtree(path, onerror=_on_rm_error)


def _supports_onexc() -> bool:
    import sys
    return sys.version_info >= (3, 12)


def dir_size_bytes(path: Path, stop_after: int | None = None) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
            if stop_after and total > stop_after:
                return total
    return total


def create_worktree(repo: str | Path, worktree_root: Path, run_id: str, base_ref: str = "HEAD"):
    """Legacy helper retained for local-path usage."""
    import re
    root = git_root(repo)
    worktree_root.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^a-zA-Z0-9-]", "-", run_id)
    branch = f"ai-remediation/{safe_id}"
    worktree = (worktree_root / safe_id).resolve()
    result = git(["worktree", "add", "-b", branch, str(worktree), base_ref], root)
    if not result.ok:
        raise RuntimeError(f"Could not create isolated worktree:\n{result.stderr}")
    return worktree, branch
