"""GitHub repository URL parsing, metadata lookup, cloning and pull-request publishing."""
from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import get_settings
from .gitops import CmdResult, dir_size_bytes, git, remove_tree

_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REF_RE = re.compile(r"^(?!.*\.\.)(?!/)(?!.*//)(?!.*@\{)[A-Za-z0-9._/+-]{1,200}(?<!/)(?<!\.lock)$")


class RepoURLError(ValueError):
    """Raised when the supplied input is not an acceptable GitHub repository link."""


class RepoAccessError(RuntimeError):
    """Raised when the repository cannot be reached, cloned or is too large."""


@dataclass(frozen=True)
class RepoRef:
    host: str
    owner: str
    name: str
    ref: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def clone_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}.git"

    @property
    def html_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}"


def validate_ref(ref: str | None) -> str | None:
    if ref is None or ref == "":
        return None
    ref = ref.strip()
    if not _REF_RE.match(ref) or ref.startswith("-"):
        raise RepoURLError(f"Invalid branch/tag/commit reference: {ref!r}")
    return ref


def parse_repo_url(url: str, ref: str | None = None) -> RepoRef:
    """Accepts the common ways people paste a GitHub repository link.

    https://github.com/owner/repo(.git)            github.com/owner/repo
    https://github.com/owner/repo/tree/<branch>    https://github.com/owner/repo/commit/<sha>
    git@github.com:owner/repo.git                  ssh://git@github.com/owner/repo.git
    """
    if not isinstance(url, str) or not url.strip():
        raise RepoURLError("A GitHub repository URL is required.")
    raw = url.strip()
    if len(raw) > 500 or any(c.isspace() for c in raw):
        raise RepoURLError("Repository URL contains invalid characters.")
    allowed = get_settings().allowed_hosts

    ssh = re.match(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$", raw)
    if ssh:
        host, path = ssh.group(1).lower(), ssh.group(2)
    else:
        m = re.match(r"^(?:(https?)://)?([^/]+)/(.+)$", raw)
        if not m:
            raise RepoURLError("Expected a link like https://github.com/<owner>/<repo>.")
        scheme, host, path = m.group(1), m.group(2).lower(), m.group(3)
        if scheme == "http":
            raise RepoURLError("Use an https:// GitHub link.")
        if "@" in host:
            raise RepoURLError("Credentials must not be embedded in the URL; configure GITHUB_TOKEN instead.")
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
    if host not in allowed:
        raise RepoURLError(f"Only repositories hosted on {', '.join(sorted(allowed))} are accepted (got {host}).")

    path = path.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = path.split("/")
    if len(parts) < 2:
        raise RepoURLError("URL must include both the owner and the repository name.")
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    url_ref = None
    if len(parts) >= 4 and parts[2] in ("tree", "commit", "blob", "releases") and parts[3]:
        rest = parts[3:]
        if parts[2] == "releases" and rest[0] == "tag" and len(rest) > 1:
            rest = rest[1:]
        url_ref = "/".join(rest if parts[2] != "blob" else rest[:1])
    if not _OWNER_RE.match(owner) or not _NAME_RE.match(name) or name in (".", ".."):
        raise RepoURLError(f"Invalid GitHub owner/repository: {owner}/{name}")
    return RepoRef(host=host, owner=owner, name=name, ref=validate_ref(ref or url_ref))


@dataclass
class RepoMetadata:
    default_branch: str | None = None
    size_kb: int | None = None
    private: bool | None = None
    archived: bool | None = None
    language: str | None = None
    can_push: bool | None = None


class GitHubClient:
    def __init__(self, token: str | None = None, api_url: str | None = None, timeout: float = 30.0):
        s = get_settings()
        self.token = s.github_token if token is None else token
        self.api_url = (api_url or s.github_api_url).rstrip("/")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "ai-remediation-pipeline"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._client = httpx.Client(base_url=self.api_url, headers=headers, timeout=timeout)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        delay = 2.0
        for attempt in range(4):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise RepoAccessError(f"GitHub API unreachable: {exc}") from exc
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status_code in (502, 503, 504) or (
                    resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0"):
                if attempt == 3:
                    return resp
                reset = resp.headers.get("retry-after")
                time.sleep(min(float(reset) if reset and reset.isdigit() else delay, 30))
                delay *= 2
                continue
            return resp
        return resp  # pragma: no cover

    def get_repo(self, repo: RepoRef) -> RepoMetadata:
        resp = self._request("GET", f"/repos/{repo.owner}/{repo.name}")
        if resp.status_code == 404:
            hint = (" Check that your GitHub token can access it." if self.token else
                    " If it is private, add a GitHub token in Settings.")
            raise RepoAccessError(f"Repository {repo.full_name} was not found or is not accessible.{hint}")
        if resp.status_code in (401, 403):
            raise RepoAccessError(f"GitHub denied access to {repo.full_name} (HTTP {resp.status_code}): "
                                  f"{resp.json().get('message', '') if resp.content else ''}")
        resp.raise_for_status()
        data = resp.json()
        perms = data.get("permissions") or {}
        return RepoMetadata(default_branch=data.get("default_branch"), size_kb=data.get("size"),
                            private=data.get("private"), archived=data.get("archived"),
                            language=data.get("language"), can_push=perms.get("push"))

    def create_pull_request(self, repo: RepoRef, head: str, base: str, title: str, body: str,
                            draft: bool = False) -> tuple[str, int | None, bool]:
        """Open a PR. Returns (url, number, is_draft). Falls back to a normal PR where drafts are unsupported."""
        payload = {"title": title, "head": head, "base": base, "body": body[:60000], "maintainer_can_modify": True,
                   "draft": draft}
        resp = self._request("POST", f"/repos/{repo.owner}/{repo.name}/pulls", json=payload)
        if resp.status_code == 422 and draft and "draft" in resp.text.lower():
            payload.update(draft=False, title="[NEEDS INVESTIGATION] " + title)
            draft = False
            resp = self._request("POST", f"/repos/{repo.owner}/{repo.name}/pulls", json=payload)
        if resp.status_code == 422 and "already exists" in resp.text:
            existing = self._request("GET", f"/repos/{repo.owner}/{repo.name}/pulls",
                                     params={"head": f"{repo.owner}:{head}", "state": "open"})
            if existing.is_success and existing.json():
                pr = existing.json()[0]
                return pr["html_url"], pr.get("number"), bool(pr.get("draft"))
        if not resp.is_success:
            raise RepoAccessError(f"Could not open pull request (HTTP {resp.status_code}): {resp.text[:500]}")
        data = resp.json()
        return data["html_url"], data.get("number"), bool(data.get("draft", draft))

    def add_labels(self, repo: RepoRef, number: int, labels: list[str]) -> None:
        self._request("POST", f"/repos/{repo.owner}/{repo.name}/issues/{number}/labels", json={"labels": labels})

    def whoami(self) -> dict:
        resp = self._request("GET", "/user")
        if not resp.is_success:
            raise RepoAccessError(f"GitHub rejected the token (HTTP {resp.status_code}).")
        return {"login": resp.json().get("login"), "scopes": resp.headers.get("x-oauth-scopes")}

    # --- GitHub Actions (the Test & Fix loop, testloop.py) ---------------------------------------

    def _actions_json(self, path: str, **params) -> dict:
        resp = self._request("GET", path, params=params or None)
        if resp.status_code in (401, 403, 404):
            raise RepoAccessError(f"GitHub Actions is not readable with this token (HTTP {resp.status_code}). "
                                  "The token needs Actions: read on the repository.")
        resp.raise_for_status()
        return resp.json()

    def workflow_runs(self, repo: RepoRef, workflow_path: str, branch: str, head_sha: str) -> list[dict]:
        """Runs of ``workflow_path`` for ``head_sha`` on ``branch``, newest first."""
        data = self._actions_json(f"/repos/{repo.owner}/{repo.name}/actions/runs", branch=branch, head_sha=head_sha,
                                  per_page=20)
        return [run for run in data.get("workflow_runs") or [] if run.get("path", "").split("@")[0] == workflow_path]

    def find_workflow_run(self, repo: RepoRef, workflow_path: str, branch: str, head_sha: str,
                          exclude: set[int] | frozenset[int] = frozenset()) -> dict | None:
        """The newest run of ``workflow_path`` for ``head_sha`` that is not in ``exclude`` (None until it appears)."""
        for run in self.workflow_runs(repo, workflow_path, branch, head_sha):
            if run["id"] not in exclude:
                return run
        return None

    def dispatch_workflow(self, repo: RepoRef, workflow_path: str, branch: str) -> None:
        """Start the workflow again on ``branch`` (used when there is nothing new to push)."""
        name = workflow_path.rsplit("/", 1)[-1]
        resp = self._request("POST", f"/repos/{repo.owner}/{repo.name}/actions/workflows/{name}/dispatches",
                             json={"ref": branch})
        if not resp.is_success:
            raise RepoAccessError(f"Could not start the test workflow again (HTTP {resp.status_code}): {resp.text[:300]}")

    def get_workflow_run(self, repo: RepoRef, run_id: int) -> dict:
        return self._actions_json(f"/repos/{repo.owner}/{repo.name}/actions/runs/{run_id}")

    def workflow_run_logs(self, repo: RepoRef, run_id: int, limit: int = 60000) -> str:
        """Plain-text logs of the run's failed jobs (newest lines last), trimmed to ``limit`` characters."""
        jobs = self._actions_json(f"/repos/{repo.owner}/{repo.name}/actions/runs/{run_id}/jobs", per_page=50)
        parts = []
        for job in jobs.get("jobs") or []:
            if job.get("conclusion") not in ("failure", "timed_out", "cancelled"):
                continue
            # GitHub answers with a redirect to short-lived log storage; httpx drops the token on that hop.
            resp = self._request("GET", f"/repos/{repo.owner}/{repo.name}/actions/jobs/{job['id']}/logs",
                                 follow_redirects=True)
            if resp.is_success:
                parts.append(f"===== job: {job.get('name')} ({job.get('conclusion')}) =====\n{resp.text}")
        text = "\n".join(parts)
        return text[-limit:]


def _auth_config(token: str | None) -> list[str]:
    if not token:
        return []
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    # Sent as a header, never embedded in the remote URL, so it does not leak into logs or .git/config.
    return [f"http.extraHeader=Authorization: Basic {basic}"]


def _redact(text: str, token: str | None) -> str:
    if token:
        text = text.replace(token, "***")
    return re.sub(r"Authorization: Basic [A-Za-z0-9+/=]+", "Authorization: ***", text)


def clone_repo(repo: RepoRef, dest: Path, ref: str | None, timeout: int | None = None) -> str:
    """Shallow-fetch a single ref into ``dest`` and check it out. Returns the commit SHA."""
    s = get_settings()
    timeout = timeout or s.clone_timeout_seconds
    token = s.github_token or None
    auth = _auth_config(token)
    if dest.exists():
        remove_tree(dest)
    dest.mkdir(parents=True)

    def step(args: list[str], t: int = 120) -> CmdResult:
        res = git(args, dest, timeout=t, extra_config=auth)
        if not res.ok:
            msg = _redact(res.stderr.strip() or res.stdout.strip(), token)
            if "could not read Username" in msg or "Authentication failed" in msg or "not found" in msg.lower():
                msg += "\nThe repository may be private or the reference may not exist; configure GITHUB_TOKEN."
            raise RepoAccessError(f"git {' '.join(args[:2])} failed: {msg[-1500:]}")
        return res

    step(["init", "-q"])
    step(["remote", "add", "origin", repo.clone_url])
    target = ref or "HEAD"
    try:
        step(["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", target], timeout)
    except RepoAccessError:
        if ref and re.fullmatch(r"[0-9a-fA-F]{7,39}", ref):
            # Abbreviated SHAs cannot be fetched directly; fetch history and resolve locally.
            step(["fetch", "-q", "--filter=blob:none", "--no-tags", "origin"], timeout)
            target = ref
            res = step(["rev-parse", "--verify", f"{ref}^{{commit}}"])
            target = res.stdout.strip()
            step(["checkout", "-q", "--detach", target])
            sha = step(["rev-parse", "HEAD"]).stdout.strip()
            return sha
        raise
    step(["checkout", "-q", "--detach", "FETCH_HEAD"])
    sha = step(["rev-parse", "HEAD"]).stdout.strip()

    size = dir_size_bytes(dest, stop_after=s.max_repo_size_mb * 1024 * 1024)
    if size > s.max_repo_size_mb * 1024 * 1024:
        raise RepoAccessError(f"Repository checkout exceeds MAX_REPO_SIZE_MB={s.max_repo_size_mb}.")
    return sha


def resolve_remote_ref(repo: RepoRef, ref: str | None) -> str | None:
    """Best-effort ``git ls-remote`` lookup of the commit a ref points at (no clone)."""
    s = get_settings()
    from .gitops import git_base_args, run_cmd
    args = git_base_args()
    for item in _auth_config(s.github_token or None):
        args += ["-c", item]
    res = run_cmd(args + ["ls-remote", repo.clone_url, ref or "HEAD"], timeout=60)
    if not res.ok:
        return None
    for line in res.stdout.splitlines():
        sha, _, name = line.partition("\t")
        if not ref or name in (ref, f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"):
            return sha.strip()
    if ref and re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    return None


def push_branch(repo: RepoRef, workdir: Path, branch: str) -> None:
    s = get_settings()
    if not s.github_token:
        raise RepoAccessError("GITHUB_TOKEN is required to push a branch and open a pull request.")
    res = git(["push", "-q", "--force-with-lease", "origin", f"HEAD:refs/heads/{branch}"], workdir,
              timeout=300, extra_config=_auth_config(s.github_token))
    if not res.ok:
        raise RepoAccessError(f"Push failed: {_redact(res.stderr.strip(), s.github_token)[-1000:]}")
