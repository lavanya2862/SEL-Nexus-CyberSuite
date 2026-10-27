import os
import subprocess
from pathlib import Path

import pytest

from remediation import config, db


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """Every test gets its own data dir/database and no external side effects."""
    env = {
        "DATA_DIR": str(tmp_path / "data"), "DATABASE_URL": "", "EMBEDDED_WORKER": "false",
        "LLM_API_KEY": "", "LLM_MODEL": "", "LLM_PROVIDER": "auto", "GITHUB_TOKEN": "", "API_KEYS": "",
        "ENABLE_TRIVY": "false", "ENABLE_SEMGREP": "false", "ENABLE_BANDIT": "false",
        "ENABLE_CODEQL": "false", "ENABLE_OSV": "false", "LOG_LEVEL": "WARNING",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setitem(config.Settings.model_config, "env_file", None)  # ignore the suite .env
    monkeypatch.chdir(tmp_path)
    config.reset_settings_cache()
    db.reset_engine()
    yield
    db.reset_engine()
    config.reset_settings_cache()


def make_git_repo(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["git", "init", "-q"], ["git", "add", "."], ["git", "-c", "commit.gpgsign=false", "commit", "-qm", "init"]):
        subprocess.run(cmd, cwd=path, check=True, env=env, capture_output=True)
    return path
