"""Repository inspection: languages, ecosystems and test commands (for the GitHub Actions tests)."""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "bower_components", ".venv", "venv", "env",
             "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "dist", "build", "target", ".next",
             ".nuxt", "coverage", ".gradle", ".idea", ".vscode", "site-packages", "third_party"}

LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".hpp": "cpp", ".swift": "swift", ".scala": "scala", ".sh": "shell", ".tf": "terraform",
}


def iter_files(root: Path, max_files: int = 50000, max_bytes: int | None = None):
    """Walk repository files, skipping vendored/generated folders and symlinks."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d in (".github",)]
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            if max_bytes is not None:
                try:
                    if path.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
            yield path
            count += 1
            if count >= max_files:
                return


@dataclass
class ProjectInfo:
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    primary_language: str | None = None
    test_command: str | None = None
    lines_of_code: int = 0  # lines in source files (vendored and generated folders skipped)


def _count_lines(path: Path, max_bytes: int = 2_000_000) -> int:
    """Lines in one source file; very large files (generated or minified) are left out."""
    try:
        if path.stat().st_size > max_bytes:
            return 0
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return 0
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def detect_project(root: Path) -> ProjectInfo:
    counts: Counter[str] = Counter()
    manifests = []
    manifest_names = {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock", "poetry.lock",
                      "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "Cargo.toml",
                      "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "Gemfile.lock",
                      "composer.json", "composer.lock", "Dockerfile"}
    lines = 0
    for path in iter_files(root):
        lang = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if lang:
            counts[lang] += 1
            if not is_vendored(path.relative_to(root).as_posix()):
                lines += _count_lines(path)
        if path.name in manifest_names or (path.name.startswith("requirements") and path.suffix == ".txt"):
            manifests.append(path.relative_to(root).as_posix())
    info = ProjectInfo(languages=dict(counts.most_common()), manifests=sorted(manifests), lines_of_code=lines)
    info.primary_language = counts.most_common(1)[0][0] if counts else None
    _detect_test_command(root, info)
    return info


def _detect_test_command(root: Path, info: ProjectInfo) -> None:
    top = {p.name for p in root.iterdir()} if root.exists() else set()
    lang = info.primary_language
    if "package.json" in top and lang in ("javascript", "typescript", None):
        try:
            pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pkg = {}
        script = (pkg.get("scripts") or {}).get("test", "")
        if script and "no test specified" not in script:
            info.test_command = "npm test --silent"
        return
    if lang == "python" or {"pyproject.toml", "setup.py", "requirements.txt"} & top:
        if (root / "tests").is_dir() or (root / "test").is_dir() or any(top_name.startswith("test_") for top_name in top):
            info.test_command = "python -m pytest -q -x"
        return
    if "go.mod" in top:
        info.test_command = "go test ./..."
    elif "Cargo.toml" in top:
        info.test_command = "cargo test -q"
    elif "pom.xml" in top:
        info.test_command = "mvn -q -B test"
    elif "build.gradle" in top or "build.gradle.kts" in top:
        info.test_command = "gradle test -q"
    elif "Gemfile" in top:
        info.test_command = "bundle exec rake test"


_VENDOR_DIR = re.compile(r"(^|/)(vendor|vendors|third[_-]?party|external|bower_components|static/(js/)?(lib|libs|vendor)|"
                         r"assets/(js/)?(lib|libs|vendor)|public/(js/)?(lib|libs|vendor))/", re.I)
_VENDOR_FILE = re.compile(r"(^|/)(jquery|bootstrap|materialize|angular|react(-dom)?|vue|lodash|underscore|moment|d3|"
                          r"chart|highcharts|backbone|ember|popper|select2|datatables|tinymce|ckeditor|codemirror|"
                          r"three|swiper|slick|semantic|foundation|bulma|axios|handlebars|mustache|knockout|zepto|"
                          r"prototype|mootools|modernizr|require|polyfills?|fontawesome|font-awesome)([.-][\w.-]*)?"
                          r"\.(js|mjs|css)$", re.I)


# Test code, fixtures, examples and docs: findings there are reported but ranked lower and not patched
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|testdata|fixtures|examples?|docs?)/|(^|/)test_[^/]*$|_test\.\w+$|\.(spec|test)\.\w+$")


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path.replace("\\", "/")))


def is_vendored(path: str) -> bool:
    """True for third-party library code bundled into the repository (fix by upgrading, not patching)."""
    p = path.replace("\\", "/")
    return bool(_VENDOR_DIR.search(p) or _VENDOR_FILE.search(p) or p.endswith((".min.js", ".min.css", ".bundle.js")))
