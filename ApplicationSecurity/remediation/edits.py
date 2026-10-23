"""Safe application of model-proposed search/replace edits."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import get_settings

PROTECTED_PREFIXES = (".git/",)
WORKFLOW_PREFIXES = (".github/workflows/", ".gitlab-ci", ".circleci/")


class EditError(ValueError):
    pass


@dataclass
class Edit:
    file: str
    search: str
    replace: str


def parse_edits(data: dict) -> list[Edit]:
    edits = []
    for item in data.get("edits") or []:
        if not isinstance(item, dict):
            raise EditError("Each edit must be an object with file/search/replace.")
        file, search, replace = item.get("file"), item.get("search"), item.get("replace")
        if not isinstance(file, str) or not isinstance(search, str) or not isinstance(replace, str):
            raise EditError("Edit is missing file, search or replace strings.")
        edits.append(Edit(file.strip(), search, replace))
    if len(edits) > 20:
        raise EditError("Too many edits proposed for a single finding.")
    return edits


def safe_path(root: Path, rel: str) -> Path:
    rel = rel.replace("\\", "/").lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel or ".." in Path(rel).parts or re.match(r"^[A-Za-z]:", rel):
        raise EditError(f"Illegal path: {rel!r}")
    if rel.startswith(PROTECTED_PREFIXES):
        raise EditError(f"Editing {rel} is not allowed.")
    if rel.startswith(WORKFLOW_PREFIXES) and not get_settings().allow_workflow_edits:
        raise EditError(f"Editing CI workflow {rel} is disabled (ALLOW_WORKFLOW_EDITS=false).")
    path = (root / rel).resolve()
    if root.resolve() not in path.parents:
        raise EditError(f"Path escapes repository: {rel}")
    if path.is_symlink():
        raise EditError(f"Refusing to edit symlink {rel}")
    return path


def _locate(content: str, search: str) -> tuple[int, int] | None:
    """Find ``search`` in ``content``: exact first, then tolerant of whitespace differences."""
    count = content.count(search)
    if count == 1:
        idx = content.index(search)
        return idx, idx + len(search)
    if count > 1:
        raise EditError("search text matches multiple locations; include more surrounding context.")
    # Tolerant match: compare line-by-line with stripped trailing whitespace / uniform indentation.
    src_lines = content.splitlines(keepends=True)
    want = [l.rstrip() for l in search.strip("\n").splitlines()]
    if not want:
        return None
    stripped_want = [l.strip() for l in want]
    hits = []
    for i in range(len(src_lines) - len(want) + 1):
        window = [src_lines[i + j].rstrip("\r\n").strip() for j in range(len(want))]
        if window == stripped_want:
            hits.append(i)
    if len(hits) > 1:
        raise EditError("search text matches multiple locations; include more surrounding context.")
    if not hits:
        return None
    start = sum(len(l) for l in src_lines[:hits[0]])
    end = start + sum(len(l) for l in src_lines[hits[0]:hits[0] + len(want)])
    if src_lines[hits[0] + len(want) - 1].endswith("\n") and not search.endswith("\n"):
        end -= 2 if src_lines[hits[0] + len(want) - 1].endswith("\r\n") else 1
    return start, end


def _reindent(replace: str, search: str, original: str) -> str:
    """When matched tolerantly, shift the replacement to the original block's indentation."""
    def indent(s: str) -> str:
        for line in s.splitlines():
            if line.strip():
                return line[:len(line) - len(line.lstrip())]
        return ""
    have, want = indent(search), indent(original)
    if have == want:
        return replace
    out = []
    for line in replace.splitlines(keepends=True):
        if line.startswith(have):
            line = want + line[len(have):]
        out.append(line)
    return "".join(out)


def apply_edits(root: Path, edits: list[Edit]) -> list[str]:
    """Apply all edits atomically (all-or-nothing). Returns changed repo-relative paths."""
    if not edits:
        raise EditError("No edits supplied.")
    pending: dict[Path, str] = {}
    originals: dict[Path, str] = {}
    for edit in edits:
        path = safe_path(root, edit.file)
        if path not in pending:
            if not path.is_file():
                if edit.search.strip():
                    raise EditError(f"File does not exist: {edit.file}")
                originals[path] = ""
                pending[path] = ""
            else:
                with open(path, encoding="utf-8", errors="strict", newline="") as fh:
                    originals[path] = fh.read()
                pending[path] = originals[path]
        content = pending[path]
        newline = "\r\n" if "\r\n" in content else "\n"
        search = edit.search.replace("\r\n", "\n")
        replace = edit.replace.replace("\r\n", "\n")
        if newline == "\r\n":
            search, replace = search.replace("\n", "\r\n"), replace.replace("\n", "\r\n")
        if not search.strip():
            if content.strip():
                raise EditError(f"Empty search block for existing file {edit.file}.")
            pending[path] = replace
            continue
        span = _locate(content, search)
        if span is None:
            raise EditError(f"search text not found in {edit.file}.")
        original_block = content[span[0]:span[1]]
        if original_block != search:
            replace = _reindent(replace, search, original_block)
        pending[path] = content[:span[0]] + replace + content[span[1]:]
    changed = []
    for path, content in pending.items():
        if content == originals[path]:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        changed.append(path.relative_to(root.resolve()).as_posix())
    if not changed:
        raise EditError("Edits did not change any file.")
    return changed
