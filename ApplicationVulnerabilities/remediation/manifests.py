"""Dependency manifest/lockfile parsing, version comparison and deterministic version bumps."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .detect import iter_files


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem name
    file: str
    line: int | None = None
    direct: bool = True


def _line_of(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else None


def canonical_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# --- Parsers ---------------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!*-]+)")


def parse_requirements(text: str, rel: str) -> list[Package]:
    pkgs = []
    for no, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_RE.match(line.split(";", 1)[0])
        if m and "*" not in m.group(3):
            pkgs.append(Package(m.group(1), m.group(3), "PyPI", rel, no))
    return pkgs


def parse_pipfile_lock(text: str, rel: str) -> list[Package]:
    data = json.loads(text)
    pkgs = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            ver = str((meta or {}).get("version", "")).lstrip("=")
            if ver:
                pkgs.append(Package(name, ver, "PyPI", rel, _line_of(text, f'"{name}"'), direct))
    return pkgs


def parse_poetry_lock(text: str, rel: str) -> list[Package]:
    data = tomllib.loads(text)
    return [Package(p["name"], p["version"], "PyPI", rel, _line_of(text, f'name = "{p["name"]}"'), False)
            for p in data.get("package", []) if p.get("name") and p.get("version")]


def parse_package_lock(text: str, rel: str) -> list[Package]:
    data = json.loads(text)
    pkgs: dict[tuple[str, str], Package] = {}
    root_deps = set()
    root = (data.get("packages") or {}).get("") or {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        root_deps.update((root.get(key) or {}).keys())
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        ver = meta.get("version")
        if name and ver:
            pkgs[(name, ver)] = Package(name, ver, "npm", rel, _line_of(text, f'"{path}"'), name in root_deps)

    def walk(deps: dict, depth: int):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version") and not str(meta["version"]).startswith(("file:", "git")):
                pkgs.setdefault((name, meta["version"]),
                                Package(name, meta["version"], "npm", rel, _line_of(text, f'"{name}"'), depth == 0))
                walk(meta.get("dependencies"), depth + 1)
    if not data.get("packages"):
        walk(data.get("dependencies"), 0)
    return list(pkgs.values())


def parse_yarn_lock(text: str, rel: str) -> list[Package]:
    pkgs = {}
    current: list[str] = []
    for no, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
                if name:
                    current.append(name)
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            for name in set(current):
                pkgs[(name, m.group(1))] = Package(name, m.group(1), "npm", rel, no, False)
            current = []
    return list(pkgs.values())


def parse_package_json(text: str, rel: str) -> list[Package]:
    data = json.loads(text)
    pkgs = []
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            m = re.match(r"^[\^~=v]?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)$", str(spec).strip())
            if m:
                pkgs.append(Package(name, m.group(1), "npm", rel, _line_of(text, f'"{name}"'), True))
    return pkgs


def parse_go_mod(text: str, rel: str) -> list[Package]:
    pkgs = []
    in_block = False
    for no, line in enumerate(text.splitlines(), 1):
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([^\s]+)\s+(v[0-9][^\s]*)$", s) if (in_block or s.startswith("require ")) else None
        if m:
            pkgs.append(Package(m.group(1), m.group(2), "Go", rel, no, "// indirect" not in line))
    return pkgs


def parse_cargo_lock(text: str, rel: str) -> list[Package]:
    data = tomllib.loads(text)
    return [Package(p["name"], p["version"], "crates.io", rel, _line_of(text, f'name = "{p["name"]}"'), False)
            for p in data.get("package", []) if p.get("source", "").startswith("registry")]


def parse_gemfile_lock(text: str, rel: str) -> list[Package]:
    pkgs = []
    in_specs = False
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", line) if in_specs else None
        if m:
            pkgs.append(Package(m.group(1), m.group(2).split("-")[0], "RubyGems", rel, no, False))
    return pkgs


def parse_composer_lock(text: str, rel: str) -> list[Package]:
    data = json.loads(text)
    return [Package(p["name"], str(p["version"]).lstrip("v"), "Packagist", rel, _line_of(text, f'"{p["name"]}"'), False)
            for key in ("packages", "packages-dev") for p in data.get(key) or [] if p.get("name") and p.get("version")]


def parse_pom(text: str, rel: str) -> list[Package]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    q = (lambda tag: f"m:{tag}") if ns else (lambda tag: tag)
    props = {}
    props_el = root.find(q("properties"), ns)
    if props_el is not None:
        for child in props_el:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    pkgs = []
    for dep in root.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
        g, a, v = (dep.find(q(t), ns) for t in ("groupId", "artifactId", "version"))
        if g is None or a is None or v is None or not v.text:
            continue
        ver = v.text.strip()
        m = re.fullmatch(r"\$\{([^}]+)\}", ver)
        if m:
            ver = props.get(m.group(1), "")
        if ver and not ver.startswith("$"):
            pkgs.append(Package(f"{g.text.strip()}:{a.text.strip()}", ver, "Maven", rel,
                                _line_of(text, f"<artifactId>{a.text.strip()}</artifactId>"), True))
    return pkgs


PARSERS = {
    "Pipfile.lock": parse_pipfile_lock, "poetry.lock": parse_poetry_lock, "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock, "yarn.lock": parse_yarn_lock, "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock, "Gemfile.lock": parse_gemfile_lock, "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
}


def discover_packages(root: Path) -> tuple[list[Package], list[str]]:
    """Return (packages, warnings) for every supported manifest in the repository."""
    packages: list[Package] = []
    warnings: list[str] = []
    files = list(iter_files(root, max_bytes=20 * 1024 * 1024))
    lock_dirs = {p.parent for p in files if p.name in ("package-lock.json", "yarn.lock", "npm-shrinkwrap.json", "pnpm-lock.yaml")}
    for path in files:
        name = path.name
        parser = PARSERS.get(name)
        if parser is None and name.startswith("requirements") and name.endswith(".txt"):
            parser = parse_requirements
        if parser is None and name == "package.json" and path.parent not in lock_dirs:
            parser = parse_package_json
        if parser is None:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            packages.extend(parser(path.read_text(encoding="utf-8", errors="replace"), rel))
        except Exception as exc:  # malformed manifests must not break the scan
            warnings.append(f"Could not parse {rel}: {type(exc).__name__}: {exc}")
    return packages, warnings


# --- Versions --------------------------------------------------------------------------------

def _generic_key(version: str):
    parts = re.split(r"[.+-]", version.lstrip("vV"))
    key = []
    for part in parts:
        key.append((0, int(part), "") if part.isdigit() else (-1, 0, part))
    return key


def version_key(version: str, ecosystem: str | None = None):
    if ecosystem == "PyPI":
        try:
            from packaging.version import Version
            return (1, Version(version))
        except Exception:
            pass
    # npm/Go/crates/etc: semver-ish. Pre-releases sort before the release.
    core, _, pre = version.lstrip("vV").partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in re.split(r"[.+]", core)[:4]]
    while len(nums) < 4:
        nums.append(0)
    return (0, tuple(nums), 0 if pre else 1, _generic_key(pre) if pre else [])


def compare_versions(a: str, b: str, ecosystem: str | None = None) -> int:
    try:
        ka, kb = version_key(a, ecosystem), version_key(b, ecosystem)
        if ka[0] != kb[0]:
            ka, kb = version_key(a), version_key(b)
        return (ka > kb) - (ka < kb)
    except TypeError:
        return (a > b) - (a < b)


def best_fixed_version(installed: str, candidates: list[str], ecosystem: str | None = None) -> str | None:
    """Smallest candidate that is newer than ``installed`` (minimises upgrade risk)."""
    newer = [stable_version(c.strip(), ecosystem) for c in candidates
             if c and c.strip() and compare_versions(c.strip(), installed, ecosystem) > 0]
    newer = [c for c in newer if compare_versions(c, installed, ecosystem) > 0]
    if not newer:
        return None
    same_major = [c for c in newer if _major(c) == _major(installed)]
    pool = same_major or newer
    best = pool[0]
    for c in pool[1:]:
        if compare_versions(c, best, ecosystem) < 0:
            best = c
    return best


def is_prerelease(version: str, ecosystem: str | None = None) -> bool:
    if ecosystem == "PyPI":
        try:
            from packaging.version import Version
            v = Version(version)
            return v.is_prerelease or v.is_devrelease
        except Exception:
            pass
    core = version.lstrip("vV").split("+", 1)[0]
    return "-" in core or bool(re.search(r"\d(a|b|rc|alpha|beta|dev|pre)\d*$", core, re.I))


def stable_version(version: str, ecosystem: str | None = None) -> str:
    """Map a pre-release fix (1.3.0b3, 2.0.0-rc.1) to its final release, which also contains the fix."""
    if not is_prerelease(version, ecosystem):
        return version
    if ecosystem == "PyPI":
        try:
            from packaging.version import Version
            return Version(version).base_version
        except Exception:
            pass
    core = version.split("+", 1)[0].split("-", 1)[0]
    return re.sub(r"(a|b|rc|alpha|beta|dev|pre)\d*$", "", core, flags=re.I)


def is_major_upgrade(old: str | None, new: str | None) -> bool:
    if not old or not new:
        return False
    o, n = _major(old), _major(new)
    if o == "0" and n == "0":  # 0.x: minor versions are breaking by convention
        return re.split(r"[.+-]", old.lstrip("vV"))[1:2] != re.split(r"[.+-]", new.lstrip("vV"))[1:2]
    return o != n


def max_version(versions: list[str], ecosystem: str | None = None) -> str | None:
    best = None
    for v in versions:
        if v and (best is None or compare_versions(v, best, ecosystem) > 0):
            best = v
    return best


def _major(v: str) -> str:
    return re.split(r"[.+-]", v.lstrip("vV"), maxsplit=1)[0]


# --- Deterministic upgrades -----------------------------------------------------------------

@dataclass
class BumpResult:
    changed: bool
    message: str
    new_text: str | None = None


def bump_requirements(text: str, package: str, new_version: str) -> BumpResult:
    target = canonical_pypi(package)
    out, changed = [], False
    for line in text.splitlines(keepends=True):
        m = _REQ_RE.match(line.split("#", 1)[0].split(";", 1)[0])
        if m and canonical_pypi(m.group(1)) == target:
            start, end = m.span(3)
            line = line[:start] + new_version + line[end:]
            changed = True
        out.append(line)
    return BumpResult(changed, "updated pinned requirement" if changed else f"{package} is not pinned with == here",
                      "".join(out) if changed else None)


def bump_package_json(text: str, package: str, new_version: str) -> BumpResult:
    changed = False

    def repl(m):
        nonlocal changed
        changed = True
        prefix = m.group(2) if m.group(2) in ("^", "~") else ""
        return f'{m.group(1)}{prefix}{new_version}"'
    pattern = re.compile(r'("' + re.escape(package) + r'"\s*:\s*")([\^~=v]?)[^"]+"')
    new = pattern.sub(repl, text)
    return BumpResult(changed, "updated package.json range" if changed else f"{package} is not a direct dependency",
                      new if changed else None)


def bump_go_mod(text: str, package: str, new_version: str) -> BumpResult:
    v = new_version if new_version.startswith("v") else "v" + new_version
    pattern = re.compile(r"^(\s*(?:require\s+)?" + re.escape(package) + r"\s+)v[^\s]+", re.M)
    new, n = pattern.subn(lambda m: m.group(1) + v, text)
    return BumpResult(n > 0, "updated go.mod (run `go mod tidy` to refresh go.sum)" if n else "module not found",
                      new if n else None)


def bump_pom(text: str, package: str, new_version: str) -> BumpResult:
    if ":" not in package:
        return BumpResult(False, "not a Maven coordinate")
    group, artifact = package.split(":", 1)
    pattern = re.compile(r"(<dependency>(?:(?!</dependency>).)*?<groupId>\s*" + re.escape(group) +
                         r"\s*</groupId>(?:(?!</dependency>).)*?<artifactId>\s*" + re.escape(artifact) +
                         r"\s*</artifactId>(?:(?!</dependency>).)*?<version>)([^<$]+)(</version>)", re.S)
    new, n = pattern.subn(lambda m: m.group(1) + new_version + m.group(3), text)
    return BumpResult(n > 0, "updated pom.xml" if n else "version is managed by a property/parent; update manually",
                      new if n else None)


LOCKFILE_HINTS = {
    "package-lock.json": "run `npm install --package-lock-only` (or `npm audit fix`)",
    "yarn.lock": "run `yarn upgrade <pkg>`", "poetry.lock": "run `poetry update <pkg>`",
    "Pipfile.lock": "run `pipenv update <pkg>`", "Cargo.lock": "run `cargo update -p <pkg>`",
    "Gemfile.lock": "run `bundle update <pkg>`", "composer.lock": "run `composer update <pkg>`",
}


def bump_dependency(root: Path, manifest_rel: str, package: str, new_version: str) -> tuple[list[str], str]:
    """Apply a version bump. Returns (changed_files, message). Lockfile-only findings are
    redirected to the sibling manifest where possible."""
    manifest = (root / manifest_rel).resolve()
    if root.resolve() not in manifest.parents:
        return [], "manifest outside repository"
    name = manifest.name
    candidates: list[tuple[Path, callable]] = []
    if name.startswith("requirements") and name.endswith(".txt"):
        candidates.append((manifest, bump_requirements))
    elif name in ("package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json"):
        candidates.append((manifest.parent / "package.json", bump_package_json))
    elif name == "go.mod":
        candidates.append((manifest, bump_go_mod))
    elif name == "pom.xml":
        candidates.append((manifest, bump_pom))
    elif name in ("Pipfile.lock", "poetry.lock"):
        for req in sorted(manifest.parent.glob("requirements*.txt")):
            candidates.append((req, bump_requirements))
    changed, messages = [], []
    for path, func in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        res = func(text, package, new_version)
        messages.append(f"{path.relative_to(root).as_posix()}: {res.message}")
        if res.changed and res.new_text is not None:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(res.new_text)
            changed.append(path.relative_to(root).as_posix())
    hint = LOCKFILE_HINTS.get(name)
    if hint:
        messages.append(f"lockfile {manifest_rel} must be regenerated: {hint.replace('<pkg>', package)}")
    if not candidates:
        messages.append(f"no automatic bump strategy for {name}; " + (hint or "update the dependency manually"))
    return changed, "; ".join(messages)
