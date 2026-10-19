"""Built-in dependency scanner backed by the public OSV.dev API (no local tooling needed)."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from ..config import get_settings
from ..manifests import Package, best_fixed_version, canonical_pypi, discover_packages
from ..models import Finding, normalize_severity
from .base import Scanner

log = logging.getLogger(__name__)
_CACHE_TTL = 24 * 3600


def _cvss_to_severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "unknown"


def _severity(vuln: dict) -> str:
    db = vuln.get("database_specific") or {}
    if db.get("severity"):
        return normalize_severity(db["severity"])
    for aff in vuln.get("affected") or []:
        sev = (aff.get("ecosystem_specific") or {}).get("severity") or (aff.get("database_specific") or {}).get("severity")
        if sev:
            return normalize_severity(sev)
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score", ""))
        try:
            return _cvss_to_severity(float(score))
        except ValueError:
            pass
        if score.startswith("CVSS:3"):
            return _cvss3_base(score)
    return "medium"


def _cvss3_base(vector: str) -> str:
    """Compute a CVSS v3 base score bucket from its vector (enough for prioritisation)."""
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        cia = [{"H": 0.56, "L": 0.22, "N": 0.0}[m[k]] for k in ("C", "I", "A")]
        iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        if impact <= 0:
            return "info"
        expl = 8.22 * av * ac * pr * ui
        base = min((impact + expl) * (1.08 if scope_changed else 1), 10)
        return _cvss_to_severity(round(base, 1))
    except (KeyError, ValueError):
        return "medium"


def _fixed_versions(vuln: dict, pkg: Package) -> list[str]:
    fixed = []
    want = canonical_pypi(pkg.name) if pkg.ecosystem == "PyPI" else pkg.name
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        name = canonical_pypi(p.get("name", "")) if pkg.ecosystem == "PyPI" else p.get("name")
        if name != want or p.get("ecosystem", "").split(":")[0] != pkg.ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    return fixed


class OsvScanner(Scanner):
    name, kind, setting = "osv", "sca", "enable_osv"
    description = "Built-in dependency scan of lockfiles/manifests against OSV.dev advisories"

    def __init__(self):
        self._client: httpx.Client | None = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(base_url=get_settings().osv_api_url, timeout=30,
                                        headers={"User-Agent": "ai-remediation-pipeline"})
        return self._client

    def _post(self, path: str, payload: dict) -> dict:
        delay = 1.0
        for attempt in range(4):
            try:
                resp = self._http().post(path, json=payload)
                if resp.status_code < 500 and resp.status_code != 429:
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError:
                if attempt == 3:
                    raise
            time.sleep(delay)
            delay *= 2
        raise RuntimeError("OSV API unavailable")

    def _vuln_details(self, vuln_id: str) -> dict | None:
        cache_dir = get_settings().cache_dir / "osv"
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / (hashlib.sha1(vuln_id.encode()).hexdigest() + ".json")
        if path.exists() and time.time() - path.stat().st_mtime < _CACHE_TTL:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                pass
        for attempt in range(3):
            try:
                resp = self._http().get(f"/v1/vulns/{vuln_id}")
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                tmp.replace(path)
                return data
            except (httpx.HTTPError, OSError):
                time.sleep(1 + attempt)
        return None

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        packages, warnings = discover_packages(root)
        self.last_message = "; ".join(warnings)[:500]
        if not packages:
            return []
        # Query unique (ecosystem, name, version) triples in batches.
        unique: dict[tuple[str, str, str], list[Package]] = {}
        for pkg in packages:
            unique.setdefault((pkg.ecosystem, pkg.name, pkg.version), []).append(pkg)
        keys = list(unique)
        hits: dict[tuple[str, str, str], list[str]] = {}
        for start in range(0, len(keys), 500):
            chunk = keys[start:start + 500]
            data = self._post("/v1/querybatch", {"queries": [
                {"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]})
            for key, result in zip(chunk, data.get("results") or []):
                ids = [v["id"] for v in (result or {}).get("vulns") or []]
                if ids:
                    hits[key] = ids
        all_ids = sorted({i for ids in hits.values() for i in ids})
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="osv") as pool:
            details = dict(zip(all_ids, pool.map(self._vuln_details, all_ids)))
        findings = []
        for key, ids in hits.items():
            for pkg in unique[key]:
                for vid in ids:
                    vuln = details.get(vid) or {"id": vid}
                    if vuln.get("withdrawn"):
                        continue
                    fixed = best_fixed_version(pkg.version, _fixed_versions(vuln, pkg), pkg.ecosystem)
                    aliases = [a for a in vuln.get("aliases") or [] if a != vid]
                    refs = [r.get("url") for r in vuln.get("references") or [] if r.get("url")][:8]
                    findings.append(Finding(
                        finding_id=f"OSV-{vid}-{len(findings) + 1}", scanner="OSV", category="dependency_vulnerability",
                        severity=_severity(vuln), title=vuln.get("summary") or f"{vid} in {pkg.name}",
                        description=(vuln.get("details") or "")[:3000], file_path=pkg.file, line=pkg.line,
                        package_name=pkg.name, ecosystem=pkg.ecosystem, installed_version=pkg.version,
                        fixed_version=fixed, advisory_id=vid, aliases=aliases, references=refs,
                        cwe=[c.split("-")[-1] for c in (vuln.get("database_specific") or {}).get("cwe_ids") or []],
                        confidence="high" if pkg.direct else "medium", remediation_type="dependency_upgrade",
                        raw={"direct": pkg.direct}))
        return findings
