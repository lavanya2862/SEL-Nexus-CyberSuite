"""KQL template library (config/kql_templates/*.kql). Header comments carry metadata:

// name: ...        // kind: ioc | behaviour | manual        // ioc_type: ip | domain | url | sha256,sha1,md5
// technique: T....

Placeholders: {{LOOKBACK}} (days) and {{VALUES}} (a comma-separated list of KQL string literals).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from threat_intel.config import CONFIG_DIR

TEMPLATE_DIR = CONFIG_DIR / "kql_templates"


@dataclass(frozen=True)
class Template:
    key: str
    name: str
    kind: str
    ioc_types: tuple[str, ...]
    technique: str
    body: str

    def render(self, lookback_days: int, values: list[str] | None = None) -> str:
        query = self.body.replace("{{LOOKBACK}}", str(int(lookback_days)))
        if "{{VALUES}}" in query:
            query = query.replace("{{VALUES}}", kql_list(values or []))
        return query


def kql_string(value: str) -> str:
    """Verbatim KQL string literal: @"..." with embedded quotes doubled (backslashes stay literal)."""
    return '@"' + value.replace('"', '""') + '"'


def kql_list(values: list[str]) -> str:
    return ", ".join(kql_string(v) for v in values) or '@"__none__"'


def parse(path: Path) -> Template:
    meta, body = {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("//") and ":" in stripped and not body:
            key, _, value = stripped[2:].partition(":")
            meta[key.strip()] = value.strip()
        elif stripped or body:
            body.append(line)
    return Template(key=path.stem, name=meta.get("name", path.stem), kind=meta.get("kind", "behaviour"),
                    ioc_types=tuple(t.strip() for t in meta.get("ioc_type", "").split(",") if t.strip()),
                    technique=meta.get("technique", ""), body="\n".join(body).strip())


def load(directory: Path = TEMPLATE_DIR) -> dict[str, Template]:
    return {p.stem: parse(p) for p in sorted(directory.glob("*.kql"))}
