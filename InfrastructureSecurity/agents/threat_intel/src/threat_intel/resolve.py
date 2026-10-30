"""Resolution steps for signs of attack, as the Attack Detection Agent wrote them (imported by attack_import).

This agent only reads them, for its report and the dashboard data.
"""

from __future__ import annotations

import json

from threat_intel.store import Store


def _j(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value


def for_findings(store: Store) -> dict[str, dict]:
    """finding_id -> resolution, for the report and the dashboard."""
    return {r["finding_id"]: {"what_happened": r["what_happened"], "steps": _j(r["steps"]), "done_when": r["done_when"],
                              "source": r["source"], "model": r["model"]}
            for r in store.query("SELECT * FROM resolutions")}
