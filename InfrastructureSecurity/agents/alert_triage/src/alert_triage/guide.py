"""Microsoft GUIDE dataset (Kaggle, CDLA-Permissive-2.0): ~1M real Defender XDR incidents, each graded by the
customer's analysts (TruePositive / BenignPositive / FalsePositive). Used to backtest the agent's decision logic.

You download GUIDE_Train.csv and GUIDE_Test.csv into data/inbox/guide/ (Kaggle: Microsoft Security Incident Prediction). `load()` copies the
columns we need into data/guide.duckdb once (the CSVs are several GB). `sample()` picks incidents from the TEST split,
stratified by grade. `replay_packet()` summarises one incident; its history (how the same detector's incidents were
graded in the same organisation) comes from the TRAIN split and only from EARLIER timestamps, so the agent can never
peek at the answer.

GUIDE is anonymised (IDs instead of names, no raw log text), so it tests the decision logic and the history signal,
not log reading. The full chain with real logs is tested on the lab incidents.
"""

from __future__ import annotations

import logging
from pathlib import Path

import duckdb

from alert_triage.config import Settings

log = logging.getLogger("alert_triage.guide")

WANTED = ["Id", "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId", "AlertTitle", "Category",
          "MitreTechniques", "IncidentGrade", "EntityType", "EvidenceRole", "SuspicionLevel", "LastVerdict",
          "ThreatFamily", "OSFamily", "CountryCode"]
GRADES = {"TruePositive": "TP", "BenignPositive": "BP", "FalsePositive": "FP"}


def db_path(settings: Settings) -> Path:
    return settings.data_dir / "guide.duckdb"


def _csv(settings: Settings, split: str) -> Path | None:
    folder = settings.inbox_dir / "guide"
    for name in (f"GUIDE_{split}.csv", f"guide_{split.lower()}.csv"):
        if (folder / name).is_file():
            return folder / name
    hits = sorted(folder.rglob(f"*{split}*.csv"))
    return hits[0] if hits else None


def load(settings: Settings, force: bool = False) -> dict:
    """CSV -> DuckDB tables guide_train / guide_test (only the columns we use). Returns row counts."""
    path = db_path(settings)
    con = duckdb.connect(str(path))
    try:
        counts = {}
        for split in ("Train", "Test"):
            table = f"guide_{split.lower()}"
            exists = con.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
                                 [table]).fetchone()[0]
            if exists and not force:
                counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                continue
            csv = _csv(settings, split)
            if csv is None:
                raise FileNotFoundError(f"GUIDE_{split}.csv not found in {settings.inbox_dir / 'guide'} "
                                        "(download it from Kaggle: 'Microsoft Security Incident Prediction')")
            header = con.execute(f"SELECT * FROM read_csv_auto(?, sample_size=20000) LIMIT 0", [str(csv)]).description
            cols = [c[0] for c in header if c[0] in WANTED]
            missing = {"OrgId", "IncidentId", "DetectorId", "IncidentGrade", "Timestamp"} - set(cols)
            if missing:
                raise ValueError(f"{csv.name} is missing columns: {', '.join(sorted(missing))}")
            log.info("Loading %s (%s) - this can take a few minutes", csv.name, ", ".join(cols))
            select = ", ".join(f'"{c}"' for c in cols)
            con.execute(f"CREATE OR REPLACE TABLE {table} AS SELECT {select} FROM read_csv_auto(?, sample_size=20000, "
                        f"all_varchar=true)", [str(csv)])
            counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return counts
    finally:
        con.close()


def sample(settings: Settings, n: int = 300, seed: int = 4) -> list[dict]:
    """n incidents from the test split, about n/3 per grade (fewer if a grade is rare)."""
    con = duckdb.connect(str(db_path(settings)), read_only=True)
    try:
        per = max(1, n // 3)
        rows = con.execute(f"""
            WITH inc AS (
                SELECT OrgId, IncidentId, any_value(IncidentGrade) AS grade, MIN(Timestamp) AS first_ts
                FROM guide_test WHERE IncidentGrade IN ('TruePositive', 'BenignPositive', 'FalsePositive')
                GROUP BY OrgId, IncidentId),
            ranked AS (
                SELECT *, row_number() OVER (PARTITION BY grade ORDER BY hash(IncidentId || ':{int(seed)}')) AS rn
                FROM inc)
            SELECT OrgId, IncidentId, grade, first_ts FROM ranked WHERE rn <= ? ORDER BY grade, rn""",
                           [per]).fetchall()
        return [{"org": r[0], "incident": r[1], "grade": r[2], "first_ts": r[3]} for r in rows]
    finally:
        con.close()


def replay_packet(settings: Settings, item: dict, con=None) -> dict:
    """Summarise one GUIDE incident + its leakage-safe history."""
    own = con is None
    con = con or duckdb.connect(str(db_path(settings)), read_only=True)
    try:
        cols = {c[0] for c in con.execute("SELECT * FROM guide_test LIMIT 0").description}

        def col(name, default="NULL"):
            return f'"{name}"' if name in cols else default

        rows = con.execute(f"""
            SELECT AlertId, DetectorId, {col('AlertTitle')}, {col('Category')}, {col('MitreTechniques')},
                   {col('EntityType')}, {col('EvidenceRole')}, {col('SuspicionLevel')}, {col('LastVerdict')},
                   {col('ThreatFamily')}, {col('OSFamily')}, Timestamp
            FROM guide_test WHERE OrgId = ? AND IncidentId = ?""", [item["org"], item["incident"]]).fetchall()
        alerts, detectors, categories, techniques = set(), set(), set(), set()
        entity_types, roles, suspicion, last_verdicts, families, os_families = {}, {}, {}, {}, set(), set()
        for r in rows:
            alerts.add(r[0]); detectors.add(r[1])
            if r[3]:
                categories.add(r[3])
            for t in (r[4] or "").replace(",", ";").split(";"):
                if t.strip():
                    techniques.add(t.strip().upper())
            _inc(entity_types, r[5]); _inc(roles, r[6]); _inc(suspicion, r[7]); _inc(last_verdicts, r[8])
            if r[9]:
                families.add(r[9])
            if r[10]:
                os_families.add(r[10])

        # leakage-safe history: same org + detector, train split, strictly earlier, other incidents
        history = {}
        for det in sorted(detectors)[:10]:
            h = con.execute("""
                SELECT IncidentGrade, COUNT(DISTINCT IncidentId) FROM guide_train
                WHERE OrgId = ? AND DetectorId = ? AND Timestamp < ? AND IncidentId <> ?
                  AND IncidentGrade IN ('TruePositive', 'BenignPositive', 'FalsePositive')
                GROUP BY IncidentGrade""", [item["org"], det, item["first_ts"], item["incident"]]).fetchall()
            if h:
                history[det] = {GRADES.get(g, g): int(n) for g, n in h}
        return {
            "incident_id": f"guide-{item['org']}-{item['incident']}",
            "alerts": len(alerts), "evidence_rows": len(rows),
            "detectors": sorted(detectors)[:10], "categories": sorted(categories),
            "techniques": sorted(techniques)[:15], "entity_types": entity_types, "evidence_roles": roles,
            "suspicion_levels": suspicion, "defender_last_verdicts": last_verdicts,
            "threat_family_present": bool(families), "os_families": sorted(os_families),
            "history_by_detector": history,
        }
    finally:
        if own:
            con.close()


def history_baseline(packet: dict) -> str:
    """The no-AI baseline: majority grade of the incident's detectors in the same org's earlier history."""
    totals = {"TP": 0, "BP": 0, "FP": 0}
    for counts in packet["history_by_detector"].values():
        for g, n in counts.items():
            totals[g] = totals.get(g, 0) + n
    if not sum(totals.values()):
        return "human"
    return max(totals, key=totals.get)


def _inc(d: dict, key) -> None:
    if key:
        d[key] = d.get(key, 0) + 1
