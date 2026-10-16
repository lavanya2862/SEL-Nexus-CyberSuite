"""Friendly computer names: config/device_names.csv (real_name,show_as), e.g. opca-wks-01 -> VM 1.
The OpCo labels are renamed the same way (OpCo A -> VM 1): each OpCo is one computer in this demo.

Only what people see changes. The data, Defender and every action (fix, isolate) keep the real name; the web app swaps
the names on screen and shows the real one on hover (web/src/lib/deviceNames.ts). Edit the file and reload the page.
"""
from __future__ import annotations

import csv

from portal.config import PORTAL_DIR

FILE = PORTAL_DIR / "config" / "device_names.csv"


def load() -> dict[str, str]:
    """{real name (lower case): friendly name}; empty when the file is missing."""
    if not FILE.is_file():
        return {}
    with FILE.open(encoding="utf-8-sig", newline="") as f:
        return {(row.get("real_name") or "").strip().lower(): (row.get("show_as") or "").strip()
                for row in csv.DictReader(f) if (row.get("real_name") or "").strip() and (row.get("show_as") or "").strip()}
