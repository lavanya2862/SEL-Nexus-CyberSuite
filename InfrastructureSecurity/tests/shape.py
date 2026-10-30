"""The shape of a JSON answer: which keys exist and what type each value has, never the values themselves.

Snapshots of shapes are safe to keep in git (no company data) and stay the same while only the data changes.
Objects whose keys are data (CVE ids, device names, software names) collapse to one "<key>" entry.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

NAME = re.compile(r"^[a-z_][A-Za-z0-9_]*$")       # a field name, not a piece of data
MAX_FIELDS = 40                                     # more keys than this means the keys are data
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"


def _merge(a, b):
    if a is None:
        return b
    if b is None or a == b:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: _merge(a.get(k), b.get(k)) for k in sorted({*a, *b})}
    if isinstance(a, list) and isinstance(b, list):
        return [_merge(a[0] if a else None, b[0] if b else None)] if (a or b) else []
    if isinstance(a, str) and isinstance(b, str):
        return "|".join(sorted({*a.split("|"), *b.split("|")}))
    if a == "null" or b == "null":           # an object or list that is sometimes missing
        return b if a == "null" else a
    return "mixed"


def shape(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        merged = None
        for item in value:
            merged = _merge(merged, shape(item))
        return [merged] if merged is not None else []
    if isinstance(value, dict):
        if value and (len(value) > MAX_FIELDS or not all(NAME.match(k) for k in value)):
            merged = None
            for item in value.values():
                merged = _merge(merged, shape(item))
            return {"<key>": merged}
        return {k: shape(v) for k, v in sorted(value.items())}
    return type(value).__name__


def differences(old, new, path: str = "") -> list[str]:
    if old == new:
        return []
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for k in sorted({*old, *new}):
            if k not in new:
                out.append(f"{path}.{k}: gone")
            elif k not in old:
                out.append(f"{path}.{k}: new")
            else:
                out += differences(old[k], new[k], f"{path}.{k}")
        return out
    if isinstance(old, list) and isinstance(new, list) and old and new:
        return differences(old[0], new[0], f"{path}[]")
    return [f"{path}: {json.dumps(old)} -> {json.dumps(new)}"]


def check(name: str, shapes: dict) -> list[str]:
    """Compare with snapshots/<name>.json. UPDATE_SNAPSHOTS=1 writes the snapshot instead (only on purpose)."""
    file = SNAPSHOTS / f"{name}.json"
    if os.environ.get("UPDATE_SNAPSHOTS") == "1" or not file.exists():
        SNAPSHOTS.mkdir(exist_ok=True)
        file.write_text(json.dumps(shapes, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return []
    old = json.loads(file.read_text(encoding="utf-8"))
    out = []
    for key in sorted({*old, *shapes}):
        if key not in shapes:
            out.append(f"{key}: missing")
        elif key not in old:
            out.append(f"{key}: not in the snapshot")
        else:
            out += [f"{key}{d}" for d in differences(old[key], shapes[key])]
    return out
