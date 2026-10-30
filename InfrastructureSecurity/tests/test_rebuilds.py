"""Each agent rebuilds the data the dashboard shows from a copy of its own database, and that data keeps its shape.

Uses the real local data (gitignored); a part without data is skipped. The copy means the live database is never
touched, so this is safe while the agents' scheduled runs are active.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from layout import REBUILDS, part_dir, python
from shape import check, shape


@pytest.mark.parametrize("part", sorted(REBUILDS))
def test_rebuild_keeps_its_shape(part, tmp_path):
    spec = REBUILDS[part]
    source = part_dir(part) / "data"
    py = python(part)
    if not py.exists() or not all((source / name).exists() for name in spec["copy"][:1]):
        pytest.skip(f"{part} has no .venv or no data on this computer")
    data = tmp_path / "data"
    data.mkdir()
    for name in spec["copy"]:
        if (source / name).is_dir():
            shutil.copytree(source / name, data / name)
        elif (source / name).exists():
            shutil.copy2(source / name, data / name)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", **{k: v.format(data=data) for k, v in spec["env"].items()}}
    done = subprocess.run([str(py), *spec["run"]], cwd=part_dir(part), env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    shapes = {}
    for out in spec["outputs"]:
        file = data / out
        assert file.exists(), f"{part} did not write {out}"
        shapes[out] = shape(json.loads(file.read_text(encoding="utf-8")))
    assert check(f"rebuild_{part}", shapes) == []
