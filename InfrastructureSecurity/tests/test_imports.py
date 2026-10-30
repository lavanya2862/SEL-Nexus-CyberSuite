"""Every module of every part imports with that part's own Python environment."""
from __future__ import annotations

import subprocess

import pytest

from layout import PARTS, part_dir, python

WALK = """
import importlib, pkgutil, sys, traceback
pkg = importlib.import_module(sys.argv[1])
bad = []
for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
    try:
        importlib.import_module(m.name)
    except Exception:
        bad.append(m.name + ": " + traceback.format_exc(limit=1).strip().splitlines()[-1])
print("\\n".join(bad))
sys.exit(1 if bad else 0)
"""


@pytest.mark.parametrize("part", sorted(PARTS))
def test_every_module_imports(part):
    py = python(part)
    if not py.exists():
        pytest.skip(f"{part} has no .venv yet (the Start script makes it)")
    done = subprocess.run([str(py), "-c", WALK, PARTS[part]["package"]], cwd=part_dir(part), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("part", sorted(p for p in PARTS if p != "dashboard"))
def test_command_line_answers(part):
    py = python(part)
    if not py.exists():
        pytest.skip(f"{part} has no .venv yet")
    done = subprocess.run([str(py), "-m", PARTS[part]["package"], "--help"], cwd=part_dir(part), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
