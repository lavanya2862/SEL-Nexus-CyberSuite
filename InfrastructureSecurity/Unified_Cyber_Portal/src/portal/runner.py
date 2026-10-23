"""Run wrapper: `python -m portal.runner --uc uc1 --root <UC folder> --run-dir <folder>`.

Started by the portal as its own detached process, so a pipeline run keeps going (and is still recorded) even if
the portal stops or restarts. It runs the use case's own `python -m ucX run`, copies every output line to
<run-dir>/output.log as it arrives, and writes <run-dir>/result.json with the exit code when the run ends.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# Agents that are not a use case's plain `run`: the Attack Detection Agent is UC1's `attack-check`.
COMMANDS = {"attack": ("uc1", "attack-check")}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uc", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    root, run_dir = Path(args.root), Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    python = root / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        python = root / ".venv" / "bin" / "python"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    code = 1
    with (run_dir / "output.log").open("a", encoding="utf-8", newline="\n") as log:
        try:
            module, command = COMMANDS.get(args.uc, (args.uc, "run"))
            proc = subprocess.Popen([str(python), "-m", module, command], cwd=str(root), env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                    creationflags=flags)
            _write_json(run_dir / "meta.json", {**meta, "wrapper_pid": os.getpid(), "pid": proc.pid})
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line if line.endswith("\n") else line + "\n")
                log.flush()
            code = proc.wait()
        except Exception as exc:  # noqa: BLE001 - always leave a result behind
            log.write(f"Run FAILED: the portal could not start the pipeline: {exc}\n")
    _write_json(run_dir / "result.json", {"exit_code": code, "finished_at": _now()})
    return code


if __name__ == "__main__":
    sys.exit(main())
