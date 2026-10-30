"""Settings by agent name, with the names from before the restructure still accepted.

`env("THREAT_INTEL_DATA_DIR", "UC1_DATA_DIR")` returns the first one that is set. When only an old name is set it still
works, and the log says once which name to use instead, so a suite .env can be renamed whenever it suits.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("infra_core.settings")
_warned: set[str] = set()


def env(name: str, *old_names: str) -> str | None:
    """The stripped value of the first of name, *old_names that is set and not empty; None when none is."""
    for key in (name, *old_names):
        value = os.getenv(key, "").strip()
        if value:
            if key != name and key not in _warned:
                _warned.add(key)
                log.warning("%s is an old setting name; rename it to %s in .env", key, name)
            return value
    return None
