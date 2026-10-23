from __future__ import annotations

import shutil
from pathlib import Path

from ..models import Finding


class ScannerUnavailable(RuntimeError):
    pass


class Scanner:
    name: str = "scanner"
    kind: str = "sast"
    description: str = ""
    languages: set[str] | None = None  # None = language agnostic
    binary: str | None = None
    setting: str | None = None  # name of the enable_* flag in Settings
    redundant_with: set[str] = set()  # skip if any of these scanners is active
    primary: bool = False
    last_message: str = ""

    def enabled(self) -> bool:
        from ..config import get_settings
        return bool(getattr(get_settings(), self.setting, True)) if self.setting else True

    def available(self) -> bool:
        return self.binary is None or shutil.which(self.binary) is not None

    def applies_to(self, languages: dict[str, int]) -> bool:
        return self.languages is None or bool(self.languages & set(languages))

    def scan(self, root: Path, workdir: Path) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError
