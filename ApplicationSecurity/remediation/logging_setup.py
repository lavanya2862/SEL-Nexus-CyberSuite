from __future__ import annotations

import json
import logging
import sys

from .config import get_settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
                "logger": record.name, "msg": record.getMessage(), "thread": record.threadName}
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def setup_logging() -> None:
    s = get_settings()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if s.log_json else
                         logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(s.log_level.upper())
    logging.getLogger("httpx").setLevel(logging.WARNING)
