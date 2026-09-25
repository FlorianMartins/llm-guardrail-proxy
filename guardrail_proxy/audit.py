"""Structured JSON audit logging.

One JSON object per line, on stdout and optionally a file, so the stream can
be shipped as-is to Loki, ELK, Datadog or a SIEM. The audit trail records
*what was detected*, never *what was said*: prompts are represented by a
SHA-256 digest, which lets an investigator correlate a known prompt with its
log line without the log itself storing user data.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

AUDIT_LOGGER = "guardrail.audit"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            payload.update(event)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    formatter = JsonFormatter()
    for h in handlers:
        h.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(level.upper())
    # uvicorn's access log would duplicate our audit line in plain text.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)


def digest(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def audit(msg: str, **event: Any) -> None:
    level = logging.WARNING if event.get("decision") not in (None, "allowed") else logging.INFO
    logging.getLogger(AUDIT_LOGGER).log(level, msg, extra={"event": event})
