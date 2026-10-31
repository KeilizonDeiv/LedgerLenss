"""Structured JSON logging with request correlation and PII redaction.

Logs end up in third-party systems (Datadog, ELK, CloudWatch). Invoices contain
emails, bank/card numbers and tax IDs, so we redact *before* anything leaves the
process. Redaction is a safety net, not a licence to log payloads.
"""
import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)bearer\s+[\w.\-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\bsk-(?:ant-)?[\w\-]{10,}"), "[API_KEY]"),
    (re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ \-]?){12,19}\b"), "[NUMBER]"),  # card / account numbers
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "request_id": request_id_ctx.get(),
            "msg": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
