"""Scrub secrets out of log messages before they're emitted.

Tool output (nmap/ffuf/curl banners) and audit meta can echo back credentials
handed to a scan target, and application logs can echo Authorization headers.
This runs on every record regardless of source. Not a substitute for not
logging secrets in the first place — a last line of defense.
"""
from __future__ import annotations

import logging
import re

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[^\s,;]+"),
]

_REPLACEMENT = "[REDACTED]"


def redact(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(_REPLACEMENT, text)
    return text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True
