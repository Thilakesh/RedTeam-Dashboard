"""Correlation context propagated onto every log record.

A single contextvar dict holds request_id/org_id/user_id/scan_id/etc. It is
task-local under asyncio (arq runs each job as its own task, FastAPI request
handling is its own task), so concurrent requests/jobs never see each other's
context. ContextFilter copies whatever is bound onto each LogRecord; python-json-
logger then serializes any non-reserved record attribute automatically, so
binding a new field here is enough to make it show up in log output — no
formatter changes needed.
"""
from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any

_context: ContextVar[dict[str, Any]] = ContextVar("log_context", default={})


def bind_context(**fields: Any) -> None:
    """Merge fields into the current task's log context (None values skipped)."""
    ctx = dict(_context.get())
    ctx.update({k: v for k, v in fields.items() if v is not None})
    _context.set(ctx)


def clear_context() -> None:
    _context.set({})


def get_context() -> dict[str, Any]:
    return dict(_context.get())


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _context.get().items():
            setattr(record, key, value)
        return True


class ServiceFilter(logging.Filter):
    """Stamps a fixed `service` field (api / worker / heavy-worker / ...)."""

    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def filter(self, record: logging.LogRecord) -> bool:
        record.service = self.service
        return True
