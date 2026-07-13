"""Central structured-logging setup. Call once per process (API startup, each
arq worker's on_startup) with a `service` tag identifying which process is
emitting."""
from __future__ import annotations

import logging.config
import os


def configure_logging(service: str) -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "redaction": {"()": "app.logging.redaction.RedactionFilter"},
                "context": {"()": "app.logging.context.ContextFilter"},
                "service": {"()": "app.logging.context.ServiceFilter", "service": service},
            },
            "formatters": {
                "json": {
                    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                    "filters": ["redaction", "context", "service"],
                },
            },
            "root": {
                "handlers": ["stdout"],
                "level": os.getenv("LOG_LEVEL", "INFO"),
            },
            "loggers": {
                "uvicorn": {"level": "INFO", "propagate": True},
                "uvicorn.error": {"level": "INFO", "propagate": True},
                "uvicorn.access": {"level": "INFO", "propagate": True},
            },
        }
    )
    logging.getLogger(__name__).info("logging configured")
