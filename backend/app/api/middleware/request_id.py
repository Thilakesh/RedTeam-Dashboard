"""Adopts an inbound X-Request-ID or generates one, binds it to the logging
context for the lifetime of the request, and echoes it back so the frontend
error boundary can reference the same id a backend log line carries."""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.logging.context import bind_context, clear_context

REQUEST_ID_HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        bind_context(request_id=request_id)
        try:
            response = await call_next(request)
        finally:
            clear_context()
        response.headers[REQUEST_ID_HEADER] = request_id
        return response
