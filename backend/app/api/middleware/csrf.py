"""CSRF protection via double-submit cookie.

Frontend reads the `rt_csrf` cookie (not HttpOnly) and echoes it in the
`X-CSRF-Token` header on every unsafe request. This middleware rejects any
unsafe request whose header doesn't match the cookie.

GET/HEAD/OPTIONS skipped. `/auth/login` and `/auth/invite/accept` skipped
because there's no session yet. `/auth/refresh` skipped because the
SameSite=Strict refresh cookie already prevents cross-site abuse.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_EXEMPT_PATHS = {"/auth/login", "/auth/refresh", "/auth/invite/accept"}
CSRF_COOKIE_NAME = "rt_csrf"
CSRF_HEADER_NAME = "x-csrf-token"


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS or request.url.path in CSRF_EXEMPT_PATHS:
            return await call_next(request)

        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)

        # If there's no auth at all (no access cookie), let the auth layer 401 first.
        if request.cookies.get("rt_access") is None:
            return await call_next(request)

        if not cookie_token or not header_token or cookie_token != header_token:
            return JSONResponse(
                status_code=403, content={"detail": "csrf token missing or invalid"}
            )
        return await call_next(request)
