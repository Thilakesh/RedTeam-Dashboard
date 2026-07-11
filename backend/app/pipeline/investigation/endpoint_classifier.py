"""Heuristic path classification shared by the ffuf and dirsearch adapters."""

from __future__ import annotations

import re

_LOGIN_PATTERNS = [
    re.compile(r"/(login|signin|sign-in|auth/login|sso|oauth)\b", re.I),
    re.compile(r"/wp-login\.php", re.I),
]
_SIGNUP_PATTERNS = [
    re.compile(r"/(signup|sign-up|register|registration|create-?account)\b", re.I),
]
_UPLOAD_PATTERNS = [
    re.compile(r"/(upload|fileupload|file-upload|media/upload)\b", re.I),
]
_API_PATTERNS = [
    re.compile(r"/(api|v1|v2|v3|graphql|rest)/", re.I),
    re.compile(r"/(openapi\.json|swagger\.json|api-docs|swagger-ui|swagger\.yaml)", re.I),
]
_ADMIN_PATTERNS = [
    re.compile(r"/(admin|manage|management|dashboard|console|control)\b", re.I),
    re.compile(r"/(wp-admin|administrator|phpmyadmin)\b", re.I),
]


def _classify(path: str) -> dict[str, bool]:
    return {
        "is_login": any(p.search(path) for p in _LOGIN_PATTERNS),
        "is_signup": any(p.search(path) for p in _SIGNUP_PATTERNS),
        "is_upload": any(p.search(path) for p in _UPLOAD_PATTERNS),
        "is_api": any(p.search(path) for p in _API_PATTERNS),
        "is_admin": any(p.search(path) for p in _ADMIN_PATTERNS),
    }
