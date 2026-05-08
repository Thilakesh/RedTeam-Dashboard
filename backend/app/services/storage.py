"""MinIO object storage client for scan artifacts (screenshots, raw tool output).

Configured via env vars:
  MINIO_URL         — internal Docker URL used by the worker (e.g. http://minio:9000)
  MINIO_PUBLIC_URL  — browser-accessible URL (e.g. http://localhost:9000); falls back
                      to MINIO_URL if not set (fine when running outside Docker)
  MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET

Falls back gracefully when MINIO_URL is not set — upload_file returns False, URLs return None.
"""
from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

from minio import Minio
from minio.error import S3Error

_client: Minio | None = None


def _get_client() -> Minio | None:
    global _client
    url = os.environ.get("MINIO_URL", "")
    if not url:
        return None
    if _client is None:
        host = url.replace("http://", "").replace("https://", "")
        secure = url.startswith("https")
        _client = Minio(
            host,
            access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
            secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
            secure=secure,
        )
    return _client


def _bucket() -> str:
    return os.environ.get("MINIO_BUCKET", "recon")


def ensure_bucket() -> None:
    """Create the bucket if it does not exist and set a public-read policy.

    Called once at worker startup. The public-read policy is idempotent — it is safe
    to re-apply on every startup and required so browsers can fetch screenshot URLs
    directly from MinIO without signed credentials.
    """
    client = _get_client()
    if client is None:
        return
    bucket = _bucket()
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
        # Allow anonymous GET on all objects so browsers can load screenshots.
        public_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        })
        client.set_bucket_policy(bucket, public_policy)
    except S3Error:
        pass


def upload_file(object_name: str, file_path: Path, content_type: str = "image/png") -> bool:
    """Upload a local file to MinIO. Returns True on success, False if MinIO is not configured."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.fput_object(_bucket(), object_name, str(file_path), content_type=content_type)
        return True
    except S3Error:
        return False


def public_url(object_name: str) -> str | None:
    """Return a direct (unsigned) URL reachable from the browser.

    Uses MINIO_PUBLIC_URL if set (the host-accessible address, e.g. http://localhost:9000).
    Falls back to MINIO_URL which works when MinIO is accessed from inside Docker but NOT
    from a browser on the host (minio hostname is not resolvable outside the Docker network).
    """
    # Prefer the externally-accessible URL so browsers can load assets directly.
    base = os.environ.get("MINIO_PUBLIC_URL") or os.environ.get("MINIO_URL", "")
    if not base:
        return None
    return f"{base.rstrip('/')}/{_bucket()}/{object_name}"


def presigned_url(object_name: str, expires_seconds: int = 3600) -> str | None:
    """Return a presigned GET URL valid for the given number of seconds."""
    client = _get_client()
    if client is None:
        return None
    try:
        return client.presigned_get_object(
            _bucket(), object_name, expires=timedelta(seconds=expires_seconds)
        )
    except S3Error:
        return None


def screenshot_url(object_name: str) -> str | None:
    """Return the appropriate screenshot URL based on MINIO_USE_SIGNED_URLS env var.

    When MINIO_USE_SIGNED_URLS=true: returns a presigned URL (1-hour expiry).
    Otherwise: returns the permanent public URL (default, fine for dev).
    """
    if os.environ.get("MINIO_USE_SIGNED_URLS", "").lower() in ("1", "true", "yes"):
        return presigned_url(object_name, expires_seconds=3600)
    return public_url(object_name)
