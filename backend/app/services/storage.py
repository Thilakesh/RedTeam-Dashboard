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
import logging
import os
from datetime import timedelta
from pathlib import Path

from minio import Minio
from minio.error import S3Error

log = logging.getLogger(__name__)

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
    """Create the bucket if it does not exist and set its access policy.

    Called once at worker startup. When MINIO_USE_SIGNED_URLS is set, the bucket is
    kept private (MinIO's default deny-all) — object access then requires a valid
    presigned URL, which is only ever minted for authenticated, tenant-scoped API
    requests (see scan_view._resolve_screenshot_url). Otherwise the bucket gets a
    public-read policy so browsers can fetch screenshot URLs unsigned (fine for local
    dev where MinIO is not internet-reachable).
    """
    client = _get_client()
    if client is None:
        return
    bucket = _bucket()
    signed = os.environ.get("MINIO_USE_SIGNED_URLS", "").lower() in ("1", "true", "yes")
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    except S3Error as e:
        log.warning("storage: could not create/verify MinIO bucket %r: %s", bucket, e)
        return

    if signed:
        try:
            client.delete_bucket_policy(bucket)
        except S3Error as e:
            # NoSuchBucketPolicy is the expected case for a bucket that was
            # already private (nothing to delete) — not an error. Anything
            # else means we couldn't confirm the bucket is actually private,
            # which matters: a previously-public bucket would silently stay
            # public if this failed and nobody noticed.
            if getattr(e, "code", None) != "NoSuchBucketPolicy":
                log.warning(
                    "storage: failed to clear bucket policy on %r — it may "
                    "still be publicly readable: %s", bucket, e,
                )
        return

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
    try:
        client.set_bucket_policy(bucket, public_policy)
    except S3Error as e:
        log.warning("storage: failed to set public-read policy on %r: %s", bucket, e)


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
    """Return a presigned GET URL valid for the given number of seconds.

    The signature is computed against MINIO_URL (the internal Docker host the client
    is configured with) — SigV4 signs the Host header, and the reverse proxy in front
    of the public MinIO endpoint rewrites Host back to that same internal value before
    forwarding, so the signature still validates. Here we only swap the scheme+host
    prefix to MINIO_PUBLIC_URL for the browser-facing URL; path and query (including
    the signature) are left untouched.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        url = client.presigned_get_object(
            _bucket(), object_name, expires=timedelta(seconds=expires_seconds)
        )
    except S3Error:
        return None
    internal_base = os.environ.get("MINIO_URL", "")
    public_base = os.environ.get("MINIO_PUBLIC_URL", "")
    if public_base and internal_base and url.startswith(internal_base):
        url = public_base.rstrip("/") + url[len(internal_base):]
    return url


def screenshot_url(object_name: str) -> str | None:
    """Return the appropriate screenshot URL based on MINIO_USE_SIGNED_URLS env var.

    When MINIO_USE_SIGNED_URLS=true: returns a presigned URL (1-hour expiry).
    Otherwise: returns the permanent public URL (default, fine for dev).
    """
    if os.environ.get("MINIO_USE_SIGNED_URLS", "").lower() in ("1", "true", "yes"):
        return presigned_url(object_name, expires_seconds=3600)
    return public_url(object_name)
