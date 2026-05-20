"""RS256 keypair management.

On first boot, if the configured PEM paths are missing, generate a fresh
2048-bit RSA keypair and persist it. Subsequent boots load existing keys.
Keys are never logged.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import get_settings


def _generate_and_write(private_path: Path, public_path: Path) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private first, restrict perms before writing.
    fd = os.open(str(private_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, private_pem)
    finally:
        os.close(fd)
    public_path.write_bytes(public_pem)


def ensure_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem). Generate on disk if absent."""
    settings = get_settings()
    private_path = Path(settings.jwt_private_key_path)
    public_path = Path(settings.jwt_public_key_path)
    if not private_path.exists() or not public_path.exists():
        _generate_and_write(private_path, public_path)
    return private_path.read_text(), public_path.read_text()


@lru_cache
def get_private_key() -> str:
    private_pem, _ = ensure_keypair()
    return private_pem


@lru_cache
def get_public_key() -> str:
    _, public_pem = ensure_keypair()
    return public_pem
