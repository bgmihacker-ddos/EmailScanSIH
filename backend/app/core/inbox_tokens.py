import base64
import hashlib

from cryptography.fernet import Fernet

from app.core.config import settings


def _cipher() -> Fernet:
    secret = settings.JWT_SECRET
    if not secret:
        raise RuntimeError("JWT_SECRET environment variable is required for inbox token encryption.")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_token(value: str | None) -> str | None:
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii") if value else None


def decrypt_token(value: str | None) -> str | None:
    return _cipher().decrypt(value.encode("ascii")).decode("utf-8") if value else None