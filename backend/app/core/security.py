"""Password hashing, JWT creation/validation, and security helpers."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt

from app.core.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (salt embedded in the output)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, extra: Optional[Dict[str, Any]] = None) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(days=settings.refresh_token_expire_days),
        "type": "refresh",
        "jti": secrets.token_urlsafe(24),
    }
    return jwt.encode(payload, settings.jwt_refresh_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, refresh: bool = False) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT. Returns the payload or None if invalid/expired."""
    secret = settings.jwt_refresh_secret if refresh else settings.jwt_secret
    try:
        payload = jwt.decode(token, secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
    expected = "refresh" if refresh else "access"
    if payload.get("type") != expected:
        return None
    return payload


def create_reset_token(subject: str) -> str:
    """Short-lived JWT for password reset links (30 minutes)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "type": "reset",
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_reset_token(token: str) -> Optional[str]:
    """Return the subject (user id) for a valid reset token, else None."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
    if payload.get("type") == "reset" and payload.get("exp", 0) > datetime.now(timezone.utc).timestamp():
        return payload.get("sub")
    return None


def generate_secure_token() -> str:
    return secrets.token_urlsafe(32)
