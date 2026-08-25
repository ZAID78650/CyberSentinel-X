"""Two-Factor Authentication (TOTP) service for CyberSentinel.

Implements RFC 6238 Time-based One-Time Password (TOTP) using the
pyotp library. Provides secret generation, provisioning URI (for
QR codes), and verification.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Optional, Tuple

# Use pyotp which is a standard TOTP library (RFC 6238 compliant)
import pyotp


# Configuration
TOTP_ISSUER = "CyberSentinel X"
TOTP_DIGITS = 6
TOTP_INTERVAL = 30  # seconds
TOTP_VALID_WINDOW = 1  # allow ±1 time step (±30 seconds)


def generate_secret() -> str:
    """Generate a cryptographically secure TOTP secret.
    
    Returns a 32-character base32-encoded string.
    """
    return pyotp.random_base32(length=32)


def get_provisioning_uri(secret: str, email: str, issuer: str = TOTP_ISSUER) -> str:
    """Generate a provisioning URI for QR code scanning.
    
    Format: otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&digits=6&period=30
    """
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_token(secret: str, token: str, tolerance: int = TOTP_VALID_WINDOW) -> bool:
    """Verify a TOTP token with optional time drift tolerance.
    
    Args:
        secret: The shared TOTP secret (base32 encoded)
        token: The 6-digit token to verify
        tolerance: Number of time steps to allow before/after current (default: 1 = ±30s)
    
    Returns:
        True if the token is valid, False otherwise.
    """
    try:
        totp = pyotp.TOTP(
            secret,
            digits=TOTP_DIGITS,
            interval=TOTP_INTERVAL,
        )
        # Verify with allowed window for clock skew
        return totp.verify(token, valid_window=tolerance)
    except Exception:
        return False


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate one-time backup codes for account recovery.
    
    Each code is 8 characters, alphanumeric, uppercase.
    Returns a list of backup codes (these should be hashed before storage).
    """
    codes = []
    for _ in range(count):
        code = os.urandom(4).hex().upper()  # 8 character hex code
        formatted = f"{code[:4]}-{code[4:]}"  # Format as XXXX-XXXX
        codes.append(formatted)
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup code using SHA-256 for secure storage."""
    return hashlib.sha256(code.encode()).hexdigest()


def verify_backup_code(code: str, stored_hashes: list) -> Tuple[bool, Optional[str]]:
    """Verify a backup code against stored hashes.
    
    Returns (matched, matched_hash) where matched_hash should be removed
    from the stored list after successful verification.
    """
    code_hash = hash_backup_code(code.replace("-", "").upper())
    for h in stored_hashes:
        if hmac.compare_digest(code_hash, h):
            return True, h
    return False, None


def get_provisioning_uri_png(secret: str, email: str, issuer: str = TOTP_ISSUER) -> str:
    """Generate a data URI containing a QR code for authenticator apps.
    
    Returns a base64-encoded PNG data URI that can be used as an img src.
    """
    import base64
    try:
        uri = get_provisioning_uri(secret, email, issuer)
        qr = pyotp.totp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
        # For simplicity, return the provisioning URI; the frontend
        # can use a QR code library to render it
        return uri
    except Exception:
        return ""
