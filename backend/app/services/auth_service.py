"""Authentication service: registration, login, token refresh."""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import Device, Role, User
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.audit import log_action

logger = logging.getLogger(__name__)

DEFAULT_ROLE = "SECURITY_ANALYST"
ADMIN_ROLE = "ADMIN"


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def get_or_create_role(db: Session, name: str, description: str = "") -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=description or f"Role: {name}")
        db.add(role)
        db.flush()
    return role


def ensure_default_roles(db: Session) -> None:
    """Idempotently create the standard RBAC roles."""
    for name, desc in [
        ("ADMIN", "Full platform access including approvals and settings"),
        ("SECURITY_ANALYST", "Investigate incidents and execute approved actions"),
        ("VIEWER", "Read-only access to dashboards and reports"),
    ]:
        get_or_create_role(db, name, desc)
    db.commit()


def register(db: Session, req: RegisterRequest, ip: Optional[str] = None, request_id: Optional[str] = None) -> User:
    existing = db.scalar(select(User).where(User.email == req.email.lower()))
    if existing:
        raise AuthError("An account with this email already exists", 409)

    ensure_default_roles(db)
    user = User(
        email=req.email.lower(),
        full_name=req.full_name.strip(),
        organization=req.organization,
        password_hash=hash_password(req.password),
        is_verified=True,
    )
    role = get_or_create_role(db, DEFAULT_ROLE)
    user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, actor=user.email, action="AUTH.REGISTER", target_type="user", target_id=str(user.id),
               ip_address=ip, request_id=request_id)
    return user


def authenticate(db: Session, req: LoginRequest, ip: Optional[str] = None, request_id: Optional[str] = None) -> User:
    user = db.scalar(select(User).where(User.email == req.email.lower()))
    if user is None or not verify_password(req.password, user.password_hash):
        log_action(db, actor=req.email.lower(), action="AUTH.LOGIN_FAILED",
                   ip_address=ip, request_id=request_id)
        raise AuthError("Invalid email or password", 401)
    if not user.is_active:
        raise AuthError("Account is disabled. Contact your administrator.", 403)

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, actor=user.email, action="AUTH.LOGIN_SUCCESS", target_type="user", target_id=str(user.id),
               ip_address=ip, request_id=request_id)
    return user


def build_tokens(user: User, remember_me: bool = False):
    # `ver` binds every token to the user's current token_version, so
    # deprovisioning (which bumps it) revokes all outstanding sessions. The
    # access token also carries `sess` (the refresh token's jti) so the API
    # can mark the current session in the session list.
    refresh = create_refresh_token(str(user.id), extra={"ver": user.token_version})
    jti = (decode_token(refresh, refresh=True) or {}).get("jti")
    access = create_access_token(str(user.id), extra={
        "roles": user.role_names, "email": user.email, "ver": user.token_version, "sess": jti})
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": 30 * 60 if not remember_me else 7 * 24 * 60 * 60,
    }


def record_session(
    db: Session,
    user: User,
    refresh_token: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[Device]:
    """Persist a login as a device/session row keyed by the refresh token jti."""
    jti = (decode_token(refresh_token, refresh=True) or {}).get("jti")
    if not jti:
        return None
    now = datetime.now(timezone.utc)
    dev = db.scalar(select(Device).where(Device.user_id == user.id, Device.device_id == jti))
    if dev is None:
        dev = Device(device_id=jti, user_id=user.id,
                     device_name=(user_agent or "Unknown device")[:255],
                     ip_address=ip, first_seen=now, last_seen=now)
        db.add(dev)
    else:
        dev.last_seen = now
        if ip:
            dev.ip_address = ip
    db.commit()
    return dev


def refresh_access_token(db: Session, refresh_token: str, ip: Optional[str] = None) -> dict:
    payload = decode_token(refresh_token, refresh=True)
    if payload is None:
        raise AuthError("Invalid or expired refresh token", 401)
    from app.core.utils import to_uuid
    user = db.get(User, to_uuid(payload["sub"]))
    if user is None or not user.is_active:
        raise AuthError("User not found or disabled", 401)
    # A bumped token_version (deprovisioning) revokes this refresh token too.
    if payload.get("ver", 0) != user.token_version:
        raise AuthError("Session revoked. Sign in again.", 401)
    # Per-session revocation: a revoked/missing session row kills this refresh.
    jti = payload.get("jti")
    if jti:
        dev = db.scalar(select(Device).where(Device.device_id == jti))
        if dev is None or dev.revoked_at is not None:
            raise AuthError("Session revoked. Sign in again.", 401)
        dev.last_seen = datetime.now(timezone.utc)
        db.commit()
    log_action(db, actor=user.email, action="AUTH.TOKEN_REFRESH", target_type="user", target_id=str(user.id),
               ip_address=ip)
    return build_tokens(user)


def get_user_with_roles(db: Session, user_id) -> Optional[User]:
    from app.core.utils import to_uuid
    stmt = select(User).options(selectinload(User.roles)).where(User.id == to_uuid(user_id))
    return db.scalar(stmt)
