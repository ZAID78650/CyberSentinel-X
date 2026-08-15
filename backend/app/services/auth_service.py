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
from app.models.user import Role, User
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
    access = create_access_token(str(user.id), extra={"roles": user.role_names, "email": user.email})
    refresh = create_refresh_token(str(user.id))
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": 30 * 60 if not remember_me else 7 * 24 * 60 * 60,
    }


def refresh_access_token(db: Session, refresh_token: str, ip: Optional[str] = None) -> dict:
    payload = decode_token(refresh_token, refresh=True)
    if payload is None:
        raise AuthError("Invalid or expired refresh token", 401)
    from app.core.utils import to_uuid
    user = db.get(User, to_uuid(payload["sub"]))
    if user is None or not user.is_active:
        raise AuthError("User not found or disabled", 401)
    log_action(db, actor=user.email, action="AUTH.TOKEN_REFRESH", target_type="user", target_id=str(user.id),
               ip_address=ip)
    return build_tokens(user)


def get_user_with_roles(db: Session, user_id) -> Optional[User]:
    from app.core.utils import to_uuid
    stmt = select(User).options(selectinload(User.roles)).where(User.id == to_uuid(user_id))
    return db.scalar(stmt)
