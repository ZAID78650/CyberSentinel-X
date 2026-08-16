"""Authentication routes."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_client_ip, get_current_user, get_request_id, require_roles
from app.core.database import get_db
from app.core.rate_limit import RateLimiter
from app.core.config import get_settings
from app.models.user import User
from app.schemas.auth import (
    AuthResponse,
    ForgotPasswordRequest,
    LoginRequest,
    PasswordUpdateRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from app.services.auth_service import AuthError, authenticate, build_tokens, refresh_access_token, register

router = APIRouter(prefix="/api/auth", tags=["auth"])
limiter = RateLimiter(max_requests=get_settings().rate_limit_max_requests,
                      window_seconds=get_settings().rate_limit_window_seconds)


@router.post("/register", response_model=AuthResponse, status_code=201)
def register_user(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    allowed, _retry = limiter.check(f"register:{ip}")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests. Try again shortly.")
    try:
        user = register(db, req, ip=ip, request_id=get_request_id(request))
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    tokens = build_tokens(user, remember_me=False)
    return AuthResponse(user=UserOut.model_validate(user), tokens=TokenResponse(**tokens))


@router.post("/login", response_model=AuthResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    allowed, retry = limiter.check(f"login:{ip}")
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many attempts. Retry in {retry}s.")

    # Credential brute-force guard: lock the account after repeated failures
    from app.core.firewall import is_brute_locked, record_brute_failure
    account_key = f"login:{req.email.lower()}"
    if is_brute_locked(account_key):
        raise HTTPException(status_code=429, detail="Account temporarily locked due to too many failed attempts. Try again later.")
    try:
        user = authenticate(db, req, ip=ip, request_id=get_request_id(request))
    except AuthError as exc:
        if exc.status_code == 401:
            record_brute_failure(account_key)
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    from app.core.firewall import brute_guard_clear
    brute_guard_clear(account_key)
    tokens = build_tokens(user, remember_me=req.remember_me)
    return AuthResponse(user=UserOut.model_validate(user), tokens=TokenResponse(**tokens))


@router.post("/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        tokens = refresh_access_token(db, req.refresh_token, ip=get_client_ip(request))
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return TokenResponse(**tokens)


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(get_current_user)):
    # JWT is stateless; logout is client-side token discard. Audit the event.
    from app.services.audit import log_action
    from app.core.database import get_db as _db
    db = next(_db())
    log_action(db, actor=user.email, action="AUTH.LOGOUT", ip_address=get_client_ip(request))
    db.close()
    return None


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut.model_validate(user)


@router.post("/me/password", response_model=UserOut)
def update_my_password(
    req: PasswordUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Set or change the current account's password.

    SSO-only accounts (empty hash) can set a password without proving the
    old one; password accounts must verify the current password first.
    """
    from app.core.security import hash_password, verify_password
    from app.services.audit import log_action

    ip = get_client_ip(request)
    if user.password_hash:
        if not req.current_password or not verify_password(req.current_password, user.password_hash):
            log_action(db, actor=user.email, action="AUTH.PASSWORD_CHANGE_FAILED",
                       target_type="user", target_id=str(user.id), ip_address=ip)
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        action = "AUTH.PASSWORD_CHANGED"
    else:
        action = "AUTH.PASSWORD_SET"

    user.password_hash = hash_password(req.new_password)
    db.commit()
    db.refresh(user)
    log_action(db, actor=user.email, action=action, target_type="user", target_id=str(user.id),
               ip_address=ip)
    return UserOut.model_validate(user)


@router.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles("ADMIN"))):
    """Admin view of all accounts including their sign-in methods."""
    users = db.scalars(
        select(User).options(selectinload(User.roles)).order_by(User.created_at.desc())
    ).all()
    return [UserOut.model_validate(u) for u in users]


@router.post("/forgot-password", status_code=200)
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    # Always respond generically (never disclose account existence), but do
    # send a reset email when the address belongs to a real account.
    from app.services.audit import log_action
    log_action(db, actor="system", action="AUTH.FORGOT_PASSWORD_REQUESTED",
               target_type="email", target_id=req.email, ip_address=get_client_ip(request))

    from app.core.email import email_enabled, send_password_reset
    if email_enabled():
        from app.core.security import create_reset_token
        user = db.scalar(__import__("sqlalchemy").select(User).where(User.email == req.email.lower()))
        if user is not None:
            token = create_reset_token(str(user.id))
            link = f"{get_settings().frontend_url.rstrip('/')}/reset-password?token={token}"
            send_password_reset(user.email, link)

    return {"message": "If that email is registered, a reset link has been sent."}
