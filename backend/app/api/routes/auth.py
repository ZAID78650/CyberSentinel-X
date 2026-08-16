"""Authentication routes."""
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_client_ip, get_current_user, get_request_id, require_roles
from app.core.database import get_db
from app.core.rate_limit import RateLimiter
from app.core.config import get_settings
from app.models.user import Device, Role, User
from app.schemas.auth import (
    AdminPasswordReset,
    AuthResponse,
    ForgotPasswordRequest,
    LoginRequest,
    PasswordUpdateRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
    UserRolesUpdate,
    UserSsoBlockUpdate,
    UserStatusUpdate,
)
from app.services.auth_service import AuthError, authenticate, build_tokens, record_session, refresh_access_token, register

KNOWN_ROLES = ("ADMIN", "SECURITY_ANALYST", "VIEWER")

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
    record_session(db, user, tokens["refresh_token"], ip=get_client_ip(request),
                   user_agent=request.headers.get("user-agent"))
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


def _iso(v) -> Optional[str]:
    return v.isoformat() if v else None


def _session_out(dev: Device, current_jti: Optional[str] = None) -> dict:
    return {
        "device_id": dev.device_id,
        "device_name": dev.device_name,
        "os": dev.os,
        "browser": dev.browser,
        "ip_address": dev.ip_address,
        "location": dev.location,
        "is_trusted": dev.is_trusted,
        "first_seen": _iso(dev.first_seen),
        "last_seen": _iso(dev.last_seen),
        "revoked": dev.revoked_at is not None,
        "current": dev.device_id == current_jti,
    }


def _current_session_jti(request: Request) -> Optional[str]:
    """The `sess` claim of the caller's access token (marks the live session)."""
    from app.core.security import decode_token
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        payload = decode_token(auth[7:])
        if payload:
            return payload.get("sess")
    return None


@router.get("/sessions")
def my_sessions(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """List the signed-in account's sessions (devices), newest first."""
    devices = db.scalars(
        select(Device).where(Device.user_id == user.id).order_by(Device.last_seen.desc())
    ).all()
    current = _current_session_jti(request)
    return [_session_out(d, current) for d in devices]


@router.post("/sessions/{device_id}/revoke")
def revoke_my_session(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Revoke one of the signed-in account's sessions. That refresh token dies
    immediately; the matching access token expires within its TTL."""
    from app.services.audit import log_action
    dev = db.scalar(select(Device).where(Device.user_id == user.id, Device.device_id == device_id))
    if dev is None:
        raise HTTPException(status_code=404, detail="Session not found")
    dev.revoked_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, actor=user.email, action="AUTH.SESSION_REVOKED", target_type="device",
               target_id=device_id, ip_address=get_client_ip(request))
    return _session_out(dev, _current_session_jti(request))


@router.get("/users/{user_id}/sessions")
def admin_user_sessions(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: list every session of an account."""
    user = _get_user_or_404(db, user_id)
    devices = db.scalars(
        select(Device).where(Device.user_id == user.id).order_by(Device.last_seen.desc())
    ).all()
    return [_session_out(d) for d in devices]


@router.post("/users/{user_id}/sessions/{device_id}/revoke")
def admin_revoke_session(
    user_id: uuid.UUID,
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: revoke a specific session of any account."""
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    dev = db.scalar(select(Device).where(Device.user_id == user.id, Device.device_id == device_id))
    if dev is None:
        raise HTTPException(status_code=404, detail="Session not found")
    dev.revoked_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, actor=admin.email, action="AUTH.USER_SESSION_REVOKED", target_type="device",
               target_id=device_id, detail={"user": user.email},
               ip_address=get_client_ip(request))
    return _session_out(dev)


@router.get("/me/export")
def export_my_data(
    fmt: str = Query("json", pattern="^(json|csv|zip)$"),
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """GDPR-style export of everything this account holds: profile, devices,
    the account's audit trail and incidents it created. JSON = full bundle;
    CSV = flat audit-events export."""
    from app.models.investigation import ActionLog
    from app.models.security import Incident
    from app.services.audit import log_action

    profile = UserOut.model_validate(user).model_dump()

    devices = [
        {
            "device_id": d.device_id, "device_name": d.device_name, "os": d.os,
            "browser": d.browser, "ip_address": d.ip_address, "location": d.location,
            "is_trusted": d.is_trusted, "first_seen": _iso(d.first_seen), "last_seen": _iso(d.last_seen),
        }
        for d in db.scalars(select(Device).where(Device.user_id == user.id)
                            .order_by(Device.last_seen.desc())).all()
    ]

    audit = [
        {
            "created_at": _iso(a.created_at), "action": a.action, "target_type": a.target_type,
            "target_id": a.target_id, "detail": a.detail, "ip_address": a.ip_address,
            "request_id": a.request_id,
        }
        for a in db.scalars(select(ActionLog).where(ActionLog.actor == user.email)
                            .order_by(ActionLog.created_at.desc())).all()
    ]

    incidents = [
        {
            "incident_id": i.incident_id, "title": i.title, "severity": i.severity,
            "status": i.status, "category": i.category, "risk_score": i.risk_score,
            "created_at": _iso(i.created_at),
        }
        for i in db.scalars(select(Incident).where(Incident.created_by == user.email)
                            .order_by(Incident.created_at.desc())).all()
    ]

    log_action(db, actor=user.email, action="AUTH.DATA_EXPORT", target_type="user", target_id=str(user.id),
               ip_address=get_client_ip(request) if request else None)

    base_name = user.email.split("@")[0].replace(".", "-")
    if fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["created_at", "action", "target_type", "target_id", "detail", "ip_address", "request_id"])
        for a in audit:
            w.writerow([a["created_at"], a["action"], a["target_type"], a["target_id"],
                        json.dumps(a["detail"]) if a["detail"] else "", a["ip_address"], a["request_id"]])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="cybersentinel-audit-{base_name}.csv"'},
        )

    payload = {
        "exported_at": _iso(datetime.now(timezone.utc)),
        "account": profile,
        "devices": devices,
        "audit_events": audit,
        "incidents": incidents,
    }
    if fmt == "zip":
        from app.models.forensics import EvidenceRecord
        import csv
        import io as _io
        import zipfile

        evidence = [
            {
                "evidence_id": e.evidence_id, "evidence_type": e.evidence_type, "title": e.title,
                "description": e.description, "chain_index": e.chain_index, "status": e.status,
                "data_source": e.data_source, "record_hash": e.record_hash, "created_by": e.created_by,
                "attachment_name": e.attachment_name, "attachment_path": e.attachment_path,
                "created_at": _iso(e.created_at),
            }
            for e in db.scalars(select(EvidenceRecord)
                                .where(EvidenceRecord.created_by == user.email)
                                .order_by(EvidenceRecord.created_at.desc())).all()
        ]

        csv_buf = _io.StringIO()
        w = csv.writer(csv_buf)
        w.writerow(["created_at", "action", "target_type", "target_id", "detail", "ip_address", "request_id"])
        for a in audit:
            w.writerow([a["created_at"], a["action"], a["target_type"], a["target_id"],
                        json.dumps(a["detail"]) if a["detail"] else "", a["ip_address"], a["request_id"]])

        counts = f"""
        <p>Devices: {len(devices)} · Audit events: {len(audit)} · Incidents: {len(incidents)} · Evidence records: {len(evidence)}</p>
        """.strip()
        summary = f"""<!doctype html><html><head><meta charset="utf-8"><title>Account export — {user.email}</title>
        <style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;color:#111}}h1{{font-size:1.3rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:.85rem}}code{{background:#f4f4f4;padding:1px 4px}}</style></head><body>
        <h1>CyberSentinel X — account data export</h1>
        <p>Exported {payload['exported_at']} · {user.email} · roles: {', '.join(profile['roles'])}</p>
        {counts}
        <h2>Recent audit events</h2>
        <table><tr><th>Time</th><th>Action</th><th>Target</th><th>IP</th></tr>
        {''.join(f"<tr><td>{a['created_at'] or ''}</td><td><code>{a['action']}</code></td><td>{a['target_type'] or ''} {a['target_id'] or ''}</td><td>{a['ip_address'] or ''}</td></tr>" for a in audit[:25])}
        </table></body></html>"""

        zf_buf = _io.BytesIO()
        with zipfile.ZipFile(zf_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("account.json", json.dumps(payload, indent=2, default=str))
            zf.writestr("audit.csv", csv_buf.getvalue())
            zf.writestr("evidence.json", json.dumps(evidence, indent=2, default=str))
            zf.writestr("summary.html", summary)
            # Evidence attachments (files stored on disk) travel in the bundle
            for e in evidence:
                if not e.get("attachment_name"):
                    continue
                from pathlib import Path as _Path
                p = _Path(e.get("attachment_path")) if e.get("attachment_path") else None
                if p and p.exists():
                    zf.writestr(f"evidence/{e['evidence_id']}/{e['attachment_name']}", p.read_bytes())
        return Response(
            content=zf_buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="cybersentinel-bundle-{base_name}.zip"'},
        )

    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="cybersentinel-account-{base_name}.json"'},
    )


def _get_user_or_404(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _signed_detail(detail: dict, actor: str, action: str) -> dict:
    """Tamper-evident audit detail: HMAC-SHA256 over the canonical record."""
    now = datetime.now(timezone.utc)
    canonical = f"{actor}|{action}|{json.dumps(detail, sort_keys=True, default=str)}|{now.isoformat()}"
    sig = hmac.new(
        get_settings().jwt_secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    return {**detail, "_signed_at": now.isoformat(), "_sig": sig}


@router.post("/users/{user_id}/status", response_model=UserOut)
def set_user_status(
    user_id: uuid.UUID,
    req: UserStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: enable or disable an account (no self-disable)."""
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    if user.id == admin.id and not req.is_active:
        raise HTTPException(status_code=400, detail="You cannot disable your own account.")
    user.is_active = req.is_active
    db.commit()
    db.refresh(user)
    log_action(db, actor=admin.email, action="AUTH.USER_ACTIVE_CHANGED",
               target_type="user", target_id=str(user.id),
               detail={"is_active": req.is_active},
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/password", response_model=UserOut)
def admin_reset_password(
    user_id: uuid.UUID,
    req: AdminPasswordReset,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: force-set a user's password (also gives SSO-only accounts a fallback)."""
    from app.core.security import hash_password
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    user.password_hash = hash_password(req.new_password)
    db.commit()
    db.refresh(user)
    log_action(db, actor=admin.email, action="AUTH.USER_PASSWORD_RESET",
               target_type="user", target_id=str(user.id),
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/deprovision", response_model=UserOut)
def deprovision_user(
    user_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: archive an account and revoke every outstanding session.

    Sets the account inactive, blocks SSO sign-in, and bumps token_version so
    all previously issued access/refresh tokens immediately fail validation.
    """
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot deprovision your own account.")
    user.is_active = False
    user.sso_blocked = True
    user.token_version += 1
    db.commit()
    db.refresh(user)
    detail = _signed_detail({"token_version": user.token_version, "is_active": False, "sso_blocked": True},
                            admin.email, "AUTH.USER_DEPROVISIONED")
    log_action(db, actor=admin.email, action="AUTH.USER_DEPROVISIONED",
               target_type="user", target_id=str(user.id), detail=detail,
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/restore", response_model=UserOut)
def restore_user(
    user_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: re-enable a deprovisioned account. Old sessions stay revoked."""
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    user.is_active = True
    user.sso_blocked = False
    db.commit()
    db.refresh(user)
    detail = _signed_detail({"token_version": user.token_version, "is_active": True, "sso_blocked": False},
                            admin.email, "AUTH.USER_RESTORED")
    log_action(db, actor=admin.email, action="AUTH.USER_RESTORED",
               target_type="user", target_id=str(user.id), detail=detail,
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/sso-block", response_model=UserOut)
def set_user_sso_block(
    user_id: uuid.UUID,
    req: UserSsoBlockUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: block SSO sign-in for an account while password login stays active."""
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)
    if user.id == admin.id and req.blocked:
        raise HTTPException(status_code=400, detail="You cannot block SSO on your own account.")
    user.sso_blocked = req.blocked
    db.commit()
    db.refresh(user)
    detail = _signed_detail({"blocked": req.blocked}, admin.email, "AUTH.USER_SSO_BLOCKED")
    log_action(db, actor=admin.email, action="AUTH.USER_SSO_BLOCKED",
               target_type="user", target_id=str(user.id), detail=detail,
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


@router.put("/users/{user_id}/roles", response_model=UserOut)
def update_user_roles(
    user_id: uuid.UUID,
    req: UserRolesUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("ADMIN")),
):
    """Admin: replace an account's roles, keeping the platform safe."""
    from app.services.audit import log_action
    user = _get_user_or_404(db, user_id)

    unknown = sorted(set(req.roles) - set(KNOWN_ROLES))
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown roles: {', '.join(unknown)}")
    if user.id == admin.id and "ADMIN" not in req.roles:
        raise HTTPException(status_code=400, detail="You cannot remove your own ADMIN role.")
    if "ADMIN" in user.role_names and "ADMIN" not in req.roles:
        other_admins = db.scalar(
            select(func.count())
            .select_from(User)
            .join(User.roles)
            .where(Role.name == "ADMIN", User.is_active.is_(True), User.id != user.id)
        ) or 0
        if other_admins == 0:
            raise HTTPException(status_code=400, detail="Cannot remove the last active ADMIN account.")

    role_objs = db.scalars(select(Role).where(Role.name.in_(req.roles))).all()
    by_name = {r.name: r for r in role_objs}
    if len(by_name) != len(set(req.roles)):
        raise HTTPException(status_code=400, detail="One or more roles do not exist.")
    user.roles = [by_name[r] for r in req.roles]
    db.commit()
    db.refresh(user)
    log_action(db, actor=admin.email, action="AUTH.USER_ROLES_CHANGED",
               target_type="user", target_id=str(user.id),
               detail={"roles": req.roles},
               ip_address=get_client_ip(request))
    return UserOut.model_validate(user)


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
