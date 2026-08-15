"""Social login (OAuth 2.0) routes for Google and GitHub.

Providers are configured through environment variables:
    GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
    GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET

When credentials are absent the endpoints report `configured: false` and the
frontend shows a friendly "SSO not configured" state instead of failing.
"""
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip
from app.core.config import get_settings
from app.core.database import get_db
from app.core.firewall import brute_guard_clear
from app.models.user import User
from app.services.auth_service import build_tokens, get_or_create_role
from app.services.audit import log_action

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth/oauth", tags=["oauth"])

PROVIDERS = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile",
        "client_id_env": "GOOGLE_CLIENT_ID",
        "client_secret_env": "GOOGLE_CLIENT_SECRET",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
        "client_id_env": "GITHUB_CLIENT_ID",
        "client_secret_env": "GITHUB_CLIENT_SECRET",
    },
}


def _provider_config(provider: str) -> dict:
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
    return PROVIDERS[provider]


def _client_ids(provider: str) -> tuple:
    cfg = _provider_config(provider)
    settings = get_settings()
    client_id = getattr(settings, cfg["client_id_env"].lower(), "") or ""
    client_secret = getattr(settings, cfg["client_secret_env"].lower(), "") or ""
    return client_id, client_secret


@router.get("/providers")
def list_providers():
    settings = get_settings()
    out = []
    for name, cfg in PROVIDERS.items():
        cid = getattr(settings, cfg["client_id_env"].lower(), "") or ""
        out.append({
            "provider": name,
            "name": name.capitalize(),
            "configured": bool(cid),
        })
    return {"providers": out}


@router.get("/{provider}/authorize")
def authorize(provider: str, request: Request):
    cfg = _provider_config(provider)
    client_id, _secret = _client_ids(provider)
    if not client_id:
        return {"provider": provider, "configured": False,
                "message": f"{provider.capitalize()} SSO is not configured. Add {cfg['client_id_env']} to your environment."}

    state = secrets.token_urlsafe(16)
    request.state.oauth_state = state  # opaque; validated on callback via the query param
    params = {
        "client_id": client_id,
        "redirect_uri": get_settings().backend_url.rstrip("/") + f"/api/auth/oauth/{provider}/callback",
        "response_type": "code",
        "scope": cfg["scope"],
        "state": state,
    }
    return {"provider": provider, "configured": True, "authorize_url": f"{cfg['authorize_url']}?{urlencode(params)}"}


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    code: str = Query(""),
    error: str = Query(""),
    state: str = Query(""),
    request: Request = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = _provider_config(provider)
    client_id, client_secret = _client_ids(provider)
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail=f"{provider.capitalize()} SSO is not configured on the server.")

    redirect_uri = get_settings().backend_url.rstrip("/") + f"/api/auth/oauth/{provider}/callback"

    # 1) Exchange the authorization code for tokens
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if provider == "github":
                headers = {"Accept": "application/json"}
            else:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
            token_res = await client.post(
                cfg["token_url"],
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                headers=headers,
            )
            token_payload = token_res.json()
            access_token = token_payload.get("access_token")
            if not access_token:
                logger.warning("oauth token exchange failed for %s: %s", provider, token_payload)
                raise HTTPException(status_code=401, detail="OAuth token exchange failed")
    except httpx.HTTPError as exc:
        logger.error("oauth token exchange error: %s", exc)
        raise HTTPException(status_code=502, detail="OAuth provider unreachable")

    # 2) Fetch the user profile
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            profile_res = await client.get(cfg["userinfo_url"], headers=headers)
            profile = profile_res.json()
    except httpx.HTTPError as exc:
        logger.error("oauth userinfo error: %s", exc)
        raise HTTPException(status_code=502, detail="OAuth provider unreachable")

    email = (profile.get("email") or "").lower()
    if not email:
        raise HTTPException(status_code=400, detail=f"{provider.capitalize()} did not return an email address.")

    full_name = profile.get("name") or profile.get("login") or profile.get("given_name", "") or email.split("@")[0]

    # 3) Find or create the user
    user = db.scalar(select(User).where(User.email == email))
    created = False
    if user is None:
        from app.services.auth_service import ensure_default_roles
        ensure_default_roles(db)
        user = User(
            email=email,
            full_name=full_name,
            organization=f"Via {provider.capitalize()}",
            password_hash="",  # OAuth users have no password; login via provider only
            is_verified=True,
        )
        role = get_or_create_role(db, "SECURITY_ANALYST")
        user.roles.append(role)
        db.add(user)
        created = True
    elif not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    user.last_login_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    db.commit()
    db.refresh(user)
    brute_guard_clear(f"login:{email}")

    log_action(db, actor=user.email, action="AUTH.OAUTH_LOGIN",
               target_type="user", target_id=str(user.id),
               detail={"provider": provider, "created": created},
               ip_address=get_client_ip(request) if request else None)

    tokens = build_tokens(user, remember_me=True)
    # Redirect the browser back to the SPA with credentials in the fragment
    fe = get_settings().frontend_url.rstrip("/")
    return __import__("fastapi").responses.RedirectResponse(
        f"{fe}/oauth/callback?access={tokens['access_token']}&refresh={tokens['refresh_token']}"
    )
