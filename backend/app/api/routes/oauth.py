"""Social login (OAuth 2.0) routes for Google and GitHub.

Providers are configured through environment variables:
    GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
    GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET

When credentials are absent the endpoints report `configured: false` and the
frontend shows a friendly "SSO not configured" state instead of failing.
"""
import logging
import secrets
import uuid
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.core.firewall import brute_guard_clear
from app.models.user import User
from app.schemas.auth import UserOut
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


def _redirect_uri(provider: str) -> str:
    """The callback URL registered with the provider.

    This MUST live on the FRONTEND origin, not the backend's: the browser
    reaches /api through the frontend's nginx (or Vite dev) proxy, so the
    CSRF state cookie is set on the frontend host. The provider redirects the
    browser to the callback on that same host, the cookie is sent, and nginx
    proxies the request (cookie intact) to the backend. If we pointed the
    provider at the backend origin instead, the cookie would never be sent
    and every login would fail with "OAuth state mismatch".
    """
    return get_settings().frontend_url.rstrip("/") + f"/api/auth/oauth/{provider}/callback"


def _state_cookie(response: Response) -> str:
    """Issue the CSRF state cookie and return the bare token."""
    state = secrets.token_urlsafe(24)
    response.set_cookie(
        key="csx_oauth_state",
        value=state,
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=(get_settings().environment == "production"),
        path="/api/auth/oauth",
    )
    return state


def _build_authorize_url(provider: str, state_param: str) -> str:
    cfg = _provider_config(provider)
    client_id, _secret = _client_ids(provider)
    params = {
        "client_id": client_id,
        "redirect_uri": _redirect_uri(provider),
        "response_type": "code",
        "scope": cfg["scope"],
        "state": state_param,
    }
    return f"{cfg['authorize_url']}?{urlencode(params)}"


@router.get("/{provider}/authorize")
def authorize(provider: str, response: Response):
    cfg = _provider_config(provider)
    client_id, _secret = _client_ids(provider)
    if not client_id:
        return {"provider": provider, "configured": False,
                "message": f"{provider.capitalize()} SSO is not configured. Add {cfg['client_id_env']} to your environment."}
    state = _state_cookie(response)
    return {"provider": provider, "configured": True, "authorize_url": _build_authorize_url(provider, state)}


@router.get("/{provider}/link")
def link_authorize(
    provider: str,
    response: Response,
    user: User = Depends(get_current_user),
):
    """Start the OAuth flow to LINK a provider to the signed-in account.

    The target user id is encoded into the provider's echoed `state` param
    (token:link:<uid>); the CSRF cookie still carries the bare token.
    """
    cfg = _provider_config(provider)
    client_id, _secret = _client_ids(provider)
    if not client_id:
        return {"provider": provider, "configured": False,
                "message": f"{provider.capitalize()} SSO is not configured. Add {cfg['client_id_env']} to your environment."}
    state = _state_cookie(response)
    return {
        "provider": provider,
        "configured": True,
        "authorize_url": _build_authorize_url(provider, f"{state}:link:{user.id}"),
    }


@router.post("/{provider}/unlink", response_model=UserOut)
def unlink(
    provider: str,
    user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Detach a linked provider identity from the current account."""
    _provider_config(provider)  # 404 for unknown providers
    if user.oauth_provider != provider:
        return user
    if not user.password_hash:
        raise HTTPException(
            status_code=400,
            detail="Cannot unlink your only sign-in method — set a password first.",
        )
    user.oauth_provider = None
    user.oauth_provider_id = None
    db.commit()
    db.refresh(user)
    log_action(db, actor=user.email, action="AUTH.OAUTH_UNLINK",
               target_type="user", target_id=str(user.id),
               detail={"provider": provider},
               ip_address=get_client_ip(request) if request else None)
    return user


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

    # CSRF: the state must match the one we issued in the authorize cookie.
    # The state param may carry `token:link:<user_id>` for account-linking
    # flows started from the settings page.
    parts = state.split(":")
    token, mode = parts[0], (parts[1] if len(parts) > 1 else "login")
    link_uid = parts[2] if len(parts) > 2 else ""
    expected_state = request.cookies.get("csx_oauth_state") if request else None
    # compare_digest raises on differing lengths — guard before comparing.
    if not expected_state or len(token) != len(expected_state) or not secrets.compare_digest(token, expected_state):
        raise HTTPException(status_code=400, detail="OAuth state mismatch. Please try again.")

    redirect_uri = _redirect_uri(provider)

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
            if token_res.status_code >= 400:
                logger.warning("oauth token exchange HTTP %s for %s: %s",
                               token_res.status_code, provider, token_res.text[:300])
                raise HTTPException(status_code=401, detail="OAuth token exchange failed")
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
            if profile_res.status_code >= 400:
                logger.warning("oauth userinfo HTTP %s for %s: %s",
                               profile_res.status_code, provider, profile_res.text[:300])
                raise HTTPException(status_code=401, detail="Could not fetch your profile from the provider")
            profile = profile_res.json()
    except httpx.HTTPError as exc:
        logger.error("oauth userinfo error: %s", exc)
        raise HTTPException(status_code=502, detail="OAuth provider unreachable")

    email = (profile.get("email") or "").lower()
    # Google: only accept verified accounts (both login and linking).
    if provider == "google" and profile.get("email_verified") is False:
        raise HTTPException(status_code=400, detail="Google account email is not verified.")
    provider_id = str(profile.get("id") or profile.get("sub") or "")

    # --- Account linking flow (started from Settings) -----------------------
    if mode == "link":
        if not provider_id:
            raise HTTPException(status_code=400, detail=f"{provider.capitalize()} did not return an identity.")
        try:
            target = db.get(User, uuid.UUID(link_uid))
        except (ValueError, TypeError):
            target = None
        if target is None:
            raise HTTPException(status_code=404, detail="Target account not found.")
        if not target.is_active:
            raise HTTPException(status_code=403, detail="Account is disabled")
        if target.sso_blocked:
            raise HTTPException(status_code=403, detail="SSO sign-in is blocked for this account.")
        existing = db.scalar(select(User).where(
            User.oauth_provider == provider, User.oauth_provider_id == provider_id))
        if existing is not None and existing.id != target.id:
            raise HTTPException(
                status_code=409,
                detail=f"This {provider.capitalize()} account is already linked to {existing.email}.",
            )
        target.oauth_provider = provider
        target.oauth_provider_id = provider_id
        target.is_verified = True
        target.last_login_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        db.commit()
        log_action(db, actor=target.email, action="AUTH.OAUTH_LINK",
                   target_type="user", target_id=str(target.id),
                   detail={"provider": provider},
                   ip_address=get_client_ip(request) if request else None)
        fe = get_settings().frontend_url.rstrip("/")
        return __import__("fastapi").responses.RedirectResponse(f"{fe}/oauth/callback#linked={provider}")

    # --- Login flow ---------------------------------------------------------
    # GitHub: profile.email may be null when the user keeps their email
    # private — fetch /user/emails in that case.
    if provider == "github" and not email:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                emails_res = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                )
                emails = emails_res.json()
            verified = [e for e in emails if isinstance(e, dict) and e.get("verified")]
            primary = next((e for e in verified if e.get("primary")), None) or (verified[0] if verified else None)
            email = ((primary or {}).get("email") or "").lower()
        except httpx.HTTPError as exc:
            logger.error("oauth github emails error: %s", exc)
    if not email:
        raise HTTPException(status_code=400, detail=f"{provider.capitalize()} did not return an email address.")

    full_name = profile.get("name") or profile.get("login") or profile.get("given_name", "") or email.split("@")[0]

    # 3) Find, link, or create the user. The provider identity (provider + id)
    #    wins over email, so a renamed email still maps to the same account.
    #    If an account already exists with the same email, the provider
    #    identity is linked to it (SSO account linking) rather than creating a
    #    duplicate.
    user = None
    if provider_id:
        user = db.scalar(select(User).where(
            User.oauth_provider == provider, User.oauth_provider_id == provider_id))
    if user is None and email:
        user = db.scalar(select(User).where(User.email == email))
    created = False
    linked = False
    if user is None:
        from app.services.auth_service import ensure_default_roles
        ensure_default_roles(db)
        user = User(
            email=email,
            full_name=full_name,
            organization=f"Via {provider.capitalize()}",
            password_hash="",  # OAuth users have no password; login via provider only
            is_verified=True,
            oauth_provider=provider if provider_id else None,
            oauth_provider_id=provider_id or None,
        )
        role = get_or_create_role(db, "SECURITY_ANALYST")
        user.roles.append(role)
        db.add(user)
        created = True
    elif not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    elif user.sso_blocked:
        raise HTTPException(status_code=403, detail="SSO sign-in is blocked for this account.")
    else:
        # Account linking: bind the provider identity to the existing account.
        # Idempotent for repeat logins of an already-linked account.
        if provider_id and (user.oauth_provider != provider or user.oauth_provider_id != provider_id):
            user.oauth_provider = provider
            user.oauth_provider_id = provider_id
            linked = True

    user.last_login_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    db.commit()
    db.refresh(user)
    brute_guard_clear(f"login:{email}")

    log_action(db, actor=user.email, action="AUTH.OAUTH_LOGIN",
               target_type="user", target_id=str(user.id),
               detail={"provider": provider, "created": created, "linked": linked},
               ip_address=get_client_ip(request) if request else None)

    tokens = build_tokens(user, remember_me=True)
    # Redirect back to the SPA with credentials in the URL fragment (never the
    # query string, so tokens don't land in server/referrer logs).
    fe = get_settings().frontend_url.rstrip("/")
    return __import__("fastapi").responses.RedirectResponse(
        f"{fe}/oauth/callback#access={tokens['access_token']}&refresh={tokens['refresh_token']}"
    )
