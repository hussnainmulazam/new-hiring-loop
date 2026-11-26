"""
Google OAuth2 authentication and Workspace integration router.

Implements:
1. GET /auth/google          — Redirects user to Google OAuth2 consent screen (openid, email, profile).
2. GET /auth/google/callback — Exchanges code with Google via httpx, gets/creates SQLModel User,
                               issues JWT in httpOnly cookie, and redirects to FRONTEND_URL/dashboard.
3. GET /auth/me              — Returns current authenticated user verifying JWT (cookie or Bearer header).
4. GET /auth/google/login    — Google Workspace offline consent URL (Calendar / Gmail).
5. GET /integrations/google/url — Alias for Workspace consent URL.
"""
import urllib.parse
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlmodel import Session

from app.core.config import settings
from app.core.dependencies import CurrentUser
from app.core.security import decode_oauth_state
from app.db import SessionDep
from app.schemas.auth import UserPublic
from app.schemas.google import GoogleAuthUrlResponse
from app.services.auth_service import auth_service
from app.services.google_service import GoogleService

router = APIRouter(tags=["Google OAuth2 & Workspace"])


# ── 1. Google OAuth2 Login (Direct Redirect) ─────────────────────────────────

@router.get(
    "/auth/google",
    operation_id="auth_google_redirect",
    summary="Redirect to Google OAuth2 consent screen for login/signup",
)
def auth_google():
    """
    Initiates Google OAuth2 login flow.
    Scopes: openid, email, profile.
    Uses cryptographically signed state token for CSRF protection.
    Issues a 302 browser redirect directly to Google consent screen.
    """
    auth_url = auth_service.get_google_auth_url()
    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


# ── 2. Google OAuth2 Callback ────────────────────────────────────────────────

@router.get(
    "/auth/google/callback",
    operation_id="auth_google_callback",
    summary="Google OAuth2 callback redirect handler (Login and Workspace flows)",
)
def google_callback(
    session: SessionDep,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
):
    """
    Handles redirect callback from Google OAuth2 consent screen.
    Validates state parameter for CSRF safety.
    Dispatches based on state flow:
      - flow="login": exchanges code with Google using httpx, gets or creates SQLModel User row,
                      issues JWT, sets secure httpOnly cookie, and redirects to FRONTEND_URL/dashboard.
      - flow="workspace": exchanges code for refresh token and links Google Workspace account.
    """
    frontend_url = settings.FRONTEND_URL.rstrip("/")

    # Detect flow from signed state token
    flow = "login"
    if state:
        try:
            state_data = decode_oauth_state(state)
            if state_data.get("flow") == "workspace" or ("sub" in state_data and "flow" not in state_data) or "user_id" in state_data:
                flow = "workspace"
            else:
                flow = state_data.get("flow", "login")
        except Exception:
            flow = "login"

    # 1. Google-level consent error or user denial
    if error:
        error_msg = "Google sign-in was cancelled." if error == "access_denied" else f"Google error: {error}"
        if flow == "login":
            return RedirectResponse(
                url=f"{frontend_url}/login?error={urllib.parse.quote(error_msg)}",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/settings?google_error={urllib.parse.quote(error_msg)}&tab=google",
            status_code=status.HTTP_302_FOUND,
        )

    # 2. Missing code or state
    if not code:
        if flow == "login":
            return RedirectResponse(
                url=f"{frontend_url}/login?error=Missing+authorization+code+from+Google.",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/settings?google_error=Missing+authorization+code+from+Google.&tab=google",
            status_code=status.HTTP_302_FOUND,
        )

    if not state:
        if flow == "login":
            return RedirectResponse(
                url=f"{frontend_url}/login?error=Missing+state+parameter+or+CSRF+detected.",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/settings?google_error=Missing+state+parameter+or+CSRF+detected.&tab=google",
            status_code=status.HTTP_302_FOUND,
        )

    # 3. Flow A: User Login / Signup
    if flow == "login":
        try:
            auth_res = auth_service.authenticate_google(session=session, code=code, state=state)
        except ValueError as exc:
            return RedirectResponse(
                url=f"{frontend_url}/login?error={urllib.parse.quote(str(exc))}",
                status_code=status.HTTP_302_FOUND,
            )

        token = auth_res.access_token
        # Redirect user to FRONTEND_URL/auth/callback (with token param for instant local storage sync)
        redirect_url = f"{frontend_url}/auth/callback?token={urllib.parse.quote(token)}&setup_completed={str(auth_res.setup_completed).lower()}"
        response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
        is_https = frontend_url.startswith("https")
        response.set_cookie(
            key="auth_token",
            value=token,
            max_age=60 * 60 * 24 * 7,
            path="/",
            httponly=True,
            samesite="none" if is_https else "lax",
            secure=is_https,
        )
        return response

    # 4. Flow B: Workspace Connection (Settings > Google Workspace)
    service = GoogleService(session)
    try:
        account, user_id = service.handle_callback(code, state)
    except ValueError as exc:
        return RedirectResponse(
            url=f"{frontend_url}/settings?google_error={urllib.parse.quote(str(exc))}&tab=google",
            status_code=status.HTTP_302_FOUND,
        )

    status_param = "google_connected=true&google_connected=1&partial=1" if account.last_sync_status == "partial_access" else "google_connected=true&google_connected=1"
    redirect_target = f"{frontend_url}/settings?{status_param}&email={urllib.parse.quote(account.email)}&tab=google"
    return RedirectResponse(url=redirect_target, status_code=status.HTTP_302_FOUND)


# ── 3. Current User Profile ──────────────────────────────────────────────────

@router.get(
    "/auth/me",
    response_model=UserPublic,
    summary="Get the currently authenticated user (verifies JWT from cookie or Bearer header)",
)
def get_auth_me(current_user: CurrentUser) -> UserPublic:
    """
    Returns the profile of the currently authenticated user.
    Verifies JWT token passed via:
      1. httpOnly 'auth_token' cookie (set during Google OAuth login)
      2. 'Authorization: Bearer <token>' header
    """
    return UserPublic.model_validate(current_user)


# ── 4. Workspace Flow Helpers ────────────────────────────────────────────────

@router.get(
    "/auth/google/login",
    operation_id="auth_google_workspace_login",
    response_model=GoogleAuthUrlResponse,
    summary="Get Google Workspace OAuth2 authorization URL",
)
@router.get(
    "/integrations/google/url",
    operation_id="auth_google_workspace_url_alias",
    response_model=GoogleAuthUrlResponse,
    summary="Get Google Workspace OAuth2 authorization URL (alias)",
)
def google_workspace_login(
    current_user: CurrentUser,
    session: SessionDep,
    redirect: bool = Query(default=False),
):
    """
    Initiates Google Workspace OAuth2 authorization code flow with offline access (refresh token).
    Encodes current authenticated recruiter user_id in signed state parameter with flow="workspace".
    """
    service = GoogleService(session)
    res = service.generate_auth_url(current_user.id)
    if redirect:
        return RedirectResponse(url=res.auth_url, status_code=status.HTTP_302_FOUND)
    return res
