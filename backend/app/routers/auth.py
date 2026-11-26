"""
app/routers/auth.py
~~~~~~~~~~~~~~~~~~~
Authentication endpoints:

  POST /api/v1/auth/register   — create account, return token + user
  POST /api/v1/auth/login      — verify credentials, return token + user
  POST /api/v1/auth/login/form — OAuth2 form-compatible login (Swagger UI)
  GET  /api/v1/auth/me         — return current authenticated user
"""
import json
import urllib.parse
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.core.dependencies import CurrentUser
from app.core.rate_limit import rate_limit
from app.db import SessionDep
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserPublic,
    GoogleAuthRequest,
    GoogleAuthResponse,
)
from app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Auth"])


# ── Register ─────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account",
    dependencies=[Depends(rate_limit(times=10, seconds=60, scope="auth:register"))],
)
def register(body: RegisterRequest, session: SessionDep) -> TokenResponse:
    """
    Register a new user.

    - Hashes the password with **bcrypt** before storage.
    - Returns a signed JWT access token alongside the public user profile.
    - `hashed_password` is **never** included in any response.
    """
    try:
        return auth_service.register(session=session, data=body)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


# ── Login (JSON body) ─────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
    dependencies=[Depends(rate_limit(times=10, seconds=60, scope="auth:login"))],
)
def login(body: LoginRequest, session: SessionDep) -> TokenResponse:
    """
    Authenticate with **email + password** (JSON body).

    Returns a Bearer access token. The same error message is used whether the
    email does not exist or the password is wrong, to prevent user enumeration.
    """
    try:
        return auth_service.login(session=session, data=body)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Login (OAuth2 form — Swagger UI "Authorize" button) ──────────────────────

@router.post(
    "/login/form",
    response_model=TokenResponse,
    include_in_schema=True,
    summary="Authenticate via OAuth2 form (Swagger UI)",
)
def login_form(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
) -> TokenResponse:
    """
    OAuth2-compatible form login consumed by the Swagger UI "Authorize" dialog.
    Uses `username` field as email (standard OAuth2 form field name).
    """
    try:
        return auth_service.login(
            session=session,
            data=LoginRequest(email=form.username, password=form.password),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Me ────────────────────────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserPublic,
    summary="Get the currently authenticated user",
)
def me(current_user: CurrentUser) -> UserPublic:
    """
    Return the profile of the **currently authenticated** user.

    Requires a valid `Authorization: Bearer <token>` header.
    Returns HTTP 401 if the token is missing, expired, or invalid.
    Cached via L1/L2 cache (user:profile:{user_id}) for fast reads.
    """
    from app.services.cache_service import cache_service

    cache_key = f"user:profile:{current_user.id}"
    cached = cache_service.get(cache_key)
    if cached is not None:
        return UserPublic.model_validate(cached)

    result = UserPublic.model_validate(current_user)
    cache_service.set(cache_key, result.model_dump(), ttl=180)
    return result


# ── Google OAuth Login / Signup ──────────────────────────────────────────────

@router.get(
    "/google/url",
    summary="Get Google OAuth2 authorization URL for login / signup",
)
def google_auth_url(redirect_uri: Optional[str] = Query(default=None)):
    """
    Returns the Google OAuth2 consent URL for recruiter login/signup.
    Includes a signed state token to prevent CSRF and isolate the login flow.
    """
    try:
        url = auth_service.get_google_auth_url(redirect_uri=redirect_uri)
        return {"url": url}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get(
    "/google/callback",
    summary="Google OAuth2 login and signup callback handler (supports both Login and Workspace flows)",
)
def google_callback(
    session: SessionDep,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
):
    """
    Handles redirect callback from Google OAuth2 consent screen.
    Dispatches based on signed state token:
      - flow="login": exchanges code for tokens, finds/creates user, issues JWT session, sets auth cookie, redirects to /auth/callback.
      - flow="workspace": exchanges code, stores encrypted refresh token, redirects to /settings?google_connected=1&tab=google.
    """
    from app.core.config import settings
    from app.core.security import decode_oauth_state
    from app.services.google_service import GoogleService

    frontend_url = settings.FRONTEND_URL.rstrip("/")

    # Detect flow from signed state
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
        if flow == "workspace":
            return RedirectResponse(
                url=f"{frontend_url}/settings?google_error={urllib.parse.quote(error_msg)}&tab=google",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/login?error={urllib.parse.quote(error_msg)}",
            status_code=status.HTTP_302_FOUND,
        )

    # 2. Missing authorization code or state
    if not code:
        if flow == "workspace":
            return RedirectResponse(
                url=f"{frontend_url}/settings?google_error=Missing+authorization+code+from+Google.&tab=google",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/login?error=Missing+authorization+code+from+Google.",
            status_code=status.HTTP_302_FOUND,
        )

    if not state:
        if flow == "workspace":
            return RedirectResponse(
                url=f"{frontend_url}/settings?google_error=Missing+state+parameter+or+CSRF+detected.&tab=google",
                status_code=status.HTTP_302_FOUND,
            )
        return RedirectResponse(
            url=f"{frontend_url}/login?error=Missing+state+parameter+or+CSRF+detected.",
            status_code=status.HTTP_302_FOUND,
        )

    # 3. Handle Flow B: Workspace Connection
    if flow == "workspace":
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

    # 4. Handle Flow A: User Login / Signup
    try:
        auth_res = auth_service.authenticate_google(session=session, code=code, state=state)
    except ValueError as exc:
        error_msg = str(exc)
        return RedirectResponse(
            url=f"{frontend_url}/login?error={urllib.parse.quote(error_msg)}",
            status_code=status.HTTP_302_FOUND,
        )

    setup_str = "true" if auth_res.setup_completed else "false"
    token = auth_res.access_token

    redirect_url = f"{frontend_url}/auth/callback?token={urllib.parse.quote(token)}&setup_completed={setup_str}"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

    is_https = frontend_url.startswith("https")
    response.set_cookie(
        key="auth_token",
        value=token,
        max_age=60 * 60 * 24 * 7,  # 7 days
        path="/",
        httponly=True,
        samesite="none" if is_https else "lax",
        secure=is_https,
    )
    return response


@router.post(
    "/google",
    response_model=GoogleAuthResponse,
    summary="Authenticate or register user via Google OAuth2 authorization code",
    dependencies=[Depends(rate_limit(times=15, seconds=60, scope="auth:google"))],
)
def google_authenticate(body: GoogleAuthRequest, session: SessionDep) -> GoogleAuthResponse:
    """
    Exchanges code for tokens, verifies profile, logs in or registers user,
    and returns JWT token + setup_completed status.
    """
    try:
        return auth_service.authenticate_google(
            session=session,
            code=body.code,
            redirect_uri=body.redirect_uri,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


