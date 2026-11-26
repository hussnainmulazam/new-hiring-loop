"""
app/services/auth_service.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Business logic for user registration, login, and lookup.
Keeps routers thin — all DB queries and security calls live here.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlmodel import Session, select

from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import User
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, UserPublic, GoogleAuthResponse


class AuthService:

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_by_email(session: Session, email: str) -> Optional[User]:
        return session.exec(select(User).where(User.email == email)).first()

    @staticmethod
    def get_by_id(session: Session, user_id) -> Optional[User]:
        return session.get(User, user_id)

    # ── Register ─────────────────────────────────────────────────────────────

    @staticmethod
    def register(session: Session, data: RegisterRequest) -> TokenResponse:
        """
        Create a new user, hash their password, and return a token + public profile.
        Raises ValueError if the email is already registered.
        """
        existing = AuthService.get_by_email(session, data.email)
        if existing:
            raise ValueError("A user with that email already exists.")

        user = User(
            email=data.email,
            hashed_password=hash_password(data.password),
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        token = create_access_token(str(user.id))
        return TokenResponse(
            access_token=token,
            user=UserPublic.model_validate(user),
        )

    # ── Login ─────────────────────────────────────────────────────────────────

    @staticmethod
    def login(session: Session, data: LoginRequest) -> TokenResponse:
        """
        Verify credentials and return a fresh token.
        Always raises the same generic error to prevent user-enumeration.
        """
        INVALID_MSG = "Invalid email or password."

        user = AuthService.get_by_email(session, data.email)
        if not user:
            raise ValueError(INVALID_MSG)

        if not verify_password(data.password, user.hashed_password):
            raise ValueError(INVALID_MSG)

        token = create_access_token(str(user.id))
        return TokenResponse(
            access_token=token,
            user=UserPublic.model_validate(user),
        )

    # ── Google OAuth2 Login & Signup ──────────────────────────────────────────

    @staticmethod
    def get_google_auth_url(redirect_uri: Optional[str] = None) -> str:
        """
        Builds Google OAuth2 consent URL for recruiter login/signup.
        Requests openid, email, and profile scopes ONLY.
        Includes a signed state token to verify the callback and prevent CSRF.
        """
        import os
        import urllib.parse
        from app.core.config import settings
        from app.core.security import create_oauth_state

        client_id = settings.GOOGLE_CLIENT_ID or os.getenv("GOOGLE_CLIENT_ID")
        if not client_id or "placeholder" in client_id:
            raise ValueError("GOOGLE_CLIENT_ID is not configured on the server.")

        target_redirect_uri = (
            redirect_uri
            or os.getenv("GOOGLE_REDIRECT_URI")
            or settings.google_redirect_uri
            or os.getenv("GOOGLE_LOGIN_REDIRECT_URI")
            or settings.GOOGLE_LOGIN_REDIRECT_URI
            or "http://localhost:8000/auth/google/callback"
        ).rstrip("/")

        state = create_oauth_state(
            flow="login",
            extra={"redirect_uri": target_redirect_uri},
            expires_delta=timedelta(minutes=15),
        )

        params = {
            "client_id": client_id,
            "redirect_uri": target_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
            "state": state,
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

    @staticmethod
    def authenticate_google(
        session: Session,
        code: str,
        state: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> GoogleAuthResponse:
        """
        Exchanges Google auth code for tokens, verifies state and email,
        finds or creates the user account (never creates duplicates for the same email),
        inspects Setup Wizard completion status, and returns a signed JWT.
        """
        import os
        import secrets
        import httpx
        from app.core.config import settings
        from app.core.security import decode_oauth_state
        from app.models.onboarding import OnboardingSetup
        from app.routers.onboarding import _get_default_templates

        # Verify state if provided
        state_data = {}
        if state:
            try:
                state_data = decode_oauth_state(state)
                if state_data.get("flow") != "login":
                    raise ValueError("OAuth state flow mismatch: expected login flow.")
            except Exception as e:
                raise ValueError("Invalid or expired OAuth state parameter.")

        client_id = settings.GOOGLE_CLIENT_ID or os.getenv("GOOGLE_CLIENT_ID")
        client_secret = settings.GOOGLE_CLIENT_SECRET or os.getenv("GOOGLE_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError("Google OAuth credentials are not configured on the server. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")

        target_redirect_uri = (
            redirect_uri
            or (state_data.get("redirect_uri") if state_data else None)
            or os.getenv("GOOGLE_REDIRECT_URI")
            or settings.google_redirect_uri
            or os.getenv("GOOGLE_LOGIN_REDIRECT_URI")
            or settings.GOOGLE_LOGIN_REDIRECT_URI
            or "http://localhost:8000/auth/google/callback"
        ).rstrip("/")

        # 1. Exchange authorization code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        token_payload = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": target_redirect_uri,
            "grant_type": "authorization_code",
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                token_resp = client.post(token_url, data=token_payload)
                if token_resp.status_code != 200:
                    err_json = token_resp.json() if "application/json" in token_resp.headers.get("content-type", "") else {}
                    err_msg = err_json.get("error_description") or err_json.get("error") or token_resp.text
                    raise ValueError(f"Google token exchange failed: {err_msg}")

                tokens = token_resp.json()
                access_token_google = tokens.get("access_token")

                # 2. Fetch user profile from Google UserInfo
                userinfo_resp = client.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {access_token_google}"},
                )
                if userinfo_resp.status_code != 200:
                    raise ValueError("Failed to fetch Google user profile.")

                userinfo = userinfo_resp.json()
        except httpx.RequestError as exc:
            raise ValueError(f"Network error communicating with Google: {str(exc)}")

        email = userinfo.get("email")
        if not email:
            raise ValueError("Google account did not provide an email address.")

        email = email.lower().strip()
        name = userinfo.get("name")

        # 3. Check if user already exists (Never create duplicates for same email)
        user = AuthService.get_by_email(session, email)
        is_new_user = False
        if not user:
            is_new_user = True
            random_pw = secrets.token_urlsafe(32)
            user = User(
                email=email,
                hashed_password=hash_password(random_pw),
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            # Pre-initialize onboarding setup for the new user
            onboarding = OnboardingSetup(
                user_id=user.id,
                hr_name=name or "Recruiter",
                current_step=1,
                is_completed=False,
                agent_started=False,
                templates=_get_default_templates(hr_name=name or "Recruiting Team"),
            )
            session.add(onboarding)
            session.commit()

        # 4. Check if setup is completed
        onboarding = session.exec(select(OnboardingSetup).where(OnboardingSetup.user_id == user.id)).first()
        setup_completed = bool(
            onboarding
            and onboarding.step_1_completed
            and onboarding.step_2_completed
            and onboarding.step_3_completed
            and onboarding.step_4_completed
            and onboarding.is_completed
        )

        jwt_token = create_access_token(str(user.id))
        return GoogleAuthResponse(
            access_token=jwt_token,
            user=UserPublic.model_validate(user),
            setup_completed=setup_completed,
            is_new_user=is_new_user,
        )


auth_service = AuthService()

