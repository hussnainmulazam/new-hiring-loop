"""
app/core/security.py
~~~~~~~~~~~~~~~~~~~~
Password hashing (passlib/bcrypt) and JWT creation/verification (python-jose).
Everything in one place so routers and services have a single import target.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Union

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ── Password hashing ─────────────────────────────────────────────────────────
# bcrypt with auto-rehash enabled: if the work factor is raised in the future,
# passlib transparently re-hashes the password on the next successful login.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return _pwd_context.verify(plain, hashed)


# ── JWT ──────────────────────────────────────────────────────────────────────
def create_access_token(
    subject: Union[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """
    Encode a JWT access token.

    Parameters
    ----------
    subject:
        Value stored in the ``sub`` claim — typically the user's UUID as a str.
    expires_delta:
        How long the token is valid. Defaults to ``JWT_ACCESS_TOKEN_EXPIRE_MINUTES``.

    Returns
    -------
    str
        Signed JWT string.
    """
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {"sub": str(subject), "exp": expire}
    return jwt.encode(payload, settings.effective_jwt_secret, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.

    Raises
    ------
    jose.JWTError
        If the token is expired, malformed, or the signature is invalid.
    """
    return jwt.decode(
        token,
        settings.effective_jwt_secret,
        algorithms=[settings.JWT_ALGORITHM],
    )


def create_oauth_state(flow: str, extra: dict | None = None, expires_delta: timedelta | None = None) -> str:
    """
    Creates a signed JWT state token for OAuth flows to prevent CSRF
    and distinguish between login and workspace flows.
    """
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    payload = {"flow": flow, "exp": expire}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.effective_jwt_secret, algorithm=settings.JWT_ALGORITHM)


def decode_oauth_state(state: str) -> dict:
    """
    Decodes and validates a signed OAuth state token.
    Raises JWTError if invalid or expired.
    """
    return jwt.decode(
        state,
        settings.effective_jwt_secret,
        algorithms=[settings.JWT_ALGORITHM],
    )


