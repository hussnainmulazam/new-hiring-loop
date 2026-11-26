"""
Google OAuth2, Gmail Sync, and Email Sending Service.
Handles authorization code flow, Fernet refresh token encryption,
scope verification, rate-limited message fetching, attachment extraction,
Supabase storage upload, candidate ingestion, and sending emails via Gmail API.
"""
import base64
import email
from email.message import EmailMessage
import json
import logging
import os
import re
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlmodel import Session, select, func

from app.core.config import settings
from app.core.encryption import decrypt_token, encrypt_token
from app.core.document_parser import parse_cv_document
from app.core.security import (
    create_access_token,
    decode_access_token,
    create_oauth_state,
    decode_oauth_state,
)
from app.core.storage import save_candidate_cv_file
from app.models.candidate import Candidate, CandidateStage
from app.models.candidate_link import CandidateLink
from app.models.email_synced import EmailSynced
from app.models.google_account import GoogleAccount
from app.models.job_opening import JobOpening, JobOpeningStatus
from app.models.message import Message, MessageDirection, MessageType, MessageStatus
from app.schemas.google import (
    EmailSyncItemResult,
    GmailSyncResponse,
    GoogleAccountStatusResponse,
    GoogleAuthUrlResponse,
    GooglePreviewEmailRequest,
    GooglePreviewEmailResponse,
    GoogleSendEmailRequest,
    GoogleSendEmailResponse,
)
from app.services.audit_log_service import audit_log_service
from app.services.extractor_service import extract_all_deterministic_fields

logger = logging.getLogger(__name__)

# Required Google Workspace API Scopes (includes 8 core scopes plus Meet, Sheets, Docs, Drive)
WORKSPACE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.freebusy",
    "https://www.googleapis.com/auth/meetings.space.created",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive",
]
GOOGLE_SCOPES = WORKSPACE_SCOPES

DEFAULT_GMAIL_QUERY = "has:attachment (filename:pdf OR filename:docx) newer_than:30d"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


class GoogleService:
    def __init__(self, session: Session):
        self.session = session

    # ── 1. OAuth2 Authorization URL ──────────────────────────────────────────

    def generate_auth_url(self, user_id: uuid.UUID, redirect_uri: Optional[str] = None) -> GoogleAuthUrlResponse:
        """
        Builds Google OAuth2 consent screen URL with offline access
        and prompt=consent so a refresh token is guaranteed.
        Encodes user_id into a tamper-proof signed state token.
        """
        client_id = settings.GOOGLE_CLIENT_ID or "placeholder-google-client-id"
        target_redirect_uri = (
            redirect_uri
            or os.getenv("GOOGLE_REDIRECT_URI")
            or settings.google_redirect_uri
            or os.getenv("GOOGLE_WORKSPACE_REDIRECT_URI")
            or settings.GOOGLE_WORKSPACE_REDIRECT_URI
            or "http://localhost:8000/auth/google/callback"
        ).rstrip("/")

        # Signed state token: flow=workspace, encodes user_id and redirect_uri
        state = create_oauth_state(
            flow="workspace",
            extra={"user_id": str(user_id), "redirect_uri": target_redirect_uri},
            expires_delta=timedelta(minutes=30),
        )

        params = {
            "client_id": client_id,
            "redirect_uri": target_redirect_uri,
            "response_type": "code",
            "scope": " ".join(WORKSPACE_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
            "include_granted_scopes": "true",
        }

        auth_endpoint = settings.GOOGLE_AUTH_URI or GOOGLE_AUTH_URL
        auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        return GoogleAuthUrlResponse(auth_url=auth_url, state=state)

    # ── 2. Handle Callback & Token Exchange ──────────────────────────────────

    def handle_callback(
        self, code: str, state: str
    ) -> Tuple[GoogleAccount, uuid.UUID]:
        """
        Exchanges authorization code for tokens, encrypts the refresh token,
        fetches Google profile, and saves the GoogleAccount record.
        """
        # 1. Verify signed state token
        try:
            payload = decode_oauth_state(state)
        except Exception:
            raise ValueError("Invalid or expired OAuth state parameter.")

        user_id_raw = payload.get("user_id") or payload.get("sub")
        if not payload or not user_id_raw:
            raise ValueError("OAuth state parameter mismatch: expected workspace flow.")

        user_id = uuid.UUID(str(user_id_raw))

        client_id = settings.GOOGLE_CLIENT_ID
        client_secret = settings.GOOGLE_CLIENT_SECRET
        redirect_uri = (
            payload.get("redirect_uri")
            or os.getenv("GOOGLE_REDIRECT_URI")
            or settings.google_redirect_uri
            or os.getenv("GOOGLE_WORKSPACE_REDIRECT_URI")
            or settings.GOOGLE_WORKSPACE_REDIRECT_URI
            or "http://localhost:8000/auth/google/callback"
        ).rstrip("/")

        # 2. Exchange authorization code for tokens
        token_data: Dict[str, Any] = {}
        token_endpoint = settings.GOOGLE_TOKEN_URI or GOOGLE_TOKEN_URL

        if code.startswith("mock_") or code.startswith("test_"):
            # Mock / testing authorization code
            token_data = {
                "access_token": f"ya29.simulated_access_{uuid.uuid4().hex[:12]}",
                "refresh_token": f"1//simulated_refresh_{uuid.uuid4().hex[:16]}",
                "expires_in": 3600,
                "scope": " ".join(GOOGLE_SCOPES),
                "id_token": "simulated_id_token",
            }
        elif client_id and client_secret:
            try:
                with httpx.Client(timeout=15.0) as client:
                    resp = client.post(
                        token_endpoint,
                        data={
                            "code": code,
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "redirect_uri": redirect_uri,
                            "grant_type": "authorization_code",
                        },
                    )
                    if not resp.is_success:
                        logger.error("Google token exchange error: %s", resp.text)
                        raise ValueError(f"Google token exchange failed: {resp.text}")
                    token_data = resp.json()
            except httpx.HTTPError as exc:
                logger.error("HTTP error during Google token exchange: %s", exc)
                raise ValueError(f"Failed to communicate with Google OAuth: {exc}")
        else:
            token_data = {
                "access_token": f"ya29.simulated_access_{uuid.uuid4().hex[:12]}",
                "refresh_token": f"1//simulated_refresh_{uuid.uuid4().hex[:16]}",
                "expires_in": 3600,
                "scope": " ".join(GOOGLE_SCOPES),
                "id_token": "simulated_id_token",
            }

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        granted_scopes = (
            token_data.get("scope", "").split(" ")
            if token_data.get("scope")
            else GOOGLE_SCOPES
        )

        # 3. Fetch Google User Profile
        google_email = "recruiter@gmail.com"
        if not (code.startswith("mock_") or code.startswith("test_")) and access_token and client_id and client_secret:
            try:
                with httpx.Client(timeout=10.0) as client:
                    user_resp = client.get(
                        GOOGLE_USERINFO_URL,
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    if user_resp.is_success:
                        google_email = user_resp.json().get("email", google_email)
            except Exception as e:
                logger.warning("Could not fetch userinfo from Google: %s", e)

        # 4. Check granted scopes against required workspace scopes
        def _norm_scope(s: str) -> str:
            return s.lower().replace("https://www.googleapis.com/auth/", "").strip()

        granted_norms = {_norm_scope(s) for s in granted_scopes}
        missing_scopes = [req for req in WORKSPACE_SCOPES if _norm_scope(req) not in granted_norms]
        initial_status = "partial_access" if missing_scopes else "connected"

        # 5. Check if account already exists for user
        account = self.session.exec(
            select(GoogleAccount).where(GoogleAccount.user_id == user_id)
        ).first()

        encrypted_ref = encrypt_token(refresh_token) if refresh_token else ""

        if account:
            account.email = google_email
            if refresh_token:
                account.encrypted_refresh_token = encrypted_ref
            account.access_token = access_token
            account.token_expires_at = token_expires_at
            account.scopes = granted_scopes
            account.last_sync_status = initial_status
            account.updated_at = datetime.now(timezone.utc)
        else:
            if not refresh_token:
                encrypted_ref = encrypt_token(f"fallback_ref_{uuid.uuid4().hex}")

            account = GoogleAccount(
                user_id=user_id,
                email=google_email,
                encrypted_refresh_token=encrypted_ref,
                access_token=access_token,
                token_expires_at=token_expires_at,
                scopes=granted_scopes,
                sync_query=DEFAULT_GMAIL_QUERY,
                sync_label="INBOX",
                last_sync_status=initial_status,
            )
            self.session.add(account)

        self.session.commit()
        self.session.refresh(account)

        # Audit trail entry
        audit_log_service.record(
            session=self.session,
            user_id=user_id,
            action="google_connected",
            details=f"Connected Google account: {google_email} with offline access.",
        )

        return account, user_id

    # ── 3. Token Refresh (Decryption + OAuth2 Refresh) ────────────────────────

    def get_valid_access_token(self, account: GoogleAccount) -> str:
        """
        Ensures a fresh access token is available. If expired, decrypts
        the Fernet encrypted refresh token and calls Google OAuth token endpoint.
        """
        now = datetime.now(timezone.utc)
        if (
            account.access_token
            and account.token_expires_at
            and account.token_expires_at > now + timedelta(minutes=5)
        ):
            return account.access_token

        client_id = settings.GOOGLE_CLIENT_ID
        client_secret = settings.GOOGLE_CLIENT_SECRET
        if not client_id or not client_secret:
            return account.access_token or "simulated_access_token"

        # Decrypt refresh token
        try:
            plain_refresh = decrypt_token(account.encrypted_refresh_token)
        except Exception:
            plain_refresh = None

        if not plain_refresh:
            account.last_sync_status = "token_revoked"
            self.session.add(account)
            self.session.commit()
            raise ValueError("No valid refresh token found. Re-authentication required.")

        if "simulated" in plain_refresh or "mock" in plain_refresh:
            return account.access_token or f"ya29.simulated_access_{uuid.uuid4().hex[:12]}"

        token_endpoint = settings.GOOGLE_TOKEN_URI or GOOGLE_TOKEN_URL
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    token_endpoint,
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "refresh_token": plain_refresh,
                        "grant_type": "refresh_token",
                    },
                )
                if not resp.is_success:
                    logger.error("Token refresh failed: %s", resp.text)
                    err_msg = resp.text
                    if "invalid_grant" in err_msg or "revoked" in err_msg or "expired" in err_msg:
                        account.last_sync_status = "reconnect_required"
                        self.session.add(account)
                        self.session.commit()
                    raise ValueError(f"Failed to refresh Google access token: {resp.text}")

                data = resp.json()
                new_access_token = data["access_token"]
                expires_in = data.get("expires_in", 3600)
                account.access_token = new_access_token
                account.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                account.updated_at = datetime.now(timezone.utc)
                self.session.add(account)
                self.session.commit()
                return new_access_token
        except httpx.HTTPError as exc:
            logger.error("HTTP exception during token refresh: %s", exc)
            raise ValueError(f"Network error refreshing Google access token: {exc}")

    # ── 4. Account Status & Scope Verification ───────────────────────────────

    def get_status(self, user_id: uuid.UUID) -> GoogleAccountStatusResponse:
        account = self.session.exec(
            select(GoogleAccount).where(GoogleAccount.user_id == user_id)
        ).first()

        if not account:
            return GoogleAccountStatusResponse(
                is_connected=False,
                email=None,
                scopes=[],
                missing_scopes=[],
                reconnect_needed=False,
                reconnect_reason=None,
                last_synced_at=None,
                last_sync_status="never",
                sync_query=DEFAULT_GMAIL_QUERY,
                sync_label="INBOX",
                default_opening_id=None,
                default_opening_title=None,
                auto_reply_enabled=False,
                total_emails_synced=0,
            )

        total_synced = self.session.exec(
            select(func.count(EmailSynced.id)).where(EmailSynced.user_id == user_id)
        ).one() or 0

        # Synced from Gmail candidates count
        candidates = self.session.exec(
            select(Candidate).where(Candidate.user_id == user_id)
        ).all()
        synced_from_gmail_count = sum(
            1 for c in candidates
            if c.extracted_data and (
                c.extracted_data.get("source") == "gmail_sync"
                or c.extracted_data.get("gmail_message_id")
            )
        )

        # Recent sync results from emails_synced
        recent_synced_emails = self.session.exec(
            select(EmailSynced)
            .where(EmailSynced.user_id == user_id)
            .order_by(EmailSynced.synced_at.desc())
            .limit(10)
        ).all()

        openings_map = {
            op.id: op.title
            for op in self.session.exec(
                select(JobOpening).where(JobOpening.user_id == user_id)
            ).all()
        }

        recent_results: List[EmailSyncItemResult] = []
        for em in recent_synced_emails:
            matching_cand = next(
                (c for c in candidates if c.extracted_data and c.extracted_data.get("gmail_message_id") == em.message_id),
                None,
            )
            if not matching_cand and em.sender:
                sender_email = (
                    em.sender.split("<")[1].split(">")[0].strip().lower()
                    if "<" in em.sender
                    else em.sender.strip().lower()
                )
                matching_cand = next(
                    (c for c in candidates if c.email.lower() == sender_email),
                    None,
                )

            if matching_cand:
                op_title = openings_map.get(matching_cand.opening_id, "Assigned Opening")
                stage_val = matching_cand.stage.value if hasattr(matching_cand.stage, "value") else str(matching_cand.stage)
                status_str = "created"
                reason = f"Candidate in pipeline under stage '{stage_val}' for '{op_title}'."
                recent_results.append(
                    EmailSyncItemResult(
                        message_id=em.message_id,
                        sender=em.sender,
                        subject=em.subject,
                        status=status_str,
                        candidate_id=str(matching_cand.id),
                        candidate_name=matching_cand.name,
                        opening_title=op_title,
                        reason=reason,
                    )
                )
            else:
                recent_results.append(
                    EmailSyncItemResult(
                        message_id=em.message_id,
                        sender=em.sender,
                        subject=em.subject,
                        status="failed",
                        reason="No candidate profile created (no parseable resume attachment or text found).",
                    )
                )

        scopes_list: list[str] = []
        if isinstance(account.scopes, list):
            scopes_list = account.scopes
        elif isinstance(account.scopes, str):
            scopes_list = [s.strip() for s in account.scopes.split(",") if s.strip()]

        # Helper to normalize scope name for comparison
        def norm(s: str) -> str:
            return s.lower().replace("https://www.googleapis.com/auth/", "").strip()

        granted_norms = {norm(s) for s in scopes_list}
        missing_scopes: List[str] = []
        for req in WORKSPACE_SCOPES:
            if norm(req) not in granted_norms:
                missing_scopes.append(req)

        # Service-level grant detection for the required Workspace services
        granted_services = {
            "Gmail": any("gmail" in s for s in granted_norms),
            "Calendar": any("calendar" in s for s in granted_norms),
            "Meet": any("meetings" in s or "calendar" in s for s in granted_norms),
            "Sheets": any("spreadsheets" in s for s in granted_norms),
            "Docs": any("documents" in s for s in granted_norms),
            "Drive": any("drive" in s for s in granted_norms),
        }

        reconnect_needed = False
        reconnect_reason = None

        if account.last_sync_status in ("token_revoked", "reconnect_required"):
            reconnect_needed = True
            reconnect_reason = "Google OAuth refresh token has expired or was revoked. Please reconnect."
        elif not all(granted_services.values()) or missing_scopes:
            reconnect_needed = True
            reconnect_reason = "Missing required permissions. Please reconnect to grant all requested scopes."

        default_title: Optional[str] = None
        if account.default_opening_id:
            opening = self.session.exec(
                select(JobOpening).where(JobOpening.id == account.default_opening_id)
            ).first()
            if opening:
                default_title = opening.title

        return GoogleAccountStatusResponse(
            is_connected=True,
            email=account.email,
            scopes=scopes_list,
            missing_scopes=missing_scopes,
            granted_services=granted_services,
            reconnect_needed=reconnect_needed,
            reconnect_reason=reconnect_reason,
            last_synced_at=account.last_synced_at,
            last_sync_status=account.last_sync_status,
            sync_query=account.sync_query or DEFAULT_GMAIL_QUERY,
            sync_label=account.sync_label or "INBOX",
            auto_reply_enabled=getattr(account, "auto_reply_enabled", True),
            default_opening_id=account.default_opening_id,
            default_opening_title=default_title,
            total_emails_synced=total_synced,
            synced_from_gmail_count=synced_from_gmail_count,
            recent_sync_results=recent_results,
        )

    def disconnect(self, user_id: uuid.UUID) -> None:
        account = self.session.exec(
            select(GoogleAccount).where(GoogleAccount.user_id == user_id)
        ).first()

        if not account:
            return

        user_email = account.email

        # Attempt to revoke token at Google
        try:
            plain_refresh = decrypt_token(account.encrypted_refresh_token)
            if plain_refresh and "simulated" not in plain_refresh:
                with httpx.Client(timeout=5.0) as client:
                    client.post(GOOGLE_REVOKE_URL, params={"token": plain_refresh})
        except Exception as e:
            logger.warning("Google revoke call warning: %s", e)

        self.session.delete(account)
        self.session.commit()

        # Audit trail entry
        audit_log_service.record(
            session=self.session,
            user_id=user_id,
            action="google_disconnected",
            details=f"Disconnected Google account: {user_email}.",
        )

    # ── 5. Supabase Storage Upload Helper ────────────────────────────────────

    def _upload_to_supabase_storage(
        self, filename: str, file_bytes: bytes, mime_type: str = "application/pdf"
    ) -> str:
        """
        Uploads file to storage bucket using shared storage helper.
        """
        return save_candidate_cv_file(filename, file_bytes, mime_type)

    # ── 6. Gmail Sync Job with Rate-Limit & Backoff Handling ─────────────────

    def sync_gmail(
        self,
        user_id: uuid.UUID,
        override_query: Optional[str] = None,
        override_label: Optional[str] = None,
        query: Optional[str] = None,
        label: Optional[str] = None,
    ) -> GmailSyncResponse:
        """
        Incremental Gmail sync job:
          1. Fetches candidate emails with PDF/DOCX attachments matching HR query.
          2. Skips messages recorded in emails_synced to avoid duplicates.
          3. Handles rate limiting (HTTP 429 / 503) with exponential backoff.
          4. Saves resume attachments to Supabase Storage.
          5. Runs document parsing (PDF/DOCX/OCR) + deterministic extraction pipeline.
          6. Matches job opening by subject or uses default opening.
          7. Creates/updates Candidate profiles and records in audit trail.
        """
        account = self.session.exec(
            select(GoogleAccount).where(GoogleAccount.user_id == user_id)
        ).first()

        if not account:
            raise ValueError("No Google account connected. Please connect Google first.")

        query = query or override_query or account.sync_query or DEFAULT_GMAIL_QUERY
        label = label or override_label or account.sync_label
        account.last_sync_status = "in_progress"
        self.session.add(account)
        self.session.commit()

        # Pre-fetch user's job openings for subject matching
        all_openings = self.session.exec(
            select(JobOpening)
            .where(JobOpening.user_id == user_id)
            .order_by(JobOpening.created_at.desc())
        ).all()

        # Default opening fallback
        default_opening = None
        if account.default_opening_id:
            default_opening = self.session.exec(
                select(JobOpening).where(
                    JobOpening.id == account.default_opening_id,
                    JobOpening.user_id == user_id,
                )
            ).first()

        if not default_opening and all_openings:
            default_opening = all_openings[0]

        # Auto-create default opening if none exists so incoming resumes can always land in an opening
        if not default_opening:
            default_opening = JobOpening(
                user_id=user_id,
                title="General Applications",
                description="Default requisition for incoming resumes received via Gmail sync without an explicit job opening match.",
                status=JobOpeningStatus.active,
            )
            self.session.add(default_opening)
            self.session.commit()
            self.session.refresh(default_opening)
            all_openings = [default_opening]
            account.default_opening_id = default_opening.id
            self.session.add(account)
            self.session.commit()

        errors: List[str] = []
        results: List[EmailSyncItemResult] = []
        messages_found = 0
        messages_processed = 0
        attachments_saved = 0
        candidates_created = 0

        try:
            access_token = self.get_valid_access_token(account)
        except Exception as e:
            account.last_sync_status = "token_revoked" if "revoked" in str(e).lower() else "failed"
            self.session.add(account)
            self.session.commit()
            raise ValueError(f"Authentication error: {e}")

        # Check existing synced message IDs for incremental deduplication
        existing_synced_ids = set(
            self.session.exec(
                select(EmailSynced.message_id).where(EmailSynced.user_id == user_id)
            ).all()
        )

        # Fetch message IDs from Gmail API with exponential backoff
        message_summaries: List[Dict[str, Any]] = []
        if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET and not access_token.startswith("ya29.simulated"):
            # Include recent candidate replies & sent emails as well as resumes
            effective_query = query
            if "has:attachment" in effective_query:
                effective_query = f"({effective_query}) OR newer_than:30d"
            params = {"q": effective_query, "maxResults": 50}
            if label and label.upper() != "ALL":
                params["labelIds"] = label

            headers = {"Authorization": f"Bearer {access_token}"}
            backoff = 1.0

            for attempt in range(4):
                try:
                    with httpx.Client(timeout=20.0) as client:
                        resp = client.get(
                            f"{GMAIL_API_BASE}/messages",
                            headers=headers,
                            params=params,
                        )
                        if resp.status_code in (429, 503):
                            logger.warning("Gmail API rate limit hit. Backing off %ss...", backoff)
                            time.sleep(backoff)
                            backoff = min(backoff * 2, 8.0)
                            continue
                        if not resp.is_success:
                            errors.append(f"Gmail search failed: {resp.text}")
                            break

                        data = resp.json()
                        message_summaries = data.get("messages", [])
                        break
                except Exception as exc:
                    errors.append(f"Network error on search: {exc}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 8.0)
        else:
            message_summaries = []

        messages_found = len(message_summaries)

        # Pre-fetch candidate & message mappings for user to match threads & prevent duplicates
        openings_map = {op.id: op.title for op in all_openings}
        all_user_candidates = self.session.exec(
            select(Candidate).where(Candidate.user_id == user_id)
        ).all()
        cand_email_map: Dict[str, Candidate] = {
            c.email.lower(): c for c in all_user_candidates if c.email
        }

        user_messages = self.session.exec(
            select(Message).where(Message.user_id == user_id)
        ).all()
        existing_msg_google_ids = set()
        thread_cand_map: Dict[str, Candidate] = {}
        for m in user_messages:
            if m.whatsapp_message_id:
                existing_msg_google_ids.add(m.whatsapp_message_id)
            t_id = (m.template_variables or {}).get("thread_id")
            if t_id and m.candidate_id:
                cand_match = next((c for c in all_user_candidates if c.id == m.candidate_id), None)
                if cand_match:
                    thread_cand_map[t_id] = cand_match
            gid = (m.template_variables or {}).get("google_message_id")
            if gid:
                existing_msg_google_ids.add(gid)

        # Process each message
        for msg_summary in message_summaries:
            msg_id = msg_summary.get("id")
            if not msg_id:
                continue

            # Skip if this message is already recorded in the candidate conversation
            if msg_id in existing_msg_google_ids:
                continue

            # Fetch full message details with rate-limit retry
            msg_data: Optional[Dict[str, Any]] = None
            for attempt in range(3):
                try:
                    with httpx.Client(timeout=25.0) as client:
                        detail_resp = client.get(
                            f"{GMAIL_API_BASE}/messages/{msg_id}",
                            headers={"Authorization": f"Bearer {access_token}"},
                        )
                        if detail_resp.status_code in (429, 503):
                            time.sleep(2.0 ** attempt)
                            continue
                        if detail_resp.is_success:
                            msg_data = detail_resp.json()
                        else:
                            errors.append(f"Message {msg_id}: fetch failed with {detail_resp.status_code}")
                        break
                except Exception as exc:
                    time.sleep(1.0)
                    if attempt == 2:
                        errors.append(f"Message {msg_id}: network error {exc}")

            if not msg_data:
                continue

            # Parse headers
            payload = msg_data.get("payload", {})
            headers_list = payload.get("headers", [])
            header_map = {h.get("name", "").lower(): h.get("value", "") for h in headers_list}

            sender = header_map.get("from", "Unknown Candidate")
            to_header = header_map.get("to", "")
            subject = header_map.get("subject", "Resume Submission")
            snippet = msg_data.get("snippet", "")
            thread_id = msg_data.get("threadId")

            def extract_clean_email(raw: str) -> str:
                if not raw:
                    return ""
                if "<" in raw and ">" in raw:
                    return raw.split("<")[1].split(">")[0].strip().lower()
                return raw.strip().lower()

            sender_email = extract_clean_email(sender)
            account_email = extract_clean_email(account.email)
            is_outbound = bool(account_email and sender_email == account_email)

            recipients = [
                extract_clean_email(p)
                for p in to_header.split(",")
                if extract_clean_email(p)
            ]

            # Internal timestamp from Gmail
            internal_date_ms = msg_data.get("internalDate")
            if internal_date_ms:
                try:
                    msg_datetime = datetime.fromtimestamp(int(internal_date_ms) / 1000.0, tz=timezone.utc)
                except Exception:
                    msg_datetime = datetime.now(timezone.utc)
            else:
                msg_datetime = datetime.now(timezone.utc)

            # Match opening by email subject vs existing opening titles
            matched_opening = None
            subject_lower = subject.lower()
            for op in all_openings:
                if op.title and op.title.lower() in subject_lower:
                    matched_opening = op
                    break
                title_words = [w for w in re.split(r"\W+", op.title.lower()) if len(w) > 3]
                if title_words and all(w in subject_lower for w in title_words[:2]):
                    matched_opening = op
                    break

            target_opening = matched_opening or default_opening

            # Extract attachments & body text
            attachment_names: List[str] = []
            attachment_urls: List[str] = []
            extracted_text = ""
            best_att_bytes: Optional[bytes] = None
            best_filename: Optional[str] = None
            body_text_parts: List[str] = []

            def collect_parts(p: dict) -> list[dict]:
                parts = []
                if "parts" in p:
                    for sub in p["parts"]:
                        parts.extend(collect_parts(sub))
                else:
                    parts.append(p)
                return parts

            all_parts = collect_parts(payload)

            for part in all_parts:
                filename = part.get("filename", "")
                body = part.get("body", {})
                att_id = body.get("attachmentId")
                mime_type = part.get("mimeType", "").lower()
                lower_name = filename.lower()

                if lower_name.endswith(".pdf") or lower_name.endswith(".docx"):
                    att_bytes: Optional[bytes] = None
                    try:
                        if att_id:
                            with httpx.Client(timeout=30.0) as client:
                                att_resp = client.get(
                                    f"{GMAIL_API_BASE}/messages/{msg_id}/attachments/{att_id}",
                                    headers={"Authorization": f"Bearer {access_token}"},
                                )
                                if att_resp.is_success:
                                    raw_base64 = att_resp.json().get("data", "")
                                    att_bytes = base64.urlsafe_b64decode(raw_base64)
                                else:
                                    errors.append(f"Message {msg_id}: attachment {filename} fetch returned {att_resp.status_code}")
                        elif body.get("data"):
                            att_bytes = base64.urlsafe_b64decode(body.get("data", ""))
                    except Exception as e:
                        errors.append(f"Message {msg_id}: failed to download {filename}: {e}")

                    if att_bytes:
                        mime = (
                            "application/pdf"
                            if lower_name.endswith(".pdf")
                            else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        )
                        storage_url = self._upload_to_supabase_storage(filename, att_bytes, mime)
                        attachment_names.append(filename)
                        attachment_urls.append(storage_url)
                        attachments_saved += 1

                        if not extracted_text:
                            best_att_bytes = att_bytes
                            best_filename = filename
                            try:
                                extracted_text = parse_cv_document(att_bytes, filename=filename)
                            except Exception as parse_err:
                                errors.append(f"Message {msg_id}: text extraction failed for {filename}: {parse_err}")

                elif mime_type == "text/plain" and body.get("data"):
                    try:
                        decoded_text = base64.urlsafe_b64decode(body.get("data", "")).decode("utf-8", errors="ignore")
                        unquoted_lines = [l for l in decoded_text.splitlines() if not l.strip().startswith(">")]
                        unquoted = "\n".join(unquoted_lines).strip()
                        if unquoted:
                            body_text_parts.append(unquoted)
                        elif decoded_text.strip():
                            body_text_parts.append(decoded_text.strip())
                    except Exception:
                        pass
                elif mime_type == "text/html" and body.get("data") and not body_text_parts:
                    try:
                        decoded_html = base64.urlsafe_b64decode(body.get("data", "")).decode("utf-8", errors="ignore")
                        clean_text = re.sub(r"<[^>]+>", " ", decoded_html)
                        clean_text = re.sub(r"\s+", " ", clean_text).strip()
                        if clean_text:
                            body_text_parts.append(clean_text)
                    except Exception:
                        pass

            message_body = ""
            if body_text_parts:
                message_body = body_text_parts[0]
            elif snippet:
                message_body = snippet.strip()
            elif extracted_text:
                message_body = extracted_text[:300]

            # ── CANDIDATE MATCHING ──
            matched_candidate: Optional[Candidate] = None

            # 1. Match by thread_id if known
            if thread_id and thread_id in thread_cand_map:
                matched_candidate = thread_cand_map[thread_id]

            # 2. Match by email
            if not matched_candidate:
                if is_outbound:
                    for recip in recipients:
                        if recip in cand_email_map:
                            matched_candidate = cand_email_map[recip]
                            break
                else:
                    if sender_email and sender_email in cand_email_map:
                        matched_candidate = cand_email_map[sender_email]

            target_opening_title = (
                openings_map.get(matched_candidate.opening_id, "Candidate Opening")
                if matched_candidate
                else (target_opening.title if target_opening else "General Applications")
            )

            # ── IF MATCHED TO AN EXISTING CANDIDATE: SYNC TO CONVERSATION THREAD ──
            if matched_candidate:
                if thread_id:
                    thread_cand_map[thread_id] = matched_candidate

                msg_row = Message(
                    candidate_id=matched_candidate.id,
                    user_id=user_id,
                    direction=MessageDirection.outbound if is_outbound else MessageDirection.inbound,
                    channel="email",
                    message_type=MessageType.email,
                    body=message_body or (snippet or "Email message."),
                    status=MessageStatus.sent if is_outbound else MessageStatus.delivered,
                    sent_at=msg_datetime,
                    delivered_at=msg_datetime if not is_outbound else None,
                    created_at=msg_datetime,
                    template_name="recruiter_email" if is_outbound else "candidate_email_reply",
                    template_variables={
                        "subject": subject,
                        "thread_id": thread_id,
                        "google_message_id": msg_id,
                        "attachments": [
                            {"filename": fn, "url": u}
                            for fn, u in zip(attachment_names, attachment_urls)
                        ],
                    },
                    whatsapp_message_id=msg_id,
                )
                self.session.add(msg_row)
                existing_msg_google_ids.add(msg_id)

                if not is_outbound:
                    matched_candidate.last_inbound_whatsapp_at = msg_datetime
                    matched_candidate.updated_at = datetime.now(timezone.utc)
                    self.session.add(matched_candidate)

                    # Update candidate lifecycle stage & audit log
                    try:
                        from app.services.outreach_service import outreach_service
                        outreach_service.handle_candidate_reply(
                            session=self.session,
                            candidate_id=matched_candidate.id,
                            reply_snippet=message_body or snippet or "",
                        )
                    except Exception as reply_err:
                        logger.warning("Could not handle candidate reply stage transition: %s", reply_err)

                    # Instant alert to HR
                    try:
                        from app.services.agent_settings_service import agent_settings_service
                        agent_settings_service.notify_hr_instant(
                            session=self.session,
                            user_id=user_id,
                            event_type="reply",
                            candidate_name=matched_candidate.name,
                            opening_title=target_opening_title,
                            details=f"Subject: {subject}\n\n{message_body[:400]}",
                        )
                    except Exception as alert_err:
                        logger.warning("Could not send instant reply alert to HR: %s", alert_err)

                    # Candidate response analysis & agent email share/draft
                    try:
                        self.handle_agent_reply_automation(
                            user_id=user_id,
                            account=account,
                            candidate=matched_candidate,
                            subject=subject,
                            message_body=message_body or snippet or "",
                            thread_id=thread_id,
                            opening_title=target_opening_title,
                        )
                    except Exception as auto_err:
                        logger.warning("Candidate reply automation failed: %s", auto_err)

                # Record in emails_synced
                if msg_id not in existing_synced_ids:
                    email_synced = EmailSynced(
                        user_id=user_id,
                        google_account_id=account.id,
                        message_id=msg_id,
                        thread_id=thread_id,
                        sender=sender,
                        subject=subject,
                        snippet=snippet,
                        attachment_names=attachment_names,
                        attachment_urls=attachment_urls,
                    )
                    self.session.add(email_synced)
                    existing_synced_ids.add(msg_id)

                messages_processed += 1
                results.append(
                    EmailSyncItemResult(
                        message_id=msg_id,
                        sender=sender,
                        subject=subject,
                        status="created",
                        candidate_id=str(matched_candidate.id),
                        candidate_name=matched_candidate.name,
                        opening_title=target_opening_title,
                        reason=f"{'Sent email' if is_outbound else 'Candidate reply'} synced into conversation thread.",
                    )
                )
                continue

            # ── IF OUTBOUND AND NOT MATCHED: SKIP (Recruiter personal / non-candidate email) ──
            if is_outbound:
                continue

            # ── IF INBOUND AND NOT MATCHED: ATTEMPT NEW CANDIDATE INGESTION ──
            if not attachment_names and len(extracted_text.strip()) < 50:
                continue

            if msg_id not in existing_synced_ids:
                email_synced = EmailSynced(
                    user_id=user_id,
                    google_account_id=account.id,
                    message_id=msg_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    snippet=snippet,
                    attachment_names=attachment_names,
                    attachment_urls=attachment_urls,
                )
                self.session.add(email_synced)
                existing_synced_ids.add(msg_id)
            messages_processed += 1

            # Ingest candidate using deterministic extraction pipeline
            try:
                det = extract_all_deterministic_fields(extracted_text)
                cand_data = det.get("extracted_data")

                parsed_name = sender.split("<")[0].strip().strip('"') if "<" in sender else sender
                final_name = cand_data.name if (cand_data and cand_data.name) else parsed_name or "Applicant"

                parsed_email = sender_email or f"applicant_{uuid.uuid4().hex[:6]}@gmail.com"
                final_email = cand_data.email if (cand_data and cand_data.email) else parsed_email

                existing_cand = cand_email_map.get(final_email.lower())
                if existing_cand:
                    continue

                new_candidate = Candidate(
                    user_id=user_id,
                    opening_id=target_opening.id,
                    name=final_name,
                    email=final_email.lower(),
                    phone=cand_data.phone if cand_data else None,
                    address=cand_data.address if cand_data else None,
                    github_url=cand_data.github_url if cand_data else None,
                    linkedin_url=cand_data.linkedin_url if cand_data else None,
                    portfolio_url=cand_data.portfolio_url if cand_data else None,
                    kaggle_url=cand_data.kaggle_url if cand_data else None,
                    cv_text=extracted_text,
                    cv_file_url=attachment_urls[0] if attachment_urls else None,
                    stage=CandidateStage.applied,
                    extracted_data={
                        "source": "gmail_sync",
                        "gmail_message_id": msg_id,
                        "gmail_subject": subject,
                        "gmail_sender": sender,
                        "current_title": cand_data.current_title if cand_data else None,
                        "years_of_experience": cand_data.years_of_experience if cand_data else None,
                        "top_skills": cand_data.top_skills if cand_data else [],
                        "education": cand_data.education if cand_data else None,
                    } if cand_data else {
                        "source": "gmail_sync",
                        "gmail_message_id": msg_id,
                        "gmail_subject": subject,
                        "gmail_sender": sender,
                    },
                )
                self.session.add(new_candidate)
                self.session.flush()

                cand_email_map[new_candidate.email.lower()] = new_candidate
                if thread_id:
                    thread_cand_map[thread_id] = new_candidate

                initial_msg = Message(
                    candidate_id=new_candidate.id,
                    user_id=user_id,
                    direction=MessageDirection.inbound,
                    channel="email",
                    message_type=MessageType.email,
                    body=(body_text_parts[0] if body_text_parts else snippet) or f"Hello, please find attached my resume for the {target_opening_title} position.\n\nLooking forward to speaking with you.\n\nBest regards,\n{new_candidate.name}",
                    status=MessageStatus.delivered,
                    sent_at=msg_datetime,
                    delivered_at=msg_datetime,
                    created_at=msg_datetime,
                    template_name="application_submission",
                    template_variables={
                        "subject": subject,
                        "thread_id": thread_id,
                        "google_message_id": msg_id,
                        "attachments": [
                            {"filename": fn, "url": u}
                            for fn, u in zip(attachment_names, attachment_urls)
                        ],
                    },
                    whatsapp_message_id=msg_id,
                )
                self.session.add(initial_msg)
                existing_msg_google_ids.add(msg_id)

                if cand_data:
                    for l_type, l_url in [
                        ("github", cand_data.github_url),
                        ("linkedin", cand_data.linkedin_url),
                        ("portfolio", cand_data.portfolio_url),
                        ("kaggle", cand_data.kaggle_url),
                    ]:
                        if l_url:
                            link_row = CandidateLink(
                                candidate_id=new_candidate.id,
                                user_id=user_id,
                                link_type=l_type,
                                url=l_url,
                                is_verified=True,
                            )
                            self.session.add(link_row)

                candidates_created += 1

                audit_log_service.record(
                    session=self.session,
                    user_id=user_id,
                    action="candidate_created",
                    candidate_id=new_candidate.id,
                    opening_id=target_opening.id,
                    to_stage="applied",
                    details=f"Candidate {new_candidate.name} ingested from Gmail message '{subject}'.",
                )

                try:
                    from app.services.candidate_service import candidate_service
                    candidate_service.auto_handle_candidate_received(self.session, user_id, new_candidate)
                except Exception as auto_flow_err:
                    logger.warning("Auto scoring / auto email failed for %s: %s", new_candidate.id, auto_flow_err)

                results.append(
                    EmailSyncItemResult(
                        message_id=msg_id,
                        sender=sender,
                        subject=subject,
                        status="created",
                        candidate_id=str(new_candidate.id),
                        candidate_name=new_candidate.name,
                        opening_title=target_opening_title,
                        reason=f"Candidate profile created in pipeline under stage 'Applied' for opening '{target_opening_title}'.",
                    )
                )
            except Exception as ingest_err:
                self.session.rollback()
                err_text = f"Candidate ingestion error: {ingest_err}"
                logger.exception(err_text)
                errors.append(f"Message {msg_id}: {err_text}")
                results.append(
                    EmailSyncItemResult(
                        message_id=msg_id,
                        sender=sender,
                        subject=subject,
                        status="failed",
                        opening_title=target_opening_title,
                        reason=err_text,
                    )
                )

        now = datetime.now(timezone.utc)
        account.last_synced_at = now
        account.last_sync_status = "success" if not errors else ("partial" if messages_processed > 0 else "failed")
        self.session.add(account)
        self.session.commit()

        # Audit trail for Gmail sync completion
        audit_log_service.record(
            session=self.session,
            user_id=user_id,
            action="gmail_synced",
            details=(
                f"Gmail sync completed: {messages_processed}/{messages_found} messages processed, "
                f"{attachments_saved} resumes stored, {candidates_created} candidates ingested, "
                f"{len(errors)} warnings."
            ),
        )

        all_user_candidates = self.session.exec(
            select(Candidate).where(Candidate.user_id == user_id)
        ).all()
        synced_from_gmail_count = sum(
            1 for c in all_user_candidates
            if c.extracted_data and (
                c.extracted_data.get("source") == "gmail_sync"
                or c.extracted_data.get("gmail_message_id")
            )
        )

        return GmailSyncResponse(
            status=account.last_sync_status,
            messages_found=messages_found,
            messages_processed=messages_processed,
            attachments_saved=attachments_saved,
            candidates_created=candidates_created,
            synced_from_gmail_count=synced_from_gmail_count,
            results=results,
            errors=errors,
            last_synced_at=now,
        )

    # ── 6.5. Inbound Candidate Reply Analysis & Agent Dispatch ───────────────

    def handle_agent_reply_automation(
        self,
        user_id: uuid.UUID,
        account: GoogleAccount,
        candidate: Candidate,
        subject: str,
        message_body: str,
        thread_id: Optional[str] = None,
        opening_title: Optional[str] = None,
    ) -> None:
        """
        Analyzes inbound candidate email response, detects candidate intent,
        selects the corresponding HR template, and either auto-dispatches (if auto_reply_enabled)
        or creates a pending AI draft in Message for recruiter 1-click review.
        """
        lower_body = (message_body or "").lower()
        role = opening_title or "the position"
        cand_name = candidate.name.split()[0] if candidate.name else "there"
        clean_sub = subject.replace("Re:", "").replace("RE:", "").strip() if subject else f"Application for {role}"
        reply_subject = f"Re: {clean_sub}"

        # 1. Offer Acceptance
        if any(w in lower_body for w in ["accept the offer", "thrilled to accept", "look forward to joining", "happy to accept", "signed the offer"]):
            template_key = "offer_accepted_confirmation"
            reply_body = (
                f"Hi {cand_name},\n\n"
                f"We are thrilled that you have accepted our offer for {role}! "
                f"Our team is currently preparing your welcome and onboarding package. "
                f"We will share all starting details shortly.\n\n"
                f"Welcome aboard!\nBest regards,\nTalent Acquisition Team"
            )
        # 2. Offer Declined
        elif any(w in lower_body for w in ["decline the offer", "pursue another", "decided to reject", "withdrawing my acceptance"]):
            template_key = "offer_declined_acknowledgement"
            reply_body = (
                f"Hi {cand_name},\n\n"
                f"Thank you for letting us know. We appreciate your consideration and wish you all the best in your career.\n\n"
                f"Best regards,\nTalent Acquisition Team"
            )
        # 3. Reschedule / Conflict
        elif any(w in lower_body for w in ["reschedule", "can't make it", "conflict", "different time", "postpone", "cancel my slot"]):
            template_key = "alternate_slots"
            booking_link = f"{settings.FRONTEND_URL.rstrip('/')}/schedule/{candidate.id}"
            reply_body = (
                f"Hi {cand_name},\n\n"
                f"No problem at all! Please choose an alternative time that works best for your schedule here:\n"
                f"{booking_link}\n\n"
                f"Looking forward to speaking with you!\nBest regards,\nTalent Acquisition Team"
            )
        # 4. Availability / Agreement to meet
        elif any(w in lower_body for w in ["available", "monday", "tuesday", "wednesday", "thursday", "friday", "pm", "am", "works for me", "sounds good", "confirm"]):
            template_key = "interview_confirmed"
            reply_body = (
                f"Hi {cand_name},\n\n"
                f"Thank you for confirming your availability for {role}! "
                f"We have noted your preferred time and are finalizing the calendar invitation. "
                f"You will receive a Google Calendar invite with the video meeting link shortly.\n\n"
                f"Best regards,\nTalent Acquisition Team"
            )
        # 5. General follow-up / question
        else:
            template_key = "candidate_followup"
            reply_body = (
                f"Hi {cand_name},\n\n"
                f"Thank you for your update regarding the {role} position. "
                f"We have received your message and our team will get back to you shortly.\n\n"
                f"Best regards,\nTalent Acquisition Team"
            )

        now = datetime.now(timezone.utc)

        if account.auto_reply_enabled:
            # Auto-dispatch email via Gmail API
            try:
                self.send_email(
                    user_id=user_id,
                    request=GoogleSendEmailRequest(
                        candidate_id=candidate.id,
                        subject=reply_subject,
                        body=reply_body,
                        template_name=template_key,
                        thread_id=thread_id,
                    ),
                )
                logger.info("Agent auto-dispatched '%s' reply to %s", template_key, candidate.email)
            except Exception as send_err:
                logger.error("Failed to auto-dispatch agent reply: %s", send_err)
        else:
            # Create pending AI draft message in DB for recruiter approval
            draft_msg = Message(
                candidate_id=candidate.id,
                user_id=user_id,
                direction=MessageDirection.outbound,
                channel="email",
                message_type=MessageType.email,
                body=reply_body,
                status=MessageStatus.pending,
                created_at=now,
                template_name=template_key,
                template_variables={
                    "subject": reply_subject,
                    "thread_id": thread_id,
                    "ai_agent_generated": True,
                    "intent": template_key,
                },
            )
            self.session.add(draft_msg)
            self.session.commit()

            audit_log_service.record(
                session=self.session,
                user_id=user_id,
                candidate_id=candidate.id,
                opening_id=candidate.opening_id,
                action="agent_reply_drafted",
                details=json.dumps({"intent": template_key, "subject": reply_subject}),
            )
            logger.info("Agent drafted '%s' reply for candidate %s pending recruiter approval", template_key, candidate.email)

    # ── 7. Email Templates & Preview ─────────────────────────────────────────

    def preview_email(
        self, user_id: uuid.UUID, request: GooglePreviewEmailRequest
    ) -> GooglePreviewEmailResponse:
        """
        Renders template variables and produces a preview of the candidate email.
        """
        candidate = self.session.exec(
            select(Candidate).where(
                Candidate.id == request.candidate_id,
                Candidate.user_id == user_id,
            )
        ).first()

        if not candidate:
            raise ValueError(f"Candidate '{request.candidate_id}' not found.")

        opening = None
        if candidate.opening_id:
            opening = self.session.exec(
                select(JobOpening).where(JobOpening.id == candidate.opening_id)
            ).first()

        role_name = opening.title if opening else "Position"
        company_name = request.company_name or "Talent Corp"
        slot_link = request.slot_link or f"{settings.FRONTEND_URL}/schedule/{candidate.id}"

        variables = {
            "candidate_name": candidate.name,
            "role": role_name,
            "company": company_name,
            "slot_link": slot_link,
        }

        # Resolve template from database (single source of truth)
        from app.services.template_service import render_user_template, fill_template_variables
        tmpl = request.template_name.lower()
        if tmpl in ("custom", ""):
            subject = request.custom_subject or f"Regarding your application for {role_name}"
            body = request.custom_body or f"Regarding your application for {role_name} at {company_name}."
            subject = fill_template_variables(subject, variables)
            body = fill_template_variables(body, variables)
        else:
            subject, html_body, body, _ = render_user_template(
                session=self.session,
                user_id=user_id,
                template_id=tmpl,
                context=variables,
            )

        return GooglePreviewEmailResponse(
            candidate_id=candidate.id,
            candidate_name=candidate.name,
            candidate_email=candidate.email,
            recipient_email=candidate.email,
            subject=subject,
            body=body,
            variables=variables,
        )

    # ── 8. Send Email via Gmail API (gmail.send) ─────────────────────────────

    def send_email(
        self, user_id: uuid.UUID, request: GoogleSendEmailRequest
    ) -> GoogleSendEmailResponse:
        """
        Sends an email from the recruiter's connected Google account via Gmail API (gmail.send).
        Saves the message in the messages table and logs to the audit trail.
        """
        account = self.session.exec(
            select(GoogleAccount).where(GoogleAccount.user_id == user_id)
        ).first()

        if not account:
            raise ValueError("No Google account connected. Please connect Google first.")

        # Check for gmail.send scope
        scopes_list = account.scopes if isinstance(account.scopes, list) else []
        norm_scopes = [s.lower().replace("https://www.googleapis.com/auth/", "").strip() for s in scopes_list]
        if "gmail.send" not in norm_scopes:
            raise ValueError(
                "Missing required permission 'gmail.send'. "
                "Please reconnect your Google account in Settings to grant email sending permissions."
            )

        candidate = self.session.exec(
            select(Candidate).where(
                Candidate.id == request.candidate_id,
                Candidate.user_id == user_id,
            )
        ).first()

        if not candidate:
            raise ValueError(f"Candidate '{request.candidate_id}' not found.")

        if not candidate.email or "@" not in candidate.email or candidate.email.endswith("@no-email.com"):
            raise ValueError(f"Candidate '{candidate.name}' does not have a valid recipient email address.")

        # 1. Normalize candidate name in DB if in ALL-CAPS
        try:
            from app.services.template_service import normalize_candidate_name
            full_cand, _ = normalize_candidate_name(candidate.name)
            if candidate.name and candidate.name.isupper() and full_cand:
                candidate.name = full_cand
                self.session.add(candidate)
                self.session.commit()
        except Exception as norm_err:
            logger.debug("Candidate name normalization note: %s", norm_err)

        # 2. Idempotency Guard (Requirement 5): Never send the same template twice per candidate per stage
        tmpl_key = (request.template_name or "").strip()
        force_send = getattr(request, "force_resend", False)
        if tmpl_key and not force_send and tmpl_key != "custom":
            existing_sent = self.session.exec(
                select(Message).where(
                    Message.candidate_id == candidate.id,
                    Message.user_id == user_id,
                    Message.template_name == tmpl_key,
                    Message.status == MessageStatus.sent,
                )
            ).first()
            if existing_sent:
                logger.info(
                    "Idempotency guard: template '%s' already sent to candidate %s. Skipping duplicate.",
                    tmpl_key,
                    candidate.email,
                )
                return GoogleSendEmailResponse(
                    message_id=existing_sent.id,
                    candidate_id=candidate.id,
                    recipient_email=candidate.email,
                    subject=request.subject,
                    status="skipped_idempotent",
                    google_message_id=existing_sent.whatsapp_message_id,
                    sent_at=existing_sent.sent_at or datetime.now(timezone.utc),
                    error_message="Duplicate send skipped by idempotency guard.",
                )

        # Look for existing thread ID to reply within the same Gmail thread
        target_thread_id = getattr(request, "thread_id", None)
        if not target_thread_id:
            prev_msg = self.session.exec(
                select(Message)
                .where(Message.candidate_id == candidate.id, Message.user_id == user_id)
                .order_by(Message.created_at.desc())
            ).first()
            if prev_msg and prev_msg.template_variables:
                target_thread_id = prev_msg.template_variables.get("thread_id") or prev_msg.template_variables.get("google_message_id")

        # 3. Determine clean plain-text and rich HTML alternatives (Requirement 1)
        raw_body = request.body or ""
        html_body = getattr(request, "html_body", None)

        if not html_body and ("<!DOCTYPE" in raw_body or "<html" in raw_body):
            html_body = raw_body
            # Extract clean human-readable plain text without raw HTML tags
            clean_txt = re.sub(r"<style.*?</style>", "", raw_body, flags=re.DOTALL)
            clean_txt = re.sub(r"<script.*?</script>", "", clean_txt, flags=re.DOTALL)
            clean_txt = re.sub(r"<[^>]+>", " ", clean_txt)
            clean_txt = re.sub(r"[ \t]+", " ", clean_txt)
            clean_txt = re.sub(r"\n\s*\n+", "\n\n", clean_txt).strip()
            plain_text = clean_txt
        else:
            plain_text = raw_body

        # Construct RFC 2822 EmailMessage with multipart/alternative
        msg = EmailMessage()
        msg["To"] = candidate.email
        msg["From"] = account.email
        msg["Subject"] = request.subject
        if target_thread_id:
            msg["In-Reply-To"] = f"<{target_thread_id}>"
            msg["References"] = f"<{target_thread_id}>"

        if html_body:
            msg.set_content(plain_text)
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(plain_text)

        raw_base64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

        # Obtain fresh access token
        access_token = self.get_valid_access_token(account)

        # Create pending message record (storing human readable plain_text in DB)
        message_row = Message(
            candidate_id=candidate.id,
            user_id=user_id,
            direction=MessageDirection.outbound,
            message_type=MessageType.email,
            body=plain_text,
            status=MessageStatus.pending,
            template_name=request.template_name or "custom",
            template_variables={"subject": request.subject, "thread_id": target_thread_id},
        )
        self.session.add(message_row)
        self.session.commit()
        self.session.refresh(message_row)

        google_message_id: Optional[str] = None
        returned_thread_id: Optional[str] = None
        send_error: Optional[str] = None

        if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET and not access_token.startswith("ya29.simulated"):
            # Send via Gmail API with retry
            backoff = 1.0
            send_payload = {"raw": raw_base64}
            if target_thread_id:
                send_payload["threadId"] = target_thread_id

            for attempt in range(3):
                try:
                    with httpx.Client(timeout=20.0) as client:
                        resp = client.post(
                            f"{GMAIL_API_BASE}/messages/send",
                            headers={
                                "Authorization": f"Bearer {access_token}",
                                "Content-Type": "application/json",
                            },
                            json=send_payload,
                        )
                        if resp.status_code in (429, 503):
                            time.sleep(backoff)
                            backoff *= 2
                            continue
                        if not resp.is_success:
                            send_error = f"Gmail API error ({resp.status_code}): {resp.text}"
                            break

                        data = resp.json()
                        google_message_id = data.get("id")
                        returned_thread_id = data.get("threadId") or target_thread_id
                        break
                except Exception as exc:
                    send_error = f"Network error sending email: {exc}"
                    time.sleep(backoff)
                    backoff *= 2
        else:
            # Simulated send for testing environments without credentials
            google_message_id = f"mock_msg_{uuid.uuid4().hex[:12]}"
            returned_thread_id = target_thread_id or f"thread_{uuid.uuid4().hex[:12]}"

        now = datetime.now(timezone.utc)

        if send_error:
            message_row.status = MessageStatus.failed
            message_row.error_message = send_error
            message_row.failed_at = now
            self.session.add(message_row)
            self.session.commit()

            # Audit trail for failure
            audit_log_service.record(
                session=self.session,
                user_id=user_id,
                action="email_send_failed",
                candidate_id=candidate.id,
                opening_id=candidate.opening_id,
                details=f"Failed to send email to {candidate.email}: {send_error}",
            )
            raise ValueError(send_error)

        # Successful send
        message_row.status = MessageStatus.sent
        message_row.sent_at = now
        message_row.whatsapp_message_id = google_message_id
        message_row.template_variables = {
            "subject": request.subject,
            "thread_id": returned_thread_id,
            "google_message_id": google_message_id,
        }
        self.session.add(message_row)
        self.session.commit()

        # Audit trail for success
        audit_log_service.record(
            session=self.session,
            user_id=user_id,
            action="email_sent",
            candidate_id=candidate.id,
            opening_id=candidate.opening_id,
            details=f"Sent email '{request.subject}' to {candidate.email} via Gmail API (Message ID: {google_message_id}).",
        )

        return GoogleSendEmailResponse(
            message_id=message_row.id,
            candidate_id=candidate.id,
            recipient_email=candidate.email,
            subject=request.subject,
            status="sent",
            sent_at=now,
            google_message_id=google_message_id,
        )
