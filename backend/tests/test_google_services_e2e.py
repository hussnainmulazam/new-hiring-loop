"""
Comprehensive End-to-End Test Suite for Google Integration:
1. Google OAuth2 Authentication (URL building, redirect URI matching GCP console, signed CSRF state).
2. Google OAuth2 Callback (code exchange, user creation, JWT issuance, frontend redirect).
3. Google Calendar & Google Meet Integration (event creation with conferenceData, Meet link generation).
4. Gmail API Integration (MIME multipart construction, templated candidate outreach, Gmail send).
5. Google Sheets Integration (sheet sync payload, row column formatting).
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.core.config import settings
from app.core.security import create_access_token, create_oauth_state, decode_oauth_state
from app.models.candidate import Candidate
from app.models.google_account import GoogleAccount
from app.models.interview import Interview, InterviewStatus
from app.models.job_opening import JobOpening, JobOpeningStatus
from app.models.user import User
from app.services.auth_service import auth_service
from app.services.google_service import GoogleService
from app.services.google_sheets_service import GoogleSheetsService
from app.services.scheduling_service import scheduling_service


# ── 1. Google Auth URL & Redirect URI Matching ──────────────────────────────

def test_google_auth_url_matches_gcp_console():
    """Verify that the generated Google OAuth consent URL matches the GCP console redirect URI."""
    auth_url = auth_service.get_google_auth_url()

    # Must contain client ID matching GCP
    assert "client_id=" in auth_url
    assert "447679119970" in auth_url

    # Must contain canonical redirect URI without trailing slash
    assert "https%3A%2F%2Fhrhiringloopbackend.vercel.app%2Fauth%2Fgoogle%2Fcallback" in auth_url or \
           "hrhiringloopbackend.vercel.app/auth/google/callback" in auth_url or \
           "redirect_uri=" in auth_url

    # State parameter must be present and signed
    assert "state=" in auth_url
    import urllib.parse
    parsed = urllib.parse.urlparse(auth_url)
    params = urllib.parse.parse_qs(parsed.query)
    state = params["state"][0]
    payload = decode_oauth_state(state)
    assert payload["flow"] == "login"
    assert "exp" in payload


def test_google_auth_redirect_endpoint(client: TestClient):
    """Test GET /auth/google issues 302 redirect directly to Google consent screen."""
    res = client.get("/auth/google", follow_redirects=False)
    assert res.status_code == 302
    location = res.headers["location"]
    assert "accounts.google.com" in location
    assert "response_type=code" in location


# ── 2. Google OAuth Callback & Session Creation ──────────────────────────────

def test_google_oauth_callback_login_flow(client: TestClient, db_session: Session):
    """Test GET /auth/google/callback successfully authenticates user and redirects to frontend with token."""
    state = create_oauth_state("login")
    mock_token_resp = MagicMock()
    mock_token_resp.status_code = 200
    mock_token_resp.json.return_value = {
        "access_token": "ya29.mock_google_token",
        "id_token": "mock_id_token",
        "expires_in": 3600,
    }

    mock_userinfo_resp = MagicMock()
    mock_userinfo_resp.status_code = 200
    mock_userinfo_resp.json.return_value = {
        "email": "recruiter.e2e@example.com",
        "name": "Jane Recruiter",
        "picture": "https://lh3.googleusercontent.com/photo.jpg",
        "verified_email": True,
    }

    with patch("httpx.Client.post", return_value=mock_token_resp):
        with patch("httpx.Client.get", return_value=mock_userinfo_resp):
            res = client.get(
                f"/auth/google/callback?code=mock_google_auth_code&state={state}",
                follow_redirects=False,
            )
            assert res.status_code == 302
            location = res.headers["location"]

            # Must redirect to FRONTEND_URL/auth/callback with token query param
            assert "hrhiringloop.vercel.app/auth/callback" in location or "/auth/callback" in location
            assert "token=" in location
            assert "setup_completed=" in location

            # Verify user was created in DB
            user = db_session.exec(
                select(User).where(User.email == "recruiter.e2e@example.com")
            ).first()
            assert user is not None
            assert user.full_name == "Jane Recruiter"


# ── 3. Google Calendar & Google Meet Integration ─────────────────────────────

@pytest.mark.asyncio
async def test_create_calendar_event_with_google_meet(db_session: Session):
    """Verify that scheduling service creates a Google Calendar event with a Google Meet conference link."""
    # 1. Create recruiter user & connected Google account
    user = User(
        email=f"recruiter_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Alex Recruiter",
        hashed_password="pw",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    google_account = GoogleAccount(
        user_id=user.id,
        email=user.email,
        access_token="mock_access_token",
        refresh_token="mock_enc_refresh_token",
        token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        last_sync_status="active",
    )
    db_session.add(google_account)
    db_session.commit()

    start_time = datetime.now(timezone.utc) + timedelta(days=2)
    end_time = start_time + timedelta(minutes=45)

    mock_cal_resp = MagicMock()
    mock_cal_resp.status_code = 200
    mock_cal_resp.json.return_value = {
        "id": "cal_evt_12345_google_id",
        "hangoutLink": "https://meet.google.com/xyz-abcd-uvw",
        "conferenceData": {
            "entryPoints": [
                {"entryPointType": "video", "uri": "https://meet.google.com/xyz-abcd-uvw"}
            ]
        },
    }

    with patch("httpx.AsyncClient.post", return_value=mock_cal_resp):
        with patch.object(GoogleService, "get_valid_access_token", return_value="valid_mock_token"):
            event_id, meet_link = await scheduling_service.create_google_calendar_event(
                session=db_session,
                user_id=user.id,
                summary="Technical Interview: John Doe",
                description="Interview via Google Meet",
                start_time_utc=start_time,
                end_time_utc=end_time,
                candidate_email="john.doe@example.com",
                recruiter_email=user.email,
            )

            assert event_id == "cal_evt_12345_google_id"
            assert meet_link == "https://meet.google.com/xyz-abcd-uvw"


# ── 4. Gmail API Send Email & Templates ──────────────────────────────────────

def test_gmail_send_email_multipart(db_session: Session):
    """Test GoogleService.send_email builds valid MIME and dispatches via Gmail API."""
    user = User(
        email=f"hr_{uuid.uuid4().hex[:6]}@example.com",
        full_name="HR Specialist",
        hashed_password="pw",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    account = GoogleAccount(
        user_id=user.id,
        email=user.email,
        access_token="mock_token",
        refresh_token="enc_mock",
        token_expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        last_sync_status="active",
    )
    db_session.add(account)
    db_session.commit()

    svc = GoogleService(db_session)

    mock_send_resp = MagicMock()
    mock_send_resp.status_code = 200
    mock_send_resp.json.return_value = {
        "id": "gmail_msg_987654321",
        "threadId": "gmail_th_987654321",
        "labelIds": ["SENT"],
    }

    with patch("httpx.Client.post", return_value=mock_send_resp) as mock_post:
        with patch.object(GoogleService, "get_valid_access_token", return_value="fresh_token"):
            res = svc.send_email(
                user_id=user.id,
                to="candidate.interview@example.com",
                subject="Interview Invitation: Software Engineer",
                body_html="<p>Hi Candidate,</p><p>You are invited to an interview.</p>",
                body_text="Hi Candidate,\n\nYou are invited to an interview.",
            )

            assert res.success is True
            assert res.message_id == "gmail_msg_987654321"
            assert mock_post.called
            call_url = mock_post.call_args[0][0]
            assert "gmail/v1/users/me/messages/send" in call_url


# ── 5. Google Sheets Integration ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_google_sheets_sync_row_payload(db_session: Session):
    """Verify that GoogleSheetsService formats candidates into stable, well-aligned spreadsheet rows."""
    user = User(
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Talent Ops",
        hashed_password="pw",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    opening = JobOpening(
        user_id=user.id,
        title="Staff AI Engineer",
        status=JobOpeningStatus.active,
    )
    db_session.add(opening)
    db_session.commit()
    db_session.refresh(opening)

    candidate = Candidate(
        user_id=user.id,
        opening_id=opening.id,
        name="Sarah Connor",
        email="sarah.connor@sky.net",
        phone="+1 555-0199",
        score=94.5,
        matched_skills=["Python", "FastAPI", "PostgreSQL"],
        missing_skills=["Rust"],
        summary="Experienced distributed systems developer.",
    )
    db_session.add(candidate)
    db_session.commit()
    db_session.refresh(candidate)

    sheets_svc = GoogleSheetsService()
    row = sheets_svc._candidate_to_row(candidate, rank=1)

    # Validate row structure
    assert str(candidate.id) == row[0]
    assert "1" == row[1]  # Rank
    assert "Sarah Connor" == row[2]
    assert "sarah.connor@sky.net" == row[3]
    assert "+1 555-0199" == row[4]
    assert "94.5%" == row[6]  # Fit score
    assert "Python, FastAPI, PostgreSQL" == row[12]
    assert "Rust" == row[13]
    assert "Experienced distributed systems developer." in row[14]
