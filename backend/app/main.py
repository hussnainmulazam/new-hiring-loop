import asyncio
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db import init_db, engine
from sqlmodel import Session, select
from app.routers import (
    ai,
    api_router,
    auth_google,
    calendar,
    health_router,
    integrations_google,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def _periodic_gmail_sync_worker():
    """Background task that runs automatic Gmail sync every 30 seconds for connected accounts."""
    logger.info("Periodic Gmail sync worker initiated (every 30 seconds).")
    # Quick initial sleep to allow application to fully start
    await asyncio.sleep(5)
    while True:
        try:
            from app.models.google_account import GoogleAccount
            from app.services.google_service import GoogleService

            with Session(engine) as session:
                accounts = session.exec(select(GoogleAccount)).all()
                for account in accounts:
                    if account.last_sync_status == "token_revoked":
                        continue
                    try:
                        logger.info("Automatic Gmail sync starting for %s (user: %s)...", account.email, account.user_id)

                        def _sync_user(target_user_id):
                            with Session(engine) as sync_session:
                                s = GoogleService(sync_session)
                                return s.sync_gmail(user_id=target_user_id)

                        res = await asyncio.to_thread(_sync_user, account.user_id)
                        logger.info(
                            "Automatic Gmail sync for %s complete: %s found, %s processed, %s candidates created.",
                            account.email,
                            res.messages_found,
                            res.messages_processed,
                            res.candidates_created,
                        )
                    except Exception as sync_err:
                        logger.warning("Automatic Gmail sync error for user %s (%s): %s", account.user_id, account.email, sync_err)
        except asyncio.CancelledError:
            logger.info("Periodic Gmail sync worker cancelled.")
            break
        except Exception as exc:
            logger.error("Periodic Gmail sync unexpected loop exception: %s", exc)

        # 30 seconds interval for real-time conversation sync
        await asyncio.sleep(30)


async def _periodic_pipeline_agent_worker():
    """Background task that runs autonomous pipeline agent cycles every 30 seconds."""
    logger.info("Periodic Hiring Pipeline Agent worker initiated (every 30 seconds).")
    await asyncio.sleep(8)
    while True:
        try:
            from app.models.user import User
            from app.services.pipeline_agent_service import HiringPipelineAgent

            def _run_agent_sync():
                with Session(engine) as session:
                    users = session.exec(select(User)).all()
                    for u in users:
                        try:
                            agent = HiringPipelineAgent(session, u.id)
                            agent.process_background_cycles()
                        except Exception as ag_err:
                            logger.warning("Pipeline agent cycle error for user %s: %s", u.id, ag_err)

            await asyncio.to_thread(_run_agent_sync)
        except asyncio.CancelledError:
            logger.info("Periodic Hiring Pipeline Agent worker cancelled.")
            break
        except Exception as exc:
            logger.error("Periodic Pipeline Agent unexpected loop exception: %s", exc)

        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import sys
    is_testing = os.getenv("TESTING") == "true" or "pytest" in sys.modules

    logger.info("Starting up %s (v%s)...", settings.PROJECT_NAME, settings.VERSION)
    if not is_testing:
        # Validate FRONTEND_BASE_URL in production environment
        env_mode = (getattr(settings, "ENVIRONMENT", None) or os.getenv("ENVIRONMENT") or "development").lower()
        if env_mode in ("production", "prod"):
            base_url = settings.frontend_base_url
            if not base_url or "localhost" in base_url or "127.0.0.1" in base_url:
                raise RuntimeError(
                    f"CRITICAL CONFIGURATION ERROR: In production, FRONTEND_BASE_URL must be a valid public URL, but got '{base_url}'. "
                    "Please set FRONTEND_BASE_URL in your environment (e.g. https://hrhiringloop.vercel.app)."
                )
        try:
            init_db()
            logger.info("Database tables initialized successfully via Supabase.")
        except Exception as exc:
            logger.warning("Could not connect to database at startup: %s", exc)

    sync_task = None
    agent_task = None
    if not is_testing:
        sync_task = asyncio.create_task(_periodic_gmail_sync_worker())
        agent_task = asyncio.create_task(_periodic_pipeline_agent_worker())

    yield

    if sync_task:
        sync_task.cancel()
        try:
            await sync_task
        except asyncio.CancelledError:
            pass
    if agent_task:
        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware Configuration ─────────────────────────────────────────────
# Read allowed origins from env var CORS_ORIGINS (comma-separated), default: localhost & prod vercel
raw_cors_origins = os.getenv("CORS_ORIGINS")
if raw_cors_origins:
    parsed_origins = [origin.strip().rstrip("/") for origin in raw_cors_origins.split(",") if origin.strip()]
elif isinstance(settings.CORS_ORIGINS, list):
    parsed_origins = [origin.strip().rstrip("/") for origin in settings.CORS_ORIGINS if origin.strip()]
else:
    parsed_origins = [origin.strip().rstrip("/") for origin in str(settings.CORS_ORIGINS).split(",") if origin.strip()]

# Credentials require specific origins: wildcard '*' is strictly forbidden
cors_origins = [origin for origin in parsed_origins if origin and origin != "*"]
if not cors_origins:
    cors_origins = ["http://localhost:3000", "http://localhost:3001", "https://hrhiringloop.vercel.app"]

# Always allow credentials, all methods, and all headers (including custom header ngrok-skip-browser-warning)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server exception processing %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
    )

# Health endpoint (available at /health)
app.include_router(health_router)

# Direct AI endpoint aliases (available at /ai/tailor-cv and /ai/interview-questions)
app.include_router(ai.router)

# Direct root-level endpoints for Google OAuth2 and integrations as requested
app.include_router(auth_google.router)
app.include_router(calendar.router)
app.include_router(integrations_google.router)
from app.routers import job_openings
app.include_router(job_openings.router)
app.include_router(job_openings.openings_alias_router)

# API v1 routes (available under /api/v1)
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
    }
