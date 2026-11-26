import json
import secrets
from pathlib import Path
from typing import Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_ENV_PATH = _BACKEND_DIR / ".env"


class Settings(BaseSettings):
    PROJECT_NAME: str = "Hiring Loop API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # PostgreSQL (Loaded strictly from .env)
    DATABASE_URL: str = ""

    # CORS origins: supports comma-separated string, JSON array, or Python list
    CORS_ORIGINS: Union[list[str], str] = ["http://localhost:3000", "https://hrhiringloop.vercel.app"]

    # ── JWT ──────────────────────────────────────────────────────────────────
    # Overridden strictly by .env in production
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # ── AI Services (OpenRouter via OpenAI SDK) ──────────────────────────────
    OPENROUTER_API_KEY: Optional[str] = None
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    MODELS_SCREENING: str = "nvidia/nemotron-3-ultra-550b-a55b:free,thinkingmachines/inkling-2-small:free,google/gemma-4-31b-it:free"
    MODELS_EXTRACTION: str = "google/gemma-4-26b-a4b-it:free,nvidia/nemotron-3.5-lightning:free,google/gemma-4-31b-it:free"
    MODELS_QUESTIONS: str = "thinkingmachines/inkling-2-small:free,google/gemma-4-31b-it:free,nvidia/nemotron-3-ultra-550b-a55b:free"
    MODELS_DRAFTS: str = "google/gemma-4-31b-it:free,thinkingmachines/inkling-2-small:free,google/gemma-4-26b-a4b-it:free"
    MODELS_VISION: str = "nvidia/nemotron-3.5-super-vl:free"
    AI_TIMEOUT_SECONDS: float = 60.0

    # ── Grok / Groq AI Provider (High-Speed Inference) ───────────────────────
    # Supports GROK_API_KEY, GROk_API_KEY, GROQ_API_KEY, XAI_API_KEY from .env
    GROK_API_KEY: Optional[str] = None
    GROk_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    XAI_API_KEY: Optional[str] = None
    MODELS: Optional[str] = None
    GROQ_API_BASE: str = "https://api.groq.com/openai/v1"
    XAI_API_BASE: str = "https://api.x.ai/v1"

    @property
    def grok_api_key(self) -> Optional[str]:
        """
        Extract active Grok / Groq key from environment variables or Settings.
        Tolerates casing variants (GROK_API_KEY, GROk_API_KEY, GROQ_API_KEY, XAI_API_KEY).
        """
        import os
        candidates = [
            self.GROK_API_KEY,
            self.GROk_API_KEY,
            self.GROQ_API_KEY,
            self.XAI_API_KEY,
            os.getenv("GROK_API_KEY"),
            os.getenv("GROk_API_KEY"),
            os.getenv("GROQ_API_KEY"),
            os.getenv("XAI_API_KEY"),
        ]
        for c in candidates:
            if c and str(c).strip() and not str(c).strip().startswith("your_"):
                return str(c).strip()
        return None

    @property
    def grok_provider_details(self) -> tuple[str, str, list[str]]:
        """
        Returns (provider_name, base_url, default_models).
        Detects whether key is Groq (starts with 'gsk_') or xAI Grok (starts with 'xai-').
        """
        key = self.grok_api_key or ""
        configured_model = (self.MODELS or "").strip()

        if key.startswith("xai-"):
            models = [configured_model] if configured_model else ["grok-2-latest", "grok-beta"]
            return "xai", self.XAI_API_BASE, models

        # Default / Groq Cloud ('gsk_...')
        models = []
        if configured_model:
            models.append(configured_model)
        for m in ["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
            if m not in models:
                models.append(m)
        return "groq", self.GROQ_API_BASE, models

    # Deprecated single-model fields for backwards compatibility
    MODEL_CV_TAILOR: Optional[str] = None
    MODEL_INTERVIEW: Optional[str] = None
    MODEL_FALLBACK: Optional[str] = None

    def get_models_for_task(self, task: str) -> list[str]:
        """Return parsed list of model IDs for a given task chain."""
        # Support legacy test overrides if present
        if task.lower() in ("questions", "interview"):
            legacy = getattr(self, "MODEL_INTERVIEW", None)
            fallback = getattr(self, "MODEL_FALLBACK", None)
            if legacy and ("primary" in legacy or "fallback" in str(fallback)):
                return [m for m in [legacy, fallback] if m]
        elif task.lower() in ("screening", "cv_tailor"):
            legacy = getattr(self, "MODEL_CV_TAILOR", None)
            fallback = getattr(self, "MODEL_FALLBACK", None)
            if legacy and ("primary" in legacy or "fallback" in str(fallback)):
                return [m for m in [legacy, fallback] if m]

        task_map = {
            "screening": self.MODELS_SCREENING,
            "extraction": self.MODELS_EXTRACTION,
            "questions": self.MODELS_QUESTIONS,
            "drafts": self.MODELS_DRAFTS,
            "vision": self.MODELS_VISION,
        }
        val = task_map.get(task.lower(), self.MODELS_SCREENING)
        return [m.strip() for m in val.split(",") if m.strip()]

    # ── Google OAuth2 & Gmail Integration ────────────────────────────────────
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_LOGIN_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    GOOGLE_WORKSPACE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    GOOGLE_PROJECT_ID: Optional[str] = None
    GOOGLE_AUTH_URI: str = "https://accounts.google.com/o/oauth2/auth"
    GOOGLE_TOKEN_URI: str = "https://oauth2.googleapis.com/token"
    GOOGLE_AUTH_PROVIDER_CERT_URL: Optional[str] = None
    GOOGLE_JAVASCRIPT_ORIGINS: Optional[str] = None
    GOOGLE_ENCRYPTION_KEY: Optional[str] = None
    FRONTEND_URL: str = "http://localhost:3000"
    FRONTEND_BASE_URL: Optional[str] = None

    @property
    def frontend_base_url(self) -> str:
        """Returns the public frontend base URL, preferring FRONTEND_BASE_URL over FRONTEND_URL."""
        url = self.FRONTEND_BASE_URL or self.FRONTEND_URL or "http://localhost:3000"
        return url.rstrip("/")

    # Supabase Storage Integration
    STORAGE_BACKEND: Optional[str] = None
    SUPABASE_URL: Optional[str] = None
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = None
    SUPABASE_STORAGE_BUCKET: str = "cvs"

    # ── Redis L2 Cache (Optional) ────────────────────────────────────────────
    REDIS_URL: Optional[str] = None

    # ── Pinecone Vector Service (Optional — Semantic CV Match & Similarity) ──
    PINECONE_API_KEY: Optional[str] = None
    PINECONE_INDEX: Optional[str] = None
    PINECONE_INDEX_NAME: str = "job-tracker-cache"
    PINECONE_HOST: Optional[str] = None
    PINECONE_EMBED_MODEL: str = "multilingual-e5-large"

    # Legacy AI keys (kept for backwards compatibility)
    GEMINI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, list[str]]) -> list[str]:
        if isinstance(v, str):
            # Check if it's formatted as a JSON array e.g. ["http://localhost:3000"]
            stripped = v.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed]
                except json.JSONDecodeError:
                    pass
            # Comma-separated values e.g. "http://localhost:3000,http://127.0.0.1:3000"
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return [str(item).strip() for item in v]

    @property
    def sync_database_url(self) -> str:
        """
        Ensures the database connection string is properly formatted for SQLAlchemy / SQLModel:
        1. Reads DATABASE_URL from .env.
        2. Supports Supabase SESSION POOLER URL (*.pooler.supabase.com, port 5432).
        3. Converts postgresql:// or postgres:// to postgresql+psycopg://.
        4. Detects direct db.*.supabase.co hosts and raises a clear, helpful error to use Session pooler.
        5. URL-encodes special characters in the password.
        """
        raw_url = self.DATABASE_URL
        if not raw_url:
            return raw_url

        # 1. Scheme normalization
        scheme = "postgresql+psycopg"
        rest = raw_url
        if "://" in raw_url:
            orig_scheme, rest = raw_url.split("://", 1)
            if orig_scheme in ("postgres", "postgresql", "postgresql+psycopg"):
                scheme = "postgresql+psycopg"
            else:
                scheme = orig_scheme

        # 2. Split userinfo and hostinfo by the LAST '@'
        if "@" in rest:
            userinfo, hostinfo = rest.rsplit("@", 1)
            if ":" in userinfo:
                user, pwd = userinfo.split(":", 1)
                import urllib.parse
                # Unquote first to prevent double-encoding, then quote_plus special chars
                pwd = urllib.parse.quote_plus(urllib.parse.unquote_plus(pwd))
                userinfo = f"{user}:{pwd}"
            rest = f"{userinfo}@{hostinfo}"
        else:
            hostinfo = rest

        # 3. Detect direct db.*.supabase.co host
        host_part = hostinfo.split("/")[0].split("?")[0]
        host = host_part.split(":")[0]

        import os
        import sys
        if os.getenv("TESTING") == "true" or self.ENVIRONMENT == "test" or "pytest" in sys.modules:
            return "sqlite:///:memory:"

        if host.startswith("db.") and host.endswith(".supabase.co"):
            ref = host.replace("db.", "").replace(".supabase.co", "")
            error_msg = (
                f"\n{'='*75}\n"
                f"CRITICAL DATABASE CONFIGURATION ERROR:\n"
                f"Direct Supabase host detected: '{host}'\n"
                f"Direct connections rely on IPv6 and fail with 'getaddrinfo failed' in regions\n"
                f"without IPv6 routing (such as Pakistan).\n\n"
                f"Please update DATABASE_URL in backend/.env to the Supabase Session Pooler URL:\n"
                f"  Host:     aws-0-[region].pooler.supabase.com\n"
                f"  Port:     5432 (Session mode)\n"
                f"  User:     postgres.{ref}\n"
                f"  Format:   postgresql://postgres.{ref}:[YOUR_PASSWORD]@aws-0-[region].pooler.supabase.com:5432/postgres\n\n"
                f"Copy the Session connection string from your Supabase Dashboard:\n"
                f"  Project Settings -> Database -> Connection Pooling -> Mode: Session\n"
                f"{'='*75}\n"
            )
            import logging
            logging.getLogger(__name__).critical(error_msg)
            raise ValueError(error_msg)

        return f"{scheme}://{rest}"

    model_config = SettingsConfigDict(
        env_file=(_ENV_PATH, ".env", "backend/.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
