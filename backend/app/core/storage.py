"""
Storage utility for saving CV documents with lazy directory initialization
and configurable storage backends (local filesystem or Supabase Storage).
"""
import logging
import mimetypes
import os
from pathlib import Path
import re
import uuid
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

# Base local upload path (resolved without import-time mkdir side-effects)
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent

# Lazy singleton for Supabase client
_supabase_client = None


def get_storage_backend() -> str:
    """
    Determines active storage backend: 'local' or 'supabase'.
    Default: 'supabase' if VERCEL environment variable is set, otherwise 'local'.
    Can be explicitly overridden via STORAGE_BACKEND environment variable.
    """
    backend = os.getenv("STORAGE_BACKEND") or getattr(settings, "STORAGE_BACKEND", None)
    if backend:
        return backend.lower().strip()
    if os.getenv("VERCEL"):
        return "supabase"
    return "local"


def get_local_upload_dir() -> Path:
    """
    Returns local upload directory and ensures it exists lazily.
    On Vercel / serverless runtimes where the filesystem is read-only,
    safely directs writes to ephemeral /tmp directory.
    """
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        upload_dir = Path("/tmp/uploads/cvs")
    else:
        upload_dir = BACKEND_DIR / "uploads" / "cvs"

    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def _get_supabase_client():
    """Lazily initializes and returns the Supabase client."""
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client

        raw_url = (getattr(settings, "SUPABASE_URL", None) or os.getenv("SUPABASE_URL") or "").strip()
        base_url = re.sub(r"/rest/v1/?$", "", raw_url).rstrip("/")
        service_key = (getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", None) or os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()

        if not base_url or not service_key:
            raise ValueError(
                "Supabase storage backend requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY. "
                "Please configure them in your environment variables."
            )
        _supabase_client = create_client(base_url, service_key)
    return _supabase_client


def _save_local(unique_key: str, file_bytes: bytes) -> str:
    """Saves candidate CV file to local filesystem lazily."""
    upload_dir = get_local_upload_dir()
    local_target = upload_dir / unique_key
    with open(local_target, "wb") as f:
        f.write(file_bytes)
    logger.info("Saved CV locally to %s", local_target)
    return f"/uploads/cvs/{unique_key}"


def _save_supabase(unique_key: str, file_bytes: bytes, mime_type: str) -> str:
    """Uploads candidate CV to Supabase Storage bucket using supabase-py."""
    client = _get_supabase_client()
    bucket = os.getenv("SUPABASE_STORAGE_BUCKET") or getattr(settings, "SUPABASE_STORAGE_BUCKET", None) or "cvs"

    try:
        client.storage.from_(bucket).upload(
            path=unique_key,
            file=file_bytes,
            file_options={"content-type": mime_type, "upsert": "true"},
        )
    except Exception as exc:
        err_msg = str(exc).lower()
        if "not found" in err_msg or "404" in err_msg or "bucket" in err_msg:
            try:
                client.storage.create_bucket(bucket, options={"public": True})
                client.storage.from_(bucket).upload(
                    path=unique_key,
                    file=file_bytes,
                    file_options={"content-type": mime_type, "upsert": "true"},
                )
            except Exception:
                raise exc
        else:
            raise exc

    storage_path = f"{bucket}/{unique_key}"
    logger.info("Successfully uploaded CV to Supabase Storage: %s", storage_path)
    return storage_path


def save_candidate_cv_file(
    filename: str,
    file_bytes: bytes,
    mime_type: str = "application/pdf",
) -> str:
    """
    Saves candidate CV file based on active STORAGE_BACKEND ('local' or 'supabase').
    Keeps signature and return type unchanged so existing callers do not break.
    Returns: storage path (e.g. 'cvs/abc_resume.pdf' or '/uploads/cvs/abc_resume.pdf').
    """
    # Determine mime-type if generic
    if not mime_type or mime_type == "application/octet-stream":
        guessed_type, _ = mimetypes.guess_type(filename)
        mime_type = guessed_type or "application/pdf"

    sanitized_name = "".join(c for c in filename if c.isalnum() or c in "._-").strip() or "cv.pdf"
    unique_key = f"{uuid.uuid4().hex[:12]}_{sanitized_name}"

    backend = get_storage_backend()

    if backend == "supabase":
        try:
            return _save_supabase(unique_key, file_bytes, mime_type)
        except Exception as exc:
            logger.warning(
                "Supabase storage upload failed for %s (%s). Falling back to local storage.",
                sanitized_name,
                exc,
            )
            return _save_local(unique_key, file_bytes)

    # Default 'local' mode
    return _save_local(unique_key, file_bytes)

