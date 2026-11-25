"""
Storage utility for saving CV documents to Supabase Storage with local fallback.
"""
import logging
import mimetypes
from pathlib import Path
import uuid
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Base local upload path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
LOCAL_UPLOAD_DIR = BACKEND_DIR / "uploads" / "cvs"
LOCAL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def save_candidate_cv_file(
    filename: str,
    file_bytes: bytes,
    mime_type: str = "application/pdf",
) -> str:
    """
    Saves candidate CV file to Supabase Storage bucket.
    If Supabase credentials are missing or the upload fails, safely falls back
    to the local persistent storage directory.
    Returns: file URL or relative web-accessible path.
    """
    supabase_url = (settings.SUPABASE_URL or "").strip()
    # Normalize base URL by stripping trailing /rest/v1 or slashes
    import re
    base_supabase_url = re.sub(r"/rest/v1/?$", "", supabase_url).rstrip("/")
    service_key = (settings.SUPABASE_SERVICE_ROLE_KEY or "").strip()
    bucket = (settings.SUPABASE_STORAGE_BUCKET or "resumes").strip()

    # Determine mime-type if generic
    if not mime_type or mime_type == "application/octet-stream":
        guessed_type, _ = mimetypes.guess_type(filename)
        mime_type = guessed_type or "application/pdf"

    sanitized_name = "".join(c for c in filename if c.isalnum() or c in "._-").strip() or "cv.pdf"
    unique_key = f"{uuid.uuid4().hex[:12]}_{sanitized_name}"

    # 1. Try Supabase Storage if service role key is configured
    if base_supabase_url and service_key:
        upload_endpoint = f"{base_supabase_url}/storage/v1/object/{bucket}/{unique_key}"
        headers = {
            "Authorization": f"Bearer {service_key}",
            "Content-Type": mime_type,
            "x-upsert": "true",
        }
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(upload_endpoint, headers=headers, content=file_bytes)
                if resp.is_success:
                    public_url = f"{base_supabase_url}/storage/v1/object/public/{bucket}/{unique_key}"
                    logger.info("Successfully uploaded %s to Supabase Storage: %s", sanitized_name, public_url)
                    return public_url
                else:
                    logger.warning("Supabase storage upload returned status %d: %s", resp.status_code, resp.text[:300])
        except Exception as exc:
            logger.warning("Supabase storage upload exception for %s: %s", sanitized_name, exc)

    # 2. Resilient Local Storage Fallback
    local_target = LOCAL_UPLOAD_DIR / unique_key
    try:
        with open(local_target, "wb") as f:
            f.write(file_bytes)
        logger.info("Saved CV locally to %s", local_target)
        return f"/uploads/cvs/{unique_key}"
    except Exception as exc:
        logger.error("Failed to save CV locally: %s", exc)
        return f"/uploads/cvs/{unique_key}"
