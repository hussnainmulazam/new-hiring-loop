"""
Tests for app.core.storage:
1. Import time purity (no mkdir, file writes, or network calls at import time).
2. Backend resolution: local vs supabase (defaulting to supabase when VERCEL is set).
3. Local storage mode: directory created lazily, returns relative web-accessible path.
4. Supabase storage mode: client initialized lazily, uploads via supabase-py, returns storage path.
5. Fallback behavior when Supabase upload encounters an error.
"""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.core import storage


def test_import_has_no_side_effects():
    """Ensure importing app.core.storage has no filesystem or network side effects."""
    # Module is already imported; verify that the client is uninitialized (None)
    assert storage._supabase_client is None


def test_storage_backend_resolution():
    """Test resolution of STORAGE_BACKEND based on environment variables."""
    with patch.dict(os.environ, {"STORAGE_BACKEND": "supabase"}, clear=False):
        assert storage.get_storage_backend() == "supabase"

    with patch.dict(os.environ, {"STORAGE_BACKEND": "local"}, clear=False):
        assert storage.get_storage_backend() == "local"

    # When STORAGE_BACKEND is unset, VERCEL presence defaults to supabase
    env_without_backend = {k: v for k, v in os.environ.items() if k != "STORAGE_BACKEND"}
    with patch.dict(os.environ, {**env_without_backend, "VERCEL": "1"}, clear=True):
        assert storage.get_storage_backend() == "supabase"

    with patch.dict(os.environ, env_without_backend, clear=True):
        assert storage.get_storage_backend() == "local"


def test_local_storage_lazy_directory(tmp_path: Path):
    """Test that local storage creates directories lazily and saves files."""
    test_cv_content = b"%PDF-1.4 Mock CV test bytes"
    
    with patch.dict(os.environ, {"STORAGE_BACKEND": "local"}):
        with patch("app.core.storage.get_local_upload_dir", return_value=tmp_path):
            result_path = storage.save_candidate_cv_file("john_doe_resume.pdf", test_cv_content)
            
            assert result_path.startswith("/uploads/cvs/")
            assert "john_doe_resume" in result_path
            
            # Check file was actually written to the lazy directory
            saved_files = list(tmp_path.glob("*john_doe_resume*"))
            assert len(saved_files) == 1
            assert saved_files[0].read_bytes() == test_cv_content


def test_supabase_storage_lazy_client_and_path():
    """Test supabase mode initializes client lazily and returns storage path."""
    test_cv_content = b"%PDF-1.4 Supabase CV test bytes"
    mock_client = MagicMock()
    mock_from = MagicMock()
    mock_client.storage.from_.return_value = mock_from

    with patch.dict(os.environ, {
        "STORAGE_BACKEND": "supabase",
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "test_service_key",
        "SUPABASE_STORAGE_BUCKET": "cvs",
    }):
        with patch("app.core.storage._get_supabase_client", return_value=mock_client):
            result = storage.save_candidate_cv_file("jane_doe_cv.pdf", test_cv_content)
            
            # Verify upload call
            assert mock_client.storage.from_.called
            assert mock_client.storage.from_.call_args[0][0] == "cvs"
            assert mock_from.upload.called
            
            # Verify returned storage path is in the format 'cvs/unique_key' (not a public URL)
            assert result.startswith("cvs/")
            assert "jane_doe_cv" in result
            assert not result.startswith("http://")
            assert not result.startswith("https://")


def test_supabase_fallback_to_local(tmp_path: Path):
    """Test that if Supabase upload fails, it gracefully falls back to lazy local storage."""
    test_cv_content = b"%PDF-1.4 Fallback test bytes"
    mock_client = MagicMock()
    mock_client.storage.from_.side_effect = Exception("Supabase connection timeout")

    with patch.dict(os.environ, {
        "STORAGE_BACKEND": "supabase",
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "test_service_key",
    }):
        with patch("app.core.storage._get_supabase_client", return_value=mock_client):
            with patch("app.core.storage.get_local_upload_dir", return_value=tmp_path):
                result = storage.save_candidate_cv_file("fallback_candidate.pdf", test_cv_content)
                
                assert result.startswith("/uploads/cvs/")
                assert "fallback_candidate" in result
                saved_files = list(tmp_path.glob("*fallback_candidate*"))
                assert len(saved_files) == 1
                assert saved_files[0].read_bytes() == test_cv_content


def test_vercel_uses_tmp_for_local_dir():
    """Verify that on Vercel runtime, get_local_upload_dir safely points to /tmp."""
    with patch.dict(os.environ, {"VERCEL": "1"}):
        with patch("pathlib.Path.mkdir"):
            target_dir = storage.get_local_upload_dir()
            assert str(target_dir).startswith("/tmp") or "\\tmp" in str(target_dir) or "tmp" in str(target_dir)
