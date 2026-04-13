"""
Unit tests for generate_website_url() in plugins/common_utils.py.

Verifies that:
- APP_URL env var is used as the base when set
- Falls back to request-derived host when APP_URL is unset
- Trailing slashes on APP_URL do not produce double slashes in the output
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))

from common_utils import generate_website_url


class MockRequest:
    """Minimal request stand-in with the attributes generate_website_url reads."""

    def __init__(self, scheme="http", host="localhost:8001"):
        self.scheme = scheme
        self.headers = {"host": host}


def test_uses_app_url_when_set(monkeypatch):
    monkeypatch.setenv("APP_URL", "https://resette.envirodatagov.org")
    request = MockRequest()
    result = generate_website_url(request, "my_db")
    assert result == "https://resette.envirodatagov.org/db/my_db/homepage"


def test_falls_back_to_request_host_when_app_url_unset(monkeypatch):
    monkeypatch.delenv("APP_URL", raising=False)
    request = MockRequest(scheme="http", host="localhost:8001")
    result = generate_website_url(request, "my_db")
    assert result == "http://localhost:8001/db/my_db/homepage"


def test_app_url_trailing_slash_stripped(monkeypatch):
    monkeypatch.setenv("APP_URL", "https://resette.envirodatagov.org/")
    request = MockRequest()
    result = generate_website_url(request, "my_db")
    assert "//" not in result.replace("https://", "").replace("http://", "")
    assert result == "https://resette.envirodatagov.org/db/my_db/homepage"
