"""
Smoke test: Datasette starts with all plugins loaded and the homepage returns 200.

Catches plugin import errors and startup crashes without requiring a live server.
Uses a fresh portal.db created by migrate_database() so no external state is needed.
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import migrate_db

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


@pytest.fixture()
def portal_db(tmp_path, monkeypatch):
    """Create a minimal initialized portal.db in a temp directory."""
    db_path = str(tmp_path / "portal.db")
    monkeypatch.setenv("PORTAL_DB_PATH", db_path)
    monkeypatch.setenv("APP_URL", "https://resette.envirodatagov.org")
    monkeypatch.setenv("RESETTE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RESETTE_STATIC_DIR", os.path.join(REPO_ROOT, "static"))
    monkeypatch.setattr(migrate_db, "PORTAL_DB_PATH", db_path)
    migrate_db.migrate_database()
    import sqlite_utils
    import init_db
    db = sqlite_utils.Database(db_path)
    init_db.create_database_schema(db)
    init_db.create_portal_content(db)
    return db_path


async def test_homepage_ok(portal_db):
    from datasette.app import Datasette

    ds = Datasette(
        files=[portal_db],
        plugins_dir=os.path.join(REPO_ROOT, "plugins"),
        template_dir=os.path.join(REPO_ROOT, "templates"),
        metadata={"databases": {}},
    )
    response = await ds.client.get("/")
    assert response.status_code == 200
