"""
Unit tests for the website_url correction step in migrate_db.migrate_database().

Verifies that:
- Rows with a wrong host are rewritten to use the APP_URL canonical host
- Rows already using the correct host are left unchanged
- Running migrate_database() twice produces the same result (idempotent)
"""
import sys
import os
import sqlite3

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import migrate_db


CANONICAL_URL = "https://resette.envirodatagov.org"
BAD_URL = "http://edgi-cloud.fly.dev/db/foo/homepage"
GOOD_URL = f"{CANONICAL_URL}/db/foo/homepage"


def _insert_db_row(db_path, db_id, db_name, website_url):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO databases
           (db_id, user_id, db_name, website_url, status, created_at, updated_at)
           VALUES (?, 'user1', ?, ?, 'Published', '2025-01-01', '2025-01-01')""",
        [db_id, db_name, website_url],
    )
    conn.commit()
    conn.close()


def _read_website_url(db_path, db_id):
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT website_url FROM databases WHERE db_id = ?", [db_id]
    ).fetchone()
    conn.close()
    return row[0] if row else None


@pytest.fixture()
def initialized_db(tmp_path, monkeypatch):
    """Return the path to a temp portal.db with schema created by migrate_database()."""
    db_path = str(tmp_path / "portal.db")
    monkeypatch.setenv("PORTAL_DB_PATH", db_path)
    monkeypatch.setenv("APP_URL", CANONICAL_URL)
    monkeypatch.setattr(migrate_db, "PORTAL_DB_PATH", db_path)
    migrate_db.migrate_database()
    return db_path


def test_corrects_wrong_host(initialized_db, monkeypatch):
    _insert_db_row(initialized_db, "id1", "foo", BAD_URL)
    monkeypatch.setattr(migrate_db, "PORTAL_DB_PATH", initialized_db)
    migrate_db.migrate_database()
    assert _read_website_url(initialized_db, "id1") == GOOD_URL


def test_skips_correct_host(initialized_db, monkeypatch):
    _insert_db_row(initialized_db, "id2", "foo", GOOD_URL)
    monkeypatch.setattr(migrate_db, "PORTAL_DB_PATH", initialized_db)
    migrate_db.migrate_database()
    assert _read_website_url(initialized_db, "id2") == GOOD_URL


def test_idempotent(initialized_db, monkeypatch):
    _insert_db_row(initialized_db, "id3", "foo", BAD_URL)
    monkeypatch.setattr(migrate_db, "PORTAL_DB_PATH", initialized_db)
    migrate_db.migrate_database()
    migrate_db.migrate_database()
    assert _read_website_url(initialized_db, "id3") == GOOD_URL
