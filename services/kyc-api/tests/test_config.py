"""database_url(): explicit URL wins; otherwise built from DB_* parts with
the credentials URL-encoded (RDS-generated passwords contain reserved
characters); nothing set means KeyError, never a hardcoded fallback."""
import pytest

from app.config import database_url

PARTS = ("DATABASE_URL", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSLMODE")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in PARTS:
        monkeypatch.delenv(k, raising=False)


def test_explicit_url_wins(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/d")
    monkeypatch.setenv("DB_HOST", "ignored")
    assert database_url() == "postgresql://u:p@h:5432/d"


def test_built_from_parts_and_encodes_credentials(monkeypatch):
    monkeypatch.setenv("DB_HOST", "db.internal")
    monkeypatch.setenv("DB_USER", "sentinel_admin")
    monkeypatch.setenv("DB_PASSWORD", "p@ss:w/rd?#")
    assert database_url() == (
        "postgresql://sentinel_admin:p%40ss%3Aw%2Frd%3F%23@db.internal:5432/sentinelpay?sslmode=require"
    )


def test_nothing_set_raises(monkeypatch):
    with pytest.raises(KeyError):
        database_url()
