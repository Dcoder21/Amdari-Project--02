"""Database connection helpers."""

import psycopg2
import psycopg2.extras

from app.config import database_url


def get_connection():
    # Fix for V-CLD-04: no hardcoded fallback connection string/password.
    # Either DATABASE_URL (git-ignored .env locally) or the DB_* parts that
    # ECS injects from Secrets Manager must be set; see app/config.py.
    return psycopg2.connect(
        database_url(),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
