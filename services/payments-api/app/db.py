"""Database connection helpers."""
import os
import psycopg2
import psycopg2.extras


def get_connection():
    # Fix for V-CLD-04: no hardcoded fallback connection string/password.
    # DATABASE_URL must be set (via a git-ignored .env locally); see
    # .env.example.
    return psycopg2.connect(
        os.environ["DATABASE_URL"],
        cursor_factory=psycopg2.extras.RealDictCursor
    )
