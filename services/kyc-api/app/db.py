
import psycopg2
import psycopg2.extras

from app.config import database_url


def get_connection():
    return psycopg2.connect(
        database_url(),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
