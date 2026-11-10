"""Connection settings built from the environment.

Locally docker-compose sets DATABASE_URL / REDIS_URL directly. On ECS the
task definition injects the parts instead (DB_HOST, DB_USER, DB_PASSWORD,
REDIS_HOST, REDIS_AUTH_TOKEN) because Secrets Manager values cannot be
composed into a URL there; the explicit URL, when set, always wins.
"""
import os
from urllib.parse import quote


def database_url() -> str:
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    # KeyError on a missing part keeps "no hardcoded fallback" (V-CLD-04).
    host = os.environ["DB_HOST"]
    user = quote(os.environ["DB_USER"], safe="")
    password = quote(os.environ["DB_PASSWORD"], safe="")
    name = os.environ.get("DB_NAME", "sentinelpay")
    sslmode = os.environ.get("DB_SSLMODE", "require")
    return f"postgresql://{user}:{password}@{host}:5432/{name}?sslmode={sslmode}"


def redis_url() -> str:
    explicit = os.environ.get("REDIS_URL")
    if explicit:
        return explicit
    host = os.environ.get("REDIS_HOST")
    if not host:
        return "redis://redis:6379/0"
    token = os.environ.get("REDIS_AUTH_TOKEN")
    if token:
        # AUTH token implies in-transit encryption on ElastiCache.
        return f"rediss://:{quote(token, safe='')}@{host}:6379/0"
    return f"redis://{host}:6379/0"
