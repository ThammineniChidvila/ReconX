
"""Database connection helpers for SQLite and Neon PostgreSQL."""

import sqlite3
import threading
from contextlib import contextmanager

import config

write_lock = threading.RLock()
_path = config.DATABASE_PATH

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'not_required',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    results TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);


CREATE TABLE IF NOT EXISTS verifications (
    domain TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT
);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    owner_id TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'not_required',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    results TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);


CREATE TABLE IF NOT EXISTS verifications (
    domain TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TEXT
);
"""


class PostgresConnection:
    """Small compatibility wrapper for existing SQLite-style queries."""

    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=()):
        sql = sql.replace("?", "%s")
        return self.connection.execute(sql, params)

    def close(self):
        self.connection.close()


def set_path(path):
    global _path
    _path = str(path)


@contextmanager
def connect():
    """Open, commit/rollback, and always close a database connection."""

    if config.DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row

        raw = psycopg.connect(
            config.DATABASE_URL,
            row_factory=dict_row,
            connect_timeout=10
        )
        conn = PostgresConnection(raw)

    else:
        conn = sqlite3.connect(_path, timeout=10)
        conn.row_factory = sqlite3.Row

    try:
        yield conn
        conn.connection.commit() if isinstance(conn, PostgresConnection) else conn.commit()
    except BaseException:
        conn.connection.rollback() if isinstance(conn, PostgresConnection) else conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with write_lock, connect() as conn:
        if isinstance(conn, PostgresConnection):
            for statement in POSTGRES_SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement)

            conn.execute(
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS owner_id TEXT NOT NULL DEFAULT ''"
            )
            conn.execute(
                  "CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id)"
            )

        else:
            conn.executescript(SQLITE_SCHEMA)

            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(scans)").fetchall()
            }

            if "owner_id" not in columns:
                conn.execute(
                    "ALTER TABLE scans ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''"
                )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id)"
            )