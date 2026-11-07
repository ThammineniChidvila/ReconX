"""SQLite connection helpers."""
import sqlite3
import threading
from contextlib import contextmanager

import config

write_lock = threading.RLock()
_path = config.DATABASE_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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


def set_path(path):
    global _path
    _path = str(path)


@contextmanager
def connect():
    """Yield a connection that is ALWAYS closed.

    Note: `with sqlite3.connect(...)` only commits/rolls back and does NOT close the
    connection, which keeps the file locked on Windows. This wrapper commits on success,
    rolls back on any exception, and closes in `finally`.
    """
    conn = sqlite3.connect(_path, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with write_lock, connect() as conn:
        conn.executescript(SCHEMA)
