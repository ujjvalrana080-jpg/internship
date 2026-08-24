"""
database/db.py

Day 15 — SQLite database integration.

Handles schema creation, log insertion, and query helpers used by
both the ingestion script and the FastAPI backend.
"""

import sqlite3
from contextlib import contextmanager
from typing import List, Optional, Dict, Any

DB_PATH = "forensics.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    user TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
"""


@contextmanager
def get_connection(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    """Create the logs table if it doesn't already exist."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
    print(f"[db] Database initialized at {db_path}")


def insert_log(entry: Dict[str, Any], db_path: str = DB_PATH) -> int:
    """Insert a single parsed log entry. Returns the new row id."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO logs (timestamp, event_type, message, severity, src_ip, user)
            VALUES (:timestamp, :event_type, :message, :severity, :src_ip, :user)
            """,
            entry,
        )
        return cur.lastrowid


def insert_logs_bulk(entries: List[Dict[str, Any]], db_path: str = DB_PATH) -> int:
    """Insert many parsed log entries in one transaction. Returns count inserted."""
    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO logs (timestamp, event_type, message, severity, src_ip, user)
            VALUES (:timestamp, :event_type, :message, :severity, :src_ip, :user)
            """,
            entries,
        )
    return len(entries)


def fetch_all_logs(db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM logs ORDER BY timestamp ASC").fetchall()
        return [dict(r) for r in rows]


def fetch_logs_by_severity(severity: str, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM logs WHERE severity = ? ORDER BY timestamp ASC",
            (severity.upper(),),
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_log_by_id(log_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
        return dict(row) if row else None


def clear_logs(db_path: str = DB_PATH) -> None:
    """Utility for re-running ingestion cleanly during development/demo."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM logs")
    print("[db] Cleared all logs.")


if __name__ == "__main__":
    init_db()
    print("[db] Schema ready. Table 'logs' created (id, timestamp, event_type, message, severity, src_ip, user).")
