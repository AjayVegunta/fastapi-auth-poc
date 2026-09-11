from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "auth.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            email TEXT,
            user_id INTEGER,
            success INTEGER NOT NULL,
            status_code INTEGER,
            request_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            message TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def create_user(email: str, password_hash: str) -> int:
    conn = get_connection()

    cursor = conn.execute(
        """
        INSERT INTO users (email, password_hash)
        VALUES (?, ?)
        """,
        (email, password_hash),
    )

    conn.commit()
    user_id = cursor.lastrowid
    conn.close()

    return int(user_id)


def get_user_by_email(email: str):
    conn = get_connection()

    user = conn.execute(
        """
        SELECT id, email, password_hash, created_at
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    conn.close()
    return user


def write_audit_log(
    *,
    event_type: str,
    email: str | None,
    user_id: int | None,
    success: bool,
    status_code: int,
    request_id: str,
    ip_address: str | None,
    user_agent: str | None,
    message: str,
) -> None:
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO audit_logs (
            event_type,
            email,
            user_id,
            success,
            status_code,
            request_id,
            ip_address,
            user_agent,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            email,
            user_id,
            int(success),
            status_code,
            request_id,
            ip_address,
            user_agent,
            message,
        ),
    )

    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 100) -> list[dict]:
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]