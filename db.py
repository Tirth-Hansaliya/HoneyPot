"""SQLite database helper for honeypot log storage.

Configuration via environment variables:
  SQLITE_DB_PATH - SQLite database file path (default: honeypot_logs.db)
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SQLITE_DB_PATH", "honeypot_logs.db")
_conn_lock = threading.Lock()

# Regex to parse the standard honeypot log format:
# [SERVICE] [YYYY-MM-DD HH:MM:SS] message
_LOG_RE = re.compile(
    r"^\[(HTTP|FTP|SSH|SYSTEM)\]\s+\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.*)",
    re.DOTALL,
)
# Extract source IP from messages like "Connection from 1.2.3.4:port"
_IP_RE = re.compile(r"(?:Connection from|Request from)\s+([\d.a-fA-F:]+)")


def _get_connection() -> sqlite3.Connection:
    """Return a fresh SQLite connection with row dictionary behavior."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_log(raw: str) -> dict:
    """Parse a raw log string and return a dictionary of fields."""
    m = _LOG_RE.match(raw.strip())
    if m:
        service = m.group(1)
        try:
            timestamp = datetime.strptime(m.group(2), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = datetime.now()
        message = m.group(3)
    else:
        service = "UNKNOWN"
        timestamp = datetime.now()
        message = raw.strip()

    source_ip = None
    ip_match = _IP_RE.search(message)
    if ip_match:
        source_ip = ip_match.group(1)

    return {
        "service": service,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "source_ip": source_ip,
        "raw": raw.strip(),
    }


def init_db() -> bool:
    """Create the SQLite table and indexes if they do not already exist."""
    create_table_sql = """
        CREATE TABLE IF NOT EXISTS honeypot_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            service    TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            message    TEXT NOT NULL,
            source_ip  TEXT DEFAULT NULL,
            raw        TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """
    create_indexes_sql = [
        "CREATE INDEX IF NOT EXISTS idx_service ON honeypot_logs(service)",
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON honeypot_logs(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_source_ip ON honeypot_logs(source_ip)",
    ]

    try:
        with _conn_lock:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute(create_table_sql)
            for stmt in create_indexes_sql:
                cursor.execute(stmt)
            conn.commit()
            cursor.close()
            conn.close()
        logger.info("SQLite table honeypot_logs ready at %s", DB_PATH)
        return True
    except sqlite3.Error as exc:
        logger.error("Failed to initialize SQLite database: %s", exc)
        return False


def insert_log(raw_message: str) -> bool:
    """Parse raw_message and insert it into honeypot_logs."""
    record = _parse_log(raw_message)
    sql = """
        INSERT INTO honeypot_logs (service, timestamp, message, source_ip, raw)
        VALUES (?, ?, ?, ?, ?)
    """

    try:
        with _conn_lock:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    record["service"],
                    record["timestamp"],
                    record["message"],
                    record["source_ip"],
                    record["raw"],
                ),
            )
            conn.commit()
            cursor.close()
            conn.close()
        return True
    except sqlite3.Error as exc:
        logger.error("Failed to insert log into SQLite: %s", exc)
        return False


def get_logs(limit: int = 500, service: str | None = None) -> list[dict]:
    """Retrieve recent log entries from SQLite."""
    if service:
        sql = """
            SELECT id, service, timestamp, message, source_ip, raw, created_at
            FROM honeypot_logs
            WHERE service = ?
            ORDER BY id DESC
            LIMIT ?
        """
        params = (service.upper(), limit)
    else:
        sql = """
            SELECT id, service, timestamp, message, source_ip, raw, created_at
            FROM honeypot_logs
            ORDER BY id DESC
            LIMIT ?
        """
        params = (limit,)

    try:
        with _conn_lock:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = [dict(row) for row in cursor.fetchall()]
            cursor.close()
            conn.close()
        return rows
    except sqlite3.Error as exc:
        logger.error("Failed to fetch logs from SQLite: %s", exc)
        return []


def get_stats() -> dict:
    """Return per-service connection counts from SQLite."""
    sql = """
        SELECT service, COUNT(*) AS cnt
        FROM honeypot_logs
        WHERE message LIKE 'Connection from%'
        GROUP BY service
    """
    try:
        with _conn_lock:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            cursor.close()
            conn.close()

        result = {"http": 0, "ftp": 0, "ssh": 0, "total": 0}
        for row in rows:
            key = row["service"].lower()
            if key in result:
                result[key] = row["cnt"]
        result["total"] = result["http"] + result["ftp"] + result["ssh"]
        return result
    except sqlite3.Error as exc:
        logger.error("Failed to get stats from SQLite: %s", exc)
        return {"http": 0, "ftp": 0, "ssh": 0, "total": 0}


def clear_logs() -> bool:
    """Delete all rows from honeypot_logs."""
    try:
        with _conn_lock:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM honeypot_logs")
            conn.commit()
            cursor.close()
            conn.close()
        logger.info("SQLite honeypot_logs table cleared")
        return True
    except sqlite3.Error as exc:
        logger.error("Failed to clear SQLite logs: %s", exc)
        return False


def is_available() -> bool:
    """Return True if the SQLite database file is accessible."""
    try:
        with _conn_lock:
            conn = _get_connection()
            conn.execute("SELECT 1")
            conn.close()
        return True
    except sqlite3.Error:
        return False
