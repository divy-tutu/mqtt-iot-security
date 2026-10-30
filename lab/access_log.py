"""
Persistent log of gateway access events: failed logins, rate-limit hits,
and unauthenticated requests to a protected route.

Why this exists: gateway.py's login_attempts deque only counts attempts
in memory to enforce the 60-second rate limit — it holds no history, and
every restart wipes it. There was previously no way to see WHO tried and
failed, or WHEN, after the fact. This fixes that without changing any of
gateway.py's existing behavior, only adding calls to log_event() at the
points where a request is already being rejected.

Safety, same reasoning as the rest of this lab's accountability work:
  - parameterized queries only. This logs attacker-controlled input
    (the submitted username), so the logger itself must not be
    SQL-injectable just because it happens to be logging bad actors.
  - row count is capped (MAX_ROWS) so a flood of failed logins can't
    grow the file without bound — same anti-DoS reasoning as the rate
    limiter it's recording.
  - log_event() never raises. A logging failure must not break the
    actual request being handled (e.g. a real login that happens to
    coincide with a full disk).
  - writes go to /data, the one writable (named-volume) path the
    read_only gateway container has — same pattern already used by
    device.py for /data/lock.sqlite, /data/sensor.sqlite etc. The
    container's root filesystem stays read-only; see docker-compose.yml.
"""
import os
import sqlite3
import time

DB_PATH = os.environ.get("ACCESS_LOG_DB_PATH", "/data/access_log.sqlite")
MAX_ROWS = 500


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ts INTEGER NOT NULL,"
        "  event_type TEXT NOT NULL,"
        "  username TEXT NOT NULL,"
        "  detail TEXT NOT NULL"
        ")"
    )
    return conn


def log_event(event_type: str, username: str, detail: str = "") -> None:
    # Truncate so a malicious or garbage caller can't grow a single row
    # without bound even though MAX_ROWS caps the total table size.
    username = (username or "unknown")[:100]
    detail = (detail or "")[:200]
    try:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO events (ts, event_type, username, detail) VALUES (?, ?, ?, ?)",
                (int(time.time()), event_type, username, detail),
            )
            conn.execute(
                "DELETE FROM events WHERE id NOT IN "
                "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                (MAX_ROWS,),
            )
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        # Logging must never be the reason a real request fails.
        pass


def recent_events(limit: int = 50) -> list:
    try:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT ts, event_type, username, detail FROM events ORDER BY id DESC LIMIT ?",
                (min(limit, MAX_ROWS),),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [
        {"ts": ts, "event_type": event_type, "username": username, "detail": detail}
        for ts, event_type, username, detail in rows
    ]
