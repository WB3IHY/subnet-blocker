"""
SQLite database layer for subnet-blocker.

Tracks banned IPs, ban counts, associated subnets/ASNs, and which subnets
have been added to the nftables blocklist.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import config


@contextmanager
def _connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ip_bans (
                ip          TEXT PRIMARY KEY,
                ban_count   INTEGER NOT NULL DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_subnets (
                subnet      TEXT PRIMARY KEY,
                asn         TEXT,
                org         TEXT,
                blocked_at  TEXT NOT NULL
            );
        """)


def record_ban(ip: str):
    """Increment the ban count for an IP, inserting a new row if needed."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("""
            INSERT INTO ip_bans (ip, ban_count, first_seen, last_seen)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                ban_count = ban_count + 1,
                last_seen = excluded.last_seen
        """, (ip, now, now))


def get_repeat_offenders(threshold: int = None) -> list[dict]:
    """Return rows for IPs whose ban_count meets or exceeds threshold."""
    if threshold is None:
        threshold = config.BAN_THRESHOLD
    with _connect() as conn:
        rows = conn.execute("""
            SELECT ip, ban_count, first_seen, last_seen
            FROM ip_bans
            WHERE ban_count >= ?
            ORDER BY ban_count DESC
        """, (threshold,)).fetchall()
    return [dict(r) for r in rows]


def mark_subnet_blocked(subnet: str, asn: str = None, org: str = None):
    """Record that a subnet has been added to the nftables blocklist."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO blocked_subnets (subnet, asn, org, blocked_at)
            VALUES (?, ?, ?, ?)
        """, (subnet, asn, org, now))


def is_subnet_blocked(subnet: str) -> bool:
    """Return True if the subnet is already in the blocklist."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_subnets WHERE subnet = ?", (subnet,)
        ).fetchone()
    return row is not None


def get_blocked_subnets() -> list[dict]:
    """Return all subnets currently recorded in the blocklist."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT subnet, asn, org, blocked_at
            FROM blocked_subnets
            ORDER BY blocked_at DESC
        """).fetchall()
    return [dict(r) for r in rows]
