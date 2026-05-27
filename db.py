"""
SQLite database layer for subnet-blocker.

Tracks banned IPs, ban counts, associated subnets/ASNs, and which subnets
have been added to the nftables blocklist.
"""

import sqlite3
import config


def get_connection():
    return sqlite3.connect(config.DB_PATH)


def init_db():
    """Create tables if they don't exist."""
    pass


def record_ban(ip: str):
    """Increment the ban count for an IP, inserting a new row if needed."""
    pass


def get_repeat_offenders(threshold: int) -> list[str]:
    """Return IPs whose ban count meets or exceeds threshold."""
    pass


def mark_subnet_blocked(subnet: str):
    """Record that a subnet has been added to the nftables blocklist."""
    pass


def is_subnet_blocked(subnet: str) -> bool:
    """Return True if the subnet is already in the blocklist."""
    pass
