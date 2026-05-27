"""Tests for the SQLite database layer in db.py."""

import pytest
import config
import db


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Point DB_PATH at a temp file and initialise a fresh schema for each test."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()


# --- record_ban / get_repeat_offenders ---

def test_record_ban_inserts_new_ip():
    db.record_ban("1.2.3.4")
    rows = db.get_repeat_offenders(threshold=1)
    assert any(r["ip"] == "1.2.3.4" for r in rows)


def test_record_ban_increments_count():
    db.record_ban("1.2.3.4")
    db.record_ban("1.2.3.4")
    db.record_ban("1.2.3.4")
    rows = db.get_repeat_offenders(threshold=1)
    row = next(r for r in rows if r["ip"] == "1.2.3.4")
    assert row["ban_count"] == 3


def test_record_ban_multiple_ips_tracked_independently():
    db.record_ban("1.2.3.4")
    db.record_ban("1.2.3.4")
    db.record_ban("5.6.7.8")
    rows = {r["ip"]: r["ban_count"] for r in db.get_repeat_offenders(threshold=1)}
    assert rows["1.2.3.4"] == 2
    assert rows["5.6.7.8"] == 1


def test_get_repeat_offenders_threshold_filters_low_counts():
    db.record_ban("1.2.3.4")
    db.record_ban("1.2.3.4")
    db.record_ban("5.6.7.8")  # only 1 ban — below threshold
    rows = db.get_repeat_offenders(threshold=2)
    ips = [r["ip"] for r in rows]
    assert "1.2.3.4" in ips
    assert "5.6.7.8" not in ips


def test_get_repeat_offenders_uses_config_threshold_by_default(monkeypatch):
    monkeypatch.setattr(config, "BAN_THRESHOLD", 2)
    db.record_ban("1.2.3.4")
    db.record_ban("1.2.3.4")
    db.record_ban("5.6.7.8")
    rows = db.get_repeat_offenders()
    ips = [r["ip"] for r in rows]
    assert "1.2.3.4" in ips
    assert "5.6.7.8" not in ips


def test_get_repeat_offenders_returns_required_fields():
    db.record_ban("1.2.3.4")
    row = db.get_repeat_offenders(threshold=1)[0]
    assert "ip" in row
    assert "ban_count" in row
    assert "first_seen" in row
    assert "last_seen" in row


def test_get_repeat_offenders_sorted_by_count_descending():
    for _ in range(5):
        db.record_ban("5.6.7.8")
    for _ in range(2):
        db.record_ban("1.2.3.4")
    rows = db.get_repeat_offenders(threshold=1)
    counts = [r["ban_count"] for r in rows]
    assert counts == sorted(counts, reverse=True)


# --- mark_subnet_blocked / is_subnet_blocked / get_blocked_subnets ---

def test_is_subnet_blocked_false_for_unknown():
    assert not db.is_subnet_blocked("10.0.0.0/8")


def test_mark_subnet_blocked_and_check():
    db.mark_subnet_blocked("10.0.0.0/8", asn="AS12345", org="TEST-ORG")
    assert db.is_subnet_blocked("10.0.0.0/8")


def test_mark_subnet_blocked_idempotent():
    db.mark_subnet_blocked("10.0.0.0/8")
    db.mark_subnet_blocked("10.0.0.0/8")  # second call must not raise
    assert db.is_subnet_blocked("10.0.0.0/8")


def test_get_blocked_subnets_returns_all_entries():
    db.mark_subnet_blocked("1.0.0.0/8", asn="AS1", org="ORG1")
    db.mark_subnet_blocked("2.0.0.0/8", asn="AS2", org="ORG2")
    subnets = db.get_blocked_subnets()
    assert len(subnets) == 2
    ips = [s["subnet"] for s in subnets]
    assert "1.0.0.0/8" in ips
    assert "2.0.0.0/8" in ips


def test_get_blocked_subnets_stores_asn_and_org():
    db.mark_subnet_blocked("1.0.0.0/8", asn="AS99", org="SOME-ORG")
    row = db.get_blocked_subnets()[0]
    assert row["asn"] == "AS99"
    assert row["org"] == "SOME-ORG"


# --- get_log_offset / set_log_offset ---

def test_get_log_offset_defaults_to_zero():
    assert db.get_log_offset("/var/log/fail2ban.log") == 0


def test_log_offset_round_trip():
    db.set_log_offset("/var/log/fail2ban.log", 12345)
    assert db.get_log_offset("/var/log/fail2ban.log") == 12345


def test_log_offset_update_overwrites_previous():
    db.set_log_offset("/var/log/fail2ban.log", 100)
    db.set_log_offset("/var/log/fail2ban.log", 999)
    assert db.get_log_offset("/var/log/fail2ban.log") == 999


def test_log_offsets_tracked_per_path():
    db.set_log_offset("/path/a.log", 100)
    db.set_log_offset("/path/b.log", 200)
    assert db.get_log_offset("/path/a.log") == 100
    assert db.get_log_offset("/path/b.log") == 200
