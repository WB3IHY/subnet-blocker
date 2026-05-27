"""Tests for fail2ban log parsing in main.parse_fail2ban_log."""

import pytest
from main import parse_fail2ban_log


def test_extracts_banned_ips(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text(
        "2024-01-15 03:22:11,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4\n"
        "2024-01-15 03:23:00,000 fail2ban.actions [1234]: NOTICE [sshd] Ban 5.6.7.8\n"
    )
    ips, offset = parse_fail2ban_log(str(log))
    assert ips == ["1.2.3.4", "5.6.7.8"]
    assert offset == log.stat().st_size


def test_ignores_non_ban_lines(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text(
        "2024-01-15 03:22:11 fail2ban.actions: NOTICE [sshd] Found 1.2.3.4\n"
        "2024-01-15 03:22:11 fail2ban.actions: NOTICE [sshd] Unban 1.2.3.4\n"
        "2024-01-15 03:22:11 fail2ban.actions: NOTICE [sshd] Ban 9.9.9.9\n"
    )
    ips, _ = parse_fail2ban_log(str(log))
    assert ips == ["9.9.9.9"]


def test_duplicate_bans_returned_individually(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text("Ban 1.2.3.4\nBan 1.2.3.4\nBan 1.2.3.4\n")
    ips, _ = parse_fail2ban_log(str(log))
    assert ips == ["1.2.3.4", "1.2.3.4", "1.2.3.4"]


def test_reads_from_offset(tmp_path):
    log = tmp_path / "fail2ban.log"
    content = b"Ban 1.2.3.4\nBan 5.6.7.8\n"
    log.write_bytes(content)
    first_line_len = len(b"Ban 1.2.3.4\n")
    ips, offset = parse_fail2ban_log(str(log), offset=first_line_len)
    assert ips == ["5.6.7.8"]
    assert offset == len(content)


def test_offset_at_end_of_file_returns_empty(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text("Ban 1.2.3.4\n")
    size = log.stat().st_size
    ips, offset = parse_fail2ban_log(str(log), offset=size)
    assert ips == []
    assert offset == size


def test_log_rotation_resets_offset(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text("Ban 9.9.9.9\n")
    # Stored offset is larger than current file — log has rotated
    ips, offset = parse_fail2ban_log(str(log), offset=99999)
    assert ips == ["9.9.9.9"]
    assert offset == log.stat().st_size


def test_missing_file_returns_empty(tmp_path):
    ips, offset = parse_fail2ban_log(str(tmp_path / "nonexistent.log"))
    assert ips == []
    assert offset == 0


def test_empty_file(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text("")
    ips, offset = parse_fail2ban_log(str(log))
    assert ips == []
    assert offset == 0


def test_multiple_jails_in_log(tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text(
        "NOTICE [sshd] Ban 1.1.1.1\n"
        "NOTICE [nginx-http-auth] Ban 2.2.2.2\n"
        "NOTICE [postfix] Ban 3.3.3.3\n"
    )
    ips, _ = parse_fail2ban_log(str(log))
    assert ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
