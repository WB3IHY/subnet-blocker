"""Tests for ASN/whois lookup in asn_lookup.py."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import asn_lookup
import config

# Cymru header line as it appears in real responses
_HEADER = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"


def _cymru(data_line: str) -> str:
    return _HEADER + data_line


# --- _parse_cymru ---

def test_parse_cymru_valid_response():
    output = _cymru("15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE, US\n")
    result = asn_lookup._parse_cymru(output, "8.8.8.8")
    assert result == {"asn": "AS15169", "subnet": "8.8.8.0/24", "org": "GOOGLE, US"}


def test_parse_cymru_asn_prefixed_with_AS():
    output = _cymru("64496   | 1.2.3.4          | 1.2.0.0/16          | US | arin     | 2020-01-01 | EXAMPLE-AS\n")
    result = asn_lookup._parse_cymru(output, "1.2.3.4")
    assert result["asn"] == "AS64496"


def test_parse_cymru_na_asn_returns_empty():
    output = _cymru("NA      | 1.2.3.4          | NA                  | -- | --       | --         | NA\n")
    assert asn_lookup._parse_cymru(output, "1.2.3.4") == {}


def test_parse_cymru_na_subnet_returns_empty():
    output = _cymru("12345   | 1.2.3.4          | NA                  | US | arin     | NA         | SOME-ORG\n")
    assert asn_lookup._parse_cymru(output, "1.2.3.4") == {}


def test_parse_cymru_na_org_returns_empty_string():
    output = _cymru("12345   | 1.2.3.4          | 1.2.3.0/24          | US | arin     | 2020-01-01 | NA\n")
    result = asn_lookup._parse_cymru(output, "1.2.3.4")
    assert result["org"] == ""


def test_parse_cymru_empty_output_returns_empty():
    assert asn_lookup._parse_cymru("", "1.2.3.4") == {}


def test_parse_cymru_header_only_returns_empty():
    assert asn_lookup._parse_cymru(_HEADER, "1.2.3.4") == {}


def test_parse_cymru_too_few_fields_returns_empty():
    assert asn_lookup._parse_cymru("12345 | 1.2.3.4\n", "1.2.3.4") == {}


# --- is_whitelisted ---

def test_is_whitelisted_google():
    assert asn_lookup.is_whitelisted("AS15169")


def test_is_whitelisted_aws():
    assert asn_lookup.is_whitelisted("AS14618")
    assert asn_lookup.is_whitelisted("AS16509")


def test_is_whitelisted_azure():
    assert asn_lookup.is_whitelisted("AS8075")


def test_is_whitelisted_unknown_asn_returns_false():
    assert not asn_lookup.is_whitelisted("AS99999")


def test_is_whitelisted_requires_as_prefix():
    # Raw number without prefix must not match
    assert not asn_lookup.is_whitelisted("15169")


# --- lookup (subprocess mocked) ---

def _mock_result(stdout: str) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    return m


_VALID_RESPONSE = _cymru(
    "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE, US\n"
)


def test_lookup_returns_parsed_result():
    with patch("asn_lookup.subprocess.run", return_value=_mock_result(_VALID_RESPONSE)):
        result = asn_lookup.lookup("8.8.8.8")
    assert result["asn"] == "AS15169"
    assert result["subnet"] == "8.8.8.0/24"
    assert result["org"] == "GOOGLE, US"


def test_lookup_private_ip_skipped():
    assert asn_lookup.lookup("192.168.1.1") == {}


def test_lookup_loopback_skipped():
    assert asn_lookup.lookup("127.0.0.1") == {}


def test_lookup_link_local_skipped():
    assert asn_lookup.lookup("169.254.1.1") == {}


def test_lookup_invalid_ip_returns_empty():
    assert asn_lookup.lookup("not-an-ip") == {}


def test_lookup_timeout_returns_empty():
    with patch(
        "asn_lookup.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="whois", timeout=15),
    ):
        assert asn_lookup.lookup("8.8.8.8") == {}


def test_lookup_whois_not_installed_returns_empty():
    with patch("asn_lookup.subprocess.run", side_effect=FileNotFoundError):
        assert asn_lookup.lookup("8.8.8.8") == {}


def test_lookup_os_error_returns_empty():
    with patch("asn_lookup.subprocess.run", side_effect=OSError("network error")):
        assert asn_lookup.lookup("8.8.8.8") == {}


def test_lookup_no_subprocess_call_for_private_ip():
    with patch("asn_lookup.subprocess.run") as mock_run:
        asn_lookup.lookup("10.0.0.1")
        mock_run.assert_not_called()
