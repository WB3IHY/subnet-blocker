"""
ASN and subnet lookup for subnet-blocker.

Queries Team Cymru's whois service to resolve an IP to its originating ASN,
announced BGP prefix (CIDR), and org name. Consistent output regardless of
regional registry (ARIN, RIPE, APNIC, etc.).
"""

import ipaddress
import logging
import subprocess

import config

log = logging.getLogger(__name__)

_CYMRU_HOST = "whois.cymru.com"
_TIMEOUT = 15  # seconds


def lookup(ip: str) -> dict:
    """
    Return {'asn': str, 'subnet': str, 'org': str} for the given IP.
    Returns an empty dict if the IP is private/reserved, the lookup fails,
    or the response contains no usable data.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        log.warning("Invalid IP address: %s", ip)
        return {}

    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        log.debug("Skipping non-public address: %s", ip)
        return {}

    try:
        result = subprocess.run(
            ["whois", "-h", _CYMRU_HOST, f" -v {ip}"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except FileNotFoundError:
        log.error("whois binary not found — install whois package")
        return {}
    except subprocess.TimeoutExpired:
        log.warning("whois lookup timed out for %s", ip)
        return {}
    except OSError as exc:
        log.warning("whois lookup failed for %s: %s", ip, exc)
        return {}

    return _parse_cymru(result.stdout, ip)


def _parse_cymru(output: str, ip: str = "") -> dict:
    """
    Parse Team Cymru verbose whois output.

    Expected format (header + one data line):
        AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
        15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE, US
    """
    data_lines = [
        line for line in output.strip().splitlines()
        if "|" in line and not line.lstrip().startswith("AS ")
    ]

    if not data_lines:
        log.warning("No usable whois data for %s", ip)
        return {}

    parts = [p.strip() for p in data_lines[0].split("|")]
    if len(parts) < 7:
        log.warning("Unexpected whois response format for %s", ip)
        return {}

    raw_asn, _, subnet, _, _, _, org = parts[:7]

    if not raw_asn or raw_asn == "NA":
        log.debug("No ASN in whois response for %s", ip)
        return {}

    if not subnet or subnet == "NA":
        log.debug("No BGP prefix in whois response for %s", ip)
        return {}

    return {
        "asn": f"AS{raw_asn}",
        "subnet": subnet,
        "org": org if org and org != "NA" else "",
    }


def is_whitelisted(asn: str) -> bool:
    """Return True if the ASN is in the cloud-provider whitelist."""
    return asn in config.WHITELISTED_ASNS
