"""
ASN and subnet lookup for subnet-blocker.

Uses subprocess whois queries to resolve an IP address to its originating ASN
and announced subnet (CIDR). Results are used to decide whether to block the
entire subnet and to check against the whitelisted-ASN list in config.
"""

import subprocess
import config


def lookup(ip: str) -> dict:
    """
    Return {'asn': str, 'subnet': str, 'org': str} for the given IP.
    Returns an empty dict if the lookup fails or produces no usable data.
    """
    pass


def is_whitelisted(asn: str) -> bool:
    """Return True if the ASN is in the cloud-provider whitelist."""
    return asn in config.WHITELISTED_ASNS
