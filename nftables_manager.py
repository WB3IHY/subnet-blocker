"""
nftables blocklist management for subnet-blocker.

Adds subnets to a named nftables set and reloads the ruleset after each change.
Uses python-nftables for structured interaction with the kernel firewall.
"""

import nftables
import config


def add_subnet(subnet: str):
    """Add a CIDR subnet to the nftables blocklist set."""
    pass


def remove_subnet(subnet: str):
    """Remove a CIDR subnet from the nftables blocklist set."""
    pass


def list_blocked() -> list[str]:
    """Return the current contents of the nftables blocklist set."""
    pass


def reload():
    """Flush and reload the nftables ruleset to apply pending changes."""
    pass
