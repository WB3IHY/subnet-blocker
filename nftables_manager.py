"""
nftables blocklist management for subnet-blocker.

Adds and removes subnets from a named nftables set. Changes take effect
immediately in the kernel; state is saved to a persist file so the blocklist
survives reboots when included in the nftables service config.
"""

import json
import logging
import subprocess

import nftables

import config

log = logging.getLogger(__name__)

_FAMILY = config.NFTABLES_FAMILY
_TABLE = config.NFTABLES_TABLE
_SET = config.NFTABLES_SET
_PERSIST_FILE = config.NFTABLES_PERSIST_FILE


def _run(cmd: str) -> str:
    """Run an nftables command string, return JSON output, raise on error."""
    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(cmd)
    if rc != 0:
        raise RuntimeError(f"nftables error (rc={rc}): {error.strip()}")
    return output


def ensure_set_exists():
    """Create the table and blocklist set if they don't already exist."""
    _run(f"add table {_FAMILY} {_TABLE}")
    _run(
        f"add set {_FAMILY} {_TABLE} {_SET} "
        f"{{ type ipv4_addr; flags interval; auto-merge; }}"
    )
    log.info("Ensured nftables set %s/%s/%s exists", _FAMILY, _TABLE, _SET)


def add_subnet(subnet: str):
    """Add a CIDR subnet to the nftables blocklist set."""
    _run(f"add element {_FAMILY} {_TABLE} {_SET} {{ {subnet} }}")
    log.info("Added to blocklist: %s", subnet)
    _save_state()


def remove_subnet(subnet: str):
    """Remove a CIDR subnet from the nftables blocklist set."""
    _run(f"delete element {_FAMILY} {_TABLE} {_SET} {{ {subnet} }}")
    log.info("Removed from blocklist: %s", subnet)
    _save_state()


def list_blocked() -> list[str]:
    """Return the current contents of the nftables blocklist set as CIDR strings."""
    try:
        raw = _run(f"list set {_FAMILY} {_TABLE} {_SET}")
        return _parse_set_elements(raw)
    except RuntimeError as exc:
        log.warning("Could not read blocklist: %s", exc)
        return []


def reload():
    """
    Save state and reload the nftables service.

    Changes from add_subnet/remove_subnet are already live in the kernel.
    This persists them to disk and signals systemd so they survive reboots.
    """
    _save_state()
    try:
        subprocess.run(["systemctl", "reload", "nftables"], check=True)
        log.info("nftables service reloaded")
    except subprocess.CalledProcessError as exc:
        log.error("Failed to reload nftables service: %s", exc)
        raise
    except FileNotFoundError:
        log.warning("systemctl not found; skipping service reload (non-systemd host?)")


def _save_state():
    """Write current set elements to the nftables persistence include file."""
    try:
        raw = _run(f"list set {_FAMILY} {_TABLE} {_SET}")
    except RuntimeError as exc:
        log.error("Could not read blocklist for persistence: %s", exc)
        return

    elements = _parse_set_elements(raw)

    lines = [
        "#!/usr/sbin/nft -f",
        "",
        f"add table {_FAMILY} {_TABLE}",
        f"add set {_FAMILY} {_TABLE} {_SET} "
        f"{{ type ipv4_addr; flags interval; auto-merge; }}",
        f"flush set {_FAMILY} {_TABLE} {_SET}",
    ]
    if elements:
        lines.append(
            f"add element {_FAMILY} {_TABLE} {_SET} {{ {', '.join(elements)} }}"
        )

    try:
        with open(_PERSIST_FILE, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        log.debug("Saved %d blocklist entries to %s", len(elements), _PERSIST_FILE)
    except OSError as exc:
        log.error("Could not write persistence file %s: %s", _PERSIST_FILE, exc)


def _parse_set_elements(json_output: str) -> list[str]:
    """Parse JSON output from 'nft list set' into a list of CIDR strings."""
    if not json_output:
        return []
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return []

    for item in data.get("nftables", []):
        set_obj = item.get("set")
        if not isinstance(set_obj, dict):
            continue
        result = []
        for elem in set_obj.get("elem", []):
            if isinstance(elem, dict) and "prefix" in elem:
                addr = elem["prefix"].get("addr", "")
                length = elem["prefix"].get("len", "")
                result.append(f"{addr}/{length}")
            elif isinstance(elem, str):
                result.append(elem)
        return result

    return []
