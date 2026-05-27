"""
Entry point for subnet-blocker.

Orchestrates the pipeline: parse fail2ban logs, look up repeat-banned IPs via
ASN/whois, decide whether to block their subnet, and update the nftables blocklist.
"""

import argparse
import logging
import re
import sys

import asn_lookup
import config
import db
import nftables_manager

log = logging.getLogger(__name__)

# Matches lines like: 2024-01-15 03:22:11,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4
_BAN_RE = re.compile(r"\bBan\s+([\d]{1,3}(?:\.[\d]{1,3}){3})\b")


def parse_fail2ban_log(path: str) -> list[str]:
    """
    Return every IP address found in a 'Ban' action line in the fail2ban log.
    Each occurrence is returned individually — duplicates are intentional and
    used by record_ban() to build up per-IP counts.
    """
    banned = []
    try:
        with open(path) as fh:
            for line in fh:
                match = _BAN_RE.search(line)
                if match:
                    banned.append(match.group(1))
    except FileNotFoundError:
        log.error("fail2ban log not found: %s", path)
    except OSError as exc:
        log.error("Could not read fail2ban log: %s", exc)
    return banned


def process_offenders(dry_run: bool = False):
    """
    Core pipeline: record bans, find repeat offenders, block new subnets.
    """
    log.info("Parsing fail2ban log: %s", config.FAIL2BAN_LOG)
    banned_ips = parse_fail2ban_log(config.FAIL2BAN_LOG)
    log.info("Found %d ban events", len(banned_ips))

    if not dry_run:
        for ip in banned_ips:
            db.record_ban(ip)

    offenders = db.get_repeat_offenders()
    log.info(
        "Found %d repeat offender(s) at threshold >= %d",
        len(offenders),
        config.BAN_THRESHOLD,
    )

    newly_blocked = 0

    for row in offenders:
        ip = row["ip"]
        ban_count = row["ban_count"]

        info = asn_lookup.lookup(ip)
        if not info:
            log.warning("No ASN data for %s — skipping", ip)
            continue

        asn = info["asn"]
        subnet = info["subnet"]
        org = info["org"]

        if asn_lookup.is_whitelisted(asn):
            log.info(
                "SKIP %s (subnet %s, %s %s) — whitelisted ASN",
                ip, subnet, asn, org,
            )
            continue

        if db.is_subnet_blocked(subnet):
            log.debug("SKIP %s — subnet %s already blocked", ip, subnet)
            continue

        log.info(
            "BLOCK subnet %s  [%s %s]  triggered by %s (%d bans)",
            subnet, asn, org, ip, ban_count,
        )

        if not dry_run:
            nftables_manager.add_subnet(subnet)
            db.mark_subnet_blocked(subnet, asn=asn, org=org)
            nftables_manager.reload()

        newly_blocked += 1

    log.info(
        "Done — %d new subnet(s) blocked%s",
        newly_blocked,
        " (dry run)" if dry_run else "",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Parse fail2ban logs and block repeat-offender subnets via nftables."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the full pipeline but make no changes to nftables or the database.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

    if args.dry_run:
        log.info("--- DRY RUN MODE — no changes will be written ---")

    db.init_db()
    nftables_manager.ensure_set_exists()
    process_offenders(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
