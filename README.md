# subnet-blocker

Automatically blocks repeat-offender subnets by parsing fail2ban logs, resolving
banned IPs to their originating ASN and BGP prefix via whois, and adding the
subnet to an nftables blocklist. Designed for Ubuntu servers running fail2ban —
particularly those hosting Meshtastic MQTT brokers or other self-hosted services.

Cloud provider ASNs (AWS, GCP, Azure, Linode, etc.) are never auto-blocked.
All actions are logged for review.

---

## How it works

1. Scans `/var/log/fail2ban.log` for `Ban` events and records each IP hit in a
   local SQLite database.
2. Finds IPs whose ban count meets or exceeds the configured threshold (default: 3).
3. For each repeat offender, queries [Team Cymru](https://www.team-cymru.com/ip-bgp-mapping)
   via `whois` to resolve the IP to its ASN, announced BGP prefix (CIDR), and org name.
4. Skips any subnet belonging to a whitelisted cloud-provider ASN.
5. Skips subnets already in the blocklist.
6. Adds new subnets to the nftables `blocklist` set and saves state to
   `/etc/nftables.d/subnet-blocker.nft` for persistence across reboots.

---

## Requirements

- Ubuntu Linux (tested on 22.04/24.04)
- Python 3.10+
- fail2ban
- nftables
- `whois` package (`apt install whois`)
- `python-nftables` Python binding (installed via pip, wraps libnftables)

```
pip install -r requirements.txt
```

---

## nftables setup

subnet-blocker manages elements in an existing nftables set. You need a table,
set, and drop rule in place before running it. Add the following to
`/etc/nftables.conf` (or a file it includes):

```
table inet filter {
    set blocklist {
        type ipv4_addr
        flags interval
        auto-merge
        include "/etc/nftables.d/subnet-blocker.nft"
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @blocklist drop
    }
}
```

Create the persistence directory and an empty include file on first run:

```bash
sudo mkdir -p /etc/nftables.d
sudo touch /etc/nftables.d/subnet-blocker.nft
sudo systemctl reload nftables
```

subnet-blocker will keep `/etc/nftables.d/subnet-blocker.nft` up to date after
each blocking action.

---

## Database setup

Create the directory for the SQLite database:

```bash
sudo mkdir -p /var/lib/subnet-blocker
```

The database and its schema are created automatically on first run.

---

## Configuration

All settings are in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `FAIL2BAN_LOG` | `/var/log/fail2ban.log` | fail2ban log to parse |
| `DB_PATH` | `/var/lib/subnet-blocker/bans.db` | SQLite database path |
| `BAN_THRESHOLD` | `3` | Bans before a subnet is blocked |
| `NFTABLES_FAMILY` | `inet` | nftables address family |
| `NFTABLES_TABLE` | `filter` | nftables table name |
| `NFTABLES_SET` | `blocklist` | nftables set name |
| `NFTABLES_PERSIST_FILE` | `/etc/nftables.d/subnet-blocker.nft` | State file for reboots |

### Whitelisted ASNs

The following ASNs are never auto-blocked. Edit `WHITELISTED_ASNS` in
`config.py` to add or remove entries:

| ASN | Organisation |
|---|---|
| AS14618, AS16509 | Amazon AWS |
| AS15169 | Google GCP |
| AS8075 | Microsoft Azure |
| AS63949 | Linode / Akamai |
| AS20473 | Vultr |
| AS14061 | DigitalOcean |

---

## Usage

subnet-blocker must run as root (or with `CAP_NET_ADMIN`) to write nftables rules.

**Normal run:**
```bash
sudo python3 main.py
```

**Dry run** — full pipeline, no changes written to nftables or the database:
```bash
sudo python3 main.py --dry-run
```

**Increase log verbosity:**
```bash
sudo python3 main.py --log-level DEBUG
```

### Running on a schedule (cron)

To run every 15 minutes as root:

```bash
sudo crontab -e
```

```
*/15 * * * * /usr/bin/python3 /opt/subnet-blocker/main.py >> /var/log/subnet-blocker.log 2>&1
```

---

## Log output

Each run logs decisions for every repeat offender:

```
2026-05-26 03:15:00 INFO     Parsing fail2ban log: /var/log/fail2ban.log
2026-05-26 03:15:00 INFO     Found 142 ban events
2026-05-26 03:15:00 INFO     Found 3 repeat offender(s) at threshold >= 3
2026-05-26 03:15:01 INFO     BLOCK subnet 45.33.0.0/16  [AS63949 LINODE-US]  triggered by 45.33.12.99 (5 bans)
2026-05-26 03:15:01 INFO     SKIP 203.0.113.7 (subnet 203.0.113.0/24, AS64496 EXAMPLE-ORG) — whitelisted ASN
2026-05-26 03:15:02 INFO     Done — 1 new subnet(s) blocked
```

---

## Future

- **v1.1** — Optional MQTT reporting to a configured broker (e.g. `mqtt.tgifmesh.com`)
  for integration with Meshtastic mesh networks.
