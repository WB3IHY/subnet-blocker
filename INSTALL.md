# Installation Guide

This guide walks through deploying subnet-blocker on a fresh Ubuntu 22.04 or
24.04 server. All commands that modify system files require root privileges.

---

## 1. System dependencies

```bash
sudo apt update
sudo apt install -y git python3 python3-pip whois nftables
```

Enable and start nftables if it isn't already running:

```bash
sudo systemctl enable --now nftables
```

---

## 2. Clone the repository

Choose an install location. `/opt/subnet-blocker` is recommended for
system-wide tools:

```bash
sudo git clone https://github.com/WB3IHY/subnet-blocker.git /opt/subnet-blocker
cd /opt/subnet-blocker
```

---

## 3. Install Python dependencies

`python3-nftables` is a system package distributed with nftables and must be
installed via apt, not pip:

```bash
sudo apt install -y python3-nftables
```

subnet-blocker has no pip-installable dependencies.

---

## 4. Configure subnet-blocker

Open `config.py` in your editor of choice:

```bash
sudo nano /opt/subnet-blocker/config.py
```

Key settings to review:

| Setting | Default | Notes |
|---|---|---|
| `FAIL2BAN_LOG` | `/var/log/fail2ban.log` | Change if fail2ban logs elsewhere |
| `BAN_THRESHOLD` | `3` | Lower = more aggressive blocking |
| `NFTABLES_TABLE` | `filter` | Must match your nftables table name |
| `NFTABLES_SET` | `blocklist` | Must match your nftables set name |

Add any additional ASNs you want to protect from auto-blocking to
`WHITELISTED_ASNS`. Use the format `"AS12345"`.

---

## 5. Set up nftables

### Create the persistence directory

subnet-blocker writes its blocklist state to `/etc/nftables.d/subnet-blocker.nft`
on every run. This directory and file **must exist before the first run**:

```bash
sudo mkdir -p /etc/nftables.d
sudo touch /etc/nftables.d/subnet-blocker.nft
```

### Add the blocklist table, set, and drop rule

Edit `/etc/nftables.conf`:

```bash
sudo nano /etc/nftables.conf
```

Add the following (or merge with your existing configuration):

```
table inet filter {
    set blocklist {
        type ipv4_addr
        flags interval
        auto-merge
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @blocklist drop
    }
}
```

> **If you already have an `inet filter` table and `input` chain**, add only
> the `set blocklist { ... }` block and the `ip saddr @blocklist drop` rule to
> your existing chain — do not duplicate the table or chain declarations.

### Add the include directive

At the very bottom of `/etc/nftables.conf`, add:

```
include "/etc/nftables.d/*.nft"
```

This tells nftables to load subnet-blocker's saved state on every service start
or reload. Without this line the blocklist set will be empty after a service
restart even though the entries are saved to disk.

### Reload nftables to apply the changes

```bash
sudo systemctl reload nftables
```

### Verify the set exists

```bash
sudo nft list set inet filter blocklist
```

You should see an empty set with `flags interval`.

---

## 6. Create the database directory

```bash
sudo mkdir -p /var/lib/subnet-blocker
```

The SQLite database and schema are created automatically on first run.

---

## 7. Test with a dry run

Before letting subnet-blocker make any real changes, run it in dry-run mode to
see what it would do:

```bash
sudo python3 /opt/subnet-blocker/main.py --dry-run
```

The output will show which subnets would be blocked, which are skipped due to
whitelisted ASNs, and which are already blocked — with no changes written.

Add `--log-level DEBUG` for full detail including already-blocked skips:

```bash
sudo python3 /opt/subnet-blocker/main.py --dry-run --log-level DEBUG
```

---

## 8. Run manually (first live run)

Once the dry run output looks reasonable:

```bash
sudo python3 /opt/subnet-blocker/main.py
```

Check the nftables set to confirm any new entries:

```bash
sudo nft list set inet filter blocklist
```

---

## 9. Automate with cron or systemd

Choose one of the following.

### Option A — cron job

Run every 15 minutes as root:

```bash
sudo crontab -e
```

Add this line:

```
*/15 * * * * /usr/bin/python3 /opt/subnet-blocker/main.py >> /var/log/subnet-blocker.log 2>&1
```

Rotate the log to prevent unbounded growth (`/etc/logrotate.d/subnet-blocker`):

```
/var/log/subnet-blocker.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
```

### Option B — systemd timer

Create the service unit at `/etc/systemd/system/subnet-blocker.service`:

```ini
[Unit]
Description=Subnet Blocker — block repeat-offender subnets via nftables
After=network.target nftables.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/subnet-blocker/main.py
StandardOutput=journal
StandardError=journal
```

Create the timer unit at `/etc/systemd/system/subnet-blocker.timer`:

```ini
[Unit]
Description=Run subnet-blocker every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now subnet-blocker.timer
```

Check the timer status:

```bash
sudo systemctl list-timers subnet-blocker.timer
```

View logs:

```bash
sudo journalctl -u subnet-blocker.service -f
```

---

## 10. Verify the blocklist persists across reboots

After at least one subnet has been blocked, reboot and confirm the entries
survive:

```bash
sudo reboot
# after reboot:
sudo nft list set inet filter blocklist
```

Entries should be present, loaded from `/etc/nftables.d/subnet-blocker.nft`
by the nftables service at boot.
