"""
Configuration constants and whitelists for subnet-blocker.

Defines paths, thresholds, whitelisted ASNs (AWS, GCP, Azure, Linode, etc.),
and optional MQTT reporting settings.
"""

# Path to the fail2ban log file
FAIL2BAN_LOG = "/var/log/fail2ban.log"

# SQLite database path
DB_PATH = "/var/lib/subnet-blocker/bans.db"

# How many bans before a subnet is blocked
BAN_THRESHOLD = 3

# nftables set name for blocked subnets
NFTABLES_SET = "blocklist"

# ASNs that must never be auto-blocked (cloud provider infrastructure)
WHITELISTED_ASNS = {
    "AS14618",  # Amazon AWS
    "AS16509",  # Amazon AWS
    "AS15169",  # Google GCP
    "AS8075",   # Microsoft Azure
    "AS63949",  # Linode / Akamai
    "AS20473",  # Vultr
    "AS14061",  # DigitalOcean
}

# Optional MQTT reporting
MQTT_ENABLED = False
MQTT_BROKER = "mqtt.tgifmesh.com"
MQTT_PORT = 1883
MQTT_TOPIC = "subnet-blocker/events"
MQTT_NODE_ID = "!ac110002"
