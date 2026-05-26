## Project: Automated Subnet Blocker

### Purpose
Parse fail2ban logs for repeat-banned IPs, identify scanner infrastructure via
whois/ASN lookups, and automatically block bad subnets via nftables. Open-source
tool targeted at the Meshtastic and self-hosted MQTT community.

### Stack
- Python 3
- sqlite3 (ban tracking database)
- python-nftables (blocklist management)
- subprocess (whois lookups)

### Deployment target
Ubuntu Linux server (Ionos VPS). No Docker.

### Optional feature
MQTT reporting to mqtt.tgifmesh.com (cloud node !ac110002)

### Key design rules
- Never auto-block whitelisted cloud provider ASNs (AWS, GCP, Azure, Linode, etc.)
- All actions logged for review
- nftables blocklist reloaded after each update
