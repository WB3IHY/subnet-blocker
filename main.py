"""
Entry point for subnet-blocker.

Orchestrates the pipeline: parse fail2ban logs, look up repeat-banned IPs via
ASN/whois, decide whether to block their subnet, and update the nftables blocklist.
"""


def main():
    pass


if __name__ == "__main__":
    main()
