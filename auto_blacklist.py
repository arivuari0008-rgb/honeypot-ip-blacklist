#!/usr/bin/env python3
"""
auto_blacklist.py

Reads Cowrie honeypot JSON logs, extracts attacker IPs attempting
SSH brute-force login, and automatically blocks them using iptables.

Intended to run on a schedule via cron for continuous protection.

Usage:
    python3 auto_blacklist.py --log /var/log/cowrie/cowrie.json
"""

import json
import subprocess
import argparse
import os
from datetime import datetime

# File used to keep track of IPs we've already blocked,
# so we don't insert duplicate iptables rules.
BLOCKED_IPS_FILE = "blocked_ips.txt"

# Cowrie event types that indicate a login attempt (successful or failed).
LOGIN_EVENTS = {
    "cowrie.login.success",
    "cowrie.login.failed",
}


def load_blocked_ips():
    """Load the set of IPs already blocked in previous runs."""
    if not os.path.exists(BLOCKED_IPS_FILE):
        return set()
    with open(BLOCKED_IPS_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())


def save_blocked_ip(ip):
    """Persist a newly blocked IP so future runs don't re-process it."""
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(ip + "\n")


def extract_attacker_ips(log_path):
    """
    Parse a Cowrie JSON log file (one JSON object per line) and
    return the set of source IPs that attempted a login.
    """
    attacker_ips = set()

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines rather than crashing the whole run
                continue

            if event.get("eventid") in LOGIN_EVENTS:
                src_ip = event.get("src_ip")
                if src_ip:
                    attacker_ips.add(src_ip)

    return attacker_ips


def block_ip(ip):
    """
    Add an iptables rule to drop all incoming traffic from the given IP.
    Requires root privileges to run.
    """
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[{datetime.now()}] Blocked IP: {ip}")
        return True
    else:
        print(f"[{datetime.now()}] Failed to block {ip}: {result.stderr.strip()}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Extract attacker IPs from Cowrie logs and block them via iptables."
    )
    parser.add_argument(
        "--log",
        default="/var/log/cowrie/cowrie.json",
        help="Path to the Cowrie JSON log file",
    )
    args = parser.parse_args()

    already_blocked = load_blocked_ips()
    attacker_ips = extract_attacker_ips(args.log)

    new_ips = attacker_ips - already_blocked

    if not new_ips:
        print(f"[{datetime.now()}] No new attacker IPs found.")
        return

    for ip in new_ips:
        if block_ip(ip):
            save_blocked_ip(ip)

    print(f"[{datetime.now()}] Run complete. {len(new_ips)} new IP(s) processed.")


if _name_ == "_main_":
    main()
