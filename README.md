# Automated IP Blacklisting Firewall Using Honeypot Logs

A security automation project that uses a *Cowrie honeypot* to detect brute-force SSH
attacks, the *ELK Stack* to parse and visualize attacker activity in real time, and a
*Python script* to automatically block detected attacker IPs using iptables — scheduled
via crontab for continuous, hands-off protection.

## Overview

- *Honeypot:* Cowrie, configured to emulate an SSH/Telnet service and log every login
  attempt as structured JSON
- *Log Pipeline:* ELK Stack (Elasticsearch, Logstash, Kibana) ingests Cowrie's logs for
  real-time search and visualization of attacker IPs, usernames/passwords tried, and attack
  volume over time
- *Automated Response:* A Python script (auto_blacklist.py) parses the Cowrie log,
  extracts attacker source IPs, and blocks them with iptables
- *Scheduling:* The script runs on a crontab schedule, so new attackers get blocked
  automatically without manual intervention

## How It Works

1. Cowrie listens on the exposed SSH port and logs every connection/login attempt to
   cowrie.json.
2. Logstash ships and parses these logs into Elasticsearch; Kibana is used to visualize
   attack patterns (top source IPs, attempted credentials, attack frequency).
3. auto_blacklist.py reads the Cowrie JSON log, extracts IPs tied to login events
   (cowrie.login.success / cowrie.login.failed), and checks them against a local
   blocked_ips.txt file to avoid duplicate rules.
4. Any new attacker IP is blocked immediately via an iptables DROP rule and recorded so
   it won't be reprocessed on the next run.
5. A cron job runs the script periodically, so the block list grows automatically as new
   attacks are detected.

## Example Cron Entry

Run every 5 minutes:


*/5 * * * * /usr/bin/python3 /path/to/auto_blacklist.py --log /var/log/cowrie/cowrie.json >> /var/log/auto_blacklist.log 2>&1


## Files

- auto_blacklist.py — parses Cowrie logs and blocks attacker IPs via iptables
- blocked_ips.txt — generated automatically at runtime; tracks IPs already blocked

## Skills Practiced

Cowrie Honeypot ELK Stack (Elasticsearch, Logstash, Kibana) Python scripting
iptables / firewall automation cron scheduling log parsing (JSON) SSH brute-force detection

## Notes

This repo documents a personal lab project used for learning, not a production security
tool. Run only in an isolated/lab environment — exposing a honeypot on a live network
requires careful network segmentation.
