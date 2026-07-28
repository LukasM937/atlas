#!/usr/bin/env bash
# Minimal inbound surface. Run once, then verify from another host with nmap.
set -euo pipefail
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp comment 'ssh, rate limited'
ufw allow 80/tcp  comment 'acme + redirect'
ufw allow 443/tcp comment 'apache'
# 8787 is loopback-only and must never appear here.
ufw --force enable
ufw status verbose

# Optional, tighter: restrict 443 to Anthropic's outbound range plus your home
# address. Only do this if you never need the REST facade from elsewhere, and
# remember that http-01 renewal still needs 80 open to the world.
#   ufw delete allow 443/tcp
#   ufw allow from 160.79.104.0/21 to any port 443 proto tcp comment 'anthropic mcp'
#   ufw allow from <home-ip>/32     to any port 443 proto tcp comment 'lukas'
