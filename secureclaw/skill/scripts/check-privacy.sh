#!/bin/bash
# SecureClaw — Privacy Checker v2.0
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
# Usage: echo "draft text" | bash check-privacy.sh
#    or: bash check-privacy.sh "draft text"
# Returns: exit 0 if clean, exit 1 if flagged
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEXT="${1:-$(cat)}"
FLAGGED=0

flag() {
  local sev="$1" id="$2" match="$3"
  printf "⚠️  [%s] %s: found '%s'\n" "$sev" "$id" "$match"
  FLAGGED=1
}

# Critical — block entirely
echo "$TEXT" | grep -ioE '(sk-ant-|sk-proj-|xoxb-|xoxp-|ghp_|gho_|AKIA)\S+' >/dev/null 2>&1 \
  && flag "CRITICAL" "api_key" "API key/token detected" || true

echo "$TEXT" | grep -oE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' >/dev/null 2>&1 \
  && flag "CRITICAL" "ip_address" "IP address" || true

echo "$TEXT" | grep -ioE '(redis|postgres|mysql|mongo|nginx|apache|minio)\s+(on|running|listening|port)' >/dev/null 2>&1 \
  && flag "CRITICAL" "service" "Service exposure" || true

echo "$TEXT" | grep -ioE 'ssh\s+(login|attempt|key|connect|fail|brute)' >/dev/null 2>&1 \
  && flag "CRITICAL" "ssh" "SSH details" || true

# High — rewrite
echo "$TEXT" | grep -ioE 'my human [A-Z][a-z]+' >/dev/null 2>&1 \
  && flag "HIGH" "owner_name" "Human's name" || true

echo "$TEXT" | grep -oE '~/\.[a-zA-Z]+/' >/dev/null 2>&1 \
  && flag "HIGH" "path" "Internal path" || true

echo "$TEXT" | grep -ioE '(port|listening on)\s+[0-9]{2,5}' >/dev/null 2>&1 \
  && flag "HIGH" "port" "Port number" || true

echo "$TEXT" | grep -ioE "(my human'?s? )(wife|husband|partner|child|daughter|son|mother|father|sister|brother)\s+[A-Z]" >/dev/null 2>&1 \
  && flag "HIGH" "family" "Family member name" || true

echo "$TEXT" | grep -ioE '(pray|mosque|church|temple|synagogue|sabbath|ramadan|diwali)' >/dev/null 2>&1 \
  && flag "HIGH" "religion" "Religious practice" || true

# Medium — rewrite
echo "$TEXT" | grep -ioE '(live[sd]? in|based in|located in|from)\s+[A-Z]' >/dev/null 2>&1 \
  && flag "MEDIUM" "location" "Location" || true

echo "$TEXT" | grep -ioE '(works? (as|at|for)|employed at|studies at|student at)' >/dev/null 2>&1 \
  && flag "MEDIUM" "occupation" "Occupation" || true

echo "$TEXT" | grep -ioE '(pixel|iphone|macbook|mac mini|thinkpad|galaxy|surface)\s*[0-9]*' >/dev/null 2>&1 \
  && flag "MEDIUM" "device" "Device name" || true

echo "$TEXT" | grep -ioE '(tailscale|wireguard|zerotier|cloudflare tunnel|ngrok)' >/dev/null 2>&1 \
  && flag "MEDIUM" "vpn" "VPN/network tool" || true

echo "$TEXT" | grep -ioE '(every (morning|night|day)|daily routine|wakes? up|goes to bed|leaves for)' >/dev/null 2>&1 \
  && flag "MEDIUM" "routine" "Daily routine" || true

if [ $FLAGGED -eq 0 ]; then
  echo "✅ Clean — no PII detected"
  exit 0
else
  echo ""
  echo "🔒 Rewrite to remove flagged items before posting."
  echo "   Quick rule: could a hostile stranger use this to identify your human?"
  exit 1
fi
