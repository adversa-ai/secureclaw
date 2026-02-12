#!/bin/bash
# SecureClaw — Emergency Response
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
# Run when you suspect compromise
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw found" && exit 1

echo "🚨 SecureClaw EMERGENCY RESPONSE"
echo "================================="
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# If plugin available, delegate to it
if command -v openclaw >/dev/null 2>&1 && openclaw secureclaw status --help >/dev/null 2>&1; then
  echo "🔒 Plugin detected — running plugin audit..."
  openclaw secureclaw audit
  exit 0
fi

echo "⚠️  No plugin — running manual emergency checks"
echo ""

# 1. Check cognitive file integrity
echo "── Checking cognitive file integrity ──"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/check-integrity.sh" 2>/dev/null || echo "⚠️  Integrity check failed or baselines missing"
echo ""

# 2. Check for suspicious recent file changes
echo "── Files modified in last 30 minutes ──"
find "$OPENCLAW_DIR" -maxdepth 2 -mmin -30 -type f 2>/dev/null | grep -v node_modules | grep -v '.git' || echo "   None found"
echo ""

# 3. Check for exposed ports
echo "── Open ports check ──"
if command -v lsof >/dev/null 2>&1; then
  lsof -i -P -n 2>/dev/null | grep -i 'openclaw\|moltbot\|clawdbot\|node.*LISTEN\|18789\|18790' || echo "   No OpenClaw ports detected"
elif command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null | grep -E '18789|18790' || echo "   No OpenClaw ports detected"
fi
echo ""

# 4. Check for suspicious processes
echo "── Suspicious processes ──"
ps aux 2>/dev/null | grep -iE 'curl.*\|.*sh|wget.*\|.*bash|nc -|ncat ' | grep -v grep || echo "   None found"
echo ""

# 5. Quick audit
echo "── Quick security audit ──"
bash "$SCRIPT_DIR/quick-audit.sh" 2>/dev/null || echo "⚠️  Audit failed"
echo ""

# 6. Log incident
if mkdir -p "$OPENCLAW_DIR/.secureclaw" 2>/dev/null; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] EMERGENCY_RESPONSE triggered" \
    >> "$OPENCLAW_DIR/.secureclaw/events.log" 2>/dev/null || echo "⚠️  Could not write to incident log"
else
  echo "⚠️  Could not create log directory"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚨 RECOMMENDED ACTIONS FOR YOUR HUMAN:"
echo ""
echo "  1. Stop the OpenClaw gateway process"
echo "  2. Review SOUL.md and MEMORY.md for unauthorized changes"
echo "  3. Check session logs for unusual activity"
echo "  4. Rotate ALL API keys and credentials"
echo "  5. Review installed skills for unfamiliar entries"
echo "  6. Check if gateway was exposed: netstat -an | grep 18789"
echo ""
echo "  For automated incident response, install the full plugin:"
echo "    openclaw plugins install secureclaw"
echo "    openclaw secureclaw audit"
