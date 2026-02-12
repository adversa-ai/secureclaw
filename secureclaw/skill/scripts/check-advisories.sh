#!/bin/bash
# SecureClaw — Advisory Feed Checker
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

FEED_URL="${SECURECLAW_FEED_URL:-https://adversa-ai.github.io/secureclaw-advisories/feed.json}"

echo "🔒 SecureClaw — Advisory Check"
echo "==============================="

# Try fetching feed
FEED=$(curl -sf --max-time 10 "$FEED_URL" 2>/dev/null || echo "")

if [ -z "$FEED" ]; then
  echo "ℹ️  Could not reach advisory feed"
  echo "   URL: $FEED_URL"
  echo "   This is expected if the feed hasn't been set up yet."
  exit 0
fi

# Parse with python3 if available
if command -v python3 >/dev/null 2>&1; then
  python3 -c "
import json, sys
try:
    feed = json.loads(sys.stdin.read())
    advisories = feed.get('advisories', [])
    critical = [a for a in advisories if a.get('severity') in ('critical', 'high')]
    if not critical:
        print('✅ No critical or high advisories')
    else:
        print(f'⚠️  {len(critical)} critical/high advisories:')
        for a in critical[:10]:
            print(f\"  [{a.get('severity','?').upper()}] {a.get('id','?')}: {a.get('title','?')}\")
            if a.get('action'):
                print(f\"    Action: {a['action']}\")
except Exception as e:
    print(f'⚠️  Error parsing feed: {e}')
" <<< "$FEED"
else
  echo "ℹ️  python3 not available for feed parsing"
  echo "   Raw feed available at: $FEED_URL"
fi
