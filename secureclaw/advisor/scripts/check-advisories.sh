#!/bin/bash
# SecureClaw Advisor — Security Advisory Feed Checker
set -euo pipefail

FEED_URL="${SECURECLAW_ADVISORY_URL:-https://secureclaw.dev/advisories/feed.json}"
FALLBACK_URL="https://raw.githubusercontent.com/adversa-ai/secureclaw/main/advisories/feed.json"

echo "🔒 Checking security advisories..."

# Try primary URL, fall back to GitHub raw
FEED=$(curl -sf --max-time 10 "$FEED_URL" 2>/dev/null || \
       curl -sf --max-time 10 "$FALLBACK_URL" 2>/dev/null || \
       echo "")

if [ -z "$FEED" ]; then
  echo "⚠️ Could not fetch advisory feed (network issue or feed unavailable)"
  exit 1
fi

# Parse advisories using python3 (available on most systems)
echo "$FEED" | python3 -c "
import json, sys
try:
    feed = json.load(sys.stdin)
    advisories = feed.get('advisories', [])
    critical = [a for a in advisories if a.get('severity') in ('critical', 'high')]

    if not critical:
        print('✅ No critical or high-severity advisories.')
        sys.exit(0)

    print(f'⚠️  {len(critical)} critical/high advisories found:')
    print()
    for a in critical[:10]:
        sev = a.get('severity', 'unknown').upper()
        title = a.get('title', 'No title')
        aid = a.get('id', 'Unknown')
        action = a.get('action', 'Review advisory')
        print(f'  🔴 [{sev}] {aid}: {title}')
        print(f'     Action: {action}')
        print()
except Exception as e:
    print(f'⚠️ Error parsing advisory feed: {e}')
    sys.exit(1)
"
