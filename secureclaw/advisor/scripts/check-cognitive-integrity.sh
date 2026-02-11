#!/bin/bash
# SecureClaw Advisor — Cognitive File Integrity Check
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done

[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

BASELINE_DIR="$OPENCLAW_DIR/.secureclaw/baselines"

if [ ! -d "$BASELINE_DIR" ]; then
  echo "ℹ️ No baselines found. Creating initial baselines..."
  mkdir -p "$BASELINE_DIR"
  for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md MEMORY.md; do
    [ -f "$OPENCLAW_DIR/$f" ] && shasum -a 256 "$OPENCLAW_DIR/$f" > "$BASELINE_DIR/$f.sha256"
  done
  echo "✅ Baselines created. Future runs will detect changes."
  exit 0
fi

echo "🔒 Checking cognitive file integrity..."

TAMPERED=0
for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
  if [ -f "$BASELINE_DIR/$f.sha256" ] && [ -f "$OPENCLAW_DIR/$f" ]; then
    EXPECTED=$(cat "$BASELINE_DIR/$f.sha256" | awk '{print $1}')
    CURRENT=$(shasum -a 256 "$OPENCLAW_DIR/$f" | awk '{print $1}')
    if [ "$EXPECTED" != "$CURRENT" ]; then
      echo "🔴 TAMPERED: $f — hash mismatch (was: ${EXPECTED:0:12}... now: ${CURRENT:0:12}...)"
      TAMPERED=$((TAMPERED + 1))
    else
      echo "✅ OK: $f"
    fi
  fi
done

if [ $TAMPERED -gt 0 ]; then
  echo ""
  echo "🚨 $TAMPERED cognitive file(s) changed since last baseline!"
  echo "   If these changes were intentional, update baselines:"
  echo "   bash $(dirname "$0")/quick-harden.sh"
  echo ""
  echo "   If NOT intentional, your agent may be compromised!"
  echo "   Recommended: review the changed files immediately."
fi
