#!/bin/bash
# SecureClaw — Cognitive File Integrity Check
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

OPENCLAW_DIR="${OPENCLAW_DIR:-}"
if [ -z "$OPENCLAW_DIR" ]; then
  for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
    [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
  done
fi
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw found" && exit 1

CONFIG="$OPENCLAW_DIR/openclaw.json"
for f in moltbot.json clawdbot.json; do
  [ ! -f "$CONFIG" ] && [ -f "$OPENCLAW_DIR/$f" ] && CONFIG="$OPENCLAW_DIR/$f"
done

# Resolve workspace dir from config, fallback to default
WORKSPACE_DIR="$OPENCLAW_DIR/workspace"
if [ -f "$CONFIG" ]; then
  _ws=$(grep -o '"workspace"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG" 2>/dev/null \
        | grep -o '"[^"]*"$' | tr -d '"' || true)
  [ -n "$_ws" ] && WORKSPACE_DIR="$_ws"
fi

BASELINE_DIR="$OPENCLAW_DIR/.secureclaw/baselines"
REBASELINE="${1:-}"

# Create baselines if they don't exist or if --rebaseline
if [ ! -d "$BASELINE_DIR" ] || [ "$REBASELINE" = "--rebaseline" ]; then
  echo "🔒 Creating baselines..."
  mkdir -p "$BASELINE_DIR"
  CREATED=0
  for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
    if [ -f "$WORKSPACE_DIR/$f" ]; then
      if shasum -a 256 "$WORKSPACE_DIR/$f" > "$BASELINE_DIR/$f.sha256"; then
        CREATED=$((CREATED + 1))
      else
        echo "⚠️  Failed to hash $f — skipping"
        rm -f "$BASELINE_DIR/$f.sha256"
      fi
    fi
  done
  if [ $CREATED -eq 0 ]; then
    echo "⚠️  No cognitive files found to baseline."
  else
    echo "✅ Baselines created for $CREATED file(s). Run again without --rebaseline to check."
  fi
  exit 0
fi

echo "🔒 SecureClaw — Cognitive File Integrity"
echo "========================================="
TAMPERED=0
MISSING=0
CHECKED=0

for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
  if [ -f "$BASELINE_DIR/$f.sha256" ] && [ -f "$WORKSPACE_DIR/$f" ]; then
    EXPECTED=$(awk '{print $1}' "$BASELINE_DIR/$f.sha256")
    CURRENT=$(shasum -a 256 "$WORKSPACE_DIR/$f" | awk '{print $1}')
    CHECKED=$((CHECKED + 1))
    if [ "$EXPECTED" = "$CURRENT" ]; then
      echo "✅ $f — intact"
    else
      echo "🚨 $f — TAMPERED (hash mismatch)"
      echo "   Expected: ${EXPECTED:0:16}..."
      echo "   Current:  ${CURRENT:0:16}..."
      TAMPERED=$((TAMPERED+1))
    fi
  elif [ -f "$WORKSPACE_DIR/$f" ] && [ ! -f "$BASELINE_DIR/$f.sha256" ]; then
    echo "⚠️  $f — no baseline (run with --rebaseline)"
  elif [ -f "$BASELINE_DIR/$f.sha256" ] && [ ! -f "$WORKSPACE_DIR/$f" ]; then
    echo "🚨 $f — DELETED (baseline exists but file is missing!)"
    MISSING=$((MISSING + 1))
  fi
done

ISSUES=$((TAMPERED + MISSING))

if [ $ISSUES -gt 0 ]; then
  echo ""
  echo "🚨 $ISSUES file(s) tampered! Review changes immediately."
  [ $TAMPERED -gt 0 ] && echo "   $TAMPERED file(s) modified since last baseline."
  [ $MISSING -gt 0 ] && echo "   $MISSING file(s) deleted since last baseline."
  echo "   If changes were intentional: bash $0 --rebaseline"
  echo "   If NOT intentional: you may be compromised — run emergency-response.sh"
  exit 2
elif [ $CHECKED -eq 0 ]; then
  echo "⚠️  No cognitive files found to check."
else
  echo ""
  echo "✅ All $CHECKED cognitive file(s) intact"
fi
