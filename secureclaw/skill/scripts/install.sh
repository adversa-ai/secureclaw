#!/bin/bash
# SecureClaw — Installer & Updater
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

echo "🔒 SecureClaw — Installer"
echo "=================================="

# Find OpenClaw
OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1
echo "📁 Found: $OPENCLAW_DIR"

# Determine source
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$OPENCLAW_DIR/skills/secureclaw"

# Get new version
NEW_VER="unknown"
if [ -f "$SCRIPT_DIR/skill.json" ]; then
  NEW_VER=$(grep '"version"' "$SCRIPT_DIR/skill.json" | head -1 | sed 's/.*"version".*"\([^"]*\)".*/\1/')
fi

# Check existing installation
if [ -d "$DEST" ]; then
  OLD_VER="unknown"
  if [ -f "$DEST/skill.json" ]; then
    OLD_VER=$(grep '"version"' "$DEST/skill.json" | head -1 | sed 's/.*"version".*"\([^"]*\)".*/\1/')
  fi

  if [ "$OLD_VER" = "$NEW_VER" ]; then
    echo "ℹ️  Already at v$NEW_VER — reinstalling"
  else
    echo "⬆️  Updating: v$OLD_VER → v$NEW_VER"
  fi

  BACKUP_DIR="$DEST.bak.$(date +%s)"
  echo "📦 Backing up to $(basename "$BACKUP_DIR")"
  cp -r "$DEST" "$BACKUP_DIR"
else
  echo "🆕 Fresh install — v$NEW_VER"
fi

# Install (skip copy if source and dest are the same directory)
if [ "$(cd "$SCRIPT_DIR" && pwd -P)" = "$(cd "$DEST" 2>/dev/null && pwd -P)" ] 2>/dev/null; then
  echo "ℹ️  Source and destination are the same — skipping copy"
else
  mkdir -p "$DEST"
  cp -r "$SCRIPT_DIR"/* "$DEST/"
fi
chmod +x "$DEST/scripts/"*.sh

echo ""
echo "✅ SecureClaw v$NEW_VER installed to $DEST"
echo ""
echo "Next steps:"
echo "  1. Run audit:  bash $DEST/scripts/quick-audit.sh"
echo "  2. Fix issues: bash $DEST/scripts/quick-harden.sh"
echo "  3. The SKILL.md is now active for your agent"
