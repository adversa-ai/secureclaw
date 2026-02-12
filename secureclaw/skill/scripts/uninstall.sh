#!/bin/bash
# SecureClaw — Uninstaller
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

echo "🔒 SecureClaw — Uninstaller"
echo "============================"

# Find OpenClaw
OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

DEST="$OPENCLAW_DIR/skills/secureclaw"

if [ ! -d "$DEST" ]; then
  echo "ℹ️  SecureClaw skill not installed at $DEST"
  exit 0
fi

# Show what will be removed
VER="unknown"
if [ -f "$DEST/skill.json" ]; then
  VER=$(grep '"version"' "$DEST/skill.json" | head -1 | sed 's/.*"version".*"\([^"]*\)".*/\1/')
fi
echo "📁 Found: SecureClaw v$VER at $DEST"

# Check for --force flag
FORCE="${1:-}"
if [ "$FORCE" != "--force" ]; then
  echo ""
  echo "This will remove:"
  echo "  • $DEST/ (skill files)"
  echo "  • $OPENCLAW_DIR/.secureclaw/baselines/ (integrity baselines)"
  echo ""
  echo "This will NOT remove:"
  echo "  • SecureClaw directives added to SOUL.md (manual removal needed)"
  echo "  • Backup directories ($DEST.bak.*)"
  echo "  • The SecureClaw plugin (if installed via openclaw plugins)"
  echo ""
  echo "Run with --force to proceed:  bash $0 --force"
  exit 0
fi

# Remove skill directory
echo "🗑️  Removing $DEST/"
rm -rf "$DEST"

# Remove baselines
if [ -d "$OPENCLAW_DIR/.secureclaw/baselines" ]; then
  echo "🗑️  Removing integrity baselines"
  rm -rf "$OPENCLAW_DIR/.secureclaw/baselines"
fi

# Remove .secureclaw dir if empty
if [ -d "$OPENCLAW_DIR/.secureclaw" ]; then
  rmdir "$OPENCLAW_DIR/.secureclaw" 2>/dev/null || true
fi

# Clean up old backups
BACKUP_COUNT=$(ls -d "$DEST".bak.* 2>/dev/null | wc -l | tr -d ' ')
if [ "$BACKUP_COUNT" -gt 0 ]; then
  echo "🗑️  Removing $BACKUP_COUNT backup(s)"
  rm -rf "$DEST".bak.*
fi

echo ""
echo "✅ SecureClaw skill removed"
echo ""
echo "⚠️  Manual steps:"
echo "  1. Edit $OPENCLAW_DIR/SOUL.md and remove the"
echo "     '## SecureClaw Privacy Directives' and"
echo "     '## SecureClaw Injection Awareness' sections if present"
echo "  2. Restart your agent to clear SKILL.md from context"
