#!/bin/bash
# SecureClaw — Uninstaller
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

echo "🔒 SecureClaw — Uninstaller"
echo "============================"

# Find OpenClaw
OPENCLAW_DIR="${OPENCLAW_DIR:-}"
if [ -z "$OPENCLAW_DIR" ]; then
  for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
    [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
  done
fi
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

DEST="$OPENCLAW_DIR/skills/secureclaw"
WORKSPACE_DEST="$OPENCLAW_DIR/workspace/skills/secureclaw"
TOOLS_FILE="$OPENCLAW_DIR/workspace/TOOLS.md"
AGENTS_FILE="$OPENCLAW_DIR/workspace/AGENTS.md"

if [ ! -d "$DEST" ] && [ ! -d "$WORKSPACE_DEST" ]; then
  echo "ℹ️  SecureClaw skill not installed at $DEST"
  exit 0
fi

# Show what will be removed
VER="unknown"
if [ -f "$DEST/skill.json" ]; then
  VER=$(grep '"version"' "$DEST/skill.json" | head -1 | sed 's/.*"version".*"\([^"]*\)".*/\1/')
elif [ -f "$WORKSPACE_DEST/skill.json" ]; then
  VER=$(grep '"version"' "$WORKSPACE_DEST/skill.json" | head -1 | sed 's/.*"version".*"\([^"]*\)".*/\1/')
fi
echo "📁 Found: SecureClaw v$VER"

# Check for --force flag
FORCE="${1:-}"
if [ "$FORCE" != "--force" ]; then
  echo ""
  echo "This will remove:"
  echo "  • $DEST/ (skill files)"
  [ -d "$WORKSPACE_DEST" ] && echo "  • $WORKSPACE_DEST/ (workspace install)"
  [ -d "$OPENCLAW_DIR/.secureclaw/baselines" ] && echo "  • $OPENCLAW_DIR/.secureclaw/baselines/ (integrity baselines)"
  BACKUP_COUNT=$(ls -d "$DEST".bak.* 2>/dev/null | wc -l | tr -d ' ' || true)
  [ "$BACKUP_COUNT" -gt 0 ] && echo "  • $BACKUP_COUNT backup director(ies) ($DEST.bak.*)"
  grep -q "## SecureClaw Security Skill" "$TOOLS_FILE" 2>/dev/null && echo "  • SecureClaw block in TOOLS.md"
  grep -q "SecureClaw Security Skill" "$AGENTS_FILE" 2>/dev/null && echo "  • SecureClaw block in AGENTS.md"
  echo ""
  echo "This will NOT remove:"
  echo "  • SecureClaw directives added to SOUL.md (manual removal needed)"
  echo "  • The SecureClaw plugin (if installed via openclaw plugins)"
  echo ""
  echo "WARNING: this action is irreversible and cannot be undone."
  echo "Run with --force to proceed:  bash $0 --force"
  exit 0
fi

# Remove primary skill directory
if [ -d "$DEST" ]; then
  echo "🗑️  Removing $DEST/"
  rm -rf "$DEST"
fi

# Remove workspace install
if [ -d "$WORKSPACE_DEST" ]; then
  echo "🗑️  Removing workspace install $WORKSPACE_DEST/"
  rm -rf "$WORKSPACE_DEST"
fi

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
BACKUP_COUNT=$(ls -d "$DEST".bak.* 2>/dev/null | wc -l | tr -d ' ' || true)
if [ "$BACKUP_COUNT" -gt 0 ]; then
  echo "🗑️  Removing $BACKUP_COUNT backup(s)"
  rm -rf "$DEST".bak.*
fi

# Remove SecureClaw block from TOOLS.md.
if [ -f "$TOOLS_FILE" ] && grep -q "Secureclaw" "$TOOLS_FILE" 2>/dev/null; then
  echo "📝 Removing SecureClaw entry from TOOLS.md"
  sed -i '/<!-- Secureclaw -->/,/<!-- Secureclaw:end -->/d' "$TOOLS_FILE"
fi

# Remove SecureClaw block from AGENTS.md
if [ -f "$AGENTS_FILE" ] && grep -q "Secureclaw" "$AGENTS_FILE" 2>/dev/null; then
  echo "📝 Removing SecureClaw entry from AGENTS.md"
  sed -i '/<!-- Secureclaw -->/,/<!-- Secureclaw:end -->/d' "$AGENTS_FILE"
fi

echo ""
echo "✅ SecureClaw skill removed"
echo ""
echo "⚠️  Manual steps:"
echo "  1. Edit $OPENCLAW_DIR/workspace/SOUL.md and remove the"
echo "     '## SecureClaw Privacy Directives' and"
echo "     '## SecureClaw Injection Awareness' sections if present"
echo "  2. Restart your agent to clear SKILL.md from context"
