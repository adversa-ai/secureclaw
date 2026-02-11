#!/bin/bash
# SecureClaw Advisor — Self-Installer
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done

[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

SKILL_DIR="$OPENCLAW_DIR/skills/secureclaw-advisor"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "🔒 Installing SecureClaw Advisor skill..."
echo "   Source: $SOURCE_DIR"
echo "   Target: $SKILL_DIR"

mkdir -p "$SKILL_DIR/configs" "$SKILL_DIR/scripts"

# Copy all files
cp "$SOURCE_DIR/SKILL.md" "$SKILL_DIR/"
cp "$SOURCE_DIR/skill.json" "$SKILL_DIR/"
cp "$SOURCE_DIR/checksums.json" "$SKILL_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR/configs/"* "$SKILL_DIR/configs/" 2>/dev/null || true
cp "$SOURCE_DIR/scripts/"* "$SKILL_DIR/scripts/" 2>/dev/null || true

# Make scripts executable
chmod +x "$SKILL_DIR/scripts/"*.sh 2>/dev/null || true

# Create state directory
mkdir -p "$OPENCLAW_DIR/.secureclaw"

echo "✅ SecureClaw Advisor installed to $SKILL_DIR"
echo ""
echo "Your agent will read the skill on next session."
echo "For full runtime protection, also install the SecureClaw plugin:"
echo "  openclaw plugins install secureclaw"
