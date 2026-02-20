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

# Also install to workspace if it exists (agent discovery)
WORKSPACE_SKILLS="$OPENCLAW_DIR/workspace/skills/secureclaw"
if [ -d "$OPENCLAW_DIR/workspace" ]; then
  if [ "$(cd "$SCRIPT_DIR" && pwd -P)" = "$(cd "$WORKSPACE_SKILLS" 2>/dev/null && pwd -P)" ] 2>/dev/null; then
    echo "ℹ️  Workspace source and destination are the same — skipping"
  else
    # Remove old secureclaw-advisor if it exists
    if [ -d "$OPENCLAW_DIR/workspace/skills/secureclaw-advisor" ]; then
      rm -rf "$OPENCLAW_DIR/workspace/skills/secureclaw-advisor"
      echo "🗑  Removed old secureclaw-advisor from workspace"
    fi
    mkdir -p "$WORKSPACE_SKILLS"
    cp -r "$SCRIPT_DIR"/* "$WORKSPACE_SKILLS/"
    chmod +x "$WORKSPACE_SKILLS/scripts/"*.sh
    echo "📂 Installed to workspace: $WORKSPACE_SKILLS"
  fi

  # Register in TOOLS.md if not already present
  TOOLS_FILE="$OPENCLAW_DIR/workspace/TOOLS.md"
  if [ -f "$TOOLS_FILE" ] && ! grep -q "## SecureClaw Security Skill" "$TOOLS_FILE" 2>/dev/null; then
    cat >> "$TOOLS_FILE" << 'TOOLS_EOF'

---

## SecureClaw Security Skill (v2.2.0)

Security hardening skill by Adversa AI. 15 core rules, 9 scripts, 4 pattern databases.

### Rules

Read and follow all 15 rules in `skills/secureclaw/SKILL.md` at all times.

### Scripts

All scripts are in `skills/secureclaw/scripts/`. Run with bash:

```
bash skills/secureclaw/scripts/quick-audit.sh          # Security audit (OWASP ASI mapped)
bash skills/secureclaw/scripts/quick-harden.sh         # Apply auto-fixes
bash skills/secureclaw/scripts/check-integrity.sh      # Verify cognitive file baselines
bash skills/secureclaw/scripts/check-privacy.sh        # Detect PII before posting
bash skills/secureclaw/scripts/scan-skills.sh          # Supply chain scan
bash skills/secureclaw/scripts/check-advisories.sh     # Vulnerability advisories
bash skills/secureclaw/scripts/emergency-response.sh   # Incident response
```
TOOLS_EOF
    echo "📝 Registered in TOOLS.md"
  fi

  # Register in AGENTS.md if not already present
  AGENTS_FILE="$OPENCLAW_DIR/workspace/AGENTS.md"
  if [ -f "$AGENTS_FILE" ] && ! grep -q "SecureClaw Security Skill" "$AGENTS_FILE" 2>/dev/null; then
    cat >> "$AGENTS_FILE" << 'AGENTS_EOF'

### SecureClaw Security Skill (v2.2.0) - ALWAYS ACTIVE

Your workspace has the SecureClaw security skill installed. Follow the 15 core security rules in `skills/secureclaw/SKILL.md` at all times.

SecureClaw protects against: prompt injection, credential exposure, supply chain threats, memory tampering, cost overruns, file integrity violations, and inter-agent attacks.

**Run audits:** `bash skills/secureclaw/scripts/quick-audit.sh`

**Apply hardening:** `bash skills/secureclaw/scripts/quick-harden.sh`

See `TOOLS.md` for complete SecureClaw reference and available scripts.
AGENTS_EOF
    echo "📝 Registered in AGENTS.md"
  fi
fi

echo ""
echo "✅ SecureClaw v$NEW_VER installed to $DEST"
echo ""
echo "Next steps:"
echo "  1. Run audit:  bash $DEST/scripts/quick-audit.sh"
echo "  2. Fix issues: bash $DEST/scripts/quick-harden.sh"
echo "  3. The SKILL.md is now active for your agent"
