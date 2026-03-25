#!/bin/bash
# SecureClaw — Post-install permission fix
# Run automatically by clawhub after install, or manually after any install method
# that does not set restrictive permissions (e.g. clawhub, which defaults to 664).
# Developed by Adversa AI — https://adversa.ai
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🔒 SecureClaw — fixing file permissions in $SKILL_DIR"

# Scripts: executable by owner only
chmod 700 "$SKILL_DIR/scripts/"*.sh

# Config files containing detection patterns: readable by owner only
chmod 600 "$SKILL_DIR/configs/"*.json

# Docs and metadata: standard readable
chmod 644 "$SKILL_DIR/SKILL.md" \
          "$SKILL_DIR/skill.json" \
          "$SKILL_DIR/checksums.json" 2>/dev/null || true

echo "✅ Permissions set (scripts: 700, configs: 600, docs: 644)"
