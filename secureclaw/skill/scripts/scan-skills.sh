#!/bin/bash
# SecureClaw — Skill Supply Chain Scanner
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
# Usage: bash scan-skills.sh              (scan all installed skills)
#        bash scan-skills.sh /path/to/skill (scan specific skill)
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
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

echo "🔒 SecureClaw — Skill Supply Chain Scan"
echo "========================================"
SAFE=0; SUS=0; T=0; SKIPPED=0

scan_dir() {
  local d="$1" n="$2"
  T=$((T+1)); local ISSUES=""

  # Remote code execution
  grep -rl 'curl.*|.*sh\|wget.*|.*bash\|curl.*|.*python' "$d" 2>/dev/null | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🔴 Remote code execution\n" || true

  # Dynamic execution
  grep -rl 'eval(\|exec(\|Function(\|subprocess\.\|os\.system' "$d" 2>/dev/null | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🔴 Dynamic code execution\n" || true

  # Obfuscation
  grep -rl 'atob(\|btoa(\|String\.fromCharCode\|\\x[0-9a-f]' "$d" 2>/dev/null | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🟠 Obfuscated code\n" || true

  # Credential access
  grep -rl 'process\.env\|\.env\|api_key\|apiKey' "$d" 2>/dev/null | grep -v node_modules | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🟠 Credential access\n" || true

  # Config modification
  grep -rl 'SOUL\.md\|IDENTITY\.md\|TOOLS\.md\|openclaw\.json' "$d" 2>/dev/null | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🟠 Config/identity modification\n" || true

  # ClawHavoc patterns
  grep -rl 'osascript.*display\|xattr.*quarantine\|ClickFix\|webhook\.site' "$d" 2>/dev/null | head -1 | grep -q . \
    && ISSUES="${ISSUES}  🔴 ClawHavoc campaign pattern\n" || true

  # ClawHavoc name patterns
  case "$n" in
    *solana-wallet*|*phantom-tracker*|*polymarket-*|*better-polymarket*|*auto-updater*|*clawhub[0-9]*|*clawhubb*|*cllawhub*)
      ISSUES="${ISSUES}  🔴 Name matches ClawHavoc blocklist\n" ;;
  esac

  if [ -z "$ISSUES" ]; then
    echo "✅ $n — clean"; SAFE=$((SAFE+1))
  else
    echo "⚠️  $n:"; echo -e "$ISSUES"; SUS=$((SUS+1))
  fi
}

if [ "${1:-}" != "" ]; then
  # Custom path provided — preserve original single-dir behavior
  SCAN_DIR="$1"
  [ ! -d "$SCAN_DIR" ] && echo "✅ Nothing to scan at $SCAN_DIR" && exit 0
  for skill_dir in "$SCAN_DIR"/*/; do
    [ ! -d "$skill_dir" ] && continue
    [ "$(basename "$skill_dir")" = "secureclaw" ] && SKIPPED=$((SKIPPED+1)) && continue
    scan_dir "$skill_dir" "$(basename "$skill_dir")"
  done
  # If scanning a single skill dir directly (no subdirs) — scan it as-is
  if [ $T -eq 0 ] && [ $SKIPPED -eq 0 ]; then
    scan_dir "$SCAN_DIR" "$(basename "$SCAN_DIR")"
  fi
else
  # Default: scan both primary and workspace skill locations
  for SCAN_BASE in "$OPENCLAW_DIR/skills" "$WORKSPACE_DIR/skills"; do
    [ -d "$SCAN_BASE" ] || continue
    for skill_dir in "$SCAN_BASE"/*/; do
      [ ! -d "$skill_dir" ] && continue
      # Skip ourselves — our configs contain the detection patterns we're scanning for
      [ "$(basename "$skill_dir")" = "secureclaw" ] && SKIPPED=$((SKIPPED+1)) && continue
      scan_dir "$skill_dir" "$(basename "$skill_dir")"
    done
  done
fi

echo ""
echo "📊 Scanned $T: $SAFE clean, $SUS suspicious"
if [ $SUS -gt 0 ]; then
  echo "⚠️  Review suspicious skills. Remove any you didn't install yourself."
fi
