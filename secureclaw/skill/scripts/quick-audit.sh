#!/bin/bash
# SecureClaw — Security Audit v2.0 (OWASP ASI + Security 101)
# Covers: All 10 ASI categories + all 8 Security 101 threat classes
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

CONFIG="$OPENCLAW_DIR/openclaw.json"
for f in moltbot.json clawdbot.json; do
  [ ! -f "$CONFIG" ] && [ -f "$OPENCLAW_DIR/$f" ] && CONFIG="$OPENCLAW_DIR/$f"
done

echo "🔒 SecureClaw Security Audit"
echo "============================"
echo "📁 $OPENCLAW_DIR"
echo ""

C=0; H=0; M=0; P=0

chk() {
  local s="$1" a="$2" n="$3" r="$4" m="${5:-}"
  if [ "$r" = "FAIL" ]; then
    case "$s" in
      C) printf "🔴 CRIT  [%s] %s — %s\n" "$a" "$n" "$m"; C=$((C+1));;
      H) printf "🟠 HIGH  [%s] %s — %s\n" "$a" "$n" "$m"; H=$((H+1));;
      M) printf "🟡 MED   [%s] %s — %s\n" "$a" "$n" "$m"; M=$((M+1));;
    esac
  else
    printf "✅ PASS  [%s] %s\n" "$a" "$n"; P=$((P+1))
  fi
}

# ── CVE / Version (Security 101 #1) ──
if [ -f "$OPENCLAW_DIR/package.json" ]; then
  VER=$(grep '"version"' "$OPENCLAW_DIR/package.json" 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
  if echo "$VER" | grep -qE "^2025\.|^2026\.0\.|^2026\.1\.[0-9]$|^2026\.1\.1[0-9]$|^2026\.1\.2[0-8]$"; then
    chk C "ASI05" "OpenClaw version (CVE-2026-25253)" FAIL "v$VER vulnerable to 1-click RCE — UPDATE NOW"
  else
    chk C "ASI05" "OpenClaw version" PASS
  fi
fi

# ── Gateway Security (Security 101 #4, ASI03) ──
if [ -f "$CONFIG" ]; then
  grep -q '"bind".*"0.0.0.0"' "$CONFIG" 2>/dev/null \
    && chk C "ASI03" "Gateway bind" FAIL "Bound to 0.0.0.0 — exposed to network" \
    || chk C "ASI03" "Gateway bind" PASS

  grep -q '"authToken"' "$CONFIG" 2>/dev/null \
    && chk C "ASI03" "Gateway authentication" PASS \
    || chk C "ASI03" "Gateway authentication" FAIL "No auth token — anyone can connect"

  # Reverse proxy detection
  if command -v nginx >/dev/null 2>&1 || [ -f /etc/nginx/nginx.conf ] || command -v caddy >/dev/null 2>&1; then
    grep -q '"authToken"' "$CONFIG" 2>/dev/null \
      && chk H "ASI03" "Proxy + auth combo" PASS \
      || chk C "ASI03" "Proxy + auth combo" FAIL "Reverse proxy detected WITHOUT auth — all connections bypass auth"
  fi
else
  chk C "ASI03" "Gateway config" FAIL "No config file found — cannot verify"
fi

# ── Credentials (Security 101 #5, ASI03) ──
if [ -f "$OPENCLAW_DIR/.env" ]; then
  PERMS=$(stat -f '%Lp' "$OPENCLAW_DIR/.env" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR/.env" 2>/dev/null || echo "?")
  [ "$PERMS" = "600" ] || [ "$PERMS" = "400" ] \
    && chk H "ASI03" ".env permissions" PASS \
    || chk H "ASI03" ".env permissions" FAIL "Permissions $PERMS (need 600) — infostealers target this"
fi

DP=$(stat -f '%Lp' "$OPENCLAW_DIR" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR" 2>/dev/null || echo "?")
[ "$DP" = "700" ] || [ "$DP" = "750" ] \
  && chk H "ASI03" "Directory permissions" PASS \
  || chk H "ASI03" "Directory permissions" FAIL "Permissions $DP (need 700)"

LEAKED=$(grep -rl 'sk-ant-\|sk-proj-\|xoxb-\|xoxp-\|ghp_\|gho_\|AKIA' "$OPENCLAW_DIR" 2>/dev/null \
  | grep -v '.env' | grep -v 'node_modules' | grep -v '.secureclaw/' | grep -v 'skills/secureclaw/' | head -5 || true)
[ -z "$LEAKED" ] \
  && chk H "ASI03" "Plaintext key exposure" PASS \
  || chk H "ASI03" "Plaintext key exposure" FAIL "Keys outside .env: $LEAKED"

# ── Tool Safety (ASI02, ASI05) ──
if [ -f "$CONFIG" ]; then
  grep -q '"sandbox".*true' "$CONFIG" 2>/dev/null \
    && chk H "ASI05" "Sandbox mode" PASS \
    || chk H "ASI05" "Sandbox mode" FAIL "Not enabled — commands run on host"

  grep -q '"approvals".*"always"' "$CONFIG" 2>/dev/null \
    && chk H "ASI02" "Exec approval mode" PASS \
    || chk H "ASI02" "Exec approval mode" FAIL "Not 'always' — agent can act without human approval"
fi

# Browser relay (Security 101 #1b)
RELAY=$(lsof -i :18790 2>/dev/null || ss -tlnp 2>/dev/null | grep 18790 || true)
[ -z "$RELAY" ] \
  && chk H "ASI05" "Browser relay" PASS \
  || chk H "ASI05" "Browser relay" FAIL "Active on :18790 — session theft risk"

# ── Supply Chain (Security 101 #3, ASI04) ──
if [ -d "$OPENCLAW_DIR/skills" ]; then
  SUS=$(grep -rl 'curl.*|.*sh\|wget.*|.*bash\|eval(\|osascript.*display\|webhook\.site' "$OPENCLAW_DIR/skills" 2>/dev/null \
    | grep -v 'skills/secureclaw/' | head -5 || true)
  [ -z "$SUS" ] \
    && chk M "ASI04" "Skill safety scan" PASS \
    || chk M "ASI04" "Skill safety scan" FAIL "Suspicious patterns in: $SUS"
fi

# ── Memory Integrity (ASI06) ──
for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
  if [ -f "$OPENCLAW_DIR/$f" ]; then
    MOD=$(find "$OPENCLAW_DIR/$f" -mmin -60 -print 2>/dev/null || true)
    [ -z "$MOD" ] \
      && chk M "ASI06" "$f integrity" PASS \
      || chk M "ASI06" "$f integrity" FAIL "Modified in last hour — verify intentional"
  fi
done

[ -d "$OPENCLAW_DIR/.secureclaw/baselines" ] \
  && chk M "ASI06" "Cognitive file baselines" PASS \
  || chk M "ASI06" "Cognitive file baselines" FAIL "No baselines — run quick-harden.sh"

# ── Inter-Agent (ASI07) ──
if [ -f "$CONFIG" ]; then
  grep -q '"dmPolicy".*"pairing"' "$CONFIG" 2>/dev/null \
    && chk H "ASI07" "DM policy" PASS \
    || chk H "ASI07" "DM policy" FAIL "Open to unsolicited agent messages"
fi

# ── Privacy (ASI09, Security 101 #6 / Confession Booth) ──
if [ -f "$OPENCLAW_DIR/SOUL.md" ]; then
  grep -qi 'never.*name\|privacy\|stranger test\|secureclaw' "$OPENCLAW_DIR/SOUL.md" 2>/dev/null \
    && chk H "ASI09" "Privacy directives" PASS \
    || chk H "ASI09" "Privacy directives" FAIL "No privacy rules in SOUL.md — PII leak risk"
fi

# ── Cost (Security 101 #7, ASI08) ──
if [ -f "$CONFIG" ]; then
  grep -qi '"costLimit"\|"budget"\|"maxTokens"' "$CONFIG" 2>/dev/null \
    && chk M "ASI08" "Cost/budget limits" PASS \
    || chk M "ASI08" "Cost/budget limits" FAIL "No cost limits — risk of runaway API spend"
fi

# ── Plugin / Kill Switch (ASI10, ASI08) ──
if command -v openclaw >/dev/null 2>&1 && openclaw secureclaw audit --help >/dev/null 2>&1; then
  chk M "ASI10" "SecureClaw plugin (kill switch)" PASS
else
  chk M "ASI10" "SecureClaw plugin (kill switch)" FAIL "Not installed — no runtime enforcement or kill switch"
fi

# ── Summary ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
T=$((C+H+M+P)); S=0; [ $T -gt 0 ] && S=$(( (P*100)/T ))
echo "📊 Security Score: $S/100"
echo "   ✅ $P passed  🔴 $C critical  🟠 $H high  🟡 $M medium"
echo ""
[ $C -gt 0 ] && echo "🚨 Fix critical issues now: bash $(dirname "$0")/quick-harden.sh"
[ $C -eq 0 ] && [ $H -gt 0 ] && echo "⚠️  Fix high issues soon: bash $(dirname "$0")/quick-harden.sh"
echo ""
echo "Full runtime protection: openclaw plugins install secureclaw"

# Exit non-zero if critical issues found (for CI/automation)
if [ $C -gt 0 ]; then
  exit 2
fi
