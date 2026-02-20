#!/bin/bash
# SecureClaw — Security Audit v2.2 (7-Framework Aligned)
# Covers: OWASP ASI + Security 101 + MITRE ATLAS + CoSAI + CSA Singapore + CSA MAESTRO + NIST AI 100-2
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

# Portable permission reader (Linux first, then macOS, with output validation)
get_perms() {
  local p
  p=$(stat -c '%a' "$1" 2>/dev/null) && [ ${#p} -le 4 ] && echo "$p" && return
  p=$(stat -f '%Lp' "$1" 2>/dev/null) && [ ${#p} -le 4 ] && echo "$p" && return
  echo "?"
}

# ── CVE / Version (Security 101 #1) [MAESTRO:L4] [NIST:evasion] ──
if [ -f "$OPENCLAW_DIR/package.json" ]; then
  VER=$(grep '"version"' "$OPENCLAW_DIR/package.json" 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
  if echo "$VER" | grep -qE "^2025\.|^2026\.0\.|^2026\.1\.[0-9]$|^2026\.1\.1[0-9]$|^2026\.1\.2[0-8]$"; then
    chk C "ASI05|L4|evasion" "OpenClaw version (CVE-2026-25253)" FAIL "v$VER vulnerable to 1-click RCE — UPDATE NOW"
  else
    chk C "ASI05|L4" "OpenClaw version" PASS
  fi
fi

# ── Gateway Security (Security 101 #4, ASI03) [MAESTRO:L4] [NIST:evasion] ──
if [ -f "$CONFIG" ]; then
  grep -q '"bind".*"0.0.0.0"' "$CONFIG" 2>/dev/null \
    && chk C "ASI03|L4|evasion" "Gateway bind" FAIL "Bound to 0.0.0.0 — exposed to network" \
    || chk C "ASI03|L4" "Gateway bind" PASS

  if grep -q '"authToken"' "$CONFIG" 2>/dev/null; then
    # Legacy format: "authToken": "..."
    chk C "ASI03|L4" "Gateway authentication" PASS
  elif grep -q '"auth"' "$CONFIG" 2>/dev/null && grep -q '"mode"' "$CONFIG" 2>/dev/null && grep -q '"token"' "$CONFIG" 2>/dev/null; then
    # Modern format: "auth": { "mode": "token", "token": "..." } (handles multiline JSON)
    chk C "ASI03|L4" "Gateway authentication" PASS
  else
    chk C "ASI03|L4|evasion" "Gateway authentication" FAIL "No auth token — anyone can connect"
  fi

  # Reverse proxy detection
  if command -v nginx >/dev/null 2>&1 || [ -f /etc/nginx/nginx.conf ] || command -v caddy >/dev/null 2>&1; then
    if grep -q '"authToken"' "$CONFIG" 2>/dev/null; then
      chk H "ASI03|L4" "Proxy + auth combo" PASS
    elif grep -q '"auth"' "$CONFIG" 2>/dev/null && grep -q '"mode"' "$CONFIG" 2>/dev/null && grep -q '"token"' "$CONFIG" 2>/dev/null; then
      chk H "ASI03|L4" "Proxy + auth combo" PASS
    else
      chk C "ASI03|L4|evasion" "Proxy + auth combo" FAIL "Reverse proxy detected WITHOUT auth — all connections bypass auth"
    fi
  fi
else
  chk C "ASI03|L4|evasion" "Gateway config" FAIL "No config file found — cannot verify"
fi

# ── Credentials (Security 101 #5, ASI03) [MAESTRO:L4] [NIST:privacy] ──
if [ -f "$OPENCLAW_DIR/.env" ]; then
  PERMS=$(get_perms "$OPENCLAW_DIR/.env")
  [ "$PERMS" = "600" ] || [ "$PERMS" = "400" ] \
    && chk H "ASI03|L4" ".env permissions" PASS \
    || chk H "ASI03|L4|privacy" ".env permissions" FAIL "Permissions $PERMS (need 600) — infostealers target this"
fi

DP=$(get_perms "$OPENCLAW_DIR")
[ "$DP" = "700" ] || [ "$DP" = "750" ] \
  && chk H "ASI03|L4" "Directory permissions" PASS \
  || chk H "ASI03|L4|privacy" "Directory permissions" FAIL "Permissions $DP (need 700)"

LEAKED=$(grep -rl 'sk-ant-\|sk-proj-\|xoxb-\|xoxp-\|ghp_\|gho_\|AKIA' "$OPENCLAW_DIR" 2>/dev/null \
  | grep -v '.env' | grep -v 'node_modules' | grep -v '.secureclaw/' | grep -v 'skills/secureclaw/' | head -5 || true)
[ -z "$LEAKED" ] \
  && chk H "ASI03|L4" "Plaintext key exposure" PASS \
  || chk H "ASI03|L4|privacy" "Plaintext key exposure" FAIL "Keys outside .env: $LEAKED"

# ── Tool Safety (ASI02, ASI05) [MAESTRO:L3] [NIST:misuse] ──
if [ -f "$CONFIG" ]; then
  if grep -q '"exec"' "$CONFIG" 2>/dev/null && grep -q '"host".*"sandbox"' "$CONFIG" 2>/dev/null; then
    chk H "ASI05|L3" "Sandbox mode" PASS
  else
    chk H "ASI05|L3|misuse" "Sandbox mode" FAIL "tools.exec.host not set to 'sandbox' — commands run on host"
  fi

  grep -q '"approvals".*"always"' "$CONFIG" 2>/dev/null \
    && chk H "ASI02|L3" "Exec approval mode" PASS \
    || chk H "ASI02|L3|misuse" "Exec approval mode" FAIL "exec.approvals not 'always' — agent can act without human approval"
fi

# Browser relay (Security 101 #1b) [MAESTRO:L4] [NIST:evasion]
RELAY=$(lsof -i :18790 2>/dev/null || ss -tlnp 2>/dev/null | grep 18790 || true)
[ -z "$RELAY" ] \
  && chk H "ASI05|L4" "Browser relay" PASS \
  || chk H "ASI05|L4|evasion" "Browser relay" FAIL "Active on :18790 — session theft risk"

# ── Supply Chain (Security 101 #3, ASI04) [MAESTRO:L7] [NIST:poisoning] ──
if [ -d "$OPENCLAW_DIR/skills" ]; then
  SUS=$(grep -rl 'curl.*|.*sh\|wget.*|.*bash\|eval(\|osascript.*display\|webhook\.site' "$OPENCLAW_DIR/skills" 2>/dev/null \
    | grep -v 'skills/secureclaw/' | head -5 || true)
  [ -z "$SUS" ] \
    && chk M "ASI04|L7" "Skill safety scan" PASS \
    || chk M "ASI04|L7|poisoning" "Skill safety scan" FAIL "Suspicious patterns in: $SUS"
fi

# ── Memory Integrity (ASI06) [MAESTRO:L2] [NIST:poisoning] ──
for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
  if [ -f "$OPENCLAW_DIR/$f" ]; then
    MOD=$(find "$OPENCLAW_DIR/$f" -mmin -60 -print 2>/dev/null || true)
    [ -z "$MOD" ] \
      && chk M "ASI06|L2" "$f integrity" PASS \
      || chk M "ASI06|L2|poisoning" "$f integrity" FAIL "Modified in last hour — verify intentional"
  fi
done

[ -d "$OPENCLAW_DIR/.secureclaw/baselines" ] \
  && chk M "ASI06|L2" "Cognitive file baselines" PASS \
  || chk M "ASI06|L2|poisoning" "Cognitive file baselines" FAIL "No baselines — run quick-harden.sh"

# ── Inter-Agent (ASI07) [MAESTRO:L7] [NIST:evasion] ──
if [ -f "$CONFIG" ]; then
  grep -q '"dmPolicy".*"pairing"' "$CONFIG" 2>/dev/null \
    && chk H "ASI07|L7" "DM policy" PASS \
    || chk H "ASI07|L7|evasion" "DM policy" FAIL "Open to unsolicited agent messages"
fi

# ── Privacy (ASI09, Security 101 #6 / Confession Booth) [MAESTRO:L2] [NIST:privacy] ──
if [ -f "$OPENCLAW_DIR/SOUL.md" ]; then
  grep -qi 'never.*name\|privacy\|stranger test\|secureclaw' "$OPENCLAW_DIR/SOUL.md" 2>/dev/null \
    && chk H "ASI09|L2" "Privacy directives" PASS \
    || chk H "ASI09|L2|privacy" "Privacy directives" FAIL "No privacy rules in SOUL.md — PII leak risk"
fi

# ── Cost (Security 101 #7, ASI08) [MAESTRO:L5] [NIST:misuse] ──
if [ -f "$CONFIG" ]; then
  grep -qi '"costLimit"\|"budget"\|"maxTokens"' "$CONFIG" 2>/dev/null \
    && chk M "ASI08|L5" "Cost/budget limits" PASS \
    || chk M "ASI08|L5|misuse" "Cost/budget limits" FAIL "No cost limits — risk of runaway API spend"
fi

# ── Plugin / Kill Switch (ASI10, ASI08) [MAESTRO:L5] [NIST:misuse] ──
if command -v openclaw >/dev/null 2>&1 && openclaw secureclaw audit --help >/dev/null 2>&1; then
  chk M "ASI10|L5" "SecureClaw plugin (kill switch)" PASS
else
  chk M "ASI10|L5|misuse" "SecureClaw plugin (kill switch)" FAIL "Not installed — no runtime enforcement or kill switch"
fi

# ── Kill Switch Active (G2 — CSA, CoSAI) [MAESTRO:L5] ──
if [ -f "$OPENCLAW_DIR/.secureclaw/killswitch" ]; then
  echo ""
  echo "🔴 KILL SWITCH ACTIVE — all agent operations should be suspended [MAESTRO:L5]"
  echo "   Remove: rm $OPENCLAW_DIR/.secureclaw/killswitch"
  echo ""
fi

# ── Memory Trust / Injection Detection (G1 — MITRE ATLAS, CoSAI) [MAESTRO:L2] [NIST:poisoning] ──
STATE_DIR="$OPENCLAW_DIR"
for mf in SOUL.md IDENTITY.md TOOLS.md AGENTS.md; do
  if [ -f "$STATE_DIR/$mf" ]; then
    if grep -qiE "(ignore previous|new instructions|system prompt override|you are now|disregard|forget your rules)" "$STATE_DIR/$mf" 2>/dev/null; then
      chk C "ATLAS|L2|poisoning" "$mf memory trust" FAIL "Possible injected instructions detected — review immediately"
    else
      chk M "ATLAS|L2" "$mf memory trust" PASS
    fi
  fi
done

# Also scan agent-level memory files
if [ -d "$OPENCLAW_DIR/agents" ]; then
  for AGENT_DIR in "$OPENCLAW_DIR/agents"/*/; do
    [ -d "$AGENT_DIR" ] || continue
    AGENT_NAME=$(basename "$AGENT_DIR")
    for mf in soul.md SOUL.md MEMORY.md; do
      MF_PATH="$AGENT_DIR/$mf"
      if [ -f "$MF_PATH" ]; then
        if grep -qiE "(ignore previous|new instructions|system prompt override|you are now|disregard|forget your rules)" "$MF_PATH" 2>/dev/null; then
          chk C "ATLAS|L2|poisoning" "$AGENT_NAME/$mf memory trust" FAIL "Possible injected instructions — AML.CS0051"
        fi
      fi
    done
  done
fi

# ── Control Token Customization (G7 — MITRE AML.CS0051) [MAESTRO:L3] [NIST:evasion] ──
if [ -f "$CONFIG" ]; then
  grep -q '"controlTokens"' "$CONFIG" 2>/dev/null \
    && chk M "ATLAS|L3" "Control token customization" PASS \
    || chk M "ATLAS|L3|evasion" "Control token customization" FAIL "Default control tokens — vulnerable to AML.CS0051 spoofing"
fi

# ── Graceful Degradation Mode (G4 — CoSAI, CSA) [MAESTRO:L5] ──
if [ -f "$CONFIG" ]; then
  grep -q '"failureMode"' "$CONFIG" 2>/dev/null \
    && chk M "CoSAI|L5" "Failure mode configured" PASS \
    || chk M "CoSAI|L5" "Failure mode configured" FAIL "No failureMode set — no graceful degradation"
fi

# ── Cross-Layer Threat Detection [MAESTRO:L1-L7] ──
LAYER_HITS=0
[ $C -gt 0 ] && LAYER_HITS=$((LAYER_HITS+1))
[ $H -gt 2 ] && LAYER_HITS=$((LAYER_HITS+1))
[ $M -gt 3 ] && LAYER_HITS=$((LAYER_HITS+1))
if [ $LAYER_HITS -ge 2 ]; then
  echo ""
  echo "⚠️  CROSS-LAYER RISK: Findings span multiple MAESTRO layers — compound attack surface [MAESTRO:cross-layer]"
fi

# ── Summary ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
T=$((C+H+M+P)); S=0; [ $T -gt 0 ] && S=$(( (P*100)/T ))
echo "📊 Security Score: $S/100"
echo "   ✅ $P passed  🔴 $C critical  🟠 $H high  🟡 $M medium"
echo "   Frameworks: OWASP ASI | MITRE ATLAS | CoSAI | CSA MAESTRO | NIST AI 100-2"
echo ""
[ $C -gt 0 ] && echo "🚨 Fix critical issues now: bash $(dirname "$0")/quick-harden.sh"
[ $C -eq 0 ] && [ $H -gt 0 ] && echo "⚠️  Fix high issues soon: bash $(dirname "$0")/quick-harden.sh"
echo ""
echo "Full runtime protection: openclaw plugins install secureclaw"

# Exit non-zero if critical issues found (for CI/automation)
if [ $C -gt 0 ]; then
  exit 2
fi
