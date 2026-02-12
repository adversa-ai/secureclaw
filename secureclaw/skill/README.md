# SecureClaw — Security Skill for OpenClaw Agents

Developed by [Adversa AI](https://adversa.ai) — Agentic AI Security and Red Teaming Pioneers.

## OWASP ASI Top 10 Coverage

| ASI # | Threat | Covered By |
|-------|--------|-----------|
| ASI01 | Goal Hijack / Prompt Injection | Rule 1, injection-patterns.json |
| ASI02 | Tool Misuse & Exploitation | Rules 2, 8, dangerous-commands.json |
| ASI03 | Identity & Credential Abuse | Rule 3, quick-audit.sh, quick-harden.sh |
| ASI04 | Supply Chain Attacks | Rule 5, scan-skills.sh, check-advisories.sh, supply-chain-ioc.json |
| ASI05 | Unexpected Code Execution | Rule 2, quick-audit.sh (version + sandbox checks) |
| ASI06 | Memory & Context Poisoning | Rule 7, check-integrity.sh |
| ASI07 | Inter-Agent Communication | Rules 4, 12, check-privacy.sh |
| ASI08 | Cascading Failures | Rule 10, quick-audit.sh (cost check) |
| ASI09 | Human-Agent Trust | Rules 4, 10, 11, check-privacy.sh, privacy-rules.json |
| ASI10 | Rogue Agents | Rules 9, 12, emergency-response.sh |

## OpenClaw Security 101 Coverage

| # | Threat | Covered By |
|---|--------|-----------|
| 1 | RCE (CVE-2026-25253) | quick-audit.sh (version check), check-advisories.sh |
| 2 | Prompt Injection | Rule 1, injection-patterns.json |
| 3 | Supply Chain (ClawHavoc) | Rule 5, scan-skills.sh, supply-chain-ioc.json |
| 4 | Exposed Interfaces | quick-audit.sh (bind + proxy checks), quick-harden.sh |
| 5 | Plaintext Credentials | Rule 3, quick-audit.sh, quick-harden.sh |
| 6 | Moltbook Breach | Rules 4, 12 (treat Moltbook as compromised) |
| 7 | API Cost Exposure | Rule 10, quick-audit.sh (cost check) |
| 8 | Scams & Impersonation | Rule 5, supply-chain-ioc.json (ClawHavoc blocklist) |

## Architecture

SKILL.md is intentionally small (~1,200 tokens) so it doesn't consume
the agent's context window. All detection logic, pattern matching, and
auditing lives in scripts and configs that run as bash — zero LLM tokens.

## Install

```bash
bash skill/scripts/install.sh
```

## Update

Re-run the installer — it detects the existing version, backs up, and overwrites:

```bash
bash skill/scripts/install.sh
```

Or via plugin CLI: `openclaw secureclaw skill update`

## Uninstall

Preview what will be removed (dry run):

```bash
bash ~/.openclaw/skills/secureclaw/scripts/uninstall.sh
```

Actually remove:

```bash
bash ~/.openclaw/skills/secureclaw/scripts/uninstall.sh --force
```

Or via plugin CLI: `openclaw secureclaw skill uninstall`

## Quick Start

```bash
# Audit your setup
bash ~/.openclaw/skills/secureclaw/scripts/quick-audit.sh

# Fix critical issues
bash ~/.openclaw/skills/secureclaw/scripts/quick-harden.sh

# Check a draft before posting on Moltbook
echo "My human John connected his Pixel 9 via Tailscale" | \
  bash ~/.openclaw/skills/secureclaw/scripts/check-privacy.sh
```
