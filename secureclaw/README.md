# SecureClaw

Automated security hardening plugin for [OpenClaw](https://openclaw.ai).

Developed by [Adversa AI](https://adversa.ai) — Agentic AI Security and Red Teaming Pioneers.

One install. 51 audit checks. 8 security categories. Full OWASP ASI mapping.

## What It Does

SecureClaw audits your OpenClaw installation for misconfigurations and known vulnerabilities, then applies automated hardening fixes with one command.

| Category | Check IDs | Count | What It Covers |
|----------|-----------|-------|----------------|
| Gateway & Network | SC-GW-001 – 010 | 10 | Bind mode, auth, TLS, mDNS, trusted proxies, port exposure |
| Credentials | SC-CRED-001 – 008 | 8 | File permissions, plaintext API keys, OAuth tokens, key leaks |
| Execution & Sandbox | SC-EXEC-001 – 007 | 7 | Approval mode, sandbox, Docker isolation, host exec |
| Access Control | SC-AC-001 – 005 | 5 | DM/group policy, allowlists, session isolation |
| Supply Chain | SC-SKILL-001 – 006 | 6 | Skill scanning, typosquat detection, dangerous patterns, IOC hashes |
| Memory Integrity | SC-MEM-001 – 005 | 5 | Prompt injection, base64 obfuscation, memory file permissions |
| Cost Exposure | SC-COST-001 – 004 | 4 | Spending limits, cost monitoring, cron frequency, thresholds |
| Threat Intelligence | SC-IOC-000 – 005 | 6 | C2 IPs, malicious domains, infostealer artifacts, file hashes |

Three background monitors run continuously: **credential watch**, **memory integrity**, and **API cost tracking** with circuit breaker.

## Installation

### From npm (recommended)

```sh
openclaw plugins install @openclaw/secureclaw
```

### From GitHub

```sh
git clone https://github.com/adversa-ai/secureclaw.git
cd secureclaw/secureclaw
npm install
npm run build
openclaw plugins install -l .
```

### From archive

```sh
# Build the tarball
cd secureclaw/secureclaw
npm pack

# Install it
openclaw plugins install ./openclaw-secureclaw-1.0.0.tgz
```

### Verify installation

```sh
openclaw plugins list          # Should show SecureClaw as "loaded"
openclaw plugins info secureclaw
openclaw plugins doctor        # Should report 0 issues
```

## Quick Start

```sh
# Run a security audit
openclaw secureclaw audit

# Deep audit with active port probing
openclaw secureclaw audit --deep

# Apply all hardening fixes
openclaw secureclaw harden --full

# Rollback if something breaks
openclaw secureclaw harden --rollback
```

## CLI Commands

### `openclaw secureclaw audit`

Run a comprehensive security audit. Outputs a scored report (0–100) with letter grade (A–F).

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |
| `--deep` | Active network probes (TCP port scanning) |
| `--fix` | Automatically apply fixes after audit |

Each finding includes: check ID, severity, OWASP ASI reference, evidence, and remediation steps.

**Scoring:** CRITICAL = -15, HIGH = -8, MEDIUM = -3, LOW = -1, INFO = 0.

### `openclaw secureclaw status`

Show current security posture: score, active monitor status (credential, memory, cost), and recent alerts.

### `openclaw secureclaw harden`

Apply security hardening across 5 modules: gateway, credentials, config, Docker, network.

| Flag | Description |
|------|-------------|
| `--full` | Apply all modules without prompts |
| `--rollback [timestamp]` | Revert to a previous backup |

A timestamped backup is created before any changes.

### `openclaw secureclaw scan-skill <name>`

Scan a skill for malicious patterns before installation. Detects `eval()`, `child_process`, exfiltration endpoints, credential file access, IOC matches, and typosquatting.

### `openclaw secureclaw cost-report`

Show cost monitoring data: running status, session costs, projections, and alerts.

## Configuration

Configure via the `secureclaw` entry in your OpenClaw plugin config:

```json
{
  "plugins": {
    "entries": {
      "secureclaw": {
        "enabled": true,
        "config": {
          "cost": {
            "hourlyLimitUsd": 2,
            "dailyLimitUsd": 10,
            "monthlyLimitUsd": 100,
            "circuitBreakerEnabled": true
          },
          "autoHarden": false
        }
      }
    }
  }
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cost.hourlyLimitUsd` | number | — | Maximum spend per hour |
| `cost.dailyLimitUsd` | number | — | Maximum spend per day |
| `cost.monthlyLimitUsd` | number | — | Maximum spend per month |
| `cost.circuitBreakerEnabled` | boolean | false | Auto-pause when cost limit exceeded |
| `autoHarden` | boolean | false | Apply hardening automatically on gateway start |

## OWASP ASI Mapping

All findings reference the [OWASP Agentic Security Initiative](https://owasp.org/www-project-agentic-security-initiative/):

| ASI ID | Category | SecureClaw Checks |
|--------|----------|-------------------|
| ASI01 | Unauthorized Access | SC-AC-001, 002, 004 |
| ASI02 | Excessive Agency | SC-EXEC-001 |
| ASI03 | Credential & Auth Security | SC-GW-001–003, 006, 008–010, SC-CRED-* |
| ASI04 | Untrusted Supply Chain | SC-SKILL-*, SC-IOC-001–003 |
| ASI05 | Network Exposure & Sandbox | SC-GW-004, 005, 007, SC-EXEC-002–007 |
| ASI06 | Memory & Context Manipulation | SC-MEM-001–003, 005 |
| ASI08 | Uncontrolled Resource Consumption | SC-COST-* |
| ASI09 | Overprivileged Access | SC-AC-003, 005 |
| ASI10 | Exfiltration & Infostealers | SC-MEM-004, SC-IOC-004, 005 |

## Development

```sh
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run dev

# Run end-to-end demo
npx tsx demo.ts
```

### Project Structure

```
secureclaw/
├── src/
│   ├── index.ts              # Plugin entry point (OpenClaw SDK + legacy)
│   ├── auditor.ts            # Security audit engine (51 checks)
│   ├── hardener.ts           # Hardening with backup/rollback
│   ├── types.ts              # TypeScript interfaces
│   ├── hardening/            # 5 hardening modules
│   ├── monitors/             # 3 background monitors + skill scanner
│   ├── reporters/            # Console + JSON output
│   └── utils/                # IOC database, crypto, hashing
├── skill/                    # SecureClaw skill (OWASP ASI Top 10 aligned)
│   ├── SKILL.md              # 12 core rules (~1,150 tokens)
│   ├── skill.json            # Skill metadata + OWASP mapping
│   ├── configs/              # 4 JSON pattern databases
│   └── scripts/              # 9 bash scripts (audit, harden, scan, etc.)
├── ioc/                      # Threat intelligence indicators
├── templates/                # Hardening templates
├── openclaw.plugin.json      # Plugin manifest
└── package.json
```

## License

[MIT](LICENSE)
