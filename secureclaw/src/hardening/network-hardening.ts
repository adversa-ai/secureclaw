import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadIOCDatabase } from '../utils/ioc-db.js';
import type {
  AuditContext,
  AuditFinding,
  HardeningModule,
  HardeningResult,
  HardeningAction,
} from '../types.js';

const EGRESS_ALLOWLIST = [
  'api.anthropic.com',
  'api.openai.com',
  'generativelanguage.googleapis.com',
  'api.together.xyz',
  'openrouter.ai',
];

function generateIptablesScript(allowlist: string[], blocklist: string[]): string {
  const lines: string[] = [
    '#!/bin/bash',
    '# SecureClaw Network Hardening - iptables rules',
    '# Review carefully before applying!',
    '# Generated: ' + new Date().toISOString(),
    '',
    '# Block known C2 IPs',
  ];

  for (const ip of blocklist) {
    lines.push(`iptables -A OUTPUT -d ${ip} -j DROP`);
  }

  lines.push('');
  lines.push('# Egress allowlist (uncomment to enforce)');
  lines.push('# WARNING: This will restrict ALL outbound traffic to only allowed destinations');
  for (const domain of allowlist) {
    lines.push(`# iptables -A OUTPUT -d ${domain} -p tcp --dport 443 -j ACCEPT`);
  }
  lines.push('# iptables -A OUTPUT -p tcp --dport 443 -j DROP  # Block all other HTTPS');

  return lines.join('\n');
}

function generatePfScript(allowlist: string[], blocklist: string[]): string {
  const lines: string[] = [
    '# SecureClaw Network Hardening - pf rules (macOS)',
    '# Review carefully before applying!',
    '# Generated: ' + new Date().toISOString(),
    '# Add these rules to /etc/pf.conf',
    '',
    '# Block known C2 IPs',
  ];

  for (const ip of blocklist) {
    lines.push(`block out quick on en0 to ${ip}`);
  }

  lines.push('');
  lines.push('# Egress allowlist (uncomment to enforce)');
  for (const domain of allowlist) {
    lines.push(`# pass out on en0 proto tcp to ${domain} port 443`);
  }
  lines.push('# block out on en0 proto tcp to any port 443  # Block all other HTTPS');

  return lines.join('\n');
}

export const networkHardening: HardeningModule = {
  name: 'network-hardening',
  priority: 5,

  async check(ctx: AuditContext): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    findings.push({
      id: 'SC-NET-001',
      severity: 'INFO',
      category: 'network',
      title: 'Network hardening available',
      description: 'SecureClaw can generate egress allowlist and C2 blocklist scripts.',
      evidence: `Platform: ${ctx.platform}`,
      remediation: 'Run "secureclaw harden" to generate network rules',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI05',
    });

    return findings;
  },

  async fix(ctx: AuditContext, backupDir: string): Promise<HardeningResult> {
    const applied: HardeningAction[] = [];
    const skipped: HardeningAction[] = [];
    const errors: string[] = [];

    try {
      let db;
      try {
        db = await loadIOCDatabase();
      } catch {
        db = { c2_ips: [] as string[], malicious_domains: [] as string[], malicious_skill_hashes: {}, typosquat_patterns: [] as string[], dangerous_prerequisite_patterns: [] as string[], infostealer_artifacts: { macos: [] as string[], linux: [] as string[] }, version: '0', last_updated: '' };
      }

      const allowlist = ctx.config.secureclaw?.network?.egressAllowlist ?? EGRESS_ALLOWLIST;
      const blocklist = db.c2_ips;

      const platform = os.platform();
      const scriptDir = path.join(ctx.stateDir, '.secureclaw', 'network');
      await fs.mkdir(scriptDir, { recursive: true });

      if (platform === 'linux') {
        const script = generateIptablesScript(allowlist, blocklist);
        const scriptPath = path.join(scriptDir, 'egress-rules.sh');
        await fs.writeFile(scriptPath, script, { mode: 0o700 });
        applied.push({
          id: 'net-iptables',
          description: 'Generated iptables egress rules script',
          before: 'no rules',
          after: scriptPath,
        });
      } else if (platform === 'darwin') {
        const script = generatePfScript(allowlist, blocklist);
        const scriptPath = path.join(scriptDir, 'pf-rules.conf');
        await fs.writeFile(scriptPath, script, { mode: 0o600 });
        applied.push({
          id: 'net-pf',
          description: 'Generated pf egress rules (macOS)',
          before: 'no rules',
          after: scriptPath,
        });
      } else {
        skipped.push({
          id: 'net-platform',
          description: 'Network rules generation skipped — unsupported platform',
          before: `platform: ${platform}`,
          after: 'skipped',
        });
      }

      // Generate C2 blocklist file
      if (blocklist.length > 0) {
        const blocklistPath = path.join(scriptDir, 'c2-blocklist.txt');
        await fs.writeFile(blocklistPath, blocklist.join('\n') + '\n', 'utf-8');
        applied.push({
          id: 'net-blocklist',
          description: 'Generated C2 IP blocklist file',
          before: 'no blocklist',
          after: `${blocklist.length} IPs blocked`,
        });
      }
    } catch (err) {
      errors.push(`Network hardening error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return {
      module: 'network-hardening',
      applied,
      skipped,
      errors,
      note: applied.length > 0 ? 'Files generated for manual review — not auto-applied' : undefined,
    };
  },

  async rollback(backupDir: string): Promise<void> {
    // Network rules are generated as scripts, not auto-applied.
    // Rollback just removes the generated scripts.
  },
};
