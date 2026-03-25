import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type {
  AuditContext,
  AuditFinding,
  HardeningModule,
  HardeningResult,
  HardeningAction,
  OpenClawConfig,
} from '../types.js';

async function readConfig(stateDir: string): Promise<OpenClawConfig> {
  const configPath = path.join(stateDir, 'openclaw.json');
  try {
    const content = await fs.readFile(configPath, 'utf-8');
    return JSON.parse(content) as OpenClawConfig;
  } catch {
    return {};
  }
}

async function writeConfig(stateDir: string, config: OpenClawConfig): Promise<void> {
  const configPath = path.join(stateDir, 'openclaw.json');
  await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

export const configHardening: HardeningModule = {
  name: 'config-hardening',
  priority: 3,

  async check(ctx: AuditContext): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    if (ctx.config.exec?.approvals === 'off') {
      findings.push({
        id: 'SC-EXEC-001',
        severity: 'CRITICAL',
        category: 'execution',
        title: 'Execution approvals disabled',
        description: 'Execution approvals are disabled. This allows commands to run without user confirmation.',
        evidence: 'exec.approvals = "off"',
        remediation: 'Manually set exec.approvals to "always" in your OpenClaw settings (not auto-fixable — key not in OpenClaw config schema)',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI02',
      });
    }

    if (ctx.config.tools?.exec?.host !== 'sandbox') {
      findings.push({
        id: 'SC-EXEC-003',
        severity: 'MEDIUM',
        category: 'execution',
        title: 'Execution host not set to sandbox',
        description: `tools.exec.host is "${ctx.config.tools?.exec?.host ?? 'undefined'}". Commands may run directly on the host without isolation.`,
        evidence: `tools.exec.host = "${ctx.config.tools?.exec?.host ?? 'undefined'}"`,
        remediation: 'Set tools.exec.host to "sandbox" (or run secureclaw harden). For full Docker isolation also set agents.defaults.sandbox.mode to "all".',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI05',
      });
    }

    const channels = ctx.channels ?? [];
    for (const ch of channels) {
      if (ch.dmPolicy === 'open') {
        findings.push({
          id: 'SC-AC-001',
          severity: 'HIGH',
          category: 'access-control',
          title: `Channel "${ch.name}" has open DM policy`,
          description: 'Will set to "pairing".',
          evidence: `dmPolicy = "open"`,
          remediation: 'Set dmPolicy to "pairing"',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI01',
        });
      }
    }

    return findings;
  },

  async fix(ctx: AuditContext, backupDir: string): Promise<HardeningResult> {
    const applied: HardeningAction[] = [];
    const skipped: HardeningAction[] = [];
    const errors: string[] = [];

    try {
      // Backup current config
      const configPath = path.join(ctx.stateDir, 'openclaw.json');
      try {
        await fs.copyFile(configPath, path.join(backupDir, 'openclaw-config.json'));
      } catch {
        // Config may not exist yet
      }

      const config = await readConfig(ctx.stateDir);

      // NOTE: We only write keys that OpenClaw's runtime schema accepts.
      // Keys like exec.approvals, exec.autoApprove, sandbox.mode are NOT
      // valid in OpenClaw's config and would cause "Invalid config" errors.
      // Those settings are reported as audit findings with manual remediation.

      // 1. Set tools.exec.host to sandbox (valid OpenClaw key)
      if (!config.tools) config.tools = {};
      if (!config.tools.exec) config.tools.exec = {};
      const oldExecHost = config.tools.exec.host;
      if (oldExecHost !== 'sandbox') {
        config.tools.exec.host = 'sandbox';
        applied.push({
          id: 'config-exec-host',
          description: 'Set tools.exec.host to "sandbox"',
          before: oldExecHost ?? 'undefined',
          after: 'sandbox',
        });
      }

      // 2. Enable DM session isolation (valid OpenClaw key)
      if (!config.session) config.session = {};
      const oldDmScope = config.session.dmScope;
      if (oldDmScope !== 'per-channel-peer') {
        config.session.dmScope = 'per-channel-peer';
        applied.push({
          id: 'config-dm-scope',
          description: 'Set session.dmScope to "per-channel-peer"',
          before: oldDmScope ?? 'undefined',
          after: 'per-channel-peer',
        });
      }

      // 3. Enable sensitive log redaction (valid OpenClaw key)
      if (!config.logging) config.logging = {};
      const oldRedact = config.logging.redactSensitive;
      if (oldRedact !== 'tools') {
        config.logging.redactSensitive = 'tools';
        applied.push({
          id: 'config-log-redact',
          description: 'Enabled sensitive log redaction',
          before: oldRedact ?? 'undefined',
          after: 'tools',
        });
      }

      // 4. Strip keys that are NOT in OpenClaw's config schema to avoid
      //    "Invalid config" / "Unrecognized key" errors on startup.
      const configAny = config as Record<string, unknown>;
      if (configAny['exec']) {
        delete configAny['exec'];
        applied.push({
          id: 'config-strip-exec',
          description: 'Removed invalid root-level "exec" key (not in OpenClaw schema)',
          before: 'present',
          after: 'removed',
        });
      }
      if (configAny['sandbox']) {
        delete configAny['sandbox'];
        applied.push({
          id: 'config-strip-sandbox',
          description: 'Removed invalid root-level "sandbox" key (not in OpenClaw schema)',
          before: 'present',
          after: 'removed',
        });
      }

      await writeConfig(ctx.stateDir, config);
    } catch (err) {
      errors.push(`Config hardening error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return { module: 'config-hardening', applied, skipped, errors };
  },

  async rollback(backupDir: string): Promise<void> {
    // Rollback is handled by the orchestrator
  },
};
