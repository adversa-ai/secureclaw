import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runAudit } from './auditor.js';
import { harden, rollback } from './hardener.js';
import { formatConsoleReport } from './reporters/console-reporter.js';
import { formatJsonReport } from './reporters/json-reporter.js';
import { credentialMonitor } from './monitors/credential-monitor.js';
import { memoryIntegrityMonitor } from './monitors/memory-integrity.js';
import { costMonitor } from './monitors/cost-monitor.js';
import { scanSkill } from './monitors/skill-scanner.js';
import type {
  AuditContext,
  FileInfo,
  GatewayHandle,
  SecureClawPlugin,
  OpenClawConfig,
  FailureMode,
  RiskProfile,
} from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VERSION = '2.2.0';

// ============================================================
// Kill Switch (G2 — CSA, CoSAI)
// ============================================================

/**
 * Check if the kill switch is active.
 */
export async function isKillSwitchActive(stateDir: string): Promise<boolean> {
  const killPath = path.join(stateDir, '.secureclaw', 'killswitch');
  try {
    await fs.access(killPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Activate the kill switch — blocks all tool calls.
 */
export async function activateKillSwitch(stateDir: string, reason?: string): Promise<void> {
  const scDir = path.join(stateDir, '.secureclaw');
  await fs.mkdir(scDir, { recursive: true });
  const content = JSON.stringify({
    activated: new Date().toISOString(),
    reason: reason ?? 'Manual activation',
    activatedBy: 'secureclaw-cli',
  }, null, 2);
  await fs.writeFile(path.join(scDir, 'killswitch'), content, 'utf-8');
}

/**
 * Deactivate the kill switch — resumes normal operation.
 */
export async function deactivateKillSwitch(stateDir: string): Promise<void> {
  const killPath = path.join(stateDir, '.secureclaw', 'killswitch');
  try {
    await fs.unlink(killPath);
  } catch {
    // Already inactive
  }
}

// ============================================================
// Behavioral Baseline (G3 — CoSAI)
// ============================================================

/**
 * Log a tool call for behavioral baseline tracking.
 */
export async function logToolCall(
  stateDir: string,
  toolName: string,
  dataPath?: string,
): Promise<void> {
  const logDir = path.join(stateDir, '.secureclaw', 'behavioral');
  await fs.mkdir(logDir, { recursive: true });
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    tool: toolName,
    dataPath: dataPath ?? '',
  }) + '\n';
  await fs.appendFile(path.join(logDir, 'tool-calls.jsonl'), entry, 'utf-8');
}

/**
 * Get behavioral baseline statistics.
 */
export async function getBehavioralBaseline(
  stateDir: string,
  windowMinutes = 60,
): Promise<{ toolFrequency: Record<string, number>; totalCalls: number; uniqueTools: number }> {
  const logPath = path.join(stateDir, '.secureclaw', 'behavioral', 'tool-calls.jsonl');
  let content: string;
  try {
    content = await fs.readFile(logPath, 'utf-8');
  } catch {
    return { toolFrequency: {}, totalCalls: 0, uniqueTools: 0 };
  }

  const cutoff = new Date(Date.now() - windowMinutes * 60 * 1000);
  const frequency: Record<string, number> = {};
  let total = 0;

  for (const line of content.split('\n').filter(Boolean)) {
    try {
      const entry = JSON.parse(line);
      if (new Date(entry.timestamp) >= cutoff) {
        frequency[entry.tool] = (frequency[entry.tool] ?? 0) + 1;
        total++;
      }
    } catch {
      // Skip malformed lines
    }
  }

  return {
    toolFrequency: frequency,
    totalCalls: total,
    uniqueTools: Object.keys(frequency).length,
  };
}

// ============================================================
// Failure Modes (G4 — CoSAI, CSA)
// ============================================================

const FAILURE_MODE_DESCRIPTIONS: Record<FailureMode, string> = {
  block_all: 'Block ALL tool calls — full lockdown',
  safe_mode: 'Allow read operations only, block all writes',
  read_only: 'Allow ls/cat/git status, block everything else',
};

/**
 * Get the current failure mode.
 */
export function getFailureMode(config: OpenClawConfig): FailureMode {
  return config.secureclaw?.failureMode ?? 'block_all';
}

/**
 * Get the active risk profile.
 */
export function getRiskProfile(config: OpenClawConfig): RiskProfile {
  return config.secureclaw?.riskProfile ?? 'standard';
}

/**
 * Create a real AuditContext from a state directory and config.
 */
export async function createAuditContext(
  stateDir: string,
  config?: OpenClawConfig
): Promise<AuditContext> {
  let loadedConfig = config;
  if (!loadedConfig) {
    try {
      const configContent = await fs.readFile(path.join(stateDir, 'openclaw.json'), 'utf-8');
      loadedConfig = JSON.parse(configContent) as OpenClawConfig;
    } catch {
      loadedConfig = {};
    }
  }

  return {
    stateDir,
    config: loadedConfig,
    platform: `${os.platform()}-${os.arch()}`,
    deploymentMode: 'native',
    openclawVersion: 'unknown',

    async fileInfo(filePath: string): Promise<FileInfo> {
      try {
        const stat = await fs.stat(filePath);
        return {
          path: filePath,
          permissions: stat.mode & 0o777,
          exists: true,
          size: stat.size,
        };
      } catch {
        return { path: filePath, exists: false };
      }
    },

    async readFile(filePath: string): Promise<string | null> {
      try {
        return await fs.readFile(filePath, 'utf-8');
      } catch {
        return null;
      }
    },

    async listDir(dirPath: string): Promise<string[]> {
      return fs.readdir(dirPath);
    },

    async fileExists(filePath: string): Promise<boolean> {
      try {
        await fs.access(filePath);
        return true;
      } catch {
        return false;
      }
    },

    async getFilePermissions(filePath: string): Promise<number | null> {
      try {
        const stat = await fs.stat(filePath);
        return stat.mode & 0o777;
      } catch {
        return null;
      }
    },
  };
}

// ============================================================
// OpenClaw Plugin SDK Integration
// ============================================================

// Lightweight interface for the OpenClaw plugin API.
// We define our own interface rather than importing from openclaw/plugin-sdk
// to avoid a hard compile-time dependency (openclaw is a peerDependency).
// At runtime OpenClaw passes the real object that satisfies this shape.
interface PluginServiceContext {
  stateDir: string;
  config: OpenClawConfig;
}

interface PluginCliContext {
  // Commander.js Command instance
  program: {
    command(name: string): PluginCliContext['program'];
    description(desc: string): PluginCliContext['program'];
    option(flags: string, desc: string): PluginCliContext['program'];
    argument(name: string, desc: string): PluginCliContext['program'];
    action(fn: (...args: unknown[]) => void | Promise<void>): PluginCliContext['program'];
  };
  config: OpenClawConfig;
}

interface PluginLogger {
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

interface PluginApi {
  id: string;
  name: string;
  config: OpenClawConfig;
  pluginConfig?: Record<string, unknown>;
  logger: PluginLogger;
  registerCli(
    registrar: (ctx: PluginCliContext) => void | Promise<void>,
    opts?: { commands?: string[] },
  ): void;
  registerService(service: {
    id: string;
    start: (ctx: PluginServiceContext) => void | Promise<void>;
    stop?: (ctx: PluginServiceContext) => void | Promise<void>;
  }): void;
  on(
    hookName: string,
    handler: (...args: unknown[]) => void | Promise<void>,
    opts?: { priority?: number },
  ): void;
}

const secureClawPlugin = {
  id: 'secureclaw',
  name: 'SecureClaw',
  version: VERSION,
  description: 'Automated security hardening for OpenClaw',
  configSchema: {
    parse(value: unknown) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return value as Record<string, unknown>;
      }
      return {};
    },
  },

  register(api: PluginApi) {
    // ── Background Services (monitors) ─────────────────────────
    api.registerService({
      id: 'secureclaw-credential-monitor',
      async start(ctx) { await credentialMonitor.start(ctx.stateDir); },
      async stop() { await credentialMonitor.stop(); },
    });

    api.registerService({
      id: 'secureclaw-memory-monitor',
      async start(ctx) { await memoryIntegrityMonitor.start(ctx.stateDir); },
      async stop() { await memoryIntegrityMonitor.stop(); },
    });

    api.registerService({
      id: 'secureclaw-cost-monitor',
      async start(ctx) { await costMonitor.start(ctx.stateDir); },
      async stop() { await costMonitor.stop(); },
    });

    // ── Lifecycle Hooks ────────────────────────────────────────
    api.on('gateway_start', async () => {
      try {
        const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');

        // Check kill switch (G2)
        if (await isKillSwitchActive(stateDir)) {
          api.logger.warn('[SecureClaw] 🔴 KILL SWITCH ACTIVE — all operations suspended');
          return;
        }

        const ctx = await createAuditContext(stateDir, api.config);
        const report = await runAudit({ context: ctx });
        api.logger.info(`[SecureClaw] Security score: ${report.score}/100`);
        if (report.summary.critical > 0) {
          api.logger.warn(
            `[SecureClaw] WARNING: ${report.summary.critical} CRITICAL finding(s) detected!`,
          );
        }

        // Check for SecureClaw skill
        const skillPath = path.join(stateDir, 'skills', 'secureclaw', 'SKILL.md');
        try {
          await fs.access(skillPath);
          api.logger.info('[SecureClaw] Skill detected — plugin provides enforcement layer');
        } catch {
          // Skill not installed, that's fine
        }
      } catch (err) {
        api.logger.error(`[SecureClaw] Startup audit failed: ${(err as Error).message}`);
        api.logger.error(`[SecureClaw] Stack: ${(err as Error).stack}`);
        // Don't re-throw — let the gateway continue without SecureClaw
      }
    });

    api.logger.info(`[SecureClaw] v${VERSION} plugin registered (56 audit checks)`);

    // ── CLI Commands ───────────────────────────────────────────
    api.registerCli(({ program }) => {
      const sc = program
        .command('secureclaw')
        .description('SecureClaw security hardening');

      sc.command('audit')
        .description('Run a security audit')
        .option('--json', 'Output JSON format')
        .option('--deep', 'Run deep audit')
        .option('--fix', 'Auto-apply fixes')
        .action(async (...args: unknown[]) => {
          const opts = (args[0] ?? {}) as Record<string, boolean>;
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          const ctx = await createAuditContext(stateDir, api.config);
          const report = await runAudit({ deep: opts['deep'], fix: opts['fix'], context: ctx });
          if (opts['json']) {
            console.log(formatJsonReport(report));
          } else {
            console.log(formatConsoleReport(report));
          }
          if (opts['fix'] && report.summary.autoFixable > 0) {
            console.log('\nApplying automatic fixes...');
            const result = await harden({ full: true, context: ctx });
            console.log(`Fixes applied. Backup at: ${result.backupDir}`);
          }
        });

      sc.command('harden')
        .description('Apply security hardening')
        .option('--full', 'Apply all hardening steps')
        .option('--rollback [timestamp]', 'Rollback to a previous state')
        .action(async (...args: unknown[]) => {
          const opts = (args[0] ?? {}) as Record<string, string | boolean>;
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          if (opts['rollback']) {
            const timestamp = typeof opts['rollback'] === 'string' ? opts['rollback'] : undefined;
            await rollback(stateDir, timestamp);
            console.log('Rollback complete.');
            return;
          }
          const ctx = await createAuditContext(stateDir, api.config);
          const result = await harden({ full: !!opts['full'], interactive: !opts['full'], context: ctx });
          console.log(`Hardening complete. Backup at: ${result.backupDir}`);
          for (const r of result.results) {
            console.log(`  ${r.module}: ${r.applied.length} actions applied, ${r.errors.length} errors`);
          }
        });

      sc.command('status')
        .description('Show security status')
        .action(async () => {
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          const ctx = await createAuditContext(stateDir, api.config);
          const report = await runAudit({ context: ctx });
          console.log(`Security Score: ${report.score}/100`);
          console.log('Monitors:');
          console.log(`  Credential: ${credentialMonitor.status().running ? 'running' : 'stopped'}`);
          console.log(`  Memory: ${memoryIntegrityMonitor.status().running ? 'running' : 'stopped'}`);
          console.log(`  Cost: ${costMonitor.status().running ? 'running' : 'stopped'}`);
          const totalAlerts = credentialMonitor.status().alerts.length
            + memoryIntegrityMonitor.status().alerts.length
            + costMonitor.status().alerts.length;
          console.log(`Recent Alerts: ${totalAlerts}`);
        });

      sc.command('scan-skill')
        .description('Scan a skill for security issues')
        .argument('<name>', 'Skill name to scan')
        .action(async (...args: unknown[]) => {
          const skillName = args[0] as string;
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          const skillDir = path.join(stateDir, 'skills', skillName);
          const result = await scanSkill(skillDir, skillName);
          if (result.safe) {
            console.log(`Skill "${skillName}" passed security scan.`);
          } else {
            console.log(`WARNING: Skill "${skillName}" has security concerns:`);
          }
          for (const finding of result.findings) {
            console.log(`  - ${finding}`);
          }
        });

      sc.command('cost-report')
        .description('Show cost monitoring report')
        .action(() => {
          const status = costMonitor.status();
          console.log(`Cost Monitor: ${status.running ? 'running' : 'stopped'}`);
          console.log(`Recent Alerts: ${status.alerts.length}`);
          for (const alert of status.alerts.slice(-5)) {
            console.log(`  [${alert.severity}] ${alert.message}`);
          }
        });

      // ── Kill Switch (G2) ──
      sc.command('kill')
        .description('Activate the kill switch — suspend all agent operations')
        .option('--reason <reason>', 'Reason for activating kill switch')
        .action(async (...args: unknown[]) => {
          const opts = (args[0] ?? {}) as Record<string, string>;
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          await activateKillSwitch(stateDir, opts['reason']);
          console.log('🔴 KILL SWITCH ACTIVATED — all agent operations suspended');
          console.log(`   Reason: ${opts['reason'] ?? 'Manual activation'}`);
          console.log('   To resume: npx openclaw secureclaw resume');
        });

      sc.command('resume')
        .description('Deactivate the kill switch — resume agent operations')
        .action(async () => {
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          const wasActive = await isKillSwitchActive(stateDir);
          if (!wasActive) {
            console.log('Kill switch is not active. Nothing to resume.');
            return;
          }
          await deactivateKillSwitch(stateDir);
          console.log('✅ Kill switch deactivated — agent operations resumed');
        });

      // ── Behavioral Baseline (G3) ──
      sc.command('baseline')
        .description('Show behavioral baseline statistics')
        .option('--window <minutes>', 'Time window in minutes (default: 60)')
        .action(async (...args: unknown[]) => {
          const opts = (args[0] ?? {}) as Record<string, string>;
          const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          const window = parseInt(opts['window'] ?? '60', 10);
          const baseline = await getBehavioralBaseline(stateDir, window);
          console.log(`Behavioral Baseline (last ${window} minutes):`);
          console.log(`  Total tool calls: ${baseline.totalCalls}`);
          console.log(`  Unique tools: ${baseline.uniqueTools}`);
          if (baseline.totalCalls > 0) {
            console.log('  Tool frequency:');
            for (const [tool, count] of Object.entries(baseline.toolFrequency).sort((a, b) => b[1] - a[1])) {
              console.log(`    ${tool}: ${count}`);
            }
          }
        });

      const sk = sc.command('skill')
        .description('SecureClaw skill management');

      sk.command('install')
        .description('Install the SecureClaw skill')
        .action(async () => {
          const installScript = path.join(__dirname, '..', 'skill', 'scripts', 'install.sh');
          try {
            execSync(`bash "${installScript}"`, { stdio: 'inherit' });
          } catch (err) {
            console.error('Failed to install skill:', (err as Error).message);
          }
        });

      sk.command('audit')
        .description('Run skill quick audit')
        .action(async () => {
          const skStateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
          // Try installed skill location first, fall back to bundled
          let scriptDir = path.join(skStateDir, 'skills', 'secureclaw', 'scripts');
          try {
            await fs.access(path.join(scriptDir, 'quick-audit.sh'));
          } catch {
            scriptDir = path.join(__dirname, '..', 'skill', 'scripts');
          }
          try {
            execSync(`bash "${path.join(scriptDir, 'quick-audit.sh')}"`, { stdio: 'inherit' });
          } catch {
            // Script exits non-zero if checks fail — expected
          }
        });
    }, { commands: ['secureclaw'] });
  },
};

export default secureClawPlugin;

// ============================================================
// Legacy plugin interface (used by existing tests / programmatic API)
// ============================================================

async function onGatewayStart(gateway: GatewayHandle): Promise<void> {
  const stateDir = gateway.stateDir;
  const ctx = await createAuditContext(stateDir, gateway.config);
  ctx.openclawVersion = gateway.version;

  const report = await runAudit({ context: ctx });
  console.log(`[SecureClaw] Security score: ${report.score}/100`);

  if (report.summary.critical > 0) {
    console.log(`[SecureClaw] WARNING: ${report.summary.critical} CRITICAL finding(s) detected!`);
  }

  await Promise.all([
    credentialMonitor.start(stateDir),
    memoryIntegrityMonitor.start(stateDir),
    costMonitor.start(stateDir),
  ]);

  console.log('[SecureClaw] Background monitors started.');
}

async function onGatewayStop(): Promise<void> {
  await Promise.all([
    credentialMonitor.stop(),
    memoryIntegrityMonitor.stop(),
    costMonitor.stop(),
  ]);

  console.log('[SecureClaw] Background monitors stopped.');
}

export const legacyPlugin: SecureClawPlugin = {
  name: 'secureclaw',
  version: VERSION,
  description: 'Automated security hardening for OpenClaw',
  onGatewayStart,
  onGatewayStop,
  commands: {
    'secureclaw audit': async (...args: string[]) => {
      const jsonOutput = args.includes('--json');
      const deep = args.includes('--deep');
      const autoFix = args.includes('--fix');
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      const ctx = await createAuditContext(stateDir);
      const report = await runAudit({ deep, fix: autoFix, context: ctx });
      if (jsonOutput) {
        console.log(formatJsonReport(report));
      } else {
        console.log(formatConsoleReport(report));
      }
    },
    'secureclaw harden': async (...args: string[]) => {
      const full = args.includes('--full');
      const doRollback = args.includes('--rollback');
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      if (doRollback) {
        const timestamp = args.find((a) => !a.startsWith('--'));
        await rollback(stateDir, timestamp);
        console.log('Rollback complete.');
        return;
      }
      const ctx = await createAuditContext(stateDir);
      const result = await harden({ full, interactive: !full, context: ctx });
      console.log(`Hardening complete. Backup at: ${result.backupDir}`);
      for (const r of result.results) {
        console.log(`  ${r.module}: ${r.applied.length} actions applied, ${r.errors.length} errors`);
      }
    },
    'secureclaw status': async () => {
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      const ctx = await createAuditContext(stateDir);
      const report = await runAudit({ context: ctx });
      console.log(`Security Score: ${report.score}/100`);
    },
    'secureclaw scan-skill': async (...args: string[]) => {
      const skillName = args.find((a) => !a.startsWith('--'));
      if (!skillName) {
        console.error('Usage: openclaw secureclaw scan-skill <skill-name>');
        return;
      }
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      const skillDir = path.join(stateDir, 'skills', skillName);
      const result = await scanSkill(skillDir, skillName);
      if (result.safe) {
        console.log(`Skill "${skillName}" passed security scan.`);
      } else {
        console.log(`WARNING: Skill "${skillName}" has security concerns:`);
      }
      for (const finding of result.findings) {
        console.log(`  - ${finding}`);
      }
    },
    'secureclaw cost-report': async () => {
      const status = costMonitor.status();
      console.log(`Cost Monitor: ${status.running ? 'running' : 'stopped'}`);
    },
    'secureclaw kill': async (...args: string[]) => {
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      const reason = args.find((a) => !a.startsWith('--')) ?? 'Manual activation';
      await activateKillSwitch(stateDir, reason);
      console.log('🔴 KILL SWITCH ACTIVATED — all agent operations suspended');
    },
    'secureclaw resume': async () => {
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      await deactivateKillSwitch(stateDir);
      console.log('✅ Kill switch deactivated — agent operations resumed');
    },
    'secureclaw baseline': async (...args: string[]) => {
      const stateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      const windowArg = args.find((a) => !a.startsWith('--'));
      const window = windowArg ? parseInt(windowArg, 10) : 60;
      const baseline = await getBehavioralBaseline(stateDir, window);
      console.log(`Behavioral Baseline (last ${window} minutes):`);
      console.log(`  Total tool calls: ${baseline.totalCalls}`);
      console.log(`  Unique tools: ${baseline.uniqueTools}`);
    },
    'secureclaw skill install': async () => {
      const installScript = path.join(__dirname, '..', 'skill', 'scripts', 'install.sh');
      try {
        execSync(`bash "${installScript}"`, { stdio: 'inherit' });
      } catch (err) {
        console.error('Failed to install skill:', (err as Error).message);
      }
    },
    'secureclaw skill audit': async () => {
      const skStateDir = process.env['OPENCLAW_STATE_DIR'] ?? path.join(os.homedir(), '.openclaw');
      let scriptDir = path.join(skStateDir, 'skills', 'secureclaw', 'scripts');
      try {
        await fs.access(path.join(scriptDir, 'quick-audit.sh'));
      } catch {
        scriptDir = path.join(__dirname, '..', 'skill', 'scripts');
      }
      try {
        execSync(`bash "${path.join(scriptDir, 'quick-audit.sh')}"`, { stdio: 'inherit' });
      } catch {
        // Script exits non-zero if checks fail — expected
      }
    },
    'secureclaw skill update': async () => {
      const installScript = path.join(__dirname, '..', 'skill', 'scripts', 'install.sh');
      try {
        execSync(`bash "${installScript}"`, { stdio: 'inherit' });
      } catch (err) {
        console.error('Failed to update skill:', (err as Error).message);
      }
    },
    'secureclaw skill uninstall': async () => {
      const uninstallScript = path.join(__dirname, '..', 'skill', 'scripts', 'uninstall.sh');
      try {
        execSync(`bash "${uninstallScript}" --force`, { stdio: 'inherit' });
      } catch (err) {
        console.error('Failed to uninstall skill:', (err as Error).message);
      }
    },
  },
  tools: ['security_audit', 'security_status', 'skill_scan', 'cost_report', 'kill_switch', 'behavioral_baseline'],
};

// Also export individual components for programmatic use
export { runAudit } from './auditor.js';
export { harden, rollback } from './hardener.js';
export { formatConsoleReport } from './reporters/console-reporter.js';
export { formatJsonReport } from './reporters/json-reporter.js';
export { credentialMonitor } from './monitors/credential-monitor.js';
export { memoryIntegrityMonitor } from './monitors/memory-integrity.js';
export { costMonitor } from './monitors/cost-monitor.js';
export { scanSkill } from './monitors/skill-scanner.js';
export type * from './types.js';
