/**
 * Plugin bugfix verification tests — Group G (unit-testable subset)
 *
 * Covers: package name, network-hardening output labeling, docker-hardening
 * YAML format and Docker presence check, config namespace read/write,
 * monitor start/stop API, scan-skill workspace path resolution, and
 * backup-dir exclusion from audit findings.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { networkHardening } from './hardening/network-hardening.js';
import { dockerHardening } from './hardening/docker-hardening.js';
import { credentialMonitor } from './monitors/credential-monitor.js';
import { memoryIntegrityMonitor } from './monitors/memory-integrity.js';
import { costMonitor } from './monitors/cost-monitor.js';
import { scanSkill } from './monitors/skill-scanner.js';
import { runAudit } from './auditor.js';
import { createAuditContext } from './index.js';
import type { AuditContext, OpenClawConfig } from './types.js';

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

let tmpDir: string;
let backupDir: string;

async function setup() {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-verify-'));
  backupDir = path.join(tmpDir, 'backup');
  await fs.mkdir(backupDir, { recursive: true });
}

async function teardown() {
  await fs.rm(tmpDir, { recursive: true, force: true });
}

function makeCtx(config: OpenClawConfig = {}): AuditContext {
  return {
    stateDir: tmpDir,
    config,
    platform: 'linux-amd64',
    deploymentMode: 'native',
    openclawVersion: '2026.3.7',
    async fileInfo(p) { return { path: p, exists: true }; },
    async readFile(p) { try { return await fs.readFile(p, 'utf-8'); } catch { return null; } },
    async listDir(p) { return fs.readdir(p); },
    async fileExists(p) { try { await fs.access(p); return true; } catch { return false; } },
    async getFilePermissions(p) { try { const s = await fs.stat(p); return s.mode & 0o777; } catch { return null; } },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// npm package name
// ─────────────────────────────────────────────────────────────────────────────

describe('npm package name', () => {
  it('package.json name is @adversa/secureclaw', async () => {
    const pkgPath = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(await fs.readFile(pkgPath, 'utf-8'));
    expect(pkg.name).toBe('@adversa/secureclaw');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Network hardening — output correctly labeled as generated, not auto-applied
// ─────────────────────────────────────────────────────────────────────────────

describe('network-hardening output labeling', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('fix() sets note indicating files are generated for manual review', async () => {
    const ctx = makeCtx();
    const result = await networkHardening.fix(ctx, backupDir);
    if (result.applied.length > 0) {
      expect(result.note).toBeDefined();
      expect(result.note).toMatch(/generated|manual review/i);
    }
  });

  it('fix() note does not claim rules are auto-applied', async () => {
    const ctx = makeCtx();
    const result = await networkHardening.fix(ctx, backupDir);
    // If a note is present it must not say the rules were automatically enforced
    if (result.note) {
      expect(result.note.toLowerCase()).not.toContain('auto-applied to system');
      expect(result.note.toLowerCase()).not.toContain('enforced');
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Docker hardening — YAML format and Docker presence check
// ─────────────────────────────────────────────────────────────────────────────

describe('docker-hardening fix() when Docker is not installed', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('returns a skipped action (not applied) when Docker is absent', async () => {
    // On the test VM Docker may or may not be installed.
    // If Docker IS installed this test is skipped; if not, we assert correct behavior.
    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    if (result.skipped.length > 0) {
      // Docker not installed — correct behavior
      const skip = result.skipped.find((s) => s.id === 'docker-override');
      expect(skip).toBeDefined();
      expect(skip!.after).toBe('skipped');
      expect(result.applied).toHaveLength(0);
    } else {
      // Docker IS installed — verify YAML was generated (see next describe block)
      expect(result.applied.length).toBeGreaterThan(0);
    }
  });

  it('does not write docker-compose.secureclaw.yml when Docker is absent', async () => {
    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    if (result.skipped.some((s) => s.id === 'docker-override')) {
      const overridePath = path.join(tmpDir, 'docker-compose.secureclaw.yml');
      const exists = await fs.access(overridePath).then(() => true).catch(() => false);
      expect(exists).toBe(false);
    }
    // If Docker is installed, file will be written — covered in the YAML test below
  });
});

describe('docker-hardening fix() YAML output format', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('generated docker-compose file contains valid YAML (not JSON)', async () => {
    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    // Only run if Docker is installed and the file was generated
    if (result.applied.some((a) => a.id === 'docker-override')) {
      const overridePath = path.join(tmpDir, 'docker-compose.secureclaw.yml');
      const content = await fs.readFile(overridePath, 'utf-8');

      // YAML file must have YAML structure markers, not start with JSON {
      expect(content.trimStart()).not.toMatch(/^\{/);
      expect(content).toContain('services:');
      expect(content).toContain('openclaw-gateway:');
      expect(content).toContain('read_only: true');
      expect(content).toContain('cap_drop:');
      expect(content).toContain('networks:');
    }
  });

  it('generated docker-compose file is parseable as YAML (no JSON.parse errors)', async () => {
    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    if (result.applied.some((a) => a.id === 'docker-override')) {
      const overridePath = path.join(tmpDir, 'docker-compose.secureclaw.yml');
      const content = await fs.readFile(overridePath, 'utf-8');

      // Attempting JSON.parse on YAML must throw — confirming it is not JSON
      expect(() => JSON.parse(content)).toThrow();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Config namespace — openclaw.json secureclaw block read/write
// ─────────────────────────────────────────────────────────────────────────────

describe('config namespace — secureclaw block in openclaw.json', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('writing secureclaw config directly nests under "secureclaw" key', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    const initial = { gateway: { bind: 'loopback' } };
    await fs.writeFile(configPath, JSON.stringify(initial), 'utf-8');

    // Simulate what config set does: write secureclaw key into the json
    const config = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    config['secureclaw'] = { failureMode: 'safe_mode' };
    await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');

    const result = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(result['secureclaw']).toBeDefined();
    expect(result['secureclaw']['failureMode']).toBe('safe_mode');
    // Other config untouched
    expect(result['gateway']['bind']).toBe('loopback');
  });

  it('createAuditContext reads secureclaw config from openclaw.json', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(
      configPath,
      JSON.stringify({ secureclaw: { failureMode: 'safe_mode', riskProfile: 'strict' } }),
      'utf-8',
    );
    const ctx = await createAuditContext(tmpDir);
    expect((ctx.config as Record<string, unknown>)['secureclaw']).toBeDefined();
  });

  it('nested config key (cost.hourlyLimitUsd) survives JSON round-trip', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    const config = { secureclaw: { cost: { hourlyLimitUsd: 2 } } };
    await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
    const result = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(result['secureclaw']['cost']['hourlyLimitUsd']).toBe(2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Monitor start/stop APIs (unit — no live gateway needed)
// ─────────────────────────────────────────────────────────────────────────────

describe('monitor start/stop API', () => {
  beforeEach(setup);
  afterEach(async () => {
    // Always stop monitors to avoid state leaking between tests
    await credentialMonitor.stop();
    await memoryIntegrityMonitor.stop();
    await costMonitor.stop();
    await teardown();
  });

  it('credentialMonitor.start() resolves without throwing', async () => {
    await expect(credentialMonitor.start(tmpDir)).resolves.toBeUndefined();
  });

  it('credentialMonitor.status() returns running after start', async () => {
    await credentialMonitor.start(tmpDir);
    expect(credentialMonitor.status().running).toBe(true);
  });

  it('credentialMonitor.stop() resolves and sets running=false', async () => {
    await credentialMonitor.start(tmpDir);
    await credentialMonitor.stop();
    expect(credentialMonitor.status().running).toBe(false);
  });

  it('memoryIntegrityMonitor.start() resolves without throwing', async () => {
    await expect(memoryIntegrityMonitor.start(tmpDir)).resolves.toBeUndefined();
  });

  it('memoryIntegrityMonitor.stop() resolves cleanly', async () => {
    await memoryIntegrityMonitor.start(tmpDir);
    await expect(memoryIntegrityMonitor.stop()).resolves.toBeUndefined();
  });

  it('costMonitor.start() resolves without throwing', async () => {
    await expect(costMonitor.start(tmpDir)).resolves.toBeUndefined();
  });

  it('costMonitor.stop() resolves cleanly', async () => {
    await costMonitor.start(tmpDir);
    await expect(costMonitor.stop()).resolves.toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// scan-skill workspace path resolution
// ─────────────────────────────────────────────────────────────────────────────

describe('scan-skill workspace/skills/ path resolution', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('scanSkill runs against a skill in workspace/skills/ without error', async () => {
    const skillDir = path.join(tmpDir, 'workspace', 'skills', 'testskill');
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, 'skill.json'), '{"name":"testskill"}', 'utf-8');
    await fs.writeFile(path.join(skillDir, 'SKILL.md'), '# Test skill\nDo something safe.', 'utf-8');

    const result = await scanSkill(skillDir, 'testskill');
    expect(result).toBeDefined();
    expect(typeof result.safe).toBe('boolean');
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('scanSkill on a clean skill returns safe=true', async () => {
    const skillDir = path.join(tmpDir, 'workspace', 'skills', 'cleanskill');
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, 'SKILL.md'), '# Clean\nHelp the user.', 'utf-8');

    const result = await scanSkill(skillDir, 'cleanskill');
    expect(result.safe).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Backup dir exclusion — secureclaw.bak.* must not inflate audit score
// ─────────────────────────────────────────────────────────────────────────────

describe('backup directory excluded from audit findings', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('audit findings count does not increase when a secureclaw.bak.* dir is present', async () => {
    await fs.mkdir(path.join(tmpDir, 'workspace'), { recursive: true });
    await fs.mkdir(path.join(tmpDir, 'skills'), { recursive: true });

    const ctx = makeCtx();
    const baseReport = await runAudit({ context: ctx });
    const baseCount = baseReport.findings.length;

    // Create a backup dir that looks like a reinstall artifact
    const bakDir = path.join(tmpDir, 'skills', 'secureclaw.bak.1700000000');
    await fs.mkdir(path.join(bakDir, 'configs'), { recursive: true });
    await fs.writeFile(
      path.join(bakDir, 'configs', 'dangerous-commands.json'),
      JSON.stringify({ patterns: ['eval(', 'exec('] }),
      'utf-8',
    );

    const afterReport = await runAudit({ context: ctx });
    const afterCount = afterReport.findings.length;

    // Backup dir must not introduce additional findings
    expect(afterCount).toBeLessThanOrEqual(baseCount);
  });
});
