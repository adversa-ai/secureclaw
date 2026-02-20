import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import plugin, {
  legacyPlugin,
  createAuditContext,
  isKillSwitchActive,
  activateKillSwitch,
  deactivateKillSwitch,
  logToolCall,
  getBehavioralBaseline,
  getFailureMode,
  getRiskProfile,
} from './index.js';

describe('OpenClaw SDK plugin registration', () => {
  it('has correct id', () => {
    expect(plugin.id).toBe('secureclaw');
  });

  it('has name', () => {
    expect(plugin.name).toBe('SecureClaw');
  });

  it('has version 2.2.0', () => {
    expect(plugin.version).toBe('2.2.0');
  });

  it('has a description', () => {
    expect(plugin.description).toBeTruthy();
    expect(typeof plugin.description).toBe('string');
  });

  it('has a configSchema with parse()', () => {
    expect(typeof plugin.configSchema.parse).toBe('function');
  });

  it('configSchema.parse returns empty object for non-object', () => {
    expect(plugin.configSchema.parse(null)).toEqual({});
    expect(plugin.configSchema.parse(undefined)).toEqual({});
    expect(plugin.configSchema.parse(42)).toEqual({});
  });

  it('configSchema.parse passes through objects', () => {
    const input = { cost: { hourlyLimitUsd: 5 } };
    expect(plugin.configSchema.parse(input)).toEqual(input);
  });

  it('has register() function', () => {
    expect(typeof plugin.register).toBe('function');
  });
});

describe('legacy plugin interface', () => {
  it('has correct name', () => {
    expect(legacyPlugin.name).toBe('secureclaw');
  });

  it('has version 2.2.0', () => {
    expect(legacyPlugin.version).toBe('2.2.0');
  });

  it('has a description', () => {
    expect(legacyPlugin.description).toBeTruthy();
  });

  it('has onGatewayStart lifecycle hook', () => {
    expect(typeof legacyPlugin.onGatewayStart).toBe('function');
  });

  it('has onGatewayStop lifecycle hook', () => {
    expect(typeof legacyPlugin.onGatewayStop).toBe('function');
  });

  it('registers CLI commands', () => {
    expect(legacyPlugin.commands).toBeDefined();
    expect(legacyPlugin.commands['secureclaw audit']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw harden']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw status']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw scan-skill']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw cost-report']).toBeDefined();
  });

  it('registers skill CLI commands', () => {
    expect(legacyPlugin.commands['secureclaw skill install']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw skill audit']).toBeDefined();
  });

  it('registers agent tools', () => {
    expect(legacyPlugin.tools).toBeDefined();
    expect(legacyPlugin.tools).toContain('security_audit');
    expect(legacyPlugin.tools).toContain('security_status');
    expect(legacyPlugin.tools).toContain('skill_scan');
    expect(legacyPlugin.tools).toContain('cost_report');
    expect(legacyPlugin.tools).toContain('kill_switch');
    expect(legacyPlugin.tools).toContain('behavioral_baseline');
  });

  it('registers kill switch commands (G2)', () => {
    expect(legacyPlugin.commands['secureclaw kill']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw resume']).toBeDefined();
  });

  it('registers behavioral baseline command (G3)', () => {
    expect(legacyPlugin.commands['secureclaw baseline']).toBeDefined();
  });
});

describe('createAuditContext', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-idx-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('creates context with correct stateDir', async () => {
    await fs.writeFile(path.join(tmpDir, 'openclaw.json'), '{}', 'utf-8');
    const ctx = await createAuditContext(tmpDir);
    expect(ctx.stateDir).toBe(tmpDir);
  });

  it('loads config from openclaw.json', async () => {
    await fs.writeFile(
      path.join(tmpDir, 'openclaw.json'),
      JSON.stringify({ gateway: { bind: 'loopback' } }),
      'utf-8'
    );
    const ctx = await createAuditContext(tmpDir);
    expect(ctx.config.gateway?.bind).toBe('loopback');
  });

  it('handles missing config gracefully', async () => {
    const ctx = await createAuditContext(tmpDir);
    expect(ctx.config).toEqual({});
  });

  it('readFile returns content for existing file', async () => {
    await fs.writeFile(path.join(tmpDir, 'test.txt'), 'hello', 'utf-8');
    const ctx = await createAuditContext(tmpDir);
    const content = await ctx.readFile(path.join(tmpDir, 'test.txt'));
    expect(content).toBe('hello');
  });

  it('readFile returns null for missing file', async () => {
    const ctx = await createAuditContext(tmpDir);
    const content = await ctx.readFile(path.join(tmpDir, 'nope.txt'));
    expect(content).toBeNull();
  });

  it('fileExists returns true for existing file', async () => {
    await fs.writeFile(path.join(tmpDir, 'exists.txt'), '', 'utf-8');
    const ctx = await createAuditContext(tmpDir);
    expect(await ctx.fileExists(path.join(tmpDir, 'exists.txt'))).toBe(true);
  });

  it('fileExists returns false for missing file', async () => {
    const ctx = await createAuditContext(tmpDir);
    expect(await ctx.fileExists(path.join(tmpDir, 'nope.txt'))).toBe(false);
  });

  it('getFilePermissions returns mode for existing file', async () => {
    await fs.writeFile(path.join(tmpDir, 'perm.txt'), '', { mode: 0o644 });
    const ctx = await createAuditContext(tmpDir);
    const perms = await ctx.getFilePermissions(path.join(tmpDir, 'perm.txt'));
    expect(perms).toBe(0o644);
  });

  it('getFilePermissions returns null for missing file', async () => {
    const ctx = await createAuditContext(tmpDir);
    const perms = await ctx.getFilePermissions(path.join(tmpDir, 'nope.txt'));
    expect(perms).toBeNull();
  });

  it('listDir returns directory entries', async () => {
    await fs.writeFile(path.join(tmpDir, 'a.txt'), '', 'utf-8');
    await fs.writeFile(path.join(tmpDir, 'b.txt'), '', 'utf-8');
    const ctx = await createAuditContext(tmpDir);
    const entries = await ctx.listDir(tmpDir);
    expect(entries).toContain('a.txt');
    expect(entries).toContain('b.txt');
  });

  it('uses provided config over file', async () => {
    await fs.writeFile(
      path.join(tmpDir, 'openclaw.json'),
      JSON.stringify({ gateway: { bind: 'all' } }),
      'utf-8'
    );
    const ctx = await createAuditContext(tmpDir, { gateway: { bind: 'loopback' } });
    expect(ctx.config.gateway?.bind).toBe('loopback');
  });

  it('sets platform string', async () => {
    const ctx = await createAuditContext(tmpDir);
    expect(ctx.platform).toContain(os.platform());
  });
});

describe('kill switch (G2)', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-kill-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('is inactive by default', async () => {
    expect(await isKillSwitchActive(tmpDir)).toBe(false);
  });

  it('activates and deactivates', async () => {
    await activateKillSwitch(tmpDir, 'test');
    expect(await isKillSwitchActive(tmpDir)).toBe(true);
    await deactivateKillSwitch(tmpDir);
    expect(await isKillSwitchActive(tmpDir)).toBe(false);
  });

  it('writes reason to killswitch file', async () => {
    await activateKillSwitch(tmpDir, 'incident detected');
    const content = await fs.readFile(path.join(tmpDir, '.secureclaw', 'killswitch'), 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.reason).toBe('incident detected');
    expect(parsed.activated).toBeTruthy();
  });

  it('deactivate is idempotent', async () => {
    await deactivateKillSwitch(tmpDir);
    expect(await isKillSwitchActive(tmpDir)).toBe(false);
  });
});

describe('behavioral baseline (G3)', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-baseline-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('returns empty baseline with no data', async () => {
    const baseline = await getBehavioralBaseline(tmpDir);
    expect(baseline.totalCalls).toBe(0);
    expect(baseline.uniqueTools).toBe(0);
  });

  it('logs and retrieves tool calls', async () => {
    await logToolCall(tmpDir, 'bash', '/tmp/test');
    await logToolCall(tmpDir, 'bash', '/tmp/test2');
    await logToolCall(tmpDir, 'read_file', '/home/user/.env');
    const baseline = await getBehavioralBaseline(tmpDir, 60);
    expect(baseline.totalCalls).toBe(3);
    expect(baseline.uniqueTools).toBe(2);
    expect(baseline.toolFrequency['bash']).toBe(2);
    expect(baseline.toolFrequency['read_file']).toBe(1);
  });
});

describe('failure modes (G4)', () => {
  it('returns block_all by default', () => {
    expect(getFailureMode({})).toBe('block_all');
  });

  it('returns configured mode', () => {
    expect(getFailureMode({ secureclaw: { failureMode: 'safe_mode' } })).toBe('safe_mode');
    expect(getFailureMode({ secureclaw: { failureMode: 'read_only' } })).toBe('read_only');
  });
});

describe('risk profiles (G8)', () => {
  it('returns standard by default', () => {
    expect(getRiskProfile({})).toBe('standard');
  });

  it('returns configured profile', () => {
    expect(getRiskProfile({ secureclaw: { riskProfile: 'strict' } })).toBe('strict');
    expect(getRiskProfile({ secureclaw: { riskProfile: 'permissive' } })).toBe('permissive');
  });
});
