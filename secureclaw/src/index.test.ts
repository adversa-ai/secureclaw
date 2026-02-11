import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import plugin, { legacyPlugin, createAuditContext } from './index.js';

describe('OpenClaw SDK plugin registration', () => {
  it('has correct id', () => {
    expect(plugin.id).toBe('secureclaw');
  });

  it('has name', () => {
    expect(plugin.name).toBe('SecureClaw');
  });

  it('has version 1.0.0', () => {
    expect(plugin.version).toBe('1.0.0');
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

  it('has version 1.0.0', () => {
    expect(legacyPlugin.version).toBe('1.0.0');
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

  it('registers advisor CLI commands', () => {
    expect(legacyPlugin.commands['secureclaw advisor install']).toBeDefined();
    expect(legacyPlugin.commands['secureclaw advisor audit']).toBeDefined();
  });

  it('registers agent tools', () => {
    expect(legacyPlugin.tools).toBeDefined();
    expect(legacyPlugin.tools).toContain('security_audit');
    expect(legacyPlugin.tools).toContain('security_status');
    expect(legacyPlugin.tools).toContain('skill_scan');
    expect(legacyPlugin.tools).toContain('cost_report');
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
