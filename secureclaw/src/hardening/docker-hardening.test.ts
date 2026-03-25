import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { dockerHardening } from './docker-hardening.js';
import type { AuditContext, OpenClawConfig } from '../types.js';

describe('docker-hardening', () => {
  let tmpDir: string;
  let backupDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-docker-test-'));
    backupDir = path.join(tmpDir, 'backup');
    await fs.mkdir(backupDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  function makeCtx(config: OpenClawConfig = {}): AuditContext {
    return {
      stateDir: tmpDir,
      config,
      platform: 'darwin-arm64',
      deploymentMode: 'native',
      openclawVersion: '2026.2.0',
      async fileInfo(p) { return { path: p, exists: true }; },
      async readFile(p) { try { return await fs.readFile(p, 'utf-8'); } catch { return null; } },
      async listDir(p) { return fs.readdir(p); },
      async fileExists(p) { try { await fs.access(p); return true; } catch { return false; } },
      async getFilePermissions(p) { try { const s = await fs.stat(p); return s.mode & 0o777; } catch { return null; } },
    };
  }

  // ── check() tests ──────────────────────────────────────────────────

  it('check() returns INFO when no dockerCompose is present', async () => {
    const ctx = makeCtx();
    // No dockerCompose property on ctx at all
    const findings = await dockerHardening.check(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('SC-DOCKER-INFO');
    expect(findings[0].severity).toBe('INFO');
    expect(findings[0].category).toBe('execution');
    expect(findings[0].title).toContain('No Docker Compose');
  });

  it('check() returns INFO when dockerCompose has no services', async () => {
    const ctx = makeCtx();
    ctx.dockerCompose = { networks: {} };
    const findings = await dockerHardening.check(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('SC-DOCKER-INFO');
    expect(findings[0].severity).toBe('INFO');
  });

  it('check() finds read_only missing on a service', async () => {
    const ctx = makeCtx();
    ctx.dockerCompose = {
      services: {
        'my-service': {
          // read_only not set
        },
      },
    };

    const findings = await dockerHardening.check(ctx);
    const readOnlyFinding = findings.find((f) => f.id === 'SC-EXEC-004');

    expect(readOnlyFinding).toBeDefined();
    expect(readOnlyFinding!.severity).toBe('MEDIUM');
    expect(readOnlyFinding!.title).toContain('my-service');
    expect(readOnlyFinding!.title).toContain('not read-only');
    expect(readOnlyFinding!.autoFixable).toBe(true);
  });

  it('check() finds host network mode', async () => {
    const ctx = makeCtx();
    ctx.dockerCompose = {
      services: {
        'api-server': {
          read_only: true,
          network_mode: 'host',
        },
      },
    };

    const findings = await dockerHardening.check(ctx);
    const hostNetFinding = findings.find((f) => f.id === 'SC-EXEC-007');

    expect(hostNetFinding).toBeDefined();
    expect(hostNetFinding!.severity).toBe('HIGH');
    expect(hostNetFinding!.title).toContain('api-server');
    expect(hostNetFinding!.title).toContain('host network');
    expect(hostNetFinding!.autoFixable).toBe(true);
  });

  it('check() reports both read_only and host network issues on the same service', async () => {
    const ctx = makeCtx();
    ctx.dockerCompose = {
      services: {
        'bad-service': {
          network_mode: 'host',
          // read_only not set
        },
      },
    };

    const findings = await dockerHardening.check(ctx);
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.id === 'SC-EXEC-004')).toBe(true);
    expect(findings.some((f) => f.id === 'SC-EXEC-007')).toBe(true);
  });

  it('check() returns no findings for compliant services', async () => {
    const ctx = makeCtx();
    ctx.dockerCompose = {
      services: {
        'good-service': {
          read_only: true,
          network_mode: 'bridge',
        },
        'another-good-service': {
          read_only: true,
          // no network_mode at all (fine)
        },
      },
    };

    const findings = await dockerHardening.check(ctx);
    expect(findings).toHaveLength(0);
  });

  // ── fix() tests ────────────────────────────────────────────────────

  it('fix() creates docker-compose.secureclaw.yml override file with valid YAML', async () => {
    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    expect(result.module).toBe('docker-hardening');
    expect(result.errors).toHaveLength(0);

    // If Docker is not present the action is skipped — skip assertion
    if (result.skipped.some((s) => s.id === 'docker-override')) return;

    expect(result.applied.length).toBeGreaterThan(0);

    const overridePath = path.join(tmpDir, 'docker-compose.secureclaw.yml');
    const content = await fs.readFile(overridePath, 'utf-8');

    // Output must be YAML, not JSON
    expect(content.trimStart()).not.toMatch(/^\{/);
    expect(content).toContain('services:');
    expect(content).toContain('openclaw-gateway:');
    expect(content).toContain('read_only: true');
    expect(content).toContain('cap_drop:');
    expect(content).toContain('- ALL');
    expect(content).toContain('no-new-privileges:true');
    expect(content).toContain('memory: 2G');
    expect(content).toContain('networks:');
    expect(content).toContain('restricted-net:');
    expect(content).toContain('driver: bridge');
  });

  it('fix() creates backup of existing override file (skipped when Docker absent)', async () => {
    const overridePath = path.join(tmpDir, 'docker-compose.secureclaw.yml');
    const existingContent = 'services:\n  old:\n    read_only: false\n';
    await fs.writeFile(overridePath, existingContent, 'utf-8');

    const ctx = makeCtx();
    const result = await dockerHardening.fix(ctx, backupDir);

    expect(result.errors).toHaveLength(0);

    // If Docker is not installed the action is skipped — no backup written, that is correct
    if (result.skipped.some((s) => s.id === 'docker-override')) return;

    // Docker present: backup should exist and override should be YAML
    const backupPath = path.join(backupDir, 'docker-compose.secureclaw.yml');
    const backupContent = await fs.readFile(backupPath, 'utf-8');
    expect(backupContent).toBe(existingContent);

    const newContent = await fs.readFile(overridePath, 'utf-8');
    expect(newContent).toContain('services:');
    expect(newContent).toContain('read_only: true');
  });

  it('fix() handles missing stateDir gracefully (skipped when Docker absent)', async () => {
    const ctx = makeCtx();
    // Point stateDir to a nonexistent nested path
    ctx.stateDir = path.join(tmpDir, 'nonexistent', 'deeply', 'nested');

    const result = await dockerHardening.fix(ctx, backupDir);

    expect(result.module).toBe('docker-hardening');

    // When Docker is not installed, the function returns early with a skipped action — correct
    if (result.skipped.some((s) => s.id === 'docker-override')) {
      expect(result.applied).toHaveLength(0);
      return;
    }

    // Docker present: should catch the write error and report it
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('Docker hardening error');
    expect(result.applied).toHaveLength(0);
  });

  // ── rollback() test ────────────────────────────────────────────────

  it('rollback() is a no-op', async () => {
    // rollback is delegated to the orchestrator; the function should just resolve
    await expect(dockerHardening.rollback(backupDir)).resolves.toBeUndefined();
  });
});
