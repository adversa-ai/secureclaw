import { describe, it, expect } from 'vitest';
import { formatConsoleReport } from './console-reporter.js';
import type { AuditReport } from '../types.js';

function makeReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    timestamp: '2026-02-07T00:00:00Z',
    openclawVersion: '2026.2.0',
    secureclawVersion: '2.0.0',
    platform: 'darwin-arm64',
    deploymentMode: 'native',
    score: 75,
    findings: [
      {
        id: 'SC-GW-001',
        severity: 'CRITICAL',
        category: 'gateway',
        title: 'Gateway not bound to loopback',
        description: 'Test description',
        evidence: 'Test evidence',
        remediation: 'Test remediation',
        autoFixable: true,
        references: ['CVE-2026-25253'],
        owaspAsi: 'ASI03',
      },
      {
        id: 'SC-GW-006',
        severity: 'MEDIUM',
        category: 'gateway',
        title: 'TLS not enabled',
        description: 'Test TLS',
        evidence: 'No TLS',
        remediation: 'Enable TLS',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI03',
      },
      {
        id: 'SC-GW-004',
        severity: 'INFO',
        category: 'gateway',
        title: 'Port check info',
        description: 'Info finding',
        evidence: 'Port 18789',
        remediation: 'Run deep scan',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI05',
      },
    ],
    summary: {
      critical: 1,
      high: 0,
      medium: 1,
      low: 0,
      info: 1,
      autoFixable: 1,
    },
    ...overrides,
  };
}

describe('console-reporter', () => {
  it('includes the score in output', () => {
    const report = makeReport({ score: 42 });
    const output = formatConsoleReport(report);
    expect(output).toContain('42/100');
  });

  it('shows grade F for low score', () => {
    const report = makeReport({ score: 20 });
    const output = formatConsoleReport(report);
    expect(output).toContain('F');
  });

  it('shows grade A for high score', () => {
    const report = makeReport({ score: 95 });
    const output = formatConsoleReport(report);
    expect(output).toContain('A');
  });

  it('includes CRITICAL severity header', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('CRITICAL');
  });

  it('includes MEDIUM severity header', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('MEDIUM');
  });

  it('includes INFO severity header', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('INFO');
  });

  it('shows summary counts', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('CRITICAL');
    expect(output).toContain('Summary');
  });

  it('shows auto-fixable count', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('Auto-fixable');
    expect(output).toContain('1');
  });

  it('includes finding details', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('Gateway not bound to loopback');
    expect(output).toContain('SC-GW-001');
  });

  it('includes remediation advice', () => {
    const output = formatConsoleReport(makeReport());
    expect(output).toContain('Test remediation');
  });
});
