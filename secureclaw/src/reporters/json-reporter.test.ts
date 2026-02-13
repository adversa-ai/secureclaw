import { describe, it, expect } from 'vitest';
import { formatJsonReport, parseJsonReport } from './json-reporter.js';
import type { AuditReport } from '../types.js';

function makeReport(): AuditReport {
  return {
    timestamp: '2026-02-07T00:00:00Z',
    openclawVersion: '2026.2.0',
    secureclawVersion: '2.0.0',
    platform: 'darwin-arm64',
    deploymentMode: 'native',
    score: 85,
    findings: [
      {
        id: 'SC-GW-001',
        severity: 'CRITICAL',
        category: 'gateway',
        title: 'Test finding',
        description: 'Test description',
        evidence: 'Test evidence',
        remediation: 'Test remediation',
        autoFixable: true,
        references: ['CVE-2026-25253'],
        owaspAsi: 'ASI03',
      },
    ],
    summary: {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      autoFixable: 1,
    },
  };
}

describe('json-reporter', () => {
  it('produces valid JSON', () => {
    const report = makeReport();
    const json = formatJsonReport(report);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('roundtrips correctly', () => {
    const report = makeReport();
    const json = formatJsonReport(report);
    const parsed = parseJsonReport(json);
    expect(parsed.score).toBe(report.score);
    expect(parsed.findings).toHaveLength(report.findings.length);
    expect(parsed.summary.critical).toBe(report.summary.critical);
  });

  it('includes all report fields', () => {
    const report = makeReport();
    const json = formatJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed).toHaveProperty('timestamp');
    expect(parsed).toHaveProperty('openclawVersion');
    expect(parsed).toHaveProperty('secureclawVersion');
    expect(parsed).toHaveProperty('platform');
    expect(parsed).toHaveProperty('deploymentMode');
    expect(parsed).toHaveProperty('score');
    expect(parsed).toHaveProperty('findings');
    expect(parsed).toHaveProperty('summary');
  });

  it('includes finding details', () => {
    const json = formatJsonReport(makeReport());
    const parsed = JSON.parse(json);
    const finding = parsed.findings[0];
    expect(finding.id).toBe('SC-GW-001');
    expect(finding.severity).toBe('CRITICAL');
    expect(finding.autoFixable).toBe(true);
    expect(finding.references).toContain('CVE-2026-25253');
  });

  it('is pretty-printed', () => {
    const json = formatJsonReport(makeReport());
    expect(json).toContain('\n');
    expect(json).toContain('  ');
  });
});
