import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { hashString } from './utils/hash.js';
import {
  loadIOCDatabase,
  isKnownC2,
  isKnownMaliciousDomain,
  isKnownMaliciousHash,
  matchesTyposquat,
  matchesDangerousPattern,
  getInfostealerArtifacts,
} from './utils/ioc-db.js';
import type {
  AuditContext,
  AuditFinding,
  AuditOptions,
  AuditReport,
  AuditSummary,
  IOCDatabase,
  Severity,
} from './types.js';

// ============================================================
// API Key detection patterns
// ============================================================
const API_KEY_PATTERNS = [
  /sk-ant-[a-zA-Z0-9_-]{20,}/,
  /sk-proj-[a-zA-Z0-9_-]{20,}/,
  /sk-[a-zA-Z0-9_-]{20,}/,
  /xoxb-[a-zA-Z0-9_-]{20,}/,
  /xoxp-[a-zA-Z0-9_-]{20,}/,
];

// ============================================================
// Prompt injection patterns
// ============================================================
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+previous\s+instructions/i,
  /you\s+are\s+now/i,
  /new\s+system\s+prompt/i,
  /forward\s+to/i,
  /send\s+to/i,
  /exfiltrate/i,
];

const BASE64_BLOCK_PATTERN = /[A-Za-z0-9+/=]{50,}/;

// ============================================================
// Dangerous skill patterns
// ============================================================
const DANGEROUS_SKILL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /child_process/, description: 'child_process import' },
  { pattern: /\.exec\s*\(/, description: 'exec() call' },
  { pattern: /\.spawn\s*\(/, description: 'spawn() call' },
  { pattern: /eval\s*\(/, description: 'eval() call' },
  { pattern: /Function\s*\(/, description: 'Function() constructor' },
  { pattern: /webhook\.site/, description: 'webhook.site exfiltration endpoint' },
  { pattern: /reverse.shell/, description: 'reverse shell pattern' },
  { pattern: /base64.*decode/i, description: 'base64 decode (obfuscation)' },
  { pattern: /curl\s+.*\|\s*sh/, description: 'curl pipe to shell' },
  { pattern: /wget\s+.*\|\s*sh/, description: 'wget pipe to shell' },
  { pattern: /~\/\.openclaw/, description: 'access to openclaw config' },
  { pattern: /~\/\.clawdbot/, description: 'access to legacy clawdbot config' },
  { pattern: /creds\.json/, description: 'credential file access' },
  { pattern: /\.env/, description: '.env file access' },
  { pattern: /auth-profiles/, description: 'auth-profiles access' },
  { pattern: /LD_PRELOAD/, description: 'LD_PRELOAD injection' },
  { pattern: /DYLD_INSERT/, description: 'DYLD_INSERT library injection' },
  { pattern: /NODE_OPTIONS/, description: 'NODE_OPTIONS injection' },
];

// ============================================================
// Score calculation
// ============================================================
const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  CRITICAL: 15,
  HIGH: 8,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0,
};

function calculateScore(findings: AuditFinding[]): number {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_DEDUCTIONS[finding.severity];
  }
  return Math.max(0, score);
}

function computeSummary(findings: AuditFinding[]): AuditSummary {
  const summary: AuditSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    autoFixable: 0,
  };

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH': summary.high++; break;
      case 'MEDIUM': summary.medium++; break;
      case 'LOW': summary.low++; break;
      case 'INFO': summary.info++; break;
    }
    if (f.autoFixable) summary.autoFixable++;
  }

  return summary;
}

// ============================================================
// Port probe helper (used in --deep mode)
// ============================================================

/**
 * Probe whether a TCP port is listening on a given host.
 * Returns true if a connection succeeds within `timeoutMs`.
 */
export function probePort(
  port: number,
  host: string,
  timeoutMs = 2000,
): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (result: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

// ============================================================
// 2a. Gateway & Network Exposure Checks
// ============================================================
export async function auditGateway(ctx: AuditContext, deep = false): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const gw = ctx.config.gateway;

  // GW-001: Gateway bind mode
  if (gw?.bind !== 'loopback') {
    findings.push({
      id: 'SC-GW-001',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Gateway not bound to loopback',
      description: `Gateway is bound to "${gw?.bind ?? 'all interfaces'}" instead of loopback. This exposes the gateway to network attacks.`,
      evidence: `gateway.bind = "${gw?.bind ?? 'undefined'}"`,
      remediation: 'Set gateway.bind to "loopback" in openclaw.json',
      autoFixable: true,
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
    });
  }

  // GW-002: Gateway auth mode
  const authMode = gw?.auth?.mode;
  if (authMode !== 'password' && authMode !== 'token') {
    findings.push({
      id: 'SC-GW-002',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Gateway authentication disabled',
      description: `Gateway authentication mode is "${authMode ?? 'none'}". Anyone with network access can control this instance.`,
      evidence: `gateway.auth.mode = "${authMode ?? 'undefined'}"`,
      remediation: 'Set gateway.auth.mode to "password" or "token" and configure a strong credential',
      autoFixable: true,
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
    });
  }

  // GW-003: Auth token length
  const token = gw?.auth?.token ?? gw?.auth?.password ?? '';
  if (authMode === 'token' || authMode === 'password') {
    if (token.length > 0 && token.length < 32) {
      findings.push({
        id: 'SC-GW-003',
        severity: 'MEDIUM',
        category: 'gateway',
        title: 'Weak gateway authentication token',
        description: `Gateway auth token/password is only ${token.length} characters. Minimum 32 recommended.`,
        evidence: `Token length: ${token.length} characters`,
        remediation: 'Generate a token of at least 32 characters using a CSPRNG',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }
  }

  // GW-004: Gateway port accessible from non-localhost (deep probe)
  const gatewayPort = gw?.port ?? 18789;
  if (deep) {
    const listening = await probePort(gatewayPort, '127.0.0.1');
    if (listening) {
      // Port is open — check if bind is loopback-only
      const bindMode = gw?.bind ?? 'all';
      const isLoopback = bindMode === 'loopback' || bindMode === '127.0.0.1' || bindMode === 'localhost';
      findings.push({
        id: 'SC-GW-004',
        severity: isLoopback ? 'LOW' : 'HIGH',
        category: 'gateway',
        title: isLoopback
          ? 'Gateway port open on loopback only'
          : 'Gateway port open and bound to non-loopback interface',
        description: isLoopback
          ? `Port ${gatewayPort} is listening on loopback (localhost). This is the recommended configuration.`
          : `Port ${gatewayPort} is listening and bound to "${bindMode}". It may be accessible from other machines on the network.`,
        evidence: `Port: ${gatewayPort}, Bind: ${bindMode}, Status: open`,
        remediation: isLoopback
          ? 'No action needed — loopback binding is secure'
          : 'Set gateway.bind to "loopback" to restrict access to localhost only',
        autoFixable: !isLoopback,
        references: [],
        owaspAsi: 'ASI05',
      });
    } else {
      findings.push({
        id: 'SC-GW-004',
        severity: 'INFO',
        category: 'gateway',
        title: 'Gateway port not listening',
        description: `Port ${gatewayPort} is not currently accepting connections. Gateway may not be running.`,
        evidence: `Port: ${gatewayPort}, Status: closed/unreachable`,
        remediation: 'Start the gateway if it should be running',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI05',
      });
    }
  } else {
    findings.push({
      id: 'SC-GW-004',
      severity: 'INFO',
      category: 'gateway',
      title: 'Gateway port accessibility check',
      description: `Port ${gatewayPort} remote accessibility requires deep scan mode (--deep) for active probing.`,
      evidence: `Port: ${gatewayPort}`,
      remediation: 'Run audit with --deep flag for active network probing',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI05',
    });
  }

  // GW-005: Browser relay port
  const browserRelayPort = (gw?.port ?? 18789) - 897;
  if (deep) {
    const listening = await probePort(browserRelayPort, '127.0.0.1');
    if (listening) {
      const bindMode = gw?.bind ?? 'all';
      const isLoopback = bindMode === 'loopback' || bindMode === '127.0.0.1' || bindMode === 'localhost';
      findings.push({
        id: 'SC-GW-005',
        severity: isLoopback ? 'LOW' : 'MEDIUM',
        category: 'gateway',
        title: isLoopback
          ? 'Browser relay port open on loopback only'
          : 'Browser relay port open and may be network-accessible',
        description: isLoopback
          ? `Browser relay port ${browserRelayPort} is listening on loopback. This is safe.`
          : `Browser relay port ${browserRelayPort} is listening and bound to "${bindMode}". The browser automation surface may be reachable from the network.`,
        evidence: `Port: ${browserRelayPort}, Bind: ${bindMode}, Status: open`,
        remediation: isLoopback
          ? 'No action needed'
          : 'Set gateway.bind to "loopback" to restrict the browser relay to localhost',
        autoFixable: !isLoopback,
        references: [],
        owaspAsi: 'ASI05',
      });
    } else {
      findings.push({
        id: 'SC-GW-005',
        severity: 'INFO',
        category: 'gateway',
        title: 'Browser relay port not listening',
        description: `Browser relay port ${browserRelayPort} is not currently accepting connections.`,
        evidence: `Port: ${browserRelayPort}, Status: closed/unreachable`,
        remediation: 'No action needed if browser automation is not in use',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI05',
      });
    }
  } else {
    findings.push({
      id: 'SC-GW-005',
      severity: 'INFO',
      category: 'gateway',
      title: 'Browser relay port check',
      description: `Browser relay port ${browserRelayPort} accessibility requires deep scan mode.`,
      evidence: `Port: ${browserRelayPort}`,
      remediation: 'Run audit with --deep flag for active network probing',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI05',
    });
  }

  // GW-006: TLS enabled
  if (!gw?.tls?.enabled) {
    findings.push({
      id: 'SC-GW-006',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'TLS not enabled on gateway',
      description: 'Gateway traffic is unencrypted. Credentials and conversation data are transmitted in plaintext.',
      evidence: 'gateway.tls is not configured',
      remediation: 'Configure gateway.tls with a valid certificate and key',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  // GW-007: mDNS/Bonjour mode
  if (gw?.mdns && gw.mdns.mode !== 'minimal') {
    findings.push({
      id: 'SC-GW-007',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'mDNS broadcasting in full mode',
      description: 'mDNS is broadcasting sensitive instance information on the local network.',
      evidence: `gateway.mdns.mode = "${gw.mdns.mode}"`,
      remediation: 'Manually set gateway.mdns.mode to "minimal" (not auto-fixable — key not in OpenClaw config schema)',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI05',
    });
  }

  // GW-008: Reverse proxy without trustedProxies
  // If bind is not loopback but trustedProxies is empty, this is a critical bypass
  if (gw?.bind !== 'loopback' && (!gw?.trustedProxies || gw.trustedProxies.length === 0)) {
    findings.push({
      id: 'SC-GW-008',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Reverse proxy without trustedProxies configuration',
      description: 'Gateway is network-accessible without trustedProxies set. All connections appear as localhost, bypassing authentication.',
      evidence: `gateway.bind = "${gw?.bind ?? 'all'}", trustedProxies = []`,
      remediation: 'Set gateway.trustedProxies to the IP of your reverse proxy, e.g., ["127.0.0.1"]',
      autoFixable: true,
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
    });
  }

  // GW-009: dangerouslyDisableDeviceAuth
  if (gw?.controlUi?.dangerouslyDisableDeviceAuth === true) {
    findings.push({
      id: 'SC-GW-009',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Device authentication disabled on Control UI',
      description: 'dangerouslyDisableDeviceAuth is enabled, bypassing all device-level authentication for the Control UI.',
      evidence: 'gateway.controlUi.dangerouslyDisableDeviceAuth = true',
      remediation: 'Set gateway.controlUi.dangerouslyDisableDeviceAuth to false',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  // GW-010: allowInsecureAuth
  if (gw?.controlUi?.allowInsecureAuth === true) {
    findings.push({
      id: 'SC-GW-010',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'Insecure authentication allowed on Control UI',
      description: 'allowInsecureAuth is enabled, allowing weaker authentication methods.',
      evidence: 'gateway.controlUi.allowInsecureAuth = true',
      remediation: 'Set gateway.controlUi.allowInsecureAuth to false',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  return findings;
}

// ============================================================
// 2b. Credential Storage Checks
// ============================================================
export async function auditCredentials(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  // CRED-001: State directory permissions
  const stateDirPerms = await ctx.getFilePermissions(ctx.stateDir);
  if (stateDirPerms !== null && (stateDirPerms & 0o077) !== 0) {
    findings.push({
      id: 'SC-CRED-001',
      severity: 'HIGH',
      category: 'credentials',
      title: 'State directory has excessive permissions',
      description: `~/.openclaw/ directory is accessible by group/other users (${stateDirPerms.toString(8)}).`,
      evidence: `Permissions: ${stateDirPerms.toString(8)} (expected: 700)`,
      remediation: 'Run: chmod 700 ~/.openclaw/',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  // CRED-002: Config file permissions
  const configPath = path.join(ctx.stateDir, 'openclaw.json');
  const configPerms = await ctx.getFilePermissions(configPath);
  if (configPerms !== null && (configPerms & 0o077) !== 0) {
    findings.push({
      id: 'SC-CRED-002',
      severity: 'HIGH',
      category: 'credentials',
      title: 'Config file has excessive permissions',
      description: `openclaw.json is readable by group/other users (${configPerms.toString(8)}).`,
      evidence: `Permissions: ${configPerms.toString(8)} (expected: 600)`,
      remediation: 'Run: chmod 600 ~/.openclaw/openclaw.json',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  // CRED-003: .env file with plaintext API keys
  const envPath = path.join(ctx.stateDir, '.env');
  const envContent = await ctx.readFile(envPath);
  if (envContent !== null) {
    const hasKeys = API_KEY_PATTERNS.some((p) => p.test(envContent));
    if (hasKeys) {
      findings.push({
        id: 'SC-CRED-003',
        severity: 'HIGH',
        category: 'credentials',
        title: 'Plaintext API keys in .env file',
        description: 'API keys are stored in plaintext in .env file. These are targeted by infostealers.',
        evidence: `.env file contains API key patterns`,
        remediation: 'Encrypt .env using secureclaw credential-hardening or use a secrets manager',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }
  }

  // CRED-004: credentials/*.json permissions
  const credsDir = path.join(ctx.stateDir, 'credentials');
  let credFiles: string[] = [];
  try {
    credFiles = await ctx.listDir(credsDir);
  } catch {
    // No credentials directory is fine
  }
  for (const file of credFiles) {
    if (!file.endsWith('.json')) continue;
    const filePath = path.join(credsDir, file);
    const perms = await ctx.getFilePermissions(filePath);
    if (perms !== null && (perms & 0o077) !== 0) {
      findings.push({
        id: 'SC-CRED-004',
        severity: 'HIGH',
        category: 'credentials',
        title: `Credential file "${file}" has excessive permissions`,
        description: `Credential file is readable by group/other users (${perms.toString(8)}).`,
        evidence: `${filePath}: permissions ${perms.toString(8)}`,
        remediation: `Run: chmod 600 ${filePath}`,
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }
  }

  // CRED-005: auth-profiles.json permissions
  const agentsDir = path.join(ctx.stateDir, 'agents');
  let agents: string[] = [];
  try {
    agents = await ctx.listDir(agentsDir);
  } catch {
    // No agents directory is fine
  }
  for (const agent of agents) {
    const authProfilePath = path.join(agentsDir, agent, 'agent', 'auth-profiles.json');
    const exists = await ctx.fileExists(authProfilePath);
    if (!exists) continue;
    const perms = await ctx.getFilePermissions(authProfilePath);
    if (perms !== null && (perms & 0o077) !== 0) {
      findings.push({
        id: 'SC-CRED-005',
        severity: 'HIGH',
        category: 'credentials',
        title: `Auth profiles for agent "${agent}" have excessive permissions`,
        description: `auth-profiles.json is readable by group/other users (${perms.toString(8)}).`,
        evidence: `${authProfilePath}: permissions ${perms.toString(8)}`,
        remediation: `Run: chmod 600 ${authProfilePath}`,
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }
  }

  // CRED-006: OAuth tokens in plaintext
  for (const file of credFiles) {
    if (!file.endsWith('.json')) continue;
    const filePath = path.join(credsDir, file);
    const content = await ctx.readFile(filePath);
    if (content && (content.includes('"access_token"') || content.includes('"refresh_token"'))) {
      findings.push({
        id: 'SC-CRED-006',
        severity: 'MEDIUM',
        category: 'credentials',
        title: `OAuth tokens in plaintext in "${file}"`,
        description: 'OAuth access/refresh tokens are stored in plaintext, vulnerable to infostealer theft.',
        evidence: `${filePath} contains OAuth token fields`,
        remediation: 'Encrypt credential files using secureclaw credential-hardening',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }
  }

  // CRED-007: API keys in memory/soul files
  const memoryFiles = ['soul.md', 'MEMORY.md', 'SOUL.md'];
  for (const agent of agents) {
    for (const memFile of memoryFiles) {
      const memPath = path.join(agentsDir, agent, memFile);
      const content = await ctx.readFile(memPath);
      if (content) {
        const hasKeys = API_KEY_PATTERNS.some((p) => p.test(content));
        if (hasKeys) {
          findings.push({
            id: 'SC-CRED-007',
            severity: 'CRITICAL',
            category: 'credentials',
            title: `API keys found in memory file "${memFile}"`,
            description: 'API keys are present in LLM memory files. These leak credentials into the model context.',
            evidence: `${memPath} contains API key patterns`,
            remediation: 'Remove API keys from memory files and redact using secureclaw credential-hardening',
            autoFixable: true,
            references: [],
            owaspAsi: 'ASI03',
          });
        }
      }
    }
  }

  // CRED-008: Scan all .md and .json files under state dir for API keys
  const allFiles = await scanForApiKeys(ctx);
  for (const match of allFiles) {
    // Don't duplicate findings already covered above
    if (match.includes('soul.md') || match.includes('MEMORY.md') || match.includes('SOUL.md')) continue;
    if (match.includes('.env')) continue;
    findings.push({
      id: 'SC-CRED-008',
      severity: 'HIGH',
      category: 'credentials',
      title: 'API key found in configuration file',
      description: `API key pattern detected in ${path.basename(match)}.`,
      evidence: `File: ${match}`,
      remediation: 'Remove or redact API keys from this file',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI03',
    });
  }

  return findings;
}

async function scanForApiKeys(ctx: AuditContext): Promise<string[]> {
  const matches: string[] = [];
  const MAX_DEPTH = 5;

  async function scanDir(dir: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH) return;
    let entries: string[];
    try {
      entries = await ctx.listDir(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      if (entry.endsWith('.md') || entry.endsWith('.json')) {
        const content = await ctx.readFile(fullPath);
        if (content && API_KEY_PATTERNS.some((p) => p.test(content))) {
          matches.push(fullPath);
        }
      }
      // Recurse into subdirectories (but skip .secureclaw and node_modules)
      if (!entry.startsWith('.secureclaw') && entry !== 'node_modules') {
        try {
          const children = await ctx.listDir(fullPath);
          if (children.length > 0) {
            await scanDir(fullPath, depth + 1);
          }
        } catch {
          // Not a directory, skip
        }
      }
    }
  }

  await scanDir(ctx.stateDir, 0);
  return matches;
}

// ============================================================
// 2c. Execution & Sandbox Checks
// ============================================================
export async function auditExecution(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  // EXEC-001: exec.approvals off
  if (ctx.config.exec?.approvals === 'off') {
    findings.push({
      id: 'SC-EXEC-001',
      severity: 'CRITICAL',
      category: 'execution',
      title: 'Execution approvals disabled',
      description: 'exec.approvals is set to "off". The agent can execute arbitrary commands without user confirmation.',
      evidence: 'exec.approvals = "off"',
      remediation: 'Manually set exec.approvals to "always" in your OpenClaw settings (not auto-fixable — key not in OpenClaw config schema)',
      autoFixable: false,
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI02',
    });
  }

  // EXEC-002: tools.exec.host = gateway
  if (ctx.config.tools?.exec?.host === 'gateway') {
    findings.push({
      id: 'SC-EXEC-002',
      severity: 'HIGH',
      category: 'execution',
      title: 'Commands execute on host, not in sandbox',
      description: 'tools.exec.host is "gateway", meaning commands run directly on the host machine without isolation.',
      evidence: 'tools.exec.host = "gateway"',
      remediation: 'Set tools.exec.host to "sandbox"',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI05',
    });
  }

  // EXEC-003: Sandbox mode
  if (ctx.config.sandbox?.mode !== 'all') {
    findings.push({
      id: 'SC-EXEC-003',
      severity: 'MEDIUM',
      category: 'execution',
      title: 'Sandbox mode not set to "all"',
      description: `Sandbox mode is "${ctx.config.sandbox?.mode ?? 'undefined'}". Not all commands run in a sandboxed environment.`,
      evidence: `sandbox.mode = "${ctx.config.sandbox?.mode ?? 'undefined'}"`,
      remediation: 'Manually set sandbox.mode to "all" in your OpenClaw settings (not auto-fixable — key not in OpenClaw config schema)',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI05',
    });
  }

  // EXEC-004: Docker --read-only
  const dc = ctx.dockerCompose;
  if (dc?.services) {
    for (const [svcName, svc] of Object.entries(dc.services)) {
      if (!svc.read_only) {
        findings.push({
          id: 'SC-EXEC-004',
          severity: 'MEDIUM',
          category: 'execution',
          title: `Docker service "${svcName}" not read-only`,
          description: 'Container filesystem is writable, allowing post-exploitation persistence.',
          evidence: `Service "${svcName}": read_only is not set`,
          remediation: 'Add read_only: true to the service configuration',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI05',
        });
      }

      // EXEC-005: Docker --cap-drop=ALL
      if (!svc.cap_drop || !svc.cap_drop.includes('ALL')) {
        findings.push({
          id: 'SC-EXEC-005',
          severity: 'MEDIUM',
          category: 'execution',
          title: `Docker service "${svcName}" retains Linux capabilities`,
          description: 'Container has not dropped all capabilities, increasing attack surface.',
          evidence: `Service "${svcName}": cap_drop does not include "ALL"`,
          remediation: 'Add cap_drop: ["ALL"] to the service configuration',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI05',
        });
      }

      // EXEC-006: Docker no-new-privileges
      if (!svc.security_opt || !svc.security_opt.includes('no-new-privileges:true')) {
        findings.push({
          id: 'SC-EXEC-006',
          severity: 'MEDIUM',
          category: 'execution',
          title: `Docker service "${svcName}" allows privilege escalation`,
          description: 'Container does not have no-new-privileges set.',
          evidence: `Service "${svcName}": security_opt missing no-new-privileges:true`,
          remediation: 'Add security_opt: ["no-new-privileges:true"] to the service configuration',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI05',
        });
      }

      // EXEC-007: Docker host network
      if (svc.network_mode === 'host') {
        findings.push({
          id: 'SC-EXEC-007',
          severity: 'HIGH',
          category: 'execution',
          title: `Docker service "${svcName}" uses host network mode`,
          description: 'Container shares the host network namespace, bypassing network isolation.',
          evidence: `Service "${svcName}": network_mode = "host"`,
          remediation: 'Remove network_mode: "host" and use bridge networking',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI05',
        });
      }
    }
  }

  return findings;
}

// ============================================================
// 2d. DM & Access Control Checks
// ============================================================
export async function auditAccessControl(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const channels = ctx.channels ?? [];

  // AC-001: Open DM policy
  for (const ch of channels) {
    if (ch.dmPolicy === 'open') {
      findings.push({
        id: 'SC-AC-001',
        severity: 'HIGH',
        category: 'access-control',
        title: `Channel "${ch.name}" has open DM policy`,
        description: 'Anyone can send direct messages to the agent without pairing, enabling prompt injection attacks.',
        evidence: `Channel "${ch.name}": dmPolicy = "open"`,
        remediation: 'Set dmPolicy to "pairing" for this channel',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI01',
      });
    }

    // AC-002: Open group policy
    if (ch.groupPolicy === 'open') {
      findings.push({
        id: 'SC-AC-002',
        severity: 'HIGH',
        category: 'access-control',
        title: `Channel "${ch.name}" has open group policy`,
        description: 'Anyone in the group can interact with the agent without restrictions.',
        evidence: `Channel "${ch.name}": groupPolicy = "open"`,
        remediation: 'Set groupPolicy to "allowlist" for this channel',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI01',
      });
    }

    // AC-003: Wildcard allowlist
    if (ch.allowlist && ch.allowlist.includes('*')) {
      findings.push({
        id: 'SC-AC-003',
        severity: 'MEDIUM',
        category: 'access-control',
        title: `Channel "${ch.name}" has wildcard in allowlist`,
        description: 'Using "*" in the allowlist effectively makes the channel open to everyone.',
        evidence: `Channel "${ch.name}": allowlist contains "*"`,
        remediation: 'Replace "*" with specific user identifiers',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI09',
      });
    }
  }

  // AC-004: Pairing disabled without allowlist
  for (const ch of channels) {
    if (ch.dmPolicy !== 'pairing' && (!ch.allowlist || ch.allowlist.length === 0)) {
      findings.push({
        id: 'SC-AC-004',
        severity: 'HIGH',
        category: 'access-control',
        title: `Channel "${ch.name}" has no pairing and no allowlist`,
        description: 'Neither pairing nor an allowlist is configured, leaving the channel unprotected.',
        evidence: `Channel "${ch.name}": dmPolicy = "${ch.dmPolicy ?? 'undefined'}", allowlist empty`,
        remediation: 'Set dmPolicy to "pairing" or configure an allowlist',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI01',
      });
    }
  }

  // AC-005: Session DM scope
  if (ctx.config.session?.dmScope !== 'per-channel-peer' && channels.length > 1) {
    findings.push({
      id: 'SC-AC-005',
      severity: 'MEDIUM',
      category: 'access-control',
      title: 'Session DM scope not isolated per user',
      description: 'session.dmScope is not "per-channel-peer". With multiple users, context may leak between conversations.',
      evidence: `session.dmScope = "${ctx.config.session?.dmScope ?? 'undefined'}", channels: ${channels.length}`,
      remediation: 'Set session.dmScope to "per-channel-peer"',
      autoFixable: true,
      references: [],
      owaspAsi: 'ASI09',
    });
  }

  return findings;
}

// ============================================================
// 2e. Supply Chain / Skill Checks
// ============================================================
export async function auditSupplyChain(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const skills = ctx.skills ?? [];

  // SC-001: Installed skills count
  findings.push({
    id: 'SC-SKILL-001',
    severity: 'INFO',
    category: 'supply-chain',
    title: `${skills.length} skill(s) installed`,
    description: `Found ${skills.length} installed skills. Each skill has access to agent capabilities.`,
    evidence: `Installed skills: ${skills.map((s) => s.name).join(', ') || 'none'}`,
    remediation: 'Review each installed skill for necessity and trustworthiness',
    autoFixable: false,
    references: [],
    owaspAsi: 'ASI04',
  });

  // SC-002..005: Scan each skill for dangerous patterns
  for (const skill of skills) {
    const skillDir = path.join(ctx.stateDir, 'skills', skill.name);
    let skillFiles: string[] = [];
    try {
      skillFiles = await ctx.listDir(skillDir);
    } catch {
      continue;
    }

    for (const file of skillFiles) {
      const filePath = path.join(skillDir, file);
      const content = await ctx.readFile(filePath);
      if (!content) continue;

      // Check dangerous patterns
      for (const { pattern, description } of DANGEROUS_SKILL_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            id: 'SC-SKILL-002',
            severity: 'HIGH',
            category: 'supply-chain',
            title: `Dangerous pattern in skill "${skill.name}"`,
            description: `Found ${description} in ${file}. This may indicate malicious behavior.`,
            evidence: `${filePath}: matches ${pattern.source}`,
            remediation: 'Review the skill source code and remove if suspicious',
            autoFixable: false,
            references: [],
            owaspAsi: 'ASI04',
          });
        }
      }

      // Check hash against IOC database
      const fileHash = hashString(content);
      let db: IOCDatabase;
      try {
        db = await loadIOCDatabase();
      } catch {
        continue;
      }
      const campaign = isKnownMaliciousHash(db, fileHash);
      if (campaign) {
        findings.push({
          id: 'SC-SKILL-003',
          severity: 'CRITICAL',
          category: 'supply-chain',
          title: `Known malicious file in skill "${skill.name}"`,
          description: `File ${file} matches known malicious hash from campaign "${campaign}".`,
          evidence: `SHA-256: ${fileHash}, Campaign: ${campaign}`,
          remediation: 'Immediately remove this skill: openclaw skills remove ' + skill.name,
          autoFixable: false,
          references: [],
          owaspAsi: 'ASI04',
        });
      }
    }

    // SC-004: GitHub account age
    if (skill.githubAccountAge !== undefined && skill.githubAccountAge < 7) {
      findings.push({
        id: 'SC-SKILL-004',
        severity: 'MEDIUM',
        category: 'supply-chain',
        title: `Skill "${skill.name}" from new GitHub account`,
        description: `The GitHub account that published this skill is less than 7 days old.`,
        evidence: `Account age: ${skill.githubAccountAge} days`,
        remediation: 'Review the skill carefully — new accounts are commonly used for typosquatting attacks',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI04',
      });
    }

    // SC-005: Typosquat check
    let db: IOCDatabase;
    try {
      db = await loadIOCDatabase();
    } catch {
      continue;
    }
    if (matchesTyposquat(db, skill.name)) {
      findings.push({
        id: 'SC-SKILL-005',
        severity: 'HIGH',
        category: 'supply-chain',
        title: `Skill "${skill.name}" matches typosquat pattern`,
        description: 'This skill name matches known ClawHavoc typosquatting patterns.',
        evidence: `Skill name: ${skill.name}`,
        remediation: 'Verify this is the intended skill and not a malicious impersonator',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI04',
      });
    }
  }

  // SC-006: Check for dangerous prerequisites in skill metadata
  for (const skill of skills) {
    const skillDir = path.join(ctx.stateDir, 'skills', skill.name);
    const readmePath = path.join(skillDir, 'README.md');
    const readme = await ctx.readFile(readmePath);
    if (readme) {
      let db: IOCDatabase;
      try {
        db = await loadIOCDatabase();
      } catch {
        continue;
      }
      const dangerousMatches = matchesDangerousPattern(db, readme);
      if (dangerousMatches.length > 0) {
        findings.push({
          id: 'SC-SKILL-006',
          severity: 'HIGH',
          category: 'supply-chain',
          title: `Skill "${skill.name}" has dangerous prerequisites`,
          description: `README contains dangerous prerequisite patterns: ${dangerousMatches.join(', ')}`,
          evidence: `Patterns found: ${dangerousMatches.join(', ')}`,
          remediation: 'Do not follow these prerequisites blindly. Review each step manually.',
          autoFixable: false,
          references: [],
          owaspAsi: 'ASI04',
        });
      }
    }
  }

  return findings;
}

// ============================================================
// 2f. Memory Integrity Checks
// ============================================================
export async function auditMemoryIntegrity(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const agentsDir = path.join(ctx.stateDir, 'agents');
  let agents: string[] = [];
  try {
    agents = await ctx.listDir(agentsDir);
  } catch {
    findings.push({
      id: 'SC-MEM-001',
      severity: 'INFO',
      category: 'memory',
      title: 'No agents directory found',
      description: 'No agents directory exists to check memory integrity.',
      evidence: `Path: ${agentsDir}`,
      remediation: 'No action needed if this is a fresh installation',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI06',
    });
    return findings;
  }

  const memoryFileNames = ['soul.md', 'SOUL.md', 'MEMORY.md'];

  for (const agent of agents) {
    // MEM-001: Hash memory files
    for (const memFile of memoryFileNames) {
      const memPath = path.join(agentsDir, agent, memFile);
      const content = await ctx.readFile(memPath);
      if (!content) continue;

      // MEM-002: Check for prompt injection patterns
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            id: 'SC-MEM-002',
            severity: 'CRITICAL',
            category: 'memory',
            title: `Prompt injection detected in "${memFile}" for agent "${agent}"`,
            description: `Memory file contains prompt injection pattern: "${pattern.source}". This may be a time-shifted logic bomb.`,
            evidence: `File: ${memPath}, Pattern: ${pattern.source}`,
            remediation: 'Quarantine this memory file: openclaw secureclaw memory quarantine',
            autoFixable: false,
            references: [],
            owaspAsi: 'ASI06',
          });
        }
      }

      // MEM-003: Check for base64 encoded blocks
      if (BASE64_BLOCK_PATTERN.test(content)) {
        findings.push({
          id: 'SC-MEM-003',
          severity: 'MEDIUM',
          category: 'memory',
          title: `Base64 encoded content in "${memFile}" for agent "${agent}"`,
          description: 'Memory file contains long base64-encoded blocks which may hide malicious instructions.',
          evidence: `File: ${memPath}`,
          remediation: 'Review and decode the base64 content to verify it is benign',
          autoFixable: false,
          references: [],
          owaspAsi: 'ASI06',
        });
      }

      // MEM-004: Check for non-whitelisted URLs
      const urlPattern = /https?:\/\/[^\s"'<>]+/g;
      const urls = content.match(urlPattern) ?? [];
      const allowedDomains = ctx.config.secureclaw?.network?.egressAllowlist ?? [
        'api.anthropic.com',
        'api.openai.com',
        'generativelanguage.googleapis.com',
      ];
      for (const url of urls) {
        try {
          const urlObj = new URL(url);
          if (!allowedDomains.some((d) => urlObj.hostname === d || urlObj.hostname.endsWith('.' + d))) {
            findings.push({
              id: 'SC-MEM-004',
              severity: 'MEDIUM',
              category: 'memory',
              title: `Unexpected URL in memory file "${memFile}"`,
              description: `Memory file contains a URL to a non-whitelisted domain: ${urlObj.hostname}`,
              evidence: `File: ${memPath}, URL: ${url}`,
              remediation: 'Review if this URL is expected and add to allowlist if legitimate',
              autoFixable: false,
              references: [],
              owaspAsi: 'ASI10',
            });
          }
        } catch {
          // Invalid URL, skip
        }
      }
    }

    // MEM-005: Memory file permissions
    for (const memFile of memoryFileNames) {
      const memPath = path.join(agentsDir, agent, memFile);
      const exists = await ctx.fileExists(memPath);
      if (!exists) continue;
      const perms = await ctx.getFilePermissions(memPath);
      if (perms !== null && (perms & 0o077) !== 0) {
        findings.push({
          id: 'SC-MEM-005',
          severity: 'MEDIUM',
          category: 'memory',
          title: `Memory file "${memFile}" has excessive permissions`,
          description: 'Memory file is readable by group/other users, enabling unauthorized modification.',
          evidence: `${memPath}: permissions ${perms.toString(8)}`,
          remediation: `Run: chmod 600 ${memPath}`,
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI06',
        });
      }
    }
  }

  return findings;
}

// ============================================================
// 2g. API Cost Exposure Checks
// ============================================================
export async function auditCostExposure(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  // COST-001: LLM provider spending limits
  const envContent = await ctx.readFile(path.join(ctx.stateDir, '.env'));
  const hasSpendingLimits =
    envContent !== null &&
    (envContent.includes('SPENDING_LIMIT') ||
      envContent.includes('MAX_BUDGET') ||
      envContent.includes('COST_LIMIT'));

  if (!hasSpendingLimits) {
    findings.push({
      id: 'SC-COST-001',
      severity: 'MEDIUM',
      category: 'cost',
      title: 'No LLM provider spending limits configured',
      description: 'No spending limit environment variables found. Runaway API costs are possible.',
      evidence: 'No SPENDING_LIMIT, MAX_BUDGET, or COST_LIMIT variables in .env',
      remediation: 'Set spending limits via your LLM provider dashboard and add SPENDING_LIMIT to .env',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI08',
    });
  }

  // COST-002: Estimate token usage from session logs
  const sessionLogs = ctx.sessionLogs ?? [];
  let totalTokens = 0;
  let totalCost = 0;
  for (const logContent of sessionLogs) {
    const lines = logContent.split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.inputTokens) totalTokens += entry.inputTokens;
        if (entry.outputTokens) totalTokens += entry.outputTokens;
        if (entry.estimatedCostUsd) totalCost += entry.estimatedCostUsd;
      } catch {
        // Skip non-JSON lines
      }
    }
  }

  if (totalCost > 0) {
    findings.push({
      id: 'SC-COST-002',
      severity: 'INFO',
      category: 'cost',
      title: 'API cost usage detected in session logs',
      description: `Estimated total cost from recent sessions: $${totalCost.toFixed(2)} (${totalTokens} tokens)`,
      evidence: `Total tokens: ${totalTokens}, Estimated cost: $${totalCost.toFixed(2)}`,
      remediation: 'Configure cost monitoring: openclaw secureclaw cost-report --set-limit',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI08',
    });
  }

  // COST-003: High-frequency cron jobs
  // Check for cron-like invocation patterns in config
  const cronConfig = await ctx.readFile(path.join(ctx.stateDir, 'crontab'));
  if (cronConfig) {
    // Check for intervals less than 5 minutes
    const hasHighFreq = /(\*\/[1-4]\s|\*\s\*\s\*\s\*\s\*)/.test(cronConfig);
    if (hasHighFreq) {
      findings.push({
        id: 'SC-COST-003',
        severity: 'HIGH',
        category: 'cost',
        title: 'High-frequency agent invocation detected',
        description: 'Cron jobs invoke the agent every few minutes. This can cause significant API costs.',
        evidence: 'Crontab contains high-frequency schedules',
        remediation: 'Increase the cron interval to at least every 15 minutes, or use event-driven triggers',
        autoFixable: false,
        references: [],
        owaspAsi: 'ASI08',
      });
    }
  }

  // COST-004: Daily cost threshold
  const dailyThreshold = ctx.config.secureclaw?.cost?.dailyLimitUsd ?? 5;
  if (totalCost > dailyThreshold) {
    findings.push({
      id: 'SC-COST-004',
      severity: 'HIGH',
      category: 'cost',
      title: 'Daily cost threshold exceeded',
      description: `Estimated daily cost ($${totalCost.toFixed(2)}) exceeds threshold ($${dailyThreshold}).`,
      evidence: `Daily cost: $${totalCost.toFixed(2)}, Threshold: $${dailyThreshold}`,
      remediation: 'Review session logs for unexpected usage. Consider enabling the cost circuit breaker.',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI08',
    });
  }

  return findings;
}

// ============================================================
// 2h. IOC (Indicators of Compromise) Checks
// ============================================================
export async function auditIOC(ctx: AuditContext): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  let db: IOCDatabase;
  try {
    db = await loadIOCDatabase();
  } catch {
    findings.push({
      id: 'SC-IOC-000',
      severity: 'INFO',
      category: 'ioc',
      title: 'IOC database not available',
      description: 'Could not load the IOC database. Threat intelligence checks skipped.',
      evidence: 'IOC database file not found or corrupted',
      remediation: 'Ensure ioc/indicators.json exists and is valid JSON',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI04',
    });
    return findings;
  }

  // IOC-001: Check connection logs against known C2 IPs
  const connectionLogs = ctx.connectionLogs ?? [];
  for (const logEntry of connectionLogs) {
    // Extract IPs from log entries
    const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    let match;
    while ((match = ipPattern.exec(logEntry)) !== null) {
      const ip = match[1];
      if (isKnownC2(db, ip)) {
        findings.push({
          id: 'SC-IOC-001',
          severity: 'CRITICAL',
          category: 'ioc',
          title: 'Connection to known C2 infrastructure detected',
          description: `Outbound connection to known command-and-control IP: ${ip}`,
          evidence: `IP: ${ip}, Log entry: ${logEntry.substring(0, 200)}`,
          remediation: 'Immediately investigate this connection. Block the IP and check for compromise.',
          autoFixable: false,
          references: [],
          owaspAsi: 'ASI04',
        });
      }
    }
  }

  // IOC-002: Check skill URLs against malicious domains
  const skills = ctx.skills ?? [];
  for (const skill of skills) {
    if (skill.source) {
      try {
        const url = new URL(skill.source);
        if (isKnownMaliciousDomain(db, url.hostname)) {
          findings.push({
            id: 'SC-IOC-002',
            severity: 'CRITICAL',
            category: 'ioc',
            title: `Skill "${skill.name}" references malicious domain`,
            description: `Skill source URL references a known malicious domain: ${url.hostname}`,
            evidence: `Skill: ${skill.name}, Source: ${skill.source}`,
            remediation: 'Remove this skill immediately: openclaw skills remove ' + skill.name,
            autoFixable: false,
            references: [],
            owaspAsi: 'ASI04',
          });
        }
      } catch {
        // Invalid URL, skip
      }
    }
  }

  // IOC-003: Check for known malicious file hashes
  for (const skill of skills) {
    const skillDir = path.join(ctx.stateDir, 'skills', skill.name);
    let files: string[];
    try {
      files = await ctx.listDir(skillDir);
    } catch {
      continue;
    }
    for (const file of files) {
      const content = await ctx.readFile(path.join(skillDir, file));
      if (!content) continue;
      const hash = hashString(content);
      const campaign = isKnownMaliciousHash(db, hash);
      if (campaign) {
        findings.push({
          id: 'SC-IOC-003',
          severity: 'CRITICAL',
          category: 'ioc',
          title: `Malicious file detected in skill "${skill.name}"`,
          description: `File ${file} matches known malicious hash from "${campaign}" campaign.`,
          evidence: `SHA-256: ${hash}, Campaign: ${campaign}`,
          remediation: 'Remove this skill and investigate for further compromise',
          autoFixable: false,
          references: [],
          owaspAsi: 'ASI04',
        });
      }
    }
  }

  // IOC-004: Check for AMOS artifacts (macOS)
  if (ctx.platform === 'darwin') {
    const macosArtifacts = getInfostealerArtifacts(db, 'darwin');
    for (const artifactPattern of macosArtifacts) {
      // Convert pattern to a simple check
      const expandedPath = artifactPattern.replace('~', os.homedir());
      const dirPath = path.dirname(expandedPath);
      try {
        const dirEntries = await ctx.listDir(dirPath);
        const regex = new RegExp(path.basename(artifactPattern));
        for (const entry of dirEntries) {
          if (regex.test(entry)) {
            findings.push({
              id: 'SC-IOC-004',
              severity: 'CRITICAL',
              category: 'ioc',
              title: 'Potential infostealer artifact detected (macOS)',
              description: `Found suspicious file matching Atomic Stealer (AMOS) artifact pattern.`,
              evidence: `File: ${path.join(dirPath, entry)}, Pattern: ${artifactPattern}`,
              remediation: 'Investigate this file immediately. Run a full malware scan.',
              autoFixable: false,
              references: [],
              owaspAsi: 'ASI10',
            });
          }
        }
      } catch {
        // Directory doesn't exist, which is good
      }
    }
  }

  // IOC-005: Check for Redline/Lumma/Vidar artifacts (Linux)
  if (ctx.platform === 'linux') {
    const linuxArtifacts = getInfostealerArtifacts(db, 'linux');
    for (const artifactPattern of linuxArtifacts) {
      const expandedPath = artifactPattern.replace('~', os.homedir());
      const dirPath = path.dirname(expandedPath);
      try {
        const dirEntries = await ctx.listDir(dirPath);
        const regex = new RegExp(path.basename(artifactPattern));
        for (const entry of dirEntries) {
          if (regex.test(entry)) {
            findings.push({
              id: 'SC-IOC-005',
              severity: 'CRITICAL',
              category: 'ioc',
              title: 'Potential infostealer artifact detected (Linux)',
              description: `Found suspicious file matching Redline/Lumma/Vidar infostealer artifact pattern.`,
              evidence: `File: ${path.join(dirPath, entry)}, Pattern: ${artifactPattern}`,
              remediation: 'Investigate this file immediately. Run a full malware scan.',
              autoFixable: false,
              references: [],
              owaspAsi: 'ASI10',
            });
          }
        }
      } catch {
        // Directory doesn't exist, which is good
      }
    }
  }

  return findings;
}

// ============================================================
// Main audit runner
// ============================================================
export async function runAudit(options: AuditOptions = {}): Promise<AuditReport> {
  const ctx = options.context;
  if (!ctx) {
    throw new Error('AuditContext is required. Provide it via options.context');
  }

  // Run all audit categories in parallel
  const deep = options.deep ?? false;

  const [
    gatewayFindings,
    credentialFindings,
    executionFindings,
    accessControlFindings,
    supplyChainFindings,
    memoryFindings,
    costFindings,
    iocFindings,
  ] = await Promise.all([
    auditGateway(ctx, deep),
    auditCredentials(ctx),
    auditExecution(ctx),
    auditAccessControl(ctx),
    auditSupplyChain(ctx),
    auditMemoryIntegrity(ctx),
    auditCostExposure(ctx),
    auditIOC(ctx),
  ]);

  const allFindings = [
    ...gatewayFindings,
    ...credentialFindings,
    ...executionFindings,
    ...accessControlFindings,
    ...supplyChainFindings,
    ...memoryFindings,
    ...costFindings,
    ...iocFindings,
  ];

  const score = calculateScore(allFindings);
  const summary = computeSummary(allFindings);

  return {
    timestamp: new Date().toISOString(),
    openclawVersion: ctx.openclawVersion,
    secureclawVersion: '1.0.0',
    platform: ctx.platform,
    deploymentMode: ctx.deploymentMode,
    score,
    findings: allFindings,
    summary,
  };
}
