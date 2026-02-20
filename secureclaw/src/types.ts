// ============================================================
// SecureClaw Type Definitions
// ============================================================

/** Severity levels for audit findings */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** MAESTRO 7-layer agentic AI threat model (CSA) */
export type MaestroLayer = 'L1' | 'L2' | 'L3' | 'L4' | 'L5' | 'L6' | 'L7';

/** NIST AI 100-2 E2025 GenAI attack types */
export type NistAttackType = 'evasion' | 'poisoning' | 'privacy' | 'misuse';

/** A single audit finding */
export interface AuditFinding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  autoFixable: boolean;
  references: string[];
  owaspAsi: string;
  /** CSA MAESTRO layer (L1–L7) */
  maestroLayer?: MaestroLayer;
  /** NIST AI 100-2 E2025 GenAI attack type */
  nistCategory?: NistAttackType;
}

/** Summary counts of findings by severity */
export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  autoFixable: number;
}

/** Full audit report */
export interface AuditReport {
  timestamp: string;
  openclawVersion: string;
  secureclawVersion: string;
  platform: string;
  deploymentMode: string;
  score: number;
  findings: AuditFinding[];
  summary: AuditSummary;
}

/** Options for running an audit */
export interface AuditOptions {
  deep?: boolean;
  fix?: boolean;
  json?: boolean;
  context?: AuditContext;
}

/** Gateway configuration */
export interface GatewayConfig {
  bind?: string;
  port?: number;
  /** Legacy flat auth token (pre-2026 configs) */
  authToken?: string;
  auth?: {
    mode?: string;
    token?: string;
    password?: string;
  };
  tls?: {
    enabled?: boolean;
    cert?: string;
    key?: string;
  };
  mdns?: {
    mode?: string;
  };
  controlUi?: {
    dangerouslyDisableDeviceAuth?: boolean;
    allowInsecureAuth?: boolean;
  };
  trustedProxies?: string[];
}

/** Execution configuration */
export interface ExecConfig {
  approvals?: string;
  autoApprove?: string[];
}

/** Sandbox configuration */
export interface SandboxConfig {
  mode?: string;
  scope?: string;
  workspaceAccess?: string;
}

/** Tools configuration */
export interface ToolsConfig {
  exec?: {
    host?: string;
  };
}

/** Session configuration */
export interface SessionConfig {
  dmScope?: string;
}

/** Logging configuration */
export interface LoggingConfig {
  redactSensitive?: string;
}

/** Channel configuration */
export interface ChannelConfig {
  name: string;
  dmPolicy?: string;
  groupPolicy?: string;
  allowlist?: string[];
}

/** Failure mode for graceful degradation (G4) */
export type FailureMode = 'block_all' | 'safe_mode' | 'read_only';

/** Risk profile names for per-workload security (G8) */
export type RiskProfile = 'strict' | 'standard' | 'permissive';

/** Behavioral baseline entry (G3) */
export interface BehavioralBaseline {
  toolCallFrequency: Record<string, number>;
  typicalTools: string[];
  typicalDataPaths: string[];
  windowMinutes: number;
  lastUpdated: string;
}

/** SecureClaw-specific configuration */
export interface SecureClawConfig {
  monitors?: {
    credentials?: boolean;
    memory?: boolean;
    skills?: boolean;
    cost?: boolean;
  };
  cost?: {
    hourlyLimitUsd?: number;
    dailyLimitUsd?: number;
    monthlyLimitUsd?: number;
    circuitBreakerEnabled?: boolean;
  };
  memory?: {
    integrityChecks?: boolean;
    promptInjectionScan?: boolean;
    quarantineEnabled?: boolean;
    trustLevels?: boolean;
  };
  skills?: {
    blockUnaudited?: boolean;
    scanOnInstall?: boolean;
    iocCheckEnabled?: boolean;
  };
  network?: {
    egressAllowlistEnabled?: boolean;
    egressAllowlist?: string[];
  };
  failureMode?: FailureMode;
  riskProfile?: RiskProfile;
  riskProfiles?: Record<string, {
    failureMode?: FailureMode;
    approvalRequired?: boolean;
    allowedTools?: string[];
    blockedTools?: string[];
    maxCostPerSession?: number;
  }>;
  behavioral?: {
    baselineEnabled?: boolean;
    deviationThreshold?: number;
    windowMinutes?: number;
  };
}

/** Full OpenClaw configuration */
export interface OpenClawConfig {
  gateway?: GatewayConfig;
  exec?: ExecConfig;
  sandbox?: SandboxConfig;
  tools?: ToolsConfig;
  session?: SessionConfig;
  logging?: LoggingConfig;
  secureclaw?: SecureClawConfig;
}

/** Docker compose service configuration */
export interface DockerServiceConfig {
  read_only?: boolean;
  cap_drop?: string[];
  security_opt?: string[];
  networks?: string[];
  network_mode?: string;
  volumes?: string[];
  deploy?: {
    resources?: {
      limits?: {
        memory?: string;
        cpus?: string;
      };
    };
  };
}

/** Docker compose configuration */
export interface DockerComposeConfig {
  services?: Record<string, DockerServiceConfig>;
  networks?: Record<string, { driver?: string; internal?: boolean }>;
}

/** Skill metadata */
export interface SkillMetadata {
  name: string;
  source?: string;
  githubAccountAge?: number;
  installedAt?: string;
}

/** File info for auditing */
export interface FileInfo {
  path: string;
  permissions?: number;
  content?: string;
  exists?: boolean;
  size?: number;
}

/** Audit context — dependency injection for testability */
export interface AuditContext {
  stateDir: string;
  config: OpenClawConfig;
  platform: string;
  deploymentMode: string;
  openclawVersion: string;
  fileInfo: (path: string) => Promise<FileInfo>;
  readFile: (path: string) => Promise<string | null>;
  listDir: (path: string) => Promise<string[]>;
  fileExists: (path: string) => Promise<boolean>;
  getFilePermissions: (path: string) => Promise<number | null>;
  channels?: ChannelConfig[];
  skills?: SkillMetadata[];
  dockerCompose?: DockerComposeConfig;
  sessionLogs?: string[];
  connectionLogs?: string[];
}

/** IOC database structure */
export interface IOCDatabase {
  version: string;
  last_updated: string;
  c2_ips: string[];
  malicious_domains: string[];
  malicious_skill_hashes: Record<string, string>;
  typosquat_patterns: string[];
  dangerous_prerequisite_patterns: string[];
  infostealer_artifacts: {
    macos: string[];
    linux: string[];
  };
}

/** Hash baseline for integrity checking */
export interface HashBaseline {
  timestamp: string;
  files: Record<string, string>;
}

/** Baseline comparison result */
export interface BaselineComparison {
  added: string[];
  modified: string[];
  removed: string[];
}

/** Hardening module interface */
export interface HardeningModule {
  name: string;
  priority: number;
  check: (context: AuditContext) => Promise<AuditFinding[]>;
  fix: (context: AuditContext, backupDir: string) => Promise<HardeningResult>;
  rollback: (backupDir: string) => Promise<void>;
}

/** Result of a hardening action */
export interface HardeningResult {
  module: string;
  applied: HardeningAction[];
  skipped: HardeningAction[];
  errors: string[];
}

/** A single hardening action taken */
export interface HardeningAction {
  id: string;
  description: string;
  before: string;
  after: string;
}

/** Hardener options */
export interface HardenOptions {
  full?: boolean;
  interactive?: boolean;
  context?: AuditContext;
}

/** Monitor interface */
export interface Monitor {
  name: string;
  start: (stateDir: string) => Promise<void>;
  stop: () => Promise<void>;
  status: () => MonitorStatus;
  onAlert: (callback: AlertCallback) => void;
}

/** Monitor status */
export interface MonitorStatus {
  running: boolean;
  lastCheck?: string;
  alerts: MonitorAlert[];
}

/** A monitor alert */
export interface MonitorAlert {
  timestamp: string;
  severity: Severity;
  monitor: string;
  message: string;
  details?: string;
}

/** Alert callback type */
export type AlertCallback = (alert: MonitorAlert) => void;

/** Cost tracking entry */
export interface CostEntry {
  timestamp: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUsd: number;
}

/** Cost report */
export interface CostReport {
  hourly: number;
  daily: number;
  monthly: number;
  projection: {
    daily: number;
    monthly: number;
  };
  circuitBreakerTripped: boolean;
  entries: CostEntry[];
}

/** Skill scan result */
export interface SkillScanResult {
  safe: boolean;
  skillName: string;
  findings: string[];
  dangerousPatterns: string[];
  iocMatches: string[];
}

/** Plugin lifecycle gateway object */
export interface GatewayHandle {
  config: OpenClawConfig;
  stateDir: string;
  version: string;
}

/** Plugin definition (SDK-compatible) */
export interface SecureClawPlugin {
  name: string;
  version: string;
  description: string;
  onGatewayStart: (gateway: GatewayHandle) => Promise<void>;
  onGatewayStop: () => Promise<void>;
  commands: Record<string, (...args: string[]) => Promise<void>>;
  tools: string[];
}
