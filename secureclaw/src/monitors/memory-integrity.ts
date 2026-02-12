import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { hashString } from '../utils/hash.js';
import type { FSWatcher } from 'chokidar';
import type { Monitor, MonitorStatus, MonitorAlert, AlertCallback, HashBaseline } from '../types.js';

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+previous\s+instructions/i,
  /you\s+are\s+now/i,
  /new\s+system\s+prompt/i,
  /forward\s+to/i,
  /send\s+to/i,
  /exfiltrate/i,
];

const MEMORY_FILE_NAMES = ['soul.md', 'SOUL.md', 'MEMORY.md'];

let watcher: FSWatcher | null = null;
let alertCallbacks: AlertCallback[] = [];
let alerts: MonitorAlert[] = [];
let running = false;
let lastCheck: string | undefined;
let baseline: HashBaseline | null = null;

function emitAlert(alert: MonitorAlert): void {
  alerts.push(alert);
  for (const cb of alertCallbacks) {
    cb(alert);
  }
}

/**
 * Scan a file's content for prompt injection patterns.
 */
export function scanForPromptInjection(content: string): string[] {
  const matches: string[] = [];
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      matches.push(pattern.source);
    }
  }
  return matches;
}

/**
 * Create a baseline of memory file hashes.
 */
export async function createMemoryBaseline(stateDir: string): Promise<HashBaseline> {
  const agentsDir = path.join(stateDir, 'agents');
  const files: Record<string, string> = {};

  try {
    const agents = await fs.readdir(agentsDir);
    for (const agent of agents) {
      for (const memFile of MEMORY_FILE_NAMES) {
        const memPath = path.join(agentsDir, agent, memFile);
        try {
          const content = await fs.readFile(memPath, 'utf-8');
          const relPath = path.relative(stateDir, memPath);
          files[relPath] = hashString(content);
        } catch {
          // File doesn't exist
        }
      }

      // Also check memory subdirectory
      const memoryDir = path.join(agentsDir, agent, 'memory');
      try {
        const memFiles = await fs.readdir(memoryDir);
        for (const file of memFiles) {
          if (file.endsWith('.md')) {
            const filePath = path.join(memoryDir, file);
            const content = await fs.readFile(filePath, 'utf-8');
            const relPath = path.relative(stateDir, filePath);
            files[relPath] = hashString(content);
          }
        }
      } catch {
        // No memory directory
      }
    }
  } catch {
    // No agents directory
  }

  return {
    timestamp: new Date().toISOString(),
    files,
  };
}

/**
 * Check a file against the baseline and for injection patterns.
 */
async function checkFile(filePath: string, stateDir: string): Promise<void> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const relPath = path.relative(stateDir, filePath);
    const currentHash = hashString(content);

    // Check against baseline
    if (baseline && baseline.files[relPath]) {
      if (baseline.files[relPath] !== currentHash) {
        emitAlert({
          timestamp: new Date().toISOString(),
          severity: 'HIGH',
          monitor: 'memory-integrity',
          message: `Memory file modified: ${path.basename(filePath)}`,
          details: `Expected hash: ${baseline.files[relPath].substring(0, 16)}..., Got: ${currentHash.substring(0, 16)}...`,
        });
      }
    }

    // Scan for prompt injection
    const injections = scanForPromptInjection(content);
    if (injections.length > 0) {
      emitAlert({
        timestamp: new Date().toISOString(),
        severity: 'CRITICAL',
        monitor: 'memory-integrity',
        message: `Prompt injection patterns detected in ${path.basename(filePath)}`,
        details: `Patterns: ${injections.join(', ')}`,
      });
    }
  } catch {
    // File may have been deleted
  }
}

export const memoryIntegrityMonitor: Monitor = {
  name: 'memory-integrity',

  async start(stateDir: string): Promise<void> {
    if (running) return;

    // Create initial baseline
    baseline = await createMemoryBaseline(stateDir);

    const agentsDir = path.join(stateDir, 'agents');

    let chokidar: typeof import('chokidar');
    try {
      chokidar = await import('chokidar');
    } catch {
      emitAlert({
        timestamp: new Date().toISOString(),
        severity: 'INFO',
        monitor: 'memory-integrity',
        message: 'chokidar not available, memory monitoring disabled',
      });
      running = true;
      return;
    }

    try {
      await fs.access(agentsDir);
    } catch {
      running = true;
      lastCheck = new Date().toISOString();
      return;
    }

    // Watch for changes to memory files
    const watchPatterns = MEMORY_FILE_NAMES.map(
      (name) => path.join(agentsDir, '**', name)
    );
    watchPatterns.push(path.join(agentsDir, '*', 'memory', '*.md'));

    watcher = chokidar.watch(watchPatterns, {
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 500 },
    });

    watcher.on('change', (filePath: string) => {
      lastCheck = new Date().toISOString();
      checkFile(filePath, stateDir).catch(() => {});
    });

    watcher.on('add', (filePath: string) => {
      lastCheck = new Date().toISOString();
      emitAlert({
        timestamp: new Date().toISOString(),
        severity: 'MEDIUM',
        monitor: 'memory-integrity',
        message: `New memory file created: ${path.basename(filePath)}`,
        details: `Path: ${filePath}`,
      });
      checkFile(filePath, stateDir).catch(() => {});
    });

    running = true;
    lastCheck = new Date().toISOString();
  },

  async stop(): Promise<void> {
    if (watcher) {
      await watcher.close();
      watcher = null;
    }
    running = false;
  },

  status(): MonitorStatus {
    return {
      running,
      lastCheck,
      alerts: [...alerts],
    };
  },

  onAlert(callback: AlertCallback): void {
    alertCallbacks.push(callback);
  },
};

/**
 * Reset monitor state (for testing).
 */
export function resetMemoryIntegrityMonitor(): void {
  alerts = [];
  alertCallbacks = [];
  running = false;
  lastCheck = undefined;
  baseline = null;
  watcher = null;
}

/**
 * Get the current baseline (for testing).
 */
export function getBaseline(): HashBaseline | null {
  return baseline;
}

/**
 * Set baseline externally (for testing).
 */
export function setBaseline(b: HashBaseline): void {
  baseline = b;
}
