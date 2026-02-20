import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IOCDatabase } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let cachedDb: IOCDatabase | null = null;

/**
 * Load the IOC database from the bundled indicators.json file.
 */
export async function loadIOCDatabase(customPath?: string): Promise<IOCDatabase> {
  if (cachedDb && !customPath) {
    return cachedDb;
  }

  const dbPath = customPath ?? path.resolve(__dirname, '../../ioc/indicators.json');
  try {
    const content = await fs.readFile(dbPath, 'utf-8');
    const db = JSON.parse(content) as IOCDatabase;

    if (!customPath) {
      cachedDb = db;
    }
    return db;
  } catch {
    // Return empty database so audit can continue without IOC checks
    return {
      version: '0.0.0',
      last_updated: '',
      c2_ips: [],
      malicious_domains: [],
      malicious_skill_hashes: {},
      typosquat_patterns: [],
      dangerous_prerequisite_patterns: [],
      infostealer_artifacts: { macos: [], linux: [] },
    };
  }
}

/**
 * Load IOC database from a raw object (for testing).
 */
export function loadIOCDatabaseFromObject(db: IOCDatabase): void {
  cachedDb = db;
}

/**
 * Clear the cached IOC database.
 */
export function clearIOCCache(): void {
  cachedDb = null;
}

/**
 * Check if an IP address is a known C2 server.
 */
export function isKnownC2(db: IOCDatabase, ip: string): boolean {
  return db.c2_ips.includes(ip);
}

/**
 * Check if a domain is known to be malicious.
 */
export function isKnownMaliciousDomain(db: IOCDatabase, domain: string): boolean {
  return db.malicious_domains.some(
    (d) => domain === d || domain.endsWith('.' + d)
  );
}

/**
 * Check if a file hash matches a known malicious hash.
 * Returns the campaign name if matched, null otherwise.
 */
export function isKnownMaliciousHash(db: IOCDatabase, sha256: string): string | null {
  const campaign = db.malicious_skill_hashes[sha256];
  return campaign ?? null;
}

/**
 * Check if a skill name matches any known typosquat patterns.
 */
export function matchesTyposquat(db: IOCDatabase, name: string): boolean {
  const normalized = name.toLowerCase().replace(/[-_\s]/g, '');
  return db.typosquat_patterns.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase().replace(/[-_\s]/g, '');
    // Exact match or the name contains the typosquat pattern
    return normalized === normalizedPattern || normalized.includes(normalizedPattern);
  });
}

/**
 * Check if content matches any dangerous prerequisite patterns.
 */
export function matchesDangerousPattern(db: IOCDatabase, content: string): string[] {
  const matches: string[] = [];
  for (const pattern of db.dangerous_prerequisite_patterns) {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(content)) {
      matches.push(pattern);
    }
  }
  return matches;
}

/**
 * Get infostealer artifact paths for the current platform.
 */
export function getInfostealerArtifacts(db: IOCDatabase, platform: string): string[] {
  if (platform === 'darwin') {
    return db.infostealer_artifacts.macos;
  }
  if (platform === 'linux') {
    return db.infostealer_artifacts.linux;
  }
  return [];
}
