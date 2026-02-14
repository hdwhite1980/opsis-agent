/**
 * OPSIS Agent Runbook Integrity Verification
 *
 * Computes SHA-256 hashes of runbook content and stores them in Windows
 * Credential Manager (DPAPI-protected via keytar). Before executing any
 * cached runbook from disk, the agent verifies the hash to detect tampering.
 */

import * as crypto from 'crypto';
import { ensureKeytarAvailable, isKeytarAvailable } from './credential-manager';

let keytar: typeof import('keytar') | null = null;
try {
  keytar = require('keytar');
} catch {
  // Handled gracefully — isKeytarAvailable() will return false
}

const SERVICE_NAME = 'OPSIS-Agent';
const MANIFEST_ACCOUNT = 'runbookIntegrityManifest';

// Fields that change on every execution and must be excluded from the hash
const VOLATILE_FIELDS = new Set([
  'execution_count',
  'last_executed',
  'success_count',
  'saved_at',
  'resolved',
]);

export interface IntegrityManifest {
  hashes: Record<string, string>;
  version: string;
  updated_at: string;
}

export interface IntegrityCheckResult {
  valid: boolean;
  reason: 'hash_match' | 'no_stored_hash' | 'hash_mismatch' | 'manifest_unavailable';
  expected_hash?: string;
  actual_hash?: string;
}

/**
 * Compute SHA-256 hex digest of a string
 */
export function computeRunbookHash(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Recursively sort object keys for deterministic JSON serialization
 */
function sortKeysDeep(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(sortKeysDeep);
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted: Record<string, any> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortKeysDeep(obj[key]);
    }
    return sorted;
  }
  return obj;
}

/**
 * Produce a canonical JSON string for a server-cached runbook entry.
 * Strips volatile metadata fields so the hash stays stable across
 * execution-count updates.
 */
export function canonicalizeServerRunbook(runbook: any): string {
  const stripped: Record<string, any> = {};
  for (const [key, value] of Object.entries(runbook)) {
    if (!VOLATILE_FIELDS.has(key)) {
      stripped[key] = value;
    }
  }
  return JSON.stringify(sortKeysDeep(stripped));
}

/**
 * Load the integrity manifest from Windows Credential Manager
 */
export async function loadIntegrityManifest(): Promise<IntegrityManifest> {
  const empty: IntegrityManifest = { hashes: {}, version: '1.0', updated_at: new Date().toISOString() };

  if (!isKeytarAvailable() || !keytar) {
    return empty;
  }

  try {
    const raw = await keytar.getPassword(SERVICE_NAME, MANIFEST_ACCOUNT);
    if (!raw) return empty;

    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.hashes === 'object') {
      return parsed as IntegrityManifest;
    }
    return empty;
  } catch {
    return empty;
  }
}

/**
 * Save the integrity manifest to Windows Credential Manager
 */
export async function saveIntegrityManifest(manifest: IntegrityManifest): Promise<void> {
  ensureKeytarAvailable('store runbook integrity manifest');
  manifest.updated_at = new Date().toISOString();
  await keytar!.setPassword(SERVICE_NAME, MANIFEST_ACCOUNT, JSON.stringify(manifest));
}

/**
 * Compute the hash of runbook content and store it in the manifest
 */
export async function registerRunbookHash(key: string, content: string): Promise<void> {
  if (!isKeytarAvailable()) return;

  const manifest = await loadIntegrityManifest();
  manifest.hashes[key] = computeRunbookHash(content);
  await saveIntegrityManifest(manifest);
}

/**
 * Verify a runbook's content against its stored hash.
 *
 * Returns:
 *  - hash_match:            content matches stored hash
 *  - hash_mismatch:         content differs — possible tampering
 *  - no_stored_hash:        no hash on file (first load / migration)
 *  - manifest_unavailable:  keytar not available (graceful degradation)
 */
export async function verifyRunbookIntegrity(
  key: string,
  content: string
): Promise<IntegrityCheckResult> {
  if (!isKeytarAvailable()) {
    return { valid: true, reason: 'manifest_unavailable' };
  }

  const manifest = await loadIntegrityManifest();
  const storedHash = manifest.hashes[key];

  if (!storedHash) {
    return { valid: true, reason: 'no_stored_hash' };
  }

  const actualHash = computeRunbookHash(content);

  // Constant-time comparison to prevent timing side-channels
  try {
    const storedBuf = Buffer.from(storedHash, 'hex');
    const actualBuf = Buffer.from(actualHash, 'hex');

    if (storedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(storedBuf, actualBuf)) {
      return {
        valid: false,
        reason: 'hash_mismatch',
        expected_hash: storedHash,
        actual_hash: actualHash,
      };
    }
  } catch {
    // If buffers can't be compared (e.g. corrupt stored hash), treat as mismatch
    return {
      valid: false,
      reason: 'hash_mismatch',
      expected_hash: storedHash,
      actual_hash: actualHash,
    };
  }

  return { valid: true, reason: 'hash_match' };
}

/**
 * Remove a runbook's hash from the manifest
 */
export async function removeRunbookHash(key: string): Promise<void> {
  if (!isKeytarAvailable()) return;

  const manifest = await loadIntegrityManifest();
  delete manifest.hashes[key];
  await saveIntegrityManifest(manifest);
}
