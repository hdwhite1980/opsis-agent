/**
 * OPSIS Agent Security Module
 *
 * Provides:
 * - Schema validation for all data inputs
 * - HMAC-based message authentication
 * - Secure credential storage (Windows Credential Manager via keytar)
 * - Playbook validation
 * - Log sanitization
 * - Rate limiting utilities
 */

import * as crypto from 'crypto';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// Re-export credential manager functions
export {
  storeApiKey,
  getApiKey,
  storeHmacSecret,
  getHmacSecret,
  storeIpcSecret,
  getIpcSecret,
  ensureIpcSecret,
  storeCredentialsFromSetup,
  getAllCredentials,
  deleteAllCredentials,
  rotateApiKey,
  hasCredentials,
  isKeytarAvailable,
  getKeytarLoadError,
  ensureKeytarAvailable
} from './credential-manager';

// Re-export HMAC verification functions
export {
  verifyServerMessage,
  verifyPlaybook,
  verifyDiagnosticRequest,
  signMessage as signServerMessage,
  isHmacConfigured
} from './hmac-verifier';

// Re-export playbook validation functions
export {
  validatePlaybook,
  validateStep,
  validateCommand,
  validateDiagnosticRequest,
  isAllowedStepType,
  getAllowedStepTypes
} from './playbook-validator';

// Re-export key rotation handler
export {
  handleKeyRotation,
  createRotationAck,
  createRotationError
} from './key-rotation';

// Re-export runbook integrity verification functions
export {
  computeRunbookHash,
  registerRunbookHash,
  verifyRunbookIntegrity,
  removeRunbookHash,
  canonicalizeServerRunbook,
} from './runbook-integrity';

// ===========================================
// SCHEMA VALIDATION (lightweight Zod-like)
// ===========================================

export type ValidationResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

// Base validator interface
interface Validator<T> {
  parse(input: unknown): T;
  safeParse(input: unknown): ValidationResult<T>;
}

// String validator
class StringValidator implements Validator<string> {
  private minLength?: number;
  private maxLength?: number;
  private pattern?: RegExp;
  private allowedValues?: Set<string>;

  min(length: number): StringValidator {
    const v = new StringValidator();
    Object.assign(v, this);
    v.minLength = length;
    return v;
  }

  max(length: number): StringValidator {
    const v = new StringValidator();
    Object.assign(v, this);
    v.maxLength = length;
    return v;
  }

  regex(pattern: RegExp): StringValidator {
    const v = new StringValidator();
    Object.assign(v, this);
    v.pattern = pattern;
    return v;
  }

  enum(values: string[]): StringValidator {
    const v = new StringValidator();
    Object.assign(v, this);
    v.allowedValues = new Set(values);
    return v;
  }

  parse(input: unknown): string {
    const result = this.safeParse(input);
    if (!result.success) throw new Error(result.error);
    return result.data;
  }

  safeParse(input: unknown): ValidationResult<string> {
    if (typeof input !== 'string') {
      return { success: false, error: 'Expected string' };
    }
    if (this.minLength !== undefined && input.length < this.minLength) {
      return { success: false, error: `String must be at least ${this.minLength} characters` };
    }
    if (this.maxLength !== undefined && input.length > this.maxLength) {
      return { success: false, error: `String must be at most ${this.maxLength} characters` };
    }
    if (this.pattern && !this.pattern.test(input)) {
      return { success: false, error: 'String does not match required pattern' };
    }
    if (this.allowedValues && !this.allowedValues.has(input)) {
      return { success: false, error: `String must be one of: ${[...this.allowedValues].join(', ')}` };
    }
    return { success: true, data: input };
  }
}

// Number validator
class NumberValidator implements Validator<number> {
  private minValue?: number;
  private maxValue?: number;
  private integerOnly = false;

  min(value: number): NumberValidator {
    const v = new NumberValidator();
    Object.assign(v, this);
    v.minValue = value;
    return v;
  }

  max(value: number): NumberValidator {
    const v = new NumberValidator();
    Object.assign(v, this);
    v.maxValue = value;
    return v;
  }

  int(): NumberValidator {
    const v = new NumberValidator();
    Object.assign(v, this);
    v.integerOnly = true;
    return v;
  }

  parse(input: unknown): number {
    const result = this.safeParse(input);
    if (!result.success) throw new Error(result.error);
    return result.data;
  }

  safeParse(input: unknown): ValidationResult<number> {
    if (typeof input !== 'number' || isNaN(input)) {
      return { success: false, error: 'Expected number' };
    }
    if (this.integerOnly && !Number.isInteger(input)) {
      return { success: false, error: 'Expected integer' };
    }
    if (this.minValue !== undefined && input < this.minValue) {
      return { success: false, error: `Number must be at least ${this.minValue}` };
    }
    if (this.maxValue !== undefined && input > this.maxValue) {
      return { success: false, error: `Number must be at most ${this.maxValue}` };
    }
    return { success: true, data: input };
  }
}

// Boolean validator
class BooleanValidator implements Validator<boolean> {
  parse(input: unknown): boolean {
    const result = this.safeParse(input);
    if (!result.success) throw new Error(result.error);
    return result.data;
  }

  safeParse(input: unknown): ValidationResult<boolean> {
    if (typeof input !== 'boolean') {
      return { success: false, error: 'Expected boolean' };
    }
    return { success: true, data: input };
  }
}

// Object validator
class ObjectValidator<T extends Record<string, unknown>> implements Validator<T> {
  constructor(private shape: { [K in keyof T]: Validator<T[K]> }) {}

  parse(input: unknown): T {
    const result = this.safeParse(input);
    if (!result.success) throw new Error(result.error);
    return result.data;
  }

  safeParse(input: unknown): ValidationResult<T> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      return { success: false, error: 'Expected object' };
    }

    const result: Record<string, unknown> = {};
    for (const [key, validator] of Object.entries(this.shape)) {
      const fieldResult = (validator as Validator<unknown>).safeParse((input as Record<string, unknown>)[key]);
      if (!fieldResult.success) {
        return { success: false, error: `${key}: ${fieldResult.error}` };
      }
      result[key] = fieldResult.data;
    }

    return { success: true, data: result as T };
  }
}

// Optional wrapper
class OptionalValidator<T> implements Validator<T | undefined> {
  constructor(private inner: Validator<T>) {}

  parse(input: unknown): T | undefined {
    const result = this.safeParse(input);
    if (!result.success) throw new Error(result.error);
    return result.data;
  }

  safeParse(input: unknown): ValidationResult<T | undefined> {
    if (input === undefined || input === null) {
      return { success: true, data: undefined };
    }
    return this.inner.safeParse(input);
  }
}

// Schema factory
export const z = {
  string: () => new StringValidator(),
  number: () => new NumberValidator(),
  boolean: () => new BooleanValidator(),
  object: <T extends Record<string, unknown>>(shape: { [K in keyof T]: Validator<T[K]> }) =>
    new ObjectValidator(shape),
  optional: <T>(validator: Validator<T>) => new OptionalValidator(validator),
};

// ===========================================
// CONFIG SCHEMAS
// ===========================================

export const AgentConfigSchema = z.object({
  serverUrl: z.string().max(500),
  apiKey: z.string().min(10).max(200),
  autoConnect: z.boolean(),
  autoRemediation: z.boolean(),
  autoUpdate: z.boolean(),
  confidenceThreshold: z.number().int().min(0).max(100),
  updateCheckInterval: z.number().int().min(1).max(86400),
  monitorInterval: z.number().int().min(5).max(3600),
  alertEmail: z.optional(z.string().max(254)),
  logRetention: z.number().int().min(1).max(365),
});

export const DeviceConfigSchema = z.object({
  device_id: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\-_]+$/),
  tenant_id: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\-_]+$/),
  server_url: z.string().max(500),
  websocket_url: z.string().max(500),
  role: z.string().enum(['workstation', 'server', 'domain-controller']),
});

export const TicketSchema = z.object({
  ticket_id: z.string().min(1).max(100),
  timestamp: z.string().max(50),
  type: z.string().enum(['system-event', 'manual-review', 'auto-remediation', 'manual-investigation']),
  description: z.string().max(10000),
  status: z.string().enum(['open', 'in-progress', 'resolved', 'escalated', 'closed']),
  source: z.string().enum(['monitoring', 'manual', 'event-log', 'server']),
  computer_name: z.string().max(256),
  escalated: z.optional(z.number().int().min(0).max(1)),
  result: z.optional(z.string().enum(['success', 'failure', 'pending'])),
  resolution: z.optional(z.string().max(10000)),
});

// ===========================================
// IPC MESSAGE SCHEMAS
// ===========================================

export const IPCMessageTypes = [
  'get-stats', 'get-tickets', 'get-health-data', 'get-config',
  'set-config', 'execute-playbook', 'submit-manual-ticket',
  'get-diagnostics', 'restart-service', 'test-escalation',
  'create-maintenance-window', 'cancel-maintenance-window',
  'get-maintenance-windows', 'get-state-tracker-summary',
  'get-self-service-stats'
] as const;

export const IPCMessageSchema = z.object({
  type: z.string().enum([...IPCMessageTypes]),
  timestamp: z.optional(z.string().max(50)),
  signature: z.optional(z.string().max(128)),
  data: z.optional(z.object({})),
});

// ===========================================
// WEBSOCKET MESSAGE SCHEMAS
// ===========================================

export const WSMessageTypes = [
  'welcome', 'pong', 'ack', 'decision', 'execute_playbook',
  'update_config', 'diagnostic_request', 'diagnostic_response',
  'escalation_response', 'heartbeat', 'register', 'telemetry'
] as const;

export const WSMessageSchema = z.object({
  type: z.string().enum([...WSMessageTypes]),
  timestamp: z.optional(z.string().max(50)),
  signature: z.optional(z.string().max(128)),
  nonce: z.optional(z.string().max(64)),
});

// ===========================================
// HMAC MESSAGE AUTHENTICATION
// ===========================================

const HMAC_ALGORITHM = 'sha256';
const NONCE_LENGTH = 32;
const NONCE_EXPIRY_MS = 300000; // 5 minutes

// Store used nonces to prevent replay attacks
const usedNonces = new Map<string, number>();

// Clean up old nonces periodically
setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > NONCE_EXPIRY_MS * 2) {
      usedNonces.delete(nonce);
    }
  }
}, 60000);

export function generateNonce(): string {
  return crypto.randomBytes(NONCE_LENGTH).toString('hex');
}

export function signMessage(message: object, secret: string): { signature: string; nonce: string; timestamp: string } {
  const nonce = generateNonce();
  const timestamp = new Date().toISOString();

  // Create canonical representation
  const payload = JSON.stringify({ ...message, nonce, timestamp });

  // Generate HMAC
  const hmac = crypto.createHmac(HMAC_ALGORITHM, secret);
  hmac.update(payload);
  const signature = hmac.digest('hex');

  return { signature, nonce, timestamp };
}

export function verifySignature(
  message: object,
  signature: string,
  nonce: string,
  timestamp: string,
  secret: string
): { valid: boolean; error?: string } {
  // Check timestamp freshness
  const messageTime = new Date(timestamp).getTime();
  const now = Date.now();

  if (isNaN(messageTime)) {
    return { valid: false, error: 'Invalid timestamp format' };
  }

  if (Math.abs(now - messageTime) > NONCE_EXPIRY_MS) {
    return { valid: false, error: 'Message timestamp too old or in future' };
  }

  // Check nonce hasn't been used
  if (usedNonces.has(nonce)) {
    return { valid: false, error: 'Nonce already used (replay attack detected)' };
  }

  // Verify signature
  const payload = JSON.stringify({ ...message, nonce, timestamp });
  const hmac = crypto.createHmac(HMAC_ALGORITHM, secret);
  hmac.update(payload);
  const expectedSignature = hmac.digest('hex');

  // Constant-time comparison to prevent timing attacks
  if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'))) {
    return { valid: false, error: 'Invalid signature' };
  }

  // Mark nonce as used
  usedNonces.set(nonce, now);

  return { valid: true };
}

// ===========================================
// SECURE CREDENTIAL STORAGE
// ===========================================

const CREDENTIAL_TARGET = 'OPSIS_Agent_Credentials';

export interface StoredCredentials {
  apiKey?: string;
  serverSecret?: string;
  ipcSecret?: string;
}

/**
 * Store credentials in Windows Credential Manager
 */
export async function storeCredentials(credentials: StoredCredentials): Promise<boolean> {
  try {
    const credJson = JSON.stringify(credentials);

    // Encode credential as Base64 for PowerShell
    const encodedCred = Buffer.from(credJson, 'utf8').toString('base64');

    const script = `
      $ErrorActionPreference = 'Stop'

      # Add required assembly
      Add-Type -AssemblyName System.Security

      # Encrypt the data using DPAPI (current user)
      $bytes = [System.Convert]::FromBase64String('${encodedCred}')
      $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
      )
      $encryptedBase64 = [System.Convert]::ToBase64String($encrypted)

      # Store in registry (more reliable than Credential Manager for large data)
      $regPath = 'HKLM:\\SOFTWARE\\OPSIS\\Agent'
      if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
      }
      Set-ItemProperty -Path $regPath -Name 'EncryptedCredentials' -Value $encryptedBase64

      Write-Output 'SUCCESS'
    `;

    const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', encodedCommand
    ], { encoding: 'utf-8', timeout: 30000 });

    return result.stdout?.includes('SUCCESS') || false;
  } catch {
    return false;
  }
}

/**
 * Retrieve credentials from Windows Credential Manager
 */
export async function retrieveCredentials(): Promise<StoredCredentials | null> {
  try {
    const script = `
      $ErrorActionPreference = 'Stop'

      Add-Type -AssemblyName System.Security

      $regPath = 'HKLM:\\SOFTWARE\\OPSIS\\Agent'
      if (-not (Test-Path $regPath)) {
        Write-Output 'NOT_FOUND'
        exit
      }

      $encryptedBase64 = Get-ItemPropertyValue -Path $regPath -Name 'EncryptedCredentials' -ErrorAction SilentlyContinue
      if (-not $encryptedBase64) {
        Write-Output 'NOT_FOUND'
        exit
      }

      $encrypted = [System.Convert]::FromBase64String($encryptedBase64)
      $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
      )
      $credJson = [System.Text.Encoding]::UTF8.GetString($decrypted)

      Write-Output $credJson
    `;

    const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', encodedCommand
    ], { encoding: 'utf-8', timeout: 30000 });

    if (result.stdout?.includes('NOT_FOUND')) {
      return null;
    }

    const credJson = result.stdout?.trim();
    if (credJson) {
      return JSON.parse(credJson) as StoredCredentials;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Generate and store IPC secret for local authentication
 * Uses keytar for secure storage
 */
export { ensureIpcSecret as ensureIPCSecret } from './credential-manager';

// ===========================================
// LOG SANITIZATION
// ===========================================

const SENSITIVE_PATTERNS = [
  // API keys and tokens
  { pattern: /Bearer\s+[A-Za-z0-9\-_]+/gi, replacement: 'Bearer [REDACTED]' },
  { pattern: /api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9\-_]+/gi, replacement: 'apiKey: [REDACTED]' },
  { pattern: /opsis_[a-f0-9]{32}/gi, replacement: '[REDACTED_API_KEY]' },

  // Passwords and secrets
  { pattern: /password["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, replacement: 'password: [REDACTED]' },
  { pattern: /secret["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, replacement: 'secret: [REDACTED]' },

  // Connection strings
  { pattern: /mongodb(\+srv)?:\/\/[^\s]+/gi, replacement: '[REDACTED_MONGODB_URI]' },
  { pattern: /postgres:\/\/[^\s]+/gi, replacement: '[REDACTED_POSTGRES_URI]' },

  // IP addresses (optional - may want to keep for debugging)
  // { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, replacement: '[IP_REDACTED]' },

  // Email addresses
  { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[EMAIL_REDACTED]' },

  // Windows paths with usernames
  { pattern: /C:\\Users\\[^\\]+/gi, replacement: 'C:\\Users\\[USER]' },

  // Signatures and nonces (if logged accidentally)
  { pattern: /signature["']?\s*[:=]\s*["']?[a-f0-9]{64}/gi, replacement: 'signature: [REDACTED]' },
];

export function sanitizeLogData(data: unknown): unknown {
  if (typeof data === 'string') {
    let sanitized = data;
    for (const { pattern, replacement } of SENSITIVE_PATTERNS) {
      sanitized = sanitized.replace(pattern, replacement);
    }
    return sanitized;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeLogData(item));
  }

  if (typeof data === 'object' && data !== null) {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      // Redact known sensitive field names
      const lowerKey = key.toLowerCase();
      if (['apikey', 'api_key', 'password', 'secret', 'token', 'authorization', 'signature'].includes(lowerKey)) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = sanitizeLogData(value);
      }
    }
    return sanitized;
  }

  return data;
}

// ===========================================
// SECURE FILE OPERATIONS
// ===========================================

/**
 * Atomic file write - writes to temp file first, then renames
 */
export function atomicWriteFileSync(filePath: string, data: string, mode: number = 0o600): void {
  const dir = path.dirname(filePath);
  const tempPath = path.join(dir, `.${path.basename(filePath)}.tmp.${crypto.randomBytes(8).toString('hex')}`);

  try {
    // Write to temp file with restricted permissions
    fs.writeFileSync(tempPath, data, { encoding: 'utf8', mode });

    // Rename atomically
    fs.renameSync(tempPath, filePath);
  } catch (error) {
    // Clean up temp file on error
    try { fs.unlinkSync(tempPath); } catch {}
    throw error;
  }
}

/**
 * Safe JSON parse with schema validation
 */
export function safeParseJSON<T>(
  jsonString: string,
  validator: Validator<T>
): ValidationResult<T> {
  try {
    const parsed = JSON.parse(jsonString);
    return validator.safeParse(parsed);
  } catch (error) {
    return { success: false, error: `Invalid JSON: ${(error as Error).message}` };
  }
}

/**
 * Safe JSON parse without schema - returns null on error
 * Use this for basic JSON parsing with error handling
 * For external/untrusted data, prefer safeParseJSON with a validator
 */
export function tryParseJSON(jsonString: string): { parsed: any; error: string | null } {
  try {
    // Limit input size to prevent DoS
    if (jsonString.length > 10 * 1024 * 1024) { // 10MB max
      return { parsed: null, error: 'JSON input too large' };
    }
    const parsed = JSON.parse(jsonString);
    return { parsed, error: null };
  } catch (error) {
    return { parsed: null, error: `Invalid JSON: ${(error as Error).message}` };
  }
}

/**
 * Safe file read with JSON validation
 */
export function safeReadJSONFile<T>(
  filePath: string,
  validator: Validator<T>
): ValidationResult<T> {
  try {
    // Check file exists
    if (!fs.existsSync(filePath)) {
      return { success: false, error: 'File not found' };
    }

    // Check not a symlink
    const stats = fs.lstatSync(filePath);
    if (stats.isSymbolicLink()) {
      return { success: false, error: 'Symlinks not allowed' };
    }

    const content = fs.readFileSync(filePath, 'utf8');
    return safeParseJSON(content, validator);
  } catch (error) {
    return { success: false, error: `File read error: ${(error as Error).message}` };
  }
}

// ===========================================
// CERTIFICATE PINNING
// ===========================================

// SHA256 fingerprints of trusted certificates
// Should be populated from secure configuration
let trustedCertFingerprints: Set<string> = new Set();

export function setTrustedCertificates(fingerprints: string[]): void {
  trustedCertFingerprints = new Set(fingerprints.map(f => f.toLowerCase().replace(/:/g, '')));
}

export function verifyCertificateFingerprint(cert: { fingerprint256?: string }): boolean {
  if (trustedCertFingerprints.size === 0) {
    // No pinning configured - allow default validation
    return true;
  }

  if (!cert.fingerprint256) {
    return false;
  }

  const normalized = cert.fingerprint256.toLowerCase().replace(/:/g, '');
  return trustedCertFingerprints.has(normalized);
}
