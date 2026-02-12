/**
 * OPSIS Agent HMAC Verification
 * Verifies signatures on server messages to prevent tampering and replay attacks
 */

import * as crypto from 'crypto';
import { getHmacSecret } from './credential-manager';

const HMAC_ALGORITHM = 'sha256';

/**
 * Recursively sort all object keys alphabetically.
 * Matches Python's json.dumps(sort_keys=True) behavior.
 * Arrays are preserved in order; only object keys are sorted.
 */
function sortKeysRecursive(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(sortKeysRecursive);
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted: Record<string, any> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortKeysRecursive(obj[key]);
    }
    return sorted;
  }
  return obj;
}
const MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes - replay protection

// Track used nonces to prevent replay attacks
const usedNonces = new Map<string, number>();
const NONCE_CLEANUP_INTERVAL = 60000; // Clean up every minute
const NONCE_MAX_AGE = MAX_MESSAGE_AGE_MS * 2; // Keep nonces for 2x the max age

// Start cleanup interval
setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > NONCE_MAX_AGE) {
      usedNonces.delete(nonce);
    }
  }
}, NONCE_CLEANUP_INTERVAL);

export interface SignedMessage {
  _signature: string;
  _timestamp: string;
  _nonce?: string;
  [key: string]: any;
}

export interface VerificationResult {
  valid: boolean;
  error?: string;
}

/**
 * Verify HMAC signature on a server message
 * Call this BEFORE executing any playbook or diagnostic from the server
 */
export async function verifyServerMessage(message: any): Promise<VerificationResult> {
  // Check required signature fields
  if (!message._signature || !message._timestamp) {
    return { valid: false, error: 'Missing _signature or _timestamp' };
  }

  const signature = message._signature;
  const timestamp = message._timestamp;
  const nonce = message._nonce;

  // Get HMAC secret from credential manager
  const hmacSecret = await getHmacSecret();
  if (!hmacSecret) {
    return { valid: false, error: 'HMAC secret not configured' };
  }

  // Verify timestamp is not too old (replay protection)
  const messageTime = new Date(timestamp).getTime();
  const now = Date.now();

  if (isNaN(messageTime)) {
    return { valid: false, error: 'Invalid timestamp format' };
  }

  if (now - messageTime > MAX_MESSAGE_AGE_MS) {
    return { valid: false, error: 'Message too old (replay protection)' };
  }

  if (messageTime > now + 60000) { // Allow 1 minute clock skew
    return { valid: false, error: 'Message timestamp in future' };
  }

  // Check nonce hasn't been used (replay protection)
  if (nonce) {
    if (usedNonces.has(nonce)) {
      return { valid: false, error: 'Nonce already used (replay attack detected)' };
    }
  }

  // Create payload for signature verification (exclude _signature)
  const payloadObj = { ...message };
  delete payloadObj._signature;

  // Recursive key sort to match server's json.dumps(sort_keys=True)
  const sortedPayload = JSON.stringify(sortKeysRecursive(payloadObj));

  // Compute expected signature
  const hmac = crypto.createHmac(HMAC_ALGORITHM, hmacSecret);
  hmac.update(sortedPayload);
  const expectedSignature = hmac.digest('hex');

  // Constant-time comparison to prevent timing attacks
  let signatureValid = false;
  try {
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (sigBuffer.length === expectedBuffer.length) {
      signatureValid = crypto.timingSafeEqual(sigBuffer, expectedBuffer);
    }
  } catch {
    return { valid: false, error: 'Invalid signature format' };
  }

  if (!signatureValid) {
    return { valid: false, error: 'Invalid signature (tampering detected)' };
  }

  // Mark nonce as used
  if (nonce) {
    usedNonces.set(nonce, now);
  }

  return { valid: true };
}

/**
 * Verify a playbook from the server before execution
 */
export async function verifyPlaybook(playbook: any): Promise<VerificationResult> {
  // Must have signature
  if (!playbook._signature) {
    return { valid: false, error: 'Playbook missing signature' };
  }

  return verifyServerMessage(playbook);
}

/**
 * Verify a diagnostic request from the server before execution
 */
export async function verifyDiagnosticRequest(request: any): Promise<VerificationResult> {
  // Must have signature
  if (!request._signature) {
    return { valid: false, error: 'Diagnostic request missing signature' };
  }

  return verifyServerMessage(request);
}

/**
 * Sign an outgoing message to the server
 */
export async function signMessage(message: object): Promise<object | null> {
  const hmacSecret = await getHmacSecret();
  if (!hmacSecret) {
    return null;
  }

  const timestamp = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString('hex');

  const payload = {
    ...message,
    _timestamp: timestamp,
    _nonce: nonce
  };

  // Recursive key sort to match server's json.dumps(sort_keys=True)
  const sortedPayload = JSON.stringify(sortKeysRecursive(payload));

  // Compute signature
  const hmac = crypto.createHmac(HMAC_ALGORITHM, hmacSecret);
  hmac.update(sortedPayload);
  const signature = hmac.digest('hex');

  return {
    ...payload,
    _signature: signature
  };
}

/**
 * Check if HMAC verification is available
 */
export async function isHmacConfigured(): Promise<boolean> {
  const secret = await getHmacSecret();
  return secret !== null && secret.length > 0;
}
