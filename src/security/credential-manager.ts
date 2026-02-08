/**
 * OPSIS Agent Credential Manager
 * Uses keytar for Windows Credential Manager integration
 */

import * as crypto from 'crypto';

// Keytar is a native module - import dynamically
let keytar: typeof import('keytar') | null = null;
let keytarLoadError: Error | null = null;

try {
  keytar = require('keytar');
} catch (error) {
  keytarLoadError = error as Error;
  // Log once at startup - will be enforced when credentials are actually needed
  console.error('SECURITY: keytar module failed to load - secure credential storage unavailable');
}

/**
 * Check if keytar is available - throws if not when required=true
 */
export function ensureKeytarAvailable(operationName: string): void {
  if (!keytar) {
    const msg = `SECURITY ERROR: Cannot ${operationName} - keytar not available. ` +
                `Secure credential storage is required. ` +
                `Load error: ${keytarLoadError?.message || 'unknown'}`;
    throw new Error(msg);
  }
}

const SERVICE_NAME = 'OPSIS-Agent';

export interface AgentCredentials {
  apiKey: string;
  hmacSecret: string;
  ipcSecret?: string;
}

/**
 * Store API key in Windows Credential Manager
 * Throws if keytar is not available - never fails silently
 */
export async function storeApiKey(apiKey: string): Promise<boolean> {
  ensureKeytarAvailable('store API key');
  try {
    await keytar!.setPassword(SERVICE_NAME, 'apiKey', apiKey);
    return true;
  } catch (error) {
    console.error('Failed to store API key:', error);
    throw new Error('Failed to store API key in Windows Credential Manager');
  }
}

/**
 * Retrieve API key from Windows Credential Manager
 * Throws if keytar is not available - never fails silently
 */
export async function getApiKey(): Promise<string | null> {
  ensureKeytarAvailable('retrieve API key');
  try {
    return await keytar!.getPassword(SERVICE_NAME, 'apiKey');
  } catch (error) {
    console.error('Failed to retrieve API key:', error);
    throw new Error('Failed to retrieve API key from Windows Credential Manager');
  }
}

/**
 * Store HMAC secret in Windows Credential Manager
 * Throws if keytar is not available - never fails silently
 */
export async function storeHmacSecret(hmacSecret: string): Promise<boolean> {
  ensureKeytarAvailable('store HMAC secret');
  try {
    await keytar!.setPassword(SERVICE_NAME, 'hmacSecret', hmacSecret);
    return true;
  } catch (error) {
    console.error('Failed to store HMAC secret:', error);
    throw new Error('Failed to store HMAC secret in Windows Credential Manager');
  }
}

/**
 * Retrieve HMAC secret from Windows Credential Manager
 * Throws if keytar is not available - never fails silently
 */
export async function getHmacSecret(): Promise<string | null> {
  ensureKeytarAvailable('retrieve HMAC secret');
  try {
    return await keytar!.getPassword(SERVICE_NAME, 'hmacSecret');
  } catch (error) {
    console.error('Failed to retrieve HMAC secret:', error);
    throw new Error('Failed to retrieve HMAC secret from Windows Credential Manager');
  }
}

/**
 * Store IPC secret for GUI communication
 * Throws if keytar is not available - never fails silently
 */
export async function storeIpcSecret(ipcSecret: string): Promise<boolean> {
  ensureKeytarAvailable('store IPC secret');
  try {
    await keytar!.setPassword(SERVICE_NAME, 'ipcSecret', ipcSecret);
    return true;
  } catch (error) {
    console.error('Failed to store IPC secret:', error);
    throw new Error('Failed to store IPC secret in Windows Credential Manager');
  }
}

/**
 * Retrieve IPC secret
 * Throws if keytar is not available - never fails silently
 */
export async function getIpcSecret(): Promise<string | null> {
  ensureKeytarAvailable('retrieve IPC secret');
  try {
    return await keytar!.getPassword(SERVICE_NAME, 'ipcSecret');
  } catch (error) {
    console.error('Failed to retrieve IPC secret:', error);
    throw new Error('Failed to retrieve IPC secret from Windows Credential Manager');
  }
}

/**
 * Generate and store a new IPC secret if one doesn't exist
 */
export async function ensureIpcSecret(): Promise<string> {
  let secret = await getIpcSecret();
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    await storeIpcSecret(secret);
  }
  return secret;
}

/**
 * Store all credentials from agent setup response
 */
export async function storeCredentialsFromSetup(agentConfig: {
  apiKey?: string;
  hmacSecret?: string;
}): Promise<boolean> {
  let success = true;

  if (agentConfig.apiKey) {
    success = await storeApiKey(agentConfig.apiKey) && success;
  }

  if (agentConfig.hmacSecret) {
    success = await storeHmacSecret(agentConfig.hmacSecret) && success;
  }

  return success;
}

/**
 * Get all stored credentials
 */
export async function getAllCredentials(): Promise<AgentCredentials | null> {
  const apiKey = await getApiKey();
  const hmacSecret = await getHmacSecret();
  const ipcSecret = await getIpcSecret();

  if (!apiKey || !hmacSecret) {
    return null;
  }

  return {
    apiKey,
    hmacSecret,
    ipcSecret: ipcSecret || undefined
  };
}

/**
 * Delete all stored credentials
 * Throws if keytar is not available - never fails silently
 */
export async function deleteAllCredentials(): Promise<boolean> {
  ensureKeytarAvailable('delete credentials');
  try {
    await keytar!.deletePassword(SERVICE_NAME, 'apiKey');
    await keytar!.deletePassword(SERVICE_NAME, 'hmacSecret');
    await keytar!.deletePassword(SERVICE_NAME, 'ipcSecret');
    return true;
  } catch (error) {
    console.error('Failed to delete credentials:', error);
    throw new Error('Failed to delete credentials from Windows Credential Manager');
  }
}

/**
 * Rotate API key - store new key and optionally verify with old
 */
export async function rotateApiKey(newApiKey: string): Promise<boolean> {
  return await storeApiKey(newApiKey);
}

/**
 * Check if credentials are stored
 */
export async function hasCredentials(): Promise<boolean> {
  const apiKey = await getApiKey();
  return apiKey !== null;
}

/**
 * Check if keytar (secure credential storage) is available
 * Returns false if keytar failed to load - use this for graceful checks
 */
export function isKeytarAvailable(): boolean {
  return keytar !== null;
}

/**
 * Get the keytar load error if any
 */
export function getKeytarLoadError(): Error | null {
  return keytarLoadError;
}
