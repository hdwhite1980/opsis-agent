/**
 * OPSIS Agent Key Rotation Handler
 * Handles secure rotation of API keys and HMAC secrets
 */

import { verifyServerMessage } from './hmac-verifier';
import { storeApiKey, storeHmacSecret, getHmacSecret } from './credential-manager';
import Logger from '../common/logger';

export interface KeyRotationMessage {
  type: 'key_rotation';
  new_api_key?: string;
  new_hmac_secret?: string;
  _signature: string;
  _timestamp: string;
  _nonce?: string;
}

export interface KeyRotationResult {
  success: boolean;
  error?: string;
  rotated: {
    apiKey: boolean;
    hmacSecret: boolean;
  };
}

/**
 * Handle a key rotation message from the server
 * MUST verify HMAC signature using current secret before applying new keys
 */
export async function handleKeyRotation(
  message: KeyRotationMessage,
  logger?: Logger
): Promise<KeyRotationResult> {
  const result: KeyRotationResult = {
    success: false,
    rotated: { apiKey: false, hmacSecret: false }
  };

  // Step 1: Verify the message signature using CURRENT HMAC secret
  const verification = await verifyServerMessage(message);
  if (!verification.valid) {
    result.error = `Signature verification failed: ${verification.error}`;
    logger?.warn('Key rotation rejected: invalid signature', { error: verification.error });
    return result;
  }

  logger?.info('Key rotation message verified, applying new keys');

  // Step 2: Rotate API key if provided
  if (message.new_api_key) {
    // Validate API key format
    if (typeof message.new_api_key !== 'string' || message.new_api_key.length < 10) {
      result.error = 'Invalid new API key format';
      logger?.error('Key rotation failed: invalid API key format');
      return result;
    }

    const stored = await storeApiKey(message.new_api_key);
    if (!stored) {
      result.error = 'Failed to store new API key';
      logger?.error('Key rotation failed: could not store API key');
      return result;
    }

    result.rotated.apiKey = true;
    logger?.info('API key rotated successfully');
  }

  // Step 3: Rotate HMAC secret if provided
  // IMPORTANT: Do this LAST since we used the old secret to verify this message
  if (message.new_hmac_secret) {
    // Validate HMAC secret format
    if (typeof message.new_hmac_secret !== 'string' || message.new_hmac_secret.length < 32) {
      result.error = 'Invalid new HMAC secret format';
      logger?.error('Key rotation failed: invalid HMAC secret format');
      return result;
    }

    const stored = await storeHmacSecret(message.new_hmac_secret);
    if (!stored) {
      result.error = 'Failed to store new HMAC secret';
      logger?.error('Key rotation failed: could not store HMAC secret');
      return result;
    }

    result.rotated.hmacSecret = true;
    logger?.info('HMAC secret rotated successfully');
  }

  result.success = true;
  logger?.info('Key rotation completed', { rotated: result.rotated });

  return result;
}

/**
 * Create an acknowledgment message for successful key rotation
 */
export function createRotationAck(rotated: { apiKey: boolean; hmacSecret: boolean }): object {
  return {
    type: 'key_rotation_ack',
    success: true,
    rotated,
    timestamp: new Date().toISOString()
  };
}

/**
 * Create an error response for failed key rotation
 */
export function createRotationError(error: string): object {
  return {
    type: 'key_rotation_ack',
    success: false,
    error,
    timestamp: new Date().toISOString()
  };
}
