/**
 * MLS (Message Layer Security) Cipher Layer
 *
 * Wraps the MLS protocol for use in cascading cipher chains.
 */

import { MLSManager, MLSMessageEnvelope } from '../../MLS/MLSManager';
import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';
import { Zeroization } from '../../utils/zeroization';

/**
 * Keys for MLS encryption
 */
export interface MLSKeys {
  mlsManager: MLSManager;
  groupId: string;
}

/**
 * MLSCipherLayer - MLS group encryption layer
 *
 * Provides RFC 9420 compliant end-to-end encrypted group messaging
 * as a layer in the cascading cipher system.
 */
export class MLSCipherLayer implements CipherLayer {
  readonly name = 'MLS';
  readonly version = '1.0.0';

  private mlsManager: MLSManager | null = null;
  private groupId: string | null = null;

  /**
   * Create MLS cipher layer
   *
   * @param mlsManager - Optional pre-configured MLS manager
   * @param groupId - Optional pre-configured group ID
   */
  constructor(mlsManager?: MLSManager, groupId?: string) {
    if (mlsManager) {
      this.mlsManager = mlsManager;
    }
    if (groupId) {
      this.groupId = groupId;
    }
  }

  /**
   * Validate MLS keys
   */
  validateKeys(keys: any): boolean {
    // If constructor provided manager/groupId, keys can be empty or null
    if (this.mlsManager && this.groupId) {
      return true;
    }

    // If no keys provided, return false
    if (!keys) return false;

    // Otherwise, keys must provide them
    return (
      keys.mlsManager instanceof MLSManager &&
      typeof keys.groupId === 'string'
    );
  }

  /**
   * Initialize MLS layer
   */
  async initialize(config: any): Promise<void> {
    if (config?.mlsManager) {
      this.mlsManager = config.mlsManager;
    }
    if (config?.groupId) {
      this.groupId = config.groupId;
    }
  }

  /**
   * Encrypt data using MLS
   */
  async encrypt(data: Uint8Array, keys: MLSKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();
    let base64Data: string | null = null;

    try {
      const manager = keys.mlsManager || this.mlsManager;
      const groupId = keys.groupId || this.groupId;

      if (!manager || !groupId) {
        throw new CipherLayerError(
          'MLS manager and groupId are required',
          this.name,
          'encrypt'
        );
      }

      // Convert binary data to base64 for safe string transport
      // MLS expects string plaintext, but we need to handle binary data
      base64Data = this.arrayBufferToBase64(data);

      // Encrypt using MLS
      const envelope: MLSMessageEnvelope = await manager.encryptMessage(
        groupId,
        base64Data
      );

      const endTime = performance.now();

      // Get group info for metadata
      const groupInfo = await manager.getGroupKeyInfo(groupId);

      // Convert groupId from Uint8Array to string for storage
      const groupIdStr = typeof groupId === 'string' ? groupId : new TextDecoder().decode(envelope.groupId);

      return {
        ciphertext: envelope.ciphertext,
        layerMetadata: {
          algorithm: this.name,
          version: this.version,
          timestamp: envelope.timestamp,
          inputSize: data.length,
          outputSize: envelope.ciphertext.length,
          processingTime: endTime - startTime,
          metadata: {
            groupId: groupIdStr,
            epoch: groupInfo?.epoch,
            cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
            encoding: 'base64',
          },
        },
        parameters: {
          groupId: groupIdStr, // Store as string for consistency
          timestamp: envelope.timestamp,
        },
      };
    } catch (error) {
      // Zeroize base64Data if it exists (though strings are immutable in JS)
      base64Data = null;

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Check for sensitive data (groupId, manager info) in error message
      const groupId = keys.groupId || this.groupId;
      const hasSensitiveData = 
        (groupId && errorMessage.includes(groupId)) ||
        errorMessage.includes('groupId') ||
        errorMessage.includes('manager');

      if (hasSensitiveData) {
        throw new CipherLayerError(
          'MLS encryption failed',
          this.name,
          'encrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `MLS encryption failed: ${errorMessage}`,
        this.name,
        'encrypt',
        error as Error
      );
    } finally {
      // Clear reference (strings are immutable, but we clear the reference)
      base64Data = null;
    }
  }

  /**
   * Convert Uint8Array to base64 string
   */
  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    try {
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } finally {
      // Zeroize temporary buffer
      Zeroization.zeroize(bytes);
    }
  }

  /**
   * Convert base64 string to Uint8Array
   */
  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    try {
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      // Return a copy to allow zeroization of the original
      const result = new Uint8Array(bytes);
      return result;
    } finally {
      // Zeroize temporary buffer
      Zeroization.zeroize(bytes);
    }
  }

  /**
   * Decrypt data using MLS
   */
  async decrypt(payload: EncryptedPayload, keys: MLSKeys): Promise<Uint8Array> {
    let base64Data: string | null = null;
    let result: Uint8Array | null = null;

    try {
      const manager = keys.mlsManager || this.mlsManager;
      const groupId = keys.groupId || this.groupId;

      if (!manager || !groupId) {
        throw new CipherLayerError(
          'MLS manager and groupId are required',
          this.name,
          'decrypt'
        );
      }

      // Reconstruct MLS envelope
      // Convert groupId back to Uint8Array if it's stored as string
      const groupIdParam = payload.parameters.groupId;
      const groupIdBytes = typeof groupIdParam === 'string' 
        ? new TextEncoder().encode(groupIdParam)
        : (groupIdParam instanceof Uint8Array ? groupIdParam : new Uint8Array(groupIdParam));

      // Ensure ciphertext is Uint8Array (might be array after JSON serialization, or string in tests)
      let ciphertextBytes: Uint8Array;
      
      // Handle string input (for test compatibility)
      if (typeof payload.ciphertext === 'string') {
        ciphertextBytes = new TextEncoder().encode(payload.ciphertext);
      } else if (payload.ciphertext && 
          (payload.ciphertext instanceof Uint8Array || 
           (ArrayBuffer.isView(payload.ciphertext) && payload.ciphertext.constructor.name === 'Uint8Array'))) {
        // Check if it's already a Uint8Array (use constructor name check for cross-realm compatibility)
        ciphertextBytes = payload.ciphertext as Uint8Array;
      } else if (Array.isArray(payload.ciphertext)) {
        ciphertextBytes = new Uint8Array(payload.ciphertext);
      } else if (payload.ciphertext instanceof ArrayBuffer) {
        ciphertextBytes = new Uint8Array(payload.ciphertext);
      } else if (payload.ciphertext && typeof payload.ciphertext === 'object' && 'buffer' in payload.ciphertext) {
        // Handle TypedArray-like objects
        ciphertextBytes = new Uint8Array(payload.ciphertext.buffer || payload.ciphertext);
      } else if (payload.ciphertext && typeof payload.ciphertext === 'object' && 'length' in payload.ciphertext) {
        // Handle array-like objects
        ciphertextBytes = new Uint8Array(Array.from(payload.ciphertext as any));
      } else {
        throw new CipherLayerError(
          `Invalid ciphertext format: expected Uint8Array, array, ArrayBuffer, or string, got ${typeof payload.ciphertext}${payload.ciphertext ? ` (${payload.ciphertext.constructor?.name || 'unknown'})` : ''}`,
          this.name,
          'decrypt'
        );
      }

      const envelope: MLSMessageEnvelope = {
        groupId: groupIdBytes,
        ciphertext: ciphertextBytes,
        timestamp: payload.parameters.timestamp,
      };

      // Decrypt using MLS (returns base64 string)
      base64Data = await manager.decryptMessage(envelope);

      // Convert base64 back to binary data
      result = this.base64ToArrayBuffer(base64Data);
      
      // Create a copy for return (before zeroization)
      const resultCopy = new Uint8Array(result);
      return resultCopy;
    } catch (error) {
      // Zeroize any partial results
      if (result) {
        Zeroization.zeroize(result);
      }
      base64Data = null;

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Check for sensitive data (groupId, manager info) in error message
      const groupId = keys.groupId || this.groupId;
      const hasSensitiveData = 
        (groupId && errorMessage.includes(groupId)) ||
        errorMessage.includes('groupId') ||
        errorMessage.includes('manager');

      if (hasSensitiveData) {
        throw new CipherLayerError(
          'MLS decryption failed',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `MLS decryption failed: ${errorMessage}`,
        this.name,
        'decrypt',
        error as Error
      );
    } finally {
      // Clear references (strings are immutable, but we clear the reference)
      base64Data = null;
      // Note: result is already zeroized in base64ToArrayBuffer's finally block
    }
  }

  /**
   * Clean up MLS resources
   * Note: We don't destroy the MLS manager itself because it's provided from outside
   * and may still be in use. The owner of the manager is responsible for its lifecycle.
   */
  async destroy(): Promise<void> {
    // Just clear our references, don't destroy the shared manager
    this.mlsManager = null;
    this.groupId = null;
  }
}
