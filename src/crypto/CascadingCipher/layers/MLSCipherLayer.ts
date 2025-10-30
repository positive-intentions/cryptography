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
    if (!keys) return false;

    // If constructor provided manager/groupId, keys can be empty
    if (this.mlsManager && this.groupId) {
      return true;
    }

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
      const base64Data = this.arrayBufferToBase64(data);

      // Encrypt using MLS
      const envelope: MLSMessageEnvelope = await manager.encryptMessage(
        groupId,
        base64Data
      );

      const endTime = performance.now();

      // Get group info for metadata
      const groupInfo = await manager.getGroupKeyInfo(groupId);

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
            groupId,
            epoch: groupInfo?.epoch,
            cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
            encoding: 'base64',
          },
        },
        parameters: {
          groupId: envelope.groupId,
          timestamp: envelope.timestamp,
        },
      };
    } catch (error) {
      throw new CipherLayerError(
        `MLS encryption failed: ${error.message}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Convert Uint8Array to base64 string
   */
  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to Uint8Array
   */
  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Decrypt data using MLS
   */
  async decrypt(payload: EncryptedPayload, keys: MLSKeys): Promise<Uint8Array> {
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
      const envelope: MLSMessageEnvelope = {
        groupId: payload.parameters.groupId,
        ciphertext: payload.ciphertext,
        timestamp: payload.parameters.timestamp,
      };

      // Decrypt using MLS (returns base64 string)
      const base64Data = await manager.decryptMessage(envelope);

      // Convert base64 back to binary data
      return this.base64ToArrayBuffer(base64Data);
    } catch (error) {
      throw new CipherLayerError(
        `MLS decryption failed: ${error.message}`,
        this.name,
        'decrypt',
        error as Error
      );
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
