/**
 * AES-GCM Cipher Layer
 *
 * A simple, password-based AES-GCM encryption layer demonstrating
 * the extensibility of the cascading cipher system.
 */

import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';

/**
 * Keys for AES encryption
 */
export interface AESKeys {
  password: string;
}

/**
 * AESCipherLayer - Password-based AES-GCM-256 encryption
 *
 * Uses PBKDF2 for key derivation and AES-GCM for authenticated encryption.
 * Demonstrates how to create a simple cipher layer compatible with
 * the cascading cipher system.
 */
export class AESCipherLayer implements CipherLayer {
  readonly name = 'AES-GCM-256';
  readonly version = '1.0.0';

  private readonly PBKDF2_ITERATIONS = 1000000;
  private readonly SALT_LENGTH = 16;
  private readonly IV_LENGTH = 12;
  private readonly KEY_LENGTH = 256;

  /**
   * Validate that keys contain required fields
   */
  validateKeys(keys: any): boolean {
    return keys !== null && keys !== undefined && typeof keys.password === 'string';
  }

  /**
   * Derive AES key from password using PBKDF2
   */
  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      passwordKey,
      {
        name: 'AES-GCM',
        length: this.KEY_LENGTH,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt data using AES-GCM
   */
  async encrypt(data: Uint8Array, keys: AESKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    try {
      // Validate keys
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: password is required',
          this.name,
          'encrypt'
        );
      }

      // Generate random salt and IV
      const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
      const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

      // Derive encryption key from password
      const key = await this.deriveKey(keys.password, salt);

      // Encrypt data
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        key,
        data
      );

      const ciphertext = new Uint8Array(ciphertextBuffer);
      const endTime = performance.now();

      return {
        ciphertext,
        layerMetadata: {
          algorithm: this.name,
          version: this.version,
          timestamp: Date.now(),
          inputSize: data.length,
          outputSize: ciphertext.length,
          processingTime: endTime - startTime,
          metadata: {
            keyDerivation: 'PBKDF2',
            iterations: this.PBKDF2_ITERATIONS,
          },
        },
        parameters: {
          iv,
          salt,
        },
      };
    } catch (error) {
      throw new CipherLayerError(
        `AES encryption failed: ${error.message}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Decrypt data using AES-GCM
   */
  async decrypt(payload: EncryptedPayload, keys: AESKeys): Promise<Uint8Array> {
    try {
      // Validate keys
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: password is required',
          this.name,
          'decrypt'
        );
      }

      // Extract IV and salt from parameters
      const { iv, salt } = payload.parameters;
      if (!iv || !salt) {
        throw new CipherLayerError(
          'Missing decryption parameters (IV or salt)',
          this.name,
          'decrypt'
        );
      }

      // Derive decryption key from password
      const key = await this.deriveKey(keys.password, salt);

      // Decrypt data
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        key,
        payload.ciphertext
      );

      return new Uint8Array(plaintextBuffer);
    } catch (error) {
      // Provide helpful error messages
      if (error.message?.includes('decryption failed')) {
        throw new CipherLayerError(
          'AES decryption failed: wrong password or corrupted data',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `AES decryption failed: ${error.message}`,
        this.name,
        'decrypt',
        error as Error
      );
    }
  }
}
