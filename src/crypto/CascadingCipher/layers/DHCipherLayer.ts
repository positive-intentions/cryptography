/**
 * Diffie-Hellman Cipher Layer
 *
 * Uses Diffie-Hellman key exchange to derive a shared symmetric key,
 * then encrypts data with AES-GCM using that key.
 */

import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';

/**
 * Keys for DH encryption
 */
export interface DHKeys {
  /** Private key for DH (CryptoKey or raw bytes) */
  privateKey?: CryptoKey | Uint8Array;

  /** Public key of the other party for DH (CryptoKey or raw bytes) */
  publicKey?: CryptoKey | Uint8Array;

  /** Pre-derived shared secret (if already performed DH) */
  sharedSecret?: Uint8Array;
}

/**
 * DHCipherLayer - Diffie-Hellman + AES-GCM encryption layer
 *
 * Performs DH key exchange to derive a shared symmetric key,
 * then uses AES-GCM for encryption. Compatible with the chat app's
 * Diffie-Hellman implementation.
 */
export class DHCipherLayer implements CipherLayer {
  readonly name = 'DH-AES-GCM';
  readonly version = '1.0.0';

  private readonly IV_LENGTH = 12;
  private readonly KEY_LENGTH = 256;

  /**
   * Validate DH keys
   */
  validateKeys(keys: any): boolean {
    if (!keys) return false;

    // Must have either sharedSecret OR both privateKey and publicKey
    return (
      keys.sharedSecret instanceof Uint8Array ||
      ((keys.privateKey !== undefined) && (keys.publicKey !== undefined))
    );
  }

  /**
   * Derive shared secret using ECDH
   */
  private async deriveSharedSecret(
    privateKey: CryptoKey | Uint8Array,
    publicKey: CryptoKey | Uint8Array
  ): Promise<Uint8Array> {
    try {
      // If keys are already CryptoKey objects, use them directly
      let privKey = privateKey as CryptoKey;
      let pubKey = publicKey as CryptoKey;

      // If they're Uint8Arrays, import them as CryptoKeys
      if (privateKey instanceof Uint8Array) {
        privKey = await crypto.subtle.importKey(
          'raw',
          privateKey,
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          ['deriveKey', 'deriveBits']
        );
      }

      if (publicKey instanceof Uint8Array) {
        pubKey = await crypto.subtle.importKey(
          'raw',
          publicKey,
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          []
        );
      }

      // Derive bits using ECDH
      const sharedSecretBits = await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: pubKey,
        },
        privKey,
        256 // 256 bits for AES-256
      );

      return new Uint8Array(sharedSecretBits);
    } catch (error) {
      throw new CipherLayerError(
        `Diffie-Hellman key derivation failed: ${error.message}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Derive AES key from shared secret using HKDF
   */
  private async deriveAESKey(sharedSecret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
    // Import shared secret as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using HKDF
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        salt,
        info: new TextEncoder().encode('DH-AES-GCM-Cascading-Cipher'),
        hash: 'SHA-256',
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: this.KEY_LENGTH,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt data using DH + AES-GCM
   */
  async encrypt(data: Uint8Array, keys: DHKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    try {
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: need sharedSecret OR (privateKey + publicKey)',
          this.name,
          'encrypt'
        );
      }

      // Get or derive shared secret
      let sharedSecret: Uint8Array;
      if (keys.sharedSecret) {
        sharedSecret = keys.sharedSecret;
      } else {
        sharedSecret = await this.deriveSharedSecret(keys.privateKey!, keys.publicKey!);
      }

      // Generate random salt and IV
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

      // Derive AES key from shared secret
      const aesKey = await this.deriveAESKey(sharedSecret, salt);

      // Encrypt with AES-GCM
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        aesKey,
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
            keyExchange: 'ECDH-P256',
            keyDerivation: 'HKDF-SHA256',
            encryption: 'AES-GCM-256',
          },
        },
        parameters: {
          iv,
          salt,
          usedPreSharedSecret: !!keys.sharedSecret,
        },
      };
    } catch (error) {
      throw new CipherLayerError(
        `DH-AES encryption failed: ${error.message}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Decrypt data using DH + AES-GCM
   */
  async decrypt(payload: EncryptedPayload, keys: DHKeys): Promise<Uint8Array> {
    try {
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: need sharedSecret OR (privateKey + publicKey)',
          this.name,
          'decrypt'
        );
      }

      // Get or derive shared secret
      let sharedSecret: Uint8Array;
      if (keys.sharedSecret) {
        sharedSecret = keys.sharedSecret;
      } else {
        sharedSecret = await this.deriveSharedSecret(keys.privateKey!, keys.publicKey!);
      }

      // Extract IV and salt
      const { iv, salt } = payload.parameters;
      if (!iv || !salt) {
        throw new CipherLayerError(
          'Missing decryption parameters (IV or salt)',
          this.name,
          'decrypt'
        );
      }

      // Derive AES key from shared secret
      const aesKey = await this.deriveAESKey(sharedSecret, salt);

      // Decrypt with AES-GCM
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        aesKey,
        payload.ciphertext
      );

      return new Uint8Array(plaintextBuffer);
    } catch (error) {
      if (error.message?.includes('decryption failed')) {
        throw new CipherLayerError(
          'DH-AES decryption failed: wrong keys or corrupted data',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `DH-AES decryption failed: ${error.message}`,
        this.name,
        'decrypt',
        error as Error
      );
    }
  }
}
