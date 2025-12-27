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
import { Zeroization } from '../../utils/zeroization';
import { ConstantTime } from '../../utils/constantTime';
import { KeyAuthentication } from '../../utils/keyAuthentication';

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
  /** Optional: Expected public key fingerprint for MITM protection */
  expectedPublicKeyFingerprint?: string;
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
  readonly version = '2.0.0';

  private readonly IV_LENGTH = 12;
  private readonly KEY_LENGTH = 256;
  private readonly SALT_LENGTH = 16;

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
   * Validate ECDH key format and curve
   */
  private async validateECDHKey(
    key: CryptoKey | Uint8Array,
    expectedType: 'private' | 'public'
  ): Promise<CryptoKey> {
    // Check if it's a CryptoKey by checking for Web Crypto API key properties
    if (key && typeof key === 'object' && 'type' in key && 'algorithm' in key) {
      // Validate CryptoKey format
      const cryptoKey = key as CryptoKey;
      if (cryptoKey.algorithm.name !== 'ECDH') {
        throw new CipherLayerError(
          `Invalid key algorithm: expected ECDH, got ${(cryptoKey.algorithm as any).name || 'unknown'}`,
          this.name,
          'encrypt'
        );
      }

      const ecdhKey = cryptoKey.algorithm as EcKeyAlgorithm;
      if (ecdhKey.namedCurve !== 'P-256') {
        throw new CipherLayerError(
          `Invalid curve: expected P-256, got ${ecdhKey.namedCurve}`,
          this.name,
          'encrypt'
        );
      }

      if (cryptoKey.type !== expectedType) {
        throw new CipherLayerError(
          `Invalid key type: expected ${expectedType}, got ${cryptoKey.type}`,
          this.name,
          'encrypt'
        );
      }

      return cryptoKey;
    }

    // Validate Uint8Array format
    if (!(key instanceof Uint8Array)) {
      throw new CipherLayerError(
        `Invalid key format: expected CryptoKey or Uint8Array, got ${typeof key}`,
        this.name,
        'encrypt'
      );
    }

    if (expectedType === 'private') {
      // P-256 private key should be 32 bytes
      if (key.length !== 32) {
        throw new CipherLayerError(
          `Invalid private key length: expected 32 bytes, got ${key.length}`,
          this.name,
          'encrypt'
        );
      }
    } else {
      // P-256 public key can be 65 bytes (uncompressed) or 33 bytes (compressed)
      if (key.length !== 65 && key.length !== 33) {
        throw new CipherLayerError(
          `Invalid public key length: expected 65 or 33 bytes, got ${key.length}`,
          this.name,
          'encrypt'
        );
      }

      // Validate public key format
      if (key.length === 65) {
        // Uncompressed key should start with 0x04
        if (key[0] !== 0x04) {
          throw new CipherLayerError(
            'Invalid public key format: uncompressed key must start with 0x04',
            this.name,
            'encrypt'
          );
        }
      } else if (key.length === 33) {
        // Compressed key should start with 0x02 or 0x03
        if (key[0] !== 0x02 && key[0] !== 0x03) {
          throw new CipherLayerError(
            'Invalid public key format: compressed key must start with 0x02 or 0x03',
            this.name,
            'encrypt'
          );
        }
      }
    }

    // Import and return CryptoKey
    return await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      expectedType === 'private' ? ['deriveKey', 'deriveBits'] : []
    );
  }

  /**
   * Derive shared secret using ECDH
   */
  private async deriveSharedSecret(
    privateKey: CryptoKey | Uint8Array,
    publicKey: CryptoKey | Uint8Array
  ): Promise<Uint8Array> {
    let sharedSecret: Uint8Array | null = null;

    try {
      // Validate keys before use
      const privKey = await this.validateECDHKey(privateKey, 'private');
      const pubKey = await this.validateECDHKey(publicKey, 'public');

      // Derive bits using ECDH
      const sharedSecretBits = await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: pubKey,
        },
        privKey,
        256 // 256 bits for AES-256
      );

      sharedSecret = new Uint8Array(sharedSecretBits);
      return sharedSecret;
    } catch (error) {
      // Zeroize any partial shared secret
      if (sharedSecret) {
        Zeroization.zeroize(sharedSecret);
      }

      throw new CipherLayerError(
        `Diffie-Hellman key derivation failed: ${error instanceof Error ? error.message : String(error)}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Derive AES key from shared secret using HKDF
   * 
   * Security Properties:
   * - Includes randomized contextId and timestamp in HKDF info parameter for domain separation
   * - ContextId: Random 16-byte value ensures different keys even with same shared secret
   * - Timestamp: Included to bind key derivation to specific time, preventing replay attacks
   * - Protocol version: Included to ensure version-specific key derivation
   * 
   * Security Considerations:
   * - Timestamp manipulation will cause decryption failure (timestamp must match encryption)
   * - ContextId is stored in payload parameters and must be preserved for decryption
   * - HKDF info parameter format: "DH-AES-GCM-Cascading-Cipher|v{version}|{contextIdHex}|{timestamp}"
   * - This ensures keys are unique per encryption operation, even with same shared secret
   * 
   * @param sharedSecret - The ECDH-derived shared secret
   * @param salt - Random salt for HKDF
   * @param contextId - Optional random context ID (generated if not provided)
   * @param timestamp - Optional timestamp (uses current time if not provided)
   * @returns Derived AES-GCM key
   */
  private async deriveAESKey(
    sharedSecret: Uint8Array,
    salt: Uint8Array,
    contextId?: Uint8Array,
    timestamp?: number
  ): Promise<CryptoKey> {
    let keyMaterial: CryptoKey | null = null;

    try {
      // Import shared secret as key material
      keyMaterial = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        'HKDF',
        false,
        ['deriveKey']
      );

      // Generate random context ID if not provided
      const actualContextId = contextId || crypto.getRandomValues(new Uint8Array(16));
      const contextIdHex = Array.from(actualContextId)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      // Use provided timestamp or current time
      const actualTimestamp = timestamp !== undefined ? timestamp : Date.now();

      // Include protocol version, context ID, and timestamp in HKDF info
      // Format: "DH-AES-GCM-Cascading-Cipher|v{version}|{contextIdHex}|{timestamp}"
      // This ensures domain separation: same shared secret produces different keys
      // for different contexts/timestamps, preventing key reuse attacks
      // Security: Timestamp manipulation will cause decryption failure (must match encryption)
      const infoParts = [
        'DH-AES-GCM-Cascading-Cipher',
        `v${this.version}`,
        contextIdHex,
        actualTimestamp.toString(),
      ];
      const info = new TextEncoder().encode(infoParts.join('|'));

      // Derive AES-GCM key using HKDF with randomized info
      return await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          salt,
          info,
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
    } catch (error) {
      keyMaterial = null;
      throw new CipherLayerError(
        `HKDF key derivation failed: ${error instanceof Error ? error.message : String(error)}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Encrypt data using DH + AES-GCM
   */
  async encrypt(data: Uint8Array, keys: DHKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();
    let sharedSecret: Uint8Array | null = null;
    let salt: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;
    let contextId: Uint8Array | null = null;

    try {
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys',
          this.name,
          'encrypt'
        );
      }

      // Validate public key fingerprint if provided (MITM protection)
      if (keys.publicKey && keys.expectedPublicKeyFingerprint) {
        const isValid = await KeyAuthentication.verifyFingerprint(
          keys.publicKey,
          keys.expectedPublicKeyFingerprint
        );
        if (!isValid) {
          throw new CipherLayerError(
            'Public key fingerprint mismatch',
            this.name,
            'encrypt'
          );
        }
      }

      // Get or derive shared secret
      // Create a copy to avoid zeroizing original if it's from keys
      if (keys.sharedSecret) {
        sharedSecret = new Uint8Array(keys.sharedSecret);
      } else {
        sharedSecret = await this.deriveSharedSecret(keys.privateKey, keys.publicKey);
      }

      // Generate random salt, IV, and context ID
      salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
      iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
      contextId = crypto.getRandomValues(new Uint8Array(16));

      // Get timestamp once for both HKDF and AAD
      const timestamp = Date.now();

      // Derive AES key from shared secret with randomized HKDF info
      aesKey = await this.deriveAESKey(sharedSecret, salt, contextId, timestamp);

      // Create AAD with protocol version and context
      const protocolVersion = `${this.name}-v${this.version}`;
      const aadData = {
        protocol: protocolVersion,
        context: Array.from(contextId),
        timestamp,
      };
      const encoder = new TextEncoder();
      const aad = encoder.encode(JSON.stringify(aadData));

      // Encrypt with AES-GCM and AAD
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
        },
        aesKey,
        data
      );

      const ciphertext = new Uint8Array(ciphertextBuffer);
      const endTime = performance.now();

      // Create copies for return (before zeroization)
      const ivCopy = new Uint8Array(iv);
      const saltCopy = new Uint8Array(salt);

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
            protocolVersion,
          },
        },
        parameters: {
          iv: ivCopy,
          salt: saltCopy,
          contextId,
        },
      };
    } catch (error) {
      throw new CipherLayerError(
        'Encryption failed',
        this.name,
        'encrypt',
        error as Error
      );
    } finally {
      // SECURITY: Zeroize all sensitive buffers before returning or throwing
      Zeroization.zeroizeAll(sharedSecret, salt, iv, contextId);
      aesKey = null; // Clear CryptoKey reference
    }
  }

  /**
   * Decrypt data using DH + AES-GCM
   */
  async decrypt(payload: EncryptedPayload, keys: DHKeys): Promise<Uint8Array> {
    let sharedSecret: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;
    let contextId: Uint8Array | null = null;

    try {
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: need sharedSecret OR (privateKey + publicKey)',
          this.name,
          'decrypt'
        );
      }

      // Validate public key fingerprint if provided
      // Use constant-time comparison to prevent timing attacks
      if (keys.publicKey && keys.expectedPublicKeyFingerprint) {
        const isValid = await KeyAuthentication.verifyFingerprint(
          keys.publicKey,
          keys.expectedPublicKeyFingerprint
        );
        if (!isValid) {
          throw new CipherLayerError(
            'Public key fingerprint mismatch - possible MITM attack',
            this.name,
            'decrypt'
          );
        }
      }

      // Get or derive shared secret
      // Create a copy to avoid zeroizing the original if it's from keys
      if (keys.sharedSecret) {
        sharedSecret = new Uint8Array(keys.sharedSecret);
      } else {
        if (!keys.privateKey || !keys.publicKey) {
          throw new CipherLayerError(
            'Invalid keys: need sharedSecret OR (privateKey + publicKey)',
            this.name,
            'decrypt'
          );
        }
        sharedSecret = await this.deriveSharedSecret(keys.privateKey, keys.publicKey);
      }

      // Extract IV, salt, and context ID
      // Convert to Uint8Array if they're arrays (from JSON serialization)
      let iv: Uint8Array;
      let salt: Uint8Array;
      const storedContextId = payload.parameters.contextId;

      if (payload.parameters.iv instanceof Uint8Array) {
        iv = payload.parameters.iv;
      } else if (Array.isArray(payload.parameters.iv)) {
        iv = new Uint8Array(payload.parameters.iv);
      } else {
        throw new CipherLayerError(
          'Missing or invalid IV in decryption parameters',
          this.name,
          'decrypt'
        );
      }

      if (payload.parameters.salt instanceof Uint8Array) {
        salt = payload.parameters.salt;
      } else if (Array.isArray(payload.parameters.salt)) {
        salt = new Uint8Array(payload.parameters.salt);
      } else {
        throw new CipherLayerError(
          'Missing or invalid salt in decryption parameters',
          this.name,
          'decrypt'
        );
      }

      // Use stored context ID if available
      // Handle both array and Uint8Array formats
      if (storedContextId) {
        if (Array.isArray(storedContextId)) {
          contextId = new Uint8Array(storedContextId);
        } else if (storedContextId instanceof Uint8Array) {
          contextId = storedContextId;
        } else {
          throw new CipherLayerError(
            `Invalid context ID format: expected array or Uint8Array, got ${typeof storedContextId}`,
            this.name,
            'decrypt'
          );
        }
      } else {
        // If contextId is not stored (backward compatibility), we can't decrypt
        // This means the payload was encrypted with an older version
        throw new CipherLayerError(
          'Missing context ID in payload - cannot decrypt (payload may be from older version)',
          this.name,
          'decrypt'
        );
      }

      // Get timestamp from metadata (must match encryption timestamp)
      const timestamp = payload.layerMetadata.timestamp;
      if (!timestamp || timestamp <= 0) {
        throw new CipherLayerError(
          'Missing or invalid timestamp in payload metadata',
          this.name,
          'decrypt'
        );
      }

      // Derive AES key from shared secret with same HKDF info
      // Must use exact same contextId and timestamp as encryption
      aesKey = await this.deriveAESKey(sharedSecret, salt, contextId, timestamp);

      // Reconstruct AAD (must match encryption)
      const protocolVersion = `${this.name}-v${this.version}`;
      const context = 'cascading-cipher-encrypt';
      const aadData = {
        protocol: protocolVersion,
        context,
        timestamp,
        encoding: 'binary',
      };
      const encoder = new TextEncoder();
      const aad = encoder.encode(JSON.stringify(aadData));

      // Decrypt with AES-GCM and AAD validation
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128,
        },
        aesKey,
        payload.ciphertext
      );

      return new Uint8Array(plaintextBuffer);
    } catch (error) {
      // Zeroize sensitive data before throwing
      Zeroization.zeroizeAll(sharedSecret, contextId);
      aesKey = null;

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
       // Check for sensitive data in error message to prevent leakage
      const hasSensitiveData =
        (keys?.privateKey && errorMessage.includes('private')) ||
        (keys?.publicKey && errorMessage.includes('public')) ||
        (keys?.sharedSecret && errorMessage.includes('secret')) ||
        (keys?.expectedPublicKeyFingerprint && errorMessage.includes('fingerprint'));

      if (errorMessage.includes('decryption failed') || errorMessage.includes('OperationError')) {
        throw new CipherLayerError(
          'Decryption failed',
          this.name,
          'decrypt',
          error as Error
        );
      }

      if (hasSensitiveData) {
        throw new CipherLayerError(
          'DH-AES decryption failed',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `DH-AES decryption failed`,
        this.name,
        'decrypt',
        error as Error
      );

    } finally {
      // Always zeroize sensitive data
      Zeroization.zeroizeAll(sharedSecret, contextId);
      aesKey = null;
    }
  }
}
