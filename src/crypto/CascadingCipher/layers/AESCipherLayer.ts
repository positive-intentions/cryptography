/**
 * AES-GCM Cipher Layer
 *
 * A simple, password-based AES-GCM encryption layer demonstrating
 * the extensibility of the cascading cipher system.
 *
 * Security Features:
 * - Scrypt key derivation (GPU/ASIC resistant)
 * - IV reuse protection
 * - Protocol version in AAD
 * - Zeroization of sensitive buffers
 * - Exception handling with buffer cleanup
 */

import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';
import { Zeroization } from '../../utils/zeroization';

/**
 * Keys for AES encryption
 */
export interface AESKeys {
  password: string;
}

/**
 * AESCipherLayer - Password-based AES-GCM-256 encryption
 *
 * Uses Scrypt for key derivation (GPU/ASIC resistant) and AES-GCM for authenticated encryption.
 * Includes security features: IV reuse protection, protocol version in AAD, and zeroization.
 */
export class AESCipherLayer implements CipherLayer {
  readonly name = 'AES-GCM-256';
  readonly version = '2.0.0';

  // Scrypt parameters (memory-hard, GPU-resistant)
  private readonly SCRYPT_N = 32768; // CPU/memory cost parameter
  private readonly SCRYPT_R = 8;     // Block size parameter
  private readonly SCRYPT_P = 1;     // Parallelization parameter
  private readonly SALT_LENGTH = 16;
  private readonly IV_LENGTH = 12;
  private readonly KEY_LENGTH = 256;

  // Track used IVs per key derivation (keyed by salt+password hash)
  // Structure: Map<ivKey, { ivSet: Set<string>, lastAccessTime: number }>
  private usedIVs: Map<string, { ivSet: Set<string>; lastAccessTime: number }> = new Map();
  // Per-key limit: Maximum IVs to track per password+salt combination
  // This prevents IV reuse while limiting memory per key
  // 10000 is chosen as a balance between security (preventing reuse) and memory usage
  private readonly MAX_IV_TRACKING = 10000;
  // Global limit: Maximum number of password+salt combinations to track
  // This prevents unbounded Map growth in long-running applications with many users
  // 5000 is chosen to limit memory while still supporting many concurrent users
  private readonly MAX_GLOBAL_IV_TRACKING = 5000;
  // Maximum attempts to generate a unique IV before giving up
  // Prevents infinite loops if IV space is exhausted
  // 100 attempts is sufficient given 96-bit IV space (2^96 possible IVs)
  private readonly MAX_IV_GENERATION_ATTEMPTS = 100;
  // Time-based expiration: Remove IV tracking entries older than 1 hour
  private readonly IV_TRACKING_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
  // Cleanup interval: Run cleanup every 1000 encryptions
  private readonly CLEANUP_INTERVAL = 1000;
  private encryptionCount = 0;

  // Cache scrypt function to avoid repeated imports
  private static scryptCache: any = null;
  private static scryptCachePromise: Promise<any> | null = null;

  /**
   * Validate that keys contain required fields
   */
  validateKeys(keys: any): boolean {
    return keys !== null && keys !== undefined && typeof keys.password === 'string';
  }

  /**
   * Get IV tracking key from salt and password
   */
  private getIVKey(salt: Uint8Array, password: string): string {
    // Create a key from salt + password hash for IV tracking
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    // Use first 16 chars of password hash as identifier
    const passwordHash = Array.from(new TextEncoder().encode(password))
      .slice(0, 16)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return `${saltHex}-${passwordHash}`;
  }

  /**
   * Check if IV has been used before
   */
  private isIVUsed(ivKey: string, iv: Uint8Array): boolean {
    const ivEntry = this.usedIVs.get(ivKey);
    if (!ivEntry) return false;
    // Update last access time
    ivEntry.lastAccessTime = Date.now();
    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
    return ivEntry.ivSet.has(ivHex);
  }

  /**
   * Mark IV as used
   */
  private markIVUsed(ivKey: string, iv: Uint8Array): void {
    // Enforce global limit using LRU eviction (Map maintains insertion order)
    if (this.usedIVs.size >= this.MAX_GLOBAL_IV_TRACKING && !this.usedIVs.has(ivKey)) {
      // Remove oldest entry (first in Map) to make room for new entry
      const firstKey = this.usedIVs.keys().next().value;
      this.usedIVs.delete(firstKey);
    }

    let ivEntry = this.usedIVs.get(ivKey);
    if (!ivEntry) {
      ivEntry = {
        ivSet: new Set(),
        lastAccessTime: Date.now(),
      };
      this.usedIVs.set(ivKey, ivEntry);
    } else {
      // Update last access time
      ivEntry.lastAccessTime = Date.now();
    }

    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
    ivEntry.ivSet.add(ivHex);

    // Limit memory usage per key - remove oldest entries if over limit
    // This maintains per-key limit while global limit is handled above
    if (ivEntry.ivSet.size > this.MAX_IV_TRACKING) {
      const entries = Array.from(ivEntry.ivSet);
      const toRemove = entries.length - this.MAX_IV_TRACKING;
      entries.slice(0, toRemove).forEach(e => ivEntry!.ivSet.delete(e));
    }
  }

  /**
   * Clean up old IV tracking entries based on time-based expiration
   * Removes entries that haven't been accessed in the last hour
   */
  private cleanupOldIVs(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.usedIVs.entries()) {
      if (now - entry.lastAccessTime > this.IV_TRACKING_EXPIRY_MS) {
        keysToDelete.push(key);
      }
    }

    // Delete expired entries
    keysToDelete.forEach(key => this.usedIVs.delete(key));
  }

  /**
   * Lazy-load scrypt function (handles ES module import)
   * Uses caching to avoid repeated imports
   * 
   * Browser-compatible: Uses @noble/hashes/scrypt.js which is a pure JavaScript
   * implementation that works in browsers. The dynamic import() syntax is supported
   * in all modern browsers and bundlers (webpack, vite, etc.).
   */
  private async getScryptFunction(): Promise<any> {
    // Return cached function if available
    if (AESCipherLayer.scryptCache) {
      return AESCipherLayer.scryptCache;
    }

    // Wait for ongoing import if in progress
    if (AESCipherLayer.scryptCachePromise) {
      return await AESCipherLayer.scryptCachePromise;
    }

    // Start new import
    AESCipherLayer.scryptCachePromise = (async () => {
      try {
        // Dynamic import for ES module - works in browsers and Node.js
        // @noble/hashes/scrypt.js is browser-compatible pure JavaScript
        const scryptModule = await import('@noble/hashes/scrypt.js');
        const scryptFn = scryptModule.scrypt || (scryptModule as any).default;
        AESCipherLayer.scryptCache = scryptFn;
        AESCipherLayer.scryptCachePromise = null;
        return scryptFn;
      } catch (error) {
        AESCipherLayer.scryptCachePromise = null;
        // Re-throw with better error message
        throw new Error(`Failed to load scrypt module: ${error instanceof Error ? error.message : String(error)}`);
      }
    })();

    return await AESCipherLayer.scryptCachePromise;
  }

  /**
   * Derive AES key from password using Scrypt
   */
  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    try {
      // Use Scrypt for key derivation (GPU/ASIC resistant)
      const scrypt = await this.getScryptFunction();
      const keyMaterial = scrypt(passwordBytes, salt, {
        N: this.SCRYPT_N,
        r: this.SCRYPT_R,
        p: this.SCRYPT_P,
        dkLen: 32, // 32 bytes = 256 bits for AES-256
      });

      // Import the derived key material as a CryptoKey
      return await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        {
          name: 'AES-GCM',
        },
        false,
        ['encrypt', 'decrypt']
      );
    } finally {
      // Zeroize password buffer
      Zeroization.zeroize(passwordBytes);
    }
  }

  /**
   * Encrypt data using AES-GCM
   */
  async encrypt(data: Uint8Array, keys: AESKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();
    let salt: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let passwordBuffer: Uint8Array | null = null;
    let key: CryptoKey | null = null;

    try {
      // Periodically cleanup old IV tracking entries
      this.encryptionCount++;
      if (this.encryptionCount >= this.CLEANUP_INTERVAL) {
        this.cleanupOldIVs();
        this.encryptionCount = 0;
      }

      // Validate keys
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError(
          'Invalid keys: password is required',
          this.name,
          'encrypt'
        );
      }

      // Generate random salt
      salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));

      // Generate IV with reuse protection
      const ivKey = this.getIVKey(salt, keys.password);
      let attempts = 0;
      do {
        iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
        attempts++;
        if (attempts > this.MAX_IV_GENERATION_ATTEMPTS) {
          throw new CipherLayerError(
            'Failed to generate unique IV after multiple attempts',
            this.name,
            'encrypt'
          );
        }
      } while (this.isIVUsed(ivKey, iv));

      this.markIVUsed(ivKey, iv);

      // Store password temporarily for zeroization
      const encoder = new TextEncoder();
      passwordBuffer = encoder.encode(keys.password);

      // Derive encryption key from password using Scrypt
      key = await this.deriveKey(keys.password, salt);

      // Create AAD with protocol version and context
      const protocolVersion = `${this.name}-v${this.version}`;
      const timestamp = Date.now();
      const context = 'cascading-cipher-encrypt';
      const aadData = {
        protocol: protocolVersion,
        context,
        timestamp,
        encoding: 'binary',
      };
      const aad = encoder.encode(JSON.stringify(aadData));

      // Encrypt data with AAD
      // Create a new ArrayBuffer from IV to satisfy TypeScript's strict BufferSource type requirement
      const ivArrayBuffer = new ArrayBuffer(iv.length);
      new Uint8Array(ivArrayBuffer).set(iv);
      const ivBuffer = new Uint8Array(ivArrayBuffer) as unknown as BufferSource;
      const dataBuffer = data as unknown as BufferSource;
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: ivBuffer,
          additionalData: aad,
          tagLength: 128,
        },
        key,
        dataBuffer
      );

      const ciphertext = new Uint8Array(ciphertextBuffer);
      const endTime = performance.now();

      // Create copies of salt and IV for return (before zeroization)
      const ivCopy = new Uint8Array(iv);
      const saltCopy = new Uint8Array(salt);

      return {
        ciphertext,
        layerMetadata: {
          algorithm: this.name,
          version: this.version,
          timestamp,
          inputSize: data.length,
          outputSize: ciphertext.length,
          processingTime: endTime - startTime,
          metadata: {
            keyDerivation: 'Scrypt',
            scryptN: this.SCRYPT_N,
            scryptR: this.SCRYPT_R,
            scryptP: this.SCRYPT_P,
          },
        },
        parameters: {
          iv: ivCopy,
          salt: saltCopy,
        },
      };
    } catch (error) {
      // Zeroize sensitive data before throwing
      Zeroization.zeroizeAll(salt, iv, passwordBuffer);
      key = null;

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes(keys?.password || '')) {
        throw new CipherLayerError(
          'AES encryption failed',
          this.name,
          'encrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `AES encryption failed: ${errorMessage}`,
        this.name,
        'encrypt',
        error as Error
      );
    } finally {
      // Always zeroize sensitive data
      Zeroization.zeroizeAll(salt, iv, passwordBuffer);
      key = null;
    }
  }

  /**
   * Decrypt data using AES-GCM
   */
  async decrypt(payload: EncryptedPayload, keys: AESKeys): Promise<Uint8Array> {
    let passwordBuffer: Uint8Array | null = null;
    let key: CryptoKey | null = null;

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
      // Handle case where they might be arrays after JSON serialization
      let ivBytes: Uint8Array;
      let saltBytes: Uint8Array;
      
      if (payload.parameters.iv instanceof Uint8Array) {
        ivBytes = payload.parameters.iv;
      } else if (Array.isArray(payload.parameters.iv)) {
        ivBytes = new Uint8Array(payload.parameters.iv);
      } else if (payload.parameters.iv instanceof ArrayBuffer) {
        ivBytes = new Uint8Array(payload.parameters.iv);
      } else {
        throw new CipherLayerError(
          'Invalid IV format: expected Uint8Array, array, or ArrayBuffer',
          this.name,
          'decrypt'
        );
      }

      if (payload.parameters.salt instanceof Uint8Array) {
        saltBytes = payload.parameters.salt;
      } else if (Array.isArray(payload.parameters.salt)) {
        saltBytes = new Uint8Array(payload.parameters.salt);
      } else if (payload.parameters.salt instanceof ArrayBuffer) {
        saltBytes = new Uint8Array(payload.parameters.salt);
      } else {
        throw new CipherLayerError(
          'Invalid salt format: expected Uint8Array, array, or ArrayBuffer',
          this.name,
          'decrypt'
        );
      }

      if (!ivBytes || !saltBytes) {
        throw new CipherLayerError(
          'Missing decryption parameters (IV or salt)',
          this.name,
          'decrypt'
        );
      }

      // Store password temporarily for zeroization
      const encoder = new TextEncoder();
      passwordBuffer = encoder.encode(keys.password);

      // Derive decryption key from password using Scrypt
      key = await this.deriveKey(keys.password, saltBytes);

      // Reconstruct AAD (must match encryption)
      const protocolVersion = `${this.name}-v${this.version}`;
      const context = 'cascading-cipher-encrypt';
      const timestamp = payload.layerMetadata.timestamp;
      const aadData = {
        protocol: protocolVersion,
        context,
        timestamp,
        encoding: 'binary',
      };
      const aad = encoder.encode(JSON.stringify(aadData));

      // Decrypt data with AAD validation
      // Create a new ArrayBuffer from IV to satisfy TypeScript's strict BufferSource type requirement
      const ivArrayBuffer = new ArrayBuffer(ivBytes.length);
      new Uint8Array(ivArrayBuffer).set(ivBytes);
      const ivBuffer = new Uint8Array(ivArrayBuffer) as unknown as BufferSource;
      const ciphertextBuffer = payload.ciphertext as unknown as BufferSource;
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBuffer,
          additionalData: aad,
          tagLength: 128,
        },
        key,
        ciphertextBuffer
      );
      
      const plaintext = new Uint8Array(plaintextBuffer);

      return plaintext;
    } catch (error) {
      // Zeroize sensitive data before throwing
      Zeroization.zeroizeAll(passwordBuffer);
      key = null;

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes(keys?.password || '')) {
        throw new CipherLayerError(
          'AES decryption failed: wrong password or corrupted data',
          this.name,
          'decrypt',
          error as Error
        );
      }

      // Provide helpful error messages
      if (errorMessage.includes('decryption failed') || errorMessage.includes('OperationError')) {
        throw new CipherLayerError(
          'AES decryption failed: wrong password or corrupted data',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `AES decryption failed: ${errorMessage}`,
        this.name,
        'decrypt',
        error as Error
      );
    } finally {
      // Always zeroize sensitive data
      Zeroization.zeroizeAll(passwordBuffer);
      key = null;
    }
  }
}
