/**
 * ML-KEM (CRYSTALS-Kyber) Cipher Layer
 *
 * Uses ML-KEM key encapsulation mechanism to derive a shared symmetric key,
 * then encrypts data with AES-GCM using that key.
 * ML-KEM is a NIST PQC standard for quantum-resistant cryptography.
 *
 * SECURITY UPGRADES:
 * - Added zeroization of sensitive buffers
 * - Constant-time key validation (timing attack protection)
 * - Public getter for KEM instance (encapsulation)
 * - Generic error messages (no information leakage)
 */

import { MlKem768 } from "@hpke/ml-kem";
import { CipherLayer, EncryptedPayload, CipherLayerError } from "../types";
import { Zeroization } from "../../utils/zeroization";
import { ConstantTime } from "../../utils/constantTime";

/**
 * XCryptoKey type from @hpke/ml-kem
 * Internal key object type used by the library
 */
export type XCryptoKey = {
  key: Uint8Array;
  type: "public" | "private";
};

/**
 * Keys for ML-KEM encryption
 */
export interface MLKEMKeys {
  /** Public key for encryption (Uint8Array or XCryptoKey) */
  publicKey?: Uint8Array | XCryptoKey;

  /** Private key for decryption (Uint8Array or XCryptoKey) */
  privateKey?: Uint8Array | XCryptoKey;
}

/**
 * MLKEMCipherLayer - ML-KEM-768 + AES-GCM encryption layer
 *
 * Performs ML-KEM key encapsulation to derive a shared symmetric key,
 * then uses AES-GCM for encryption. Provides quantum-resistant security.
 */
export class MLKEMCipherLayer implements CipherLayer {
  readonly name = "ML-KEM-768";
  readonly version = "1.0.0";

  private readonly IV_LENGTH = 12;
  private readonly KEY_LENGTH = 256;

  // ML-KEM-768 key sizes (in bytes)
  private readonly PUBLIC_KEY_SIZE = 1184;
  private readonly PRIVATE_KEY_SIZE = 64;
  private readonly ENCAPSULATED_KEY_SIZE = 1088;
  private readonly SHARED_SECRET_MIN_SIZE = 32;
  private readonly SALT_SIZE = 16;

  // IV Reuse Protection Constants
  private usedIVs: Map<string, { ivSet: Set<string>; lastAccessTime: number }> =
    new Map();
  private readonly MAX_IV_TRACKING = 10000;
  private readonly MAX_GLOBAL_IV_TRACKING = 5000;
  private readonly MAX_IV_GENERATION_ATTEMPTS = 100;
  private readonly IV_TRACKING_EXPIRY_MS = 60 * 60 * 1000;
  private readonly CLEANUP_INTERVAL = 1000;
  private encryptionCount = 0;

  private kem: MlKem768;

  constructor() {
    this.kem = new MlKem768();
  }

  /**
   * Public getter for KEM instance
   * Provides proper encapsulation instead of accessing private property directly
   */
  getKEMInstance(): MlKem768 {
    return this.kem;
  }

  /**
   * Validate ML-KEM keys with constant-time comparison
   *
   * SECURITY: Uses constant-time comparison to prevent timing attacks
   * on key validation operations. Always performs all checks without
   * early returns to avoid timing leaks.
   */
  validateKeys(keys: Partial<MLKEMKeys> | null): boolean {
    try {
      // Always perform all operations to avoid timing leaks
      // Check for null/undefined without early return
      const hasKeys = keys !== null && keys !== undefined;
      
      // Must have either publicKey (for encryption) or privateKey (for decryption)
      // Always check both properties regardless of early matches
      const hasPublicKey = hasKeys && keys.publicKey !== undefined;
      const hasPrivateKey = hasKeys && keys.privateKey !== undefined;
      const isValid = hasPublicKey || hasPrivateKey;

      // Use constant-time comparison without string conversion
      const isValidBuffer = new Uint8Array([isValid ? 1 : 0]);
      const expectedBuffer = new Uint8Array([1]);

      return ConstantTime.constantTimeCompareBuffers(
        isValidBuffer,
        expectedBuffer,
      );
    } catch (error) {
      // Constant-time error handling
      return false;
    }
  }

  /**
   * Get raw bytes from a key (handles both Uint8Array and XCryptoKey)
   *
   * Validates key size according to ML-KEM-768 specification:
   * - Public key: 1184 bytes
   * - Private key: 64 bytes
   * - Encapsulated key: 1088 bytes
   */
  private async getKeyBytes(
    key: Uint8Array | Record<string, unknown>,
  ): Promise<Uint8Array> {
    if (key instanceof Uint8Array) {
      const validSizes = [
        this.PUBLIC_KEY_SIZE,
        this.PRIVATE_KEY_SIZE,
        this.ENCAPSULATED_KEY_SIZE,
      ];
      if (!validSizes.includes(key.length)) {
        throw new CipherLayerError(
          "Invalid ML-KEM key format",
          this.name,
          "encrypt",
        );
      }
      return key;
    }

    // Handle XCryptoKey from @hpke/ml-kem
    if (key && "key" in key && key.key instanceof Uint8Array) {
      const validSizes = [
        this.PUBLIC_KEY_SIZE,
        this.PRIVATE_KEY_SIZE,
        this.ENCAPSULATED_KEY_SIZE,
      ];
      if (!validSizes.includes(key.key.length)) {
        throw new CipherLayerError(
          "Invalid ML-KEM key format",
          this.name,
          "encrypt",
        );
      }
      return key.key;
    }

    // Try to serialize if it's an XCryptoKey
    if (key && typeof key.type === "string") {
      try {
        // @ts-ignore: Library's type defs are incorrect - accepts internal key objects
        const serialized = await this.kem.serializePublicKey(key);
        const bytes = new Uint8Array(serialized);
        const validSizes = [
          this.PUBLIC_KEY_SIZE,
          this.PRIVATE_KEY_SIZE,
          this.ENCAPSULATED_KEY_SIZE,
        ];
        if (!validSizes.includes(bytes.length)) {
          throw new CipherLayerError(
            "Invalid ML-KEM key format",
            this.name,
            "encrypt",
          );
        }
        return bytes;
      } catch (error) {
        try {
          // @ts-ignore: Library's type defs are incorrect - accepts internal key objects
          const serialized = await this.kem.serializePrivateKey(key);
          const bytes = new Uint8Array(serialized);
          const validSizes = [
            this.PUBLIC_KEY_SIZE,
            this.PRIVATE_KEY_SIZE,
            this.ENCAPSULATED_KEY_SIZE,
          ];
          if (!validSizes.includes(bytes.length)) {
            throw new CipherLayerError(
              "Invalid ML-KEM key format",
              this.name,
              "decrypt",
            );
          }
          return bytes;
        } catch {
          throw new CipherLayerError(
            "Invalid key format",
            this.name,
            "encrypt",
          );
        }
      }
    }

    throw new CipherLayerError("Invalid key format", this.name, "encrypt");
  }

  /**
   * Import public key for encryption
   */
  private async importPublicKey(publicKey: Uint8Array | any): Promise<any> {
    if (
      publicKey &&
      typeof publicKey.type === "string" &&
      publicKey.type === "public"
    ) {
      // Already an XCryptoKey
      return publicKey;
    }

    // Convert Uint8Array to XCryptoKey
    const keyBytes = await this.getKeyBytes(publicKey);
    return await this.kem.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      true,
    );
  }

  /**
   * Import private key for decryption
   */
  private async importPrivateKey(privateKey: Uint8Array | any): Promise<any> {
    if (
      privateKey &&
      typeof privateKey.type === "string" &&
      privateKey.type === "private"
    ) {
      // Already an XCryptoKey
      return privateKey;
    }

    // Convert Uint8Array to XCryptoKey
    const keyBytes = await this.getKeyBytes(privateKey);
    return await this.kem.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      false,
    );
  }

  /**
   * Derive AES key from shared secret using HKDF
   *
   * Validates:
   * - Shared secret: >= 32 bytes (minimum for AES-256)
   * - Salt: exactly 16 bytes
   */
  private async deriveAESKey(
    sharedSecret: Uint8Array,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
    // Validate shared secret size
    if (sharedSecret.length < this.SHARED_SECRET_MIN_SIZE) {
      throw new CipherLayerError(
        "Invalid shared secret",
        this.name,
        "encrypt",
      );
    }

    // Validate salt size
    if (salt.length !== this.SALT_SIZE) {
      throw new CipherLayerError(
        "Invalid salt",
        this.name,
        "encrypt",
      );
    }

    // Use first 32 bytes of shared secret (ML-KEM produces 64 bytes, but we only need 32 for AES-256)
    const secret32 = sharedSecret.slice(0, 32);

    // Import shared secret as key material
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      secret32,
      "HKDF",
      false,
      ["deriveKey"],
    );

    // Derive AES-GCM key using HKDF
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        salt: salt.buffer as ArrayBuffer,
        info: new TextEncoder().encode("ML-KEM-768-AES-GCM-Cascading-Cipher"),
        hash: "SHA-256",
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: this.KEY_LENGTH,
      },
      false,
      ["encrypt", "decrypt"],
    );
  }

  /**
   * Get IV tracking key from public key bytes
   * Creates a unique identifier for tracking IVs per public key
   */
  private getIVTrackingKey(publicKeyBytes: Uint8Array): string {
    // Use first 16 bytes of public key as identifier
    // This provides sufficient uniqueness while keeping the key manageable
    const keyPrefix = Array.from(publicKeyBytes)
      .slice(0, 16)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return keyPrefix;
  }

  /**
   * Check if IV has been used before
   */
  private isIVUsed(ivKey: string, iv: Uint8Array): boolean {
    const ivEntry = this.usedIVs.get(ivKey);
    if (!ivEntry) return false;
    // Update last access time
    ivEntry.lastAccessTime = Date.now();
    const ivHex = Array.from(iv)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return ivEntry.ivSet.has(ivHex);
  }

  /**
   * Mark IV as used
   */
  private markIVUsed(ivKey: string, iv: Uint8Array): void {
    // Enforce global limit using LRU eviction (Map maintains insertion order)
    if (
      this.usedIVs.size >= this.MAX_GLOBAL_IV_TRACKING &&
      !this.usedIVs.has(ivKey)
    ) {
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

    const ivHex = Array.from(iv)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    ivEntry.ivSet.add(ivHex);

    // Limit memory usage per key - remove oldest entries if over limit
    // This maintains per-key limit while global limit is handled above
    if (ivEntry.ivSet.size > this.MAX_IV_TRACKING) {
      const entries = Array.from(ivEntry.ivSet);
      const toRemove = entries.length - this.MAX_IV_TRACKING;
      entries.slice(0, toRemove).forEach((e) => ivEntry!.ivSet.delete(e));
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
    keysToDelete.forEach((key) => this.usedIVs.delete(key));
  }

  /**
   * Generate a unique IV with collision detection
   * Prevents IV reuse which could compromise AES-GCM security
   */
  private async generateUniqueIV(
    publicKeyBytes: Uint8Array,
  ): Promise<Uint8Array> {
    const ivKey = this.getIVTrackingKey(publicKeyBytes);
    let attempts = 0;
    let iv: Uint8Array;

    do {
      iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
      attempts++;
      if (attempts > this.MAX_IV_GENERATION_ATTEMPTS) {
        throw new CipherLayerError(
          "Failed to generate unique IV after multiple attempts",
          this.name,
          "encrypt",
        );
      }
    } while (this.isIVUsed(ivKey, iv));

    this.markIVUsed(ivKey, iv);
    return iv;
  }

  /**
   * Encrypt data using ML-KEM + AES-GCM
   */
  async encrypt(data: Uint8Array, keys: MLKEMKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    let sharedSecretBytes: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let salt: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;

    try {
      // Periodically cleanup old IV tracking entries
      this.encryptionCount++;
      if (this.encryptionCount >= this.CLEANUP_INTERVAL) {
        this.cleanupOldIVs();
        this.encryptionCount = 0;
      }

      if (!this.validateKeys(keys)) {
        throw new CipherLayerError("Invalid keys", this.name, "encrypt");
      }

      if (!keys.publicKey) {
        throw new CipherLayerError(
          "Public key is required for encryption",
          this.name,
          "encrypt",
        );
      }

      // Import public key
      const publicKey = await this.importPublicKey(keys.publicKey);

      // Get public key bytes for IV tracking
      const publicKeyBytes = await this.getKeyBytes(keys.publicKey);

      // Perform ML-KEM encapsulation
      const { sharedSecret, enc } = await this.kem.encap({
        recipientPublicKey: publicKey,
      });

      // Convert shared secret to Uint8Array
      sharedSecretBytes = new Uint8Array(sharedSecret);

      // Generate random salt
      salt = crypto.getRandomValues(new Uint8Array(16));

      // Generate unique IV with reuse protection
      iv = await this.generateUniqueIV(publicKeyBytes);

      // Derive AES key from shared secret
      aesKey = await this.deriveAESKey(sharedSecretBytes, salt);

      // Encrypt with AES-GCM
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv.buffer as ArrayBuffer,
        },
        aesKey,
        data.buffer as ArrayBuffer,
      );

      const ciphertext = new Uint8Array(ciphertextBuffer);
      const encapsulated = new Uint8Array(enc);
      const endTime = performance.now();

      // Convert Uint8Arrays to arrays for serialization
      const ivArray = Array.from(iv);
      const saltArray = Array.from(salt);
      const encapsulatedArray = Array.from(encapsulated);

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
            keyEncapsulation: "ML-KEM-768",
            keyDerivation: "HKDF-SHA256",
            encryption: "AES-GCM-256",
          },
        },
        parameters: {
          iv: ivArray,
          salt: saltArray,
          encapsulated: encapsulatedArray,
        },
      };
    } catch (error) {
      if (process.env.NODE_ENV === "development") {
        console.error("[MLKEMCipherLayer] Encryption error:", {
          layer: this.name,
          operation: "encrypt",
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        });
      }

      throw new CipherLayerError(
        "Encryption failed",
        this.name,
        "encrypt",
        error as Error,
      );
    } finally {
      // SECURITY: Zeroize all sensitive buffers before returning or throwing
      Zeroization.zeroizeAll(sharedSecretBytes, iv, salt);
      aesKey = null; // Clear CryptoKey reference
    }
  }

  /**
   * Decrypt data using ML-KEM + AES-GCM
   */
  async decrypt(
    payload: EncryptedPayload,
    keys: MLKEMKeys,
  ): Promise<Uint8Array> {
    let sharedSecretBytes: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;

    try {
      if (!this.validateKeys(keys)) {
        throw new CipherLayerError("Invalid keys", this.name, "decrypt");
      }

      if (!keys.privateKey) {
        throw new CipherLayerError(
          "Private key is required for decryption",
          this.name,
          "decrypt",
        );
      }

      // Extract IV, salt, and encapsulated key
      const { iv, salt, encapsulated } = payload.parameters;
      if (!iv || !salt || !encapsulated) {
        throw new CipherLayerError(
          "Missing decryption parameters",
          this.name,
          "decrypt",
        );
      }

      // Convert arrays to Uint8Arrays if needed
      const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
      const saltBytes =
        salt instanceof Uint8Array ? salt : new Uint8Array(salt);
      const encapsulatedBytes =
        encapsulated instanceof Uint8Array
          ? encapsulated
          : new Uint8Array(encapsulated);

      // Validate IV size
      if (ivBytes.length !== this.IV_LENGTH) {
        throw new CipherLayerError(
          "Invalid decryption parameters",
          this.name,
          "decrypt",
        );
      }

      // Validate salt size
      if (saltBytes.length !== this.SALT_SIZE) {
        throw new CipherLayerError(
          "Invalid decryption parameters",
          this.name,
          "decrypt",
        );
      }

      // Validate encapsulated key size
      if (encapsulatedBytes.length !== this.ENCAPSULATED_KEY_SIZE) {
        throw new CipherLayerError(
          "Invalid decryption parameters",
          this.name,
          "decrypt",
        );
      }

      // Import private key
      const privateKey = await this.importPrivateKey(keys.privateKey);

      // Perform ML-KEM decapsulation
      const sharedSecret = await this.kem.decap({
        recipientKey: privateKey,
        enc: encapsulatedBytes.buffer as ArrayBuffer,
      });

      // Convert shared secret to Uint8Array
      sharedSecretBytes = new Uint8Array(sharedSecret);

      // Validate shared secret size immediately after decapsulation
      if (sharedSecretBytes.length < this.SHARED_SECRET_MIN_SIZE) {
        throw new CipherLayerError(
          "Decryption failed",
          this.name,
          "decrypt",
        );
      }

      // Derive AES key from shared secret
      aesKey = await this.deriveAESKey(sharedSecretBytes, saltBytes);

      // Decrypt with AES-GCM
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBytes.buffer as ArrayBuffer,
        },
        aesKey,
        payload.ciphertext.buffer as ArrayBuffer,
      );

      return new Uint8Array(plaintextBuffer);
    } catch (error) {
      if (process.env.NODE_ENV === "development") {
        console.error("[MLKEMCipherLayer] Decryption error:", {
          layer: this.name,
          operation: "decrypt",
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        });
      }

      // SECURITY: Generic error message to prevent information leakage
      throw new CipherLayerError(
        "Decryption failed",
        this.name,
        "decrypt",
        error as Error,
      );
    } finally {
      // SECURITY: Zeroize all sensitive buffers before returning or throwing
      Zeroization.zeroize(sharedSecretBytes);
      aesKey = null; // Clear CryptoKey reference
    }
  }
}
