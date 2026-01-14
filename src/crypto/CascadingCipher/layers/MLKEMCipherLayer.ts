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
 * Keys for ML-KEM encryption/decryption
 *
 * @interface MLKEMKeys
 * @property {Uint8Array | XCryptoKey} [publicKey] - Public key for encryption (1184 bytes as Uint8Array or XCryptoKey object)
 * @property {Uint8Array | XCryptoKey} [privateKey] - Private key for decryption (64 bytes as Uint8Array or XCryptoKey object)
 *
 * @example
 * ```typescript
 * // Using Uint8Array keys
 * const keys: MLKEMKeys = {
 *   publicKey: new Uint8Array(1184), // Public key bytes
 *   privateKey: new Uint8Array(64)   // Private key bytes
 * };
 *
 * // Using XCryptoKey objects (from @hpke/ml-kem)
 * const kem = new MlKem768();
 * const keyPair = await kem.generateKeyPair();
 * const keys: MLKEMKeys = {
 *   publicKey: keyPair.publicKey,
 *   privateKey: keyPair.privateKey
 * };
 * ```
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
  
  // Input size limits to prevent DoS attacks
  private readonly MAX_PLAINTEXT_SIZE = 10 * 1024 * 1024; // 10MB maximum

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
  private readonly CLEANUP_INTERVAL = 100; // Reduced from 1000 to prevent memory growth
  private readonly CLEANUP_TIME_INTERVAL_MS = 60000; // 1 minute time-based cleanup
  private encryptionCount = 0;
  private lastCleanupTime = Date.now();

  private kem: MlKem768;

  constructor() {
    this.kem = new MlKem768();
  }

  /**
   * Gets the underlying ML-KEM-768 instance
   *
   * Provides proper encapsulation instead of accessing private property directly.
   * This method allows external code to interact with the ML-KEM instance for
   * operations like key generation while maintaining encapsulation.
   *
   * @returns {MlKem768} The ML-KEM-768 instance used by this cipher layer
   *
   * @example
   * ```typescript
   * const layer = new MLKEMCipherLayer();
   * const kem = layer.getKEMInstance();
   * const keyPair = await kem.generateKeyPair();
   * ```
   */
  getKEMInstance(): MlKem768 {
    return this.kem;
  }

  /**
   * Validates ML-KEM keys with constant-time comparison
   *
   * Checks if the provided keys object contains either a public key (for encryption)
   * or a private key (for decryption). Uses constant-time comparison to prevent
   * timing attacks on key validation operations.
   *
   * **SECURITY:** Always performs all checks without early returns to avoid timing leaks.
   * Returns false for any invalid input (null, undefined, or missing both keys).
   *
   * @param {Partial<MLKEMKeys> | null} keys - Keys object to validate, may be null or undefined
   * @returns {boolean} True if keys are valid (contains publicKey or privateKey), false otherwise
   *
   * @throws Never throws - always returns boolean to prevent timing leaks
   *
   * @example
   * ```typescript
   * const layer = new MLKEMCipherLayer();
   *
   * // Valid - has public key
   * const isValid1 = layer.validateKeys({ publicKey: publicKeyBytes });
   *
   * // Valid - has private key
   * const isValid2 = layer.validateKeys({ privateKey: privateKeyBytes });
   *
   * // Invalid - missing both keys
   * const isValid3 = layer.validateKeys({});
   *
   * // Invalid - null input
   * const isValid4 = layer.validateKeys(null);
   * ```
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
    key: Uint8Array | XCryptoKey,
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

    // Try to serialize if it's an XCryptoKey with type property
    if (key && typeof key.type === "string") {
      try {
        // @ts-ignore: Library's type defs are incorrect - accepts internal key objects
        const serialized = await this.kem.serializePublicKey(key as XCryptoKey);
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
          const serialized = await this.kem.serializePrivateKey(key as XCryptoKey);
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
  private async importPublicKey(publicKey: Uint8Array | XCryptoKey): Promise<XCryptoKey> {
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
  private async importPrivateKey(privateKey: Uint8Array | XCryptoKey): Promise<XCryptoKey> {
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
   * Encrypts data using ML-KEM-768 key encapsulation + AES-GCM-256
   *
   * Performs ML-KEM key encapsulation to derive a shared secret, then uses AES-GCM
   * for authenticated encryption of plaintext. Provides quantum-resistant security
   * suitable for long-term data confidentiality.
   *
   * **Process:**
   * 1. Validates encryption keys (requires publicKey)
   * 2. Performs ML-KEM encapsulation to derive shared secret
   * 3. Generates random salt (16 bytes) and unique IV (12 bytes)
   * 4. Derives AES-256-GCM key using HKDF-SHA256
   * 5. Encrypts plaintext with AES-GCM
   * 6. Returns ciphertext with encapsulated key and metadata
   *
 * **Security Features:**
 * - Input size limits (10MB maximum) to prevent DoS attacks
 * - IV reuse protection (tracks used IVs per public key)
 * - Automatic zeroization of sensitive buffers
 * - Constant-time key validation
 * - Generic error messages (no information leakage)
   *
   * @param {Uint8Array} data - Plaintext to encrypt (maximum 10MB)
   * @param {MLKEMKeys} keys - Encryption keys, must contain publicKey
   * @param {Uint8Array | XCryptoKey} keys.publicKey - ML-KEM public key (1184 bytes as Uint8Array or XCryptoKey)
   *
   * @returns {Promise<EncryptedPayload>} Encrypted payload containing:
   *   - `ciphertext`: Encrypted data (Uint8Array)
   *   - `parameters`: Encryption parameters (iv, salt, encapsulated key)
   *   - `layerMetadata`: Algorithm info, timestamps, and performance metrics
   *
 * @throws {CipherLayerError} If encryption fails, keys are invalid, or publicKey is missing
 * @throws {CipherLayerError} If input size exceeds maximum allowed (10MB)
 * @throws {CipherLayerError} If IV generation fails after multiple attempts
 * @throws {CipherLayerError} If key format is invalid (wrong size)
   *
   * @example
   * ```typescript
   * const layer = new MLKEMCipherLayer();
   * const kem = new MlKem768();
   * const keyPair = await kem.generateKeyPair();
   *
   * const plaintext = new TextEncoder().encode("Hello, World!");
   * const encrypted = await layer.encrypt(plaintext, {
   *   publicKey: keyPair.publicKey
   * });
   *
   * // encrypted.ciphertext contains encrypted data
   * // encrypted.parameters.encapsulated contains ML-KEM encapsulated key
   * // encrypted.parameters.iv and encrypted.parameters.salt are included
   * ```
   */
  async encrypt(data: Uint8Array, keys: MLKEMKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    let sharedSecretBytes: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let salt: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;

    try {
      // SECURITY: Validate input size to prevent DoS attacks
      if (data.length > this.MAX_PLAINTEXT_SIZE) {
        throw new CipherLayerError(
          "Input size exceeds maximum allowed",
          this.name,
          "encrypt",
        );
      }

      // Periodically cleanup old IV tracking entries (count-based and time-based)
      const now = Date.now();
      this.encryptionCount++;
      if (
        this.encryptionCount >= this.CLEANUP_INTERVAL ||
        now - this.lastCleanupTime > this.CLEANUP_TIME_INTERVAL_MS
      ) {
        this.cleanupOldIVs();
        this.encryptionCount = 0;
        this.lastCleanupTime = now;
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
      // SECURITY: Never log errors in production - use generic error messages only
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
   * Decrypts data using ML-KEM-768 key decapsulation + AES-GCM-256
   *
   * Performs ML-KEM key decapsulation to recover the shared secret, then uses AES-GCM
   * for authenticated decryption of ciphertext. Validates all parameters before decryption.
   *
   * **Process:**
   * 1. Validates decryption keys (requires privateKey)
   * 2. Extracts and validates IV (12 bytes), salt (16 bytes), and encapsulated key (1088 bytes)
   * 3. Performs ML-KEM decapsulation to recover shared secret
   * 4. Derives AES-256-GCM key using HKDF-SHA256
   * 5. Decrypts ciphertext with AES-GCM
   * 6. Returns plaintext
   *
   * **Security Features:**
   * - Parameter validation (IV, salt, encapsulated key sizes)
   * - Automatic zeroization of sensitive buffers
   * - Constant-time key validation
   * - Generic error messages (no information leakage)
   *
   * @param {EncryptedPayload} payload - Encrypted payload from encrypt()
   * @param {Uint8Array} payload.ciphertext - Encrypted data
   * @param {object} payload.parameters - Encryption parameters
   * @param {number[] | Uint8Array} payload.parameters.iv - Initialization vector (12 bytes)
   * @param {number[] | Uint8Array} payload.parameters.salt - Salt for key derivation (16 bytes)
   * @param {number[] | Uint8Array} payload.parameters.encapsulated - ML-KEM encapsulated key (1088 bytes)
   * @param {MLKEMKeys} keys - Decryption keys, must contain privateKey
   * @param {Uint8Array | XCryptoKey} keys.privateKey - ML-KEM private key (64 bytes as Uint8Array or XCryptoKey)
   *
   * @returns {Promise<Uint8Array>} Decrypted plaintext
   *
   * @throws {CipherLayerError} If decryption fails, keys are invalid, or privateKey is missing
   * @throws {CipherLayerError} If payload parameters are missing or invalid
   * @throws {CipherLayerError} If IV size is not 12 bytes
   * @throws {CipherLayerError} If salt size is not 16 bytes
   * @throws {CipherLayerError} If encapsulated key size is not 1088 bytes
   * @throws {CipherLayerError} If shared secret size is invalid after decapsulation
   * @throws {CipherLayerError} If AES-GCM authentication fails (tampered ciphertext)
   *
   * @example
   * ```typescript
   * const layer = new MLKEMCipherLayer();
   * const kem = new MlKem768();
   * const keyPair = await kem.generateKeyPair();
   *
   * // Encrypt
   * const plaintext = new TextEncoder().encode("Hello, World!");
   * const encrypted = await layer.encrypt(plaintext, {
   *   publicKey: keyPair.publicKey
   * });
   *
   * // Decrypt
   * const decrypted = await layer.decrypt(encrypted, {
   *   privateKey: keyPair.privateKey
   * });
   *
   * // decrypted should equal plaintext
   * const text = new TextDecoder().decode(decrypted);
   * ```
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
      // SECURITY: Never log errors in production - use generic error messages only
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
