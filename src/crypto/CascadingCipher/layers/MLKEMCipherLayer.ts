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
 * Keys for ML-KEM encryption
 */
export interface MLKEMKeys {
  /** Public key for encryption (Uint8Array or XCryptoKey) */
  publicKey?: Uint8Array | any;

  /** Private key for decryption (Uint8Array or XCryptoKey) */
  privateKey?: Uint8Array | any;
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
   * on key validation operations.
   */
  validateKeys(keys: any): boolean {
    try {
      if (!keys) return false;

      // Must have either publicKey (for encryption) or privateKey (for decryption)
      const hasPublicKey = keys.publicKey !== undefined;
      const hasPrivateKey = keys.privateKey !== undefined;
      const isValid = hasPublicKey || hasPrivateKey;

      // Use constant-time comparison for result
      const resultString = String(isValid);
      const expectedString = "true";

      return ConstantTime.constantTimeCompareStrings(
        resultString,
        expectedString,
      );
    } catch (error) {
      // Constant-time error handling
      return false;
    }
  }

  /**
   * Get raw bytes from a key (handles both Uint8Array and XCryptoKey)
   */
  private async getKeyBytes(key: Uint8Array | any): Promise<Uint8Array> {
    if (key instanceof Uint8Array) {
      return key;
    }

    // Handle XCryptoKey from @hpke/ml-kem
    if (key && key.key instanceof Uint8Array) {
      return key.key;
    }

    // Try to serialize if it's an XCryptoKey
    if (key && typeof key.type === "string") {
      try {
        const serialized = await this.kem.serializePublicKey(key);
        return new Uint8Array(serialized);
      } catch {
        try {
          const serialized = await this.kem.serializePrivateKey(key);
          return new Uint8Array(serialized);
        } catch {
          throw new Error("Invalid key format");
        }
      }
    }

    throw new Error("Invalid key format");
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
    return await this.kem.importKey("raw", keyBytes, true);
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
    return await this.kem.importKey("raw", keyBytes, false);
  }

  /**
   * Derive AES key from shared secret using HKDF
   */
  private async deriveAESKey(
    sharedSecret: Uint8Array,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
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
        salt,
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
   * Encrypt data using ML-KEM + AES-GCM
   */
  async encrypt(data: Uint8Array, keys: MLKEMKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    let sharedSecretBytes: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let salt: Uint8Array | null = null;
    let aesKey: CryptoKey | null = null;

    try {
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

      // Perform ML-KEM encapsulation
      const { sharedSecret, enc } = await this.kem.encap({
        recipientPublicKey: publicKey,
      });

      // Convert shared secret to Uint8Array
      sharedSecretBytes = new Uint8Array(sharedSecret);

      // Generate random salt and IV
      salt = crypto.getRandomValues(new Uint8Array(16));
      iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

      // Derive AES key from shared secret
      aesKey = await this.deriveAESKey(sharedSecretBytes, salt);

      // Encrypt with AES-GCM
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
        },
        aesKey,
        data,
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

      // Import private key
      const privateKey = await this.importPrivateKey(keys.privateKey);

      // Perform ML-KEM decapsulation
      const sharedSecret = await this.kem.decap({
        recipientKey: privateKey,
        enc: encapsulatedBytes,
      });

      // Convert shared secret to Uint8Array
      sharedSecretBytes = new Uint8Array(sharedSecret);

      // Derive AES key from shared secret
      aesKey = await this.deriveAESKey(sharedSecretBytes, saltBytes);

      // Decrypt with AES-GCM
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBytes,
        },
        aesKey,
        payload.ciphertext,
      );

      return new Uint8Array(plaintextBuffer);
    } catch (error) {
      // SECURITY: Generic error message to prevent information leakage
      if (
        error.message?.includes("decryption failed") ||
        error.message?.includes("DecapError")
      ) {
        throw new CipherLayerError(
          "Decryption failed",
          this.name,
          "decrypt",
          error as Error,
        );
      }

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
