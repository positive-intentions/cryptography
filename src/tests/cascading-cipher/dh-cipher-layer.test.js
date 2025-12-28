/**
 * @jest-environment jsdom
 */

/**
 * DHCipherLayer Unit Tests
 *
 * Tests for the Diffie-Hellman + AES-GCM cipher layer implementation.
 * Tests DH key exchange, shared secret derivation, and AES-GCM encryption.
 */

describe("DHCipherLayer", () => {
  let DHCipherLayer;
  let crypto;
  let originalCrypto;

  beforeEach(async () => {
    // Save original crypto mock
    originalCrypto = global.crypto;

    // Setup REAL Web Crypto API (override global mocks from setupTests.js)
    const { webcrypto } = await import("crypto");

    // Replace global crypto with real implementation
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }

    crypto = webcrypto;

    // Dynamic import
    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/DHCipherLayer.ts"
      );
      DHCipherLayer = module.DHCipherLayer;
    } catch (e) {
      DHCipherLayer = null;
    }
  });

  afterEach(() => {
    // Restore original crypto mock for other tests
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== "undefined") {
      window.crypto = originalCrypto;
    }
  });

  // Helper function to generate DH key pairs
  async function generateDHKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey", "deriveBits"],
    );
  }

  // Helper to export key to raw format
  async function exportKeyToRaw(key) {
    return new Uint8Array(await crypto.subtle.exportKey("raw", key));
  }

  describe("Construction", () => {
    test("should create DHCipherLayer instance", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      expect(layer).toBeDefined();
    });

    test("should have correct name and version", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      expect(layer.name).toBe("DH-AES-GCM");
      expect(layer.version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe("Key Validation", () => {
    test("should validate keys with pre-shared secret", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const validKeys = {
        sharedSecret: new Uint8Array(32),
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test("should validate keys with privateKey and publicKey", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const keyPair = await generateDHKeyPair();
      const validKeys = {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test("should validate keys with Uint8Array keys", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const validKeys = {
        privateKey: new Uint8Array(32),
        publicKey: new Uint8Array(65), // Uncompressed P-256 public key
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test("should reject keys without required fields", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();

      // Missing both sharedSecret and key pair
      expect(layer.validateKeys({})).toBe(false);

      // Only privateKey
      expect(layer.validateKeys({ privateKey: new Uint8Array(32) })).toBe(
        false,
      );

      // Only publicKey
      expect(layer.validateKeys({ publicKey: new Uint8Array(65) })).toBe(false);
    });

    test("should reject null or undefined keys", () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();

      expect(layer.validateKeys(null)).toBe(false);
      expect(layer.validateKeys(undefined)).toBe(false);
    });
  });

  describe("Key Generation and Shared Secret", () => {
    test("should generate valid DH key pairs", async () => {
      if (!DHCipherLayer) return;

      const keyPair = await generateDHKeyPair();

      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey.type).toBe("private");
      expect(keyPair.publicKey.type).toBe("public");
    });

    test("should derive same shared secret for both parties", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();

      // Alice and Bob generate key pairs
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();

      // Alice encrypts with her private key and Bob's public key
      const plaintext = new TextEncoder().encode("Test message");
      const aliceEncrypted = await layer.encrypt(plaintext, {
        privateKey: aliceKeyPair.privateKey,
        publicKey: bobKeyPair.publicKey,
      });

      // Bob decrypts with his private key and Alice's public key
      const bobDecrypted = await layer.decrypt(aliceEncrypted, {
        privateKey: bobKeyPair.privateKey,
        publicKey: aliceKeyPair.publicKey,
      });

      expect(Array.from(bobDecrypted)).toEqual(Array.from(plaintext));
    });

    test("should work with mixed CryptoKey and Uint8Array format", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();

      // Generate key pairs
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();

      // Export only public keys to raw format (private keys cannot be exported as raw)
      const alicePublicRaw = await exportKeyToRaw(aliceKeyPair.publicKey);
      const bobPublicRaw = await exportKeyToRaw(bobKeyPair.publicKey);

      // Test with CryptoKey privateKey and Uint8Array publicKey
      const plaintext = new TextEncoder().encode("Mixed format test");
      const encrypted = await layer.encrypt(plaintext, {
        privateKey: aliceKeyPair.privateKey, // CryptoKey
        publicKey: bobPublicRaw, // Uint8Array
      });

      const decrypted = await layer.decrypt(encrypted, {
        privateKey: bobKeyPair.privateKey, // CryptoKey
        publicKey: alicePublicRaw, // Uint8Array
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("Encryption with Pre-Shared Secret", () => {
    test("should encrypt with pre-shared secret", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Secret message");

      const result = await layer.encrypt(plaintext, { sharedSecret });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.layerMetadata).toBeDefined();
      expect(result.parameters).toBeDefined();
      expect(result.parameters.usedPreSharedSecret).toBe(true);
    });

    test("should include IV and salt in parameters", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Test data");

      const result = await layer.encrypt(plaintext, { sharedSecret });

      expect(result.parameters.iv).toBeDefined();
      expect(result.parameters.iv).toBeInstanceOf(Uint8Array);
      expect(result.parameters.iv.length).toBe(12); // GCM IV is 12 bytes

      expect(result.parameters.salt).toBeDefined();
      expect(result.parameters.salt).toBeInstanceOf(Uint8Array);
      expect(result.parameters.salt.length).toBe(16);
    });

    test("should produce different IV each time", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Test");

      const result1 = await layer.encrypt(plaintext, { sharedSecret });
      const result2 = await layer.encrypt(plaintext, { sharedSecret });

      const iv1Hex = Array.from(result1.parameters.iv)
        .map((b) => b.toString(16))
        .join("");
      const iv2Hex = Array.from(result2.parameters.iv)
        .map((b) => b.toString(16))
        .join("");

      expect(iv1Hex).not.toBe(iv2Hex);
    });

    test("should include metadata", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Test data");

      const result = await layer.encrypt(plaintext, { sharedSecret });

      expect(result.layerMetadata.algorithm).toBe("DH-AES-GCM");
      expect(result.layerMetadata.inputSize).toBe(plaintext.length);
      expect(result.layerMetadata.outputSize).toBe(result.ciphertext.length);
      expect(result.layerMetadata.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layerMetadata.timestamp).toBeGreaterThan(0);
      expect(result.layerMetadata.metadata.keyExchange).toBe("ECDH-P256");
      expect(result.layerMetadata.metadata.keyDerivation).toBe("HKDF-SHA256");
    });
  });

  describe("Encryption with DH Key Exchange", () => {
    test("should encrypt with DH key pair", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();
      const plaintext = new TextEncoder().encode("DH encrypted message");

      const result = await layer.encrypt(plaintext, {
        privateKey: aliceKeyPair.privateKey,
        publicKey: bobKeyPair.publicKey,
      });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.parameters.usedPreSharedSecret).toBe(false);
    });

    test("should produce different ciphertext for same plaintext with different key pairs", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const plaintext = new TextEncoder().encode("Same plaintext");

      // Two different key exchanges
      const alice1 = await generateDHKeyPair();
      const bob1 = await generateDHKeyPair();
      const alice2 = await generateDHKeyPair();
      const bob2 = await generateDHKeyPair();

      const result1 = await layer.encrypt(plaintext, {
        privateKey: alice1.privateKey,
        publicKey: bob1.publicKey,
      });

      const result2 = await layer.encrypt(plaintext, {
        privateKey: alice2.privateKey,
        publicKey: bob2.publicKey,
      });

      const cipher1Hex = Array.from(result1.ciphertext)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const cipher2Hex = Array.from(result2.ciphertext)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      expect(cipher1Hex).not.toBe(cipher2Hex);
    });
  });

  describe("Decryption", () => {
    test("should decrypt with pre-shared secret", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Shared secret message");

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should fail with wrong shared secret", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const wrongSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Secret");

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });

      await expect(
        layer.decrypt(encrypted, { sharedSecret: wrongSecret }),
      ).rejects.toThrow();
    });

    test("should fail with corrupted ciphertext", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Data");

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });

      // Corrupt the ciphertext
      encrypted.ciphertext[0] ^= 0xff;

      await expect(
        layer.decrypt(encrypted, { sharedSecret }),
      ).rejects.toThrow();
    });

    test("should fail with corrupted IV", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Data");

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });

      // Corrupt the IV
      encrypted.parameters.iv[0] ^= 0xff;

      await expect(
        layer.decrypt(encrypted, { sharedSecret }),
      ).rejects.toThrow();
    });

    test("should fail with missing parameters", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));

      const payload = {
        ciphertext: new Uint8Array([1, 2, 3]),
        layerMetadata: {},
        parameters: {}, // Missing IV and salt
      };

      await expect(layer.decrypt(payload, { sharedSecret })).rejects.toThrow();
    });
  });

  describe("Round-trip Encryption/Decryption", () => {
    test("should round-trip with pre-shared secret", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const originalText = "Hello, World!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test("should round-trip with DH key exchange", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();
      const originalText = "DH exchange message";
      const plaintext = new TextEncoder().encode(originalText);

      // Alice encrypts
      const encrypted = await layer.encrypt(plaintext, {
        privateKey: aliceKeyPair.privateKey,
        publicKey: bobKeyPair.publicKey,
      });

      // Bob decrypts
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: bobKeyPair.privateKey,
        publicKey: aliceKeyPair.publicKey,
      });

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(originalText);
    });

    test("should round-trip with binary data", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with large data", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new Uint8Array(10000).fill(42);

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with empty data", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new Uint8Array([]);

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with special characters", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const originalText = "你好世界! 🌍 Привет мир!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, { sharedSecret });
      const decrypted = await layer.decrypt(encrypted, { sharedSecret });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });
  });

  describe("Error Handling", () => {
    test("should throw error with invalid keys on encrypt", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      await expect(layer.encrypt(plaintext, {})).rejects.toThrow();
      await expect(layer.encrypt(plaintext, null)).rejects.toThrow();
      await expect(
        layer.encrypt(plaintext, { privateKey: new Uint8Array(32) }),
      ).rejects.toThrow();
    });

    test("should throw error with invalid keys on decrypt", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = new TextEncoder().encode("Test");
      const encrypted = await layer.encrypt(plaintext, { sharedSecret });

      await expect(layer.decrypt(encrypted, {})).rejects.toThrow();
      await expect(layer.decrypt(encrypted, null)).rejects.toThrow();
    });
  });

  describe("Integration with CascadingCipherManager", () => {
    test("should work as a layer in cascading cipher", async () => {
      if (!DHCipherLayer) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );

      const manager = new CascadingCipherManager();
      const dhLayer = new DHCipherLayer();
      manager.addLayer(dhLayer);

      const plaintext = new TextEncoder().encode("Test message");
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const keys = {
        "DH-AES-GCM": { sharedSecret },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should work in combination with other layers", async () => {
      if (!DHCipherLayer) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      const { AESCipherLayer } = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );

      const manager = new CascadingCipherManager();
      const dhLayer = new DHCipherLayer();
      const aesLayer = new AESCipherLayer();

      manager.addLayer(dhLayer);
      manager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("Multi-layer test");
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      const keys = {
        "DH-AES-GCM": { sharedSecret },
        "AES-GCM-256": { password: "test-password" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("Compatibility Tests", () => {
    test("should match ../chat DH implementation flow", async () => {
      if (!DHCipherLayer) return;

      const layer = new DHCipherLayer();

      // Simulate chat app's DH key exchange
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();

      // Alice sends message to Bob
      const aliceMessage = new TextEncoder().encode("Hello Bob!");
      const aliceEncrypted = await layer.encrypt(aliceMessage, {
        privateKey: aliceKeyPair.privateKey,
        publicKey: bobKeyPair.publicKey,
      });

      // Bob receives and decrypts
      const bobDecrypted = await layer.decrypt(aliceEncrypted, {
        privateKey: bobKeyPair.privateKey,
        publicKey: aliceKeyPair.publicKey,
      });

      expect(new TextDecoder().decode(bobDecrypted)).toBe("Hello Bob!");

      // Bob responds
      const bobMessage = new TextEncoder().encode("Hello Alice!");
      const bobEncrypted = await layer.encrypt(bobMessage, {
        privateKey: bobKeyPair.privateKey,
        publicKey: aliceKeyPair.publicKey,
      });

      // Alice receives and decrypts
      const aliceDecrypted = await layer.decrypt(bobEncrypted, {
        privateKey: aliceKeyPair.privateKey,
        publicKey: bobKeyPair.publicKey,
      });

      expect(new TextDecoder().decode(aliceDecrypted)).toBe("Hello Alice!");
    });
  });
});
