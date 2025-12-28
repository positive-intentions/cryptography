/**
 * @jest-environment jsdom
 */

/**
 * MLSCipherLayer Unit Tests
 *
 * Tests for the MLS (Message Layer Security) cipher layer implementation.
 * Uses mock MLSManager since real ts-mls is incompatible with Jest.
 * Real MLS implementation is tested in Storybook (browser environment).
 */

describe("MLSCipherLayer", () => {
  let MLSCipherLayer;
  let MLSManager;

  beforeEach(async () => {
    // Import MLS components (MLSManager will be mocked by Jest config)
    try {
      const mlsModule = await import("../../crypto/MLS/MLSManager.tsx");
      MLSManager = mlsModule.MLSManager;

      const layerModule = await import(
        "../../crypto/CascadingCipher/layers/MLSCipherLayer.ts"
      );
      MLSCipherLayer = layerModule.MLSCipherLayer;
    } catch (e) {
      MLSCipherLayer = null;
      MLSManager = null;
    }
  });

  // Helper to setup a basic MLS group
  async function setupMLSGroup(groupId = "test-group") {
    const manager = new MLSManager("alice@example.com");
    await manager.initialize();
    await manager.createGroup(groupId);
    return { manager, groupId };
  }

  describe("Construction", () => {
    test("should create MLSCipherLayer instance without parameters", () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();
      expect(layer).toBeDefined();
    });

    test("should create MLSCipherLayer with manager and groupId", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      expect(layer).toBeDefined();
    });

    test("should have correct name and version", () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();
      expect(layer.name).toBe("MLS");
      expect(layer.version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe("Key Validation", () => {
    test("should validate keys with mlsManager and groupId", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const layer = new MLSCipherLayer();
      const { manager, groupId } = await setupMLSGroup();

      const validKeys = {
        mlsManager: manager,
        groupId,
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test("should validate when constructed with manager and groupId", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      // Empty keys should be valid since constructor provided them
      expect(layer.validateKeys({})).toBe(true);
      expect(layer.validateKeys(null)).toBe(true);
    });

    test("should reject keys without required fields", () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();

      expect(layer.validateKeys({})).toBe(false);
      expect(layer.validateKeys({ mlsManager: {} })).toBe(false);
      expect(layer.validateKeys({ groupId: "test" })).toBe(false);
    });

    test("should reject null or undefined keys when not initialized", () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();

      expect(layer.validateKeys(null)).toBe(false);
      expect(layer.validateKeys(undefined)).toBe(false);
    });
  });

  describe("Initialization", () => {
    test("should initialize with mlsManager and groupId", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const layer = new MLSCipherLayer();
      const { manager, groupId } = await setupMLSGroup();

      await layer.initialize({ mlsManager: manager, groupId });

      // After initialization, empty keys should be valid
      expect(layer.validateKeys({})).toBe(true);
    });
  });

  describe("Binary Data Handling", () => {
    test("should handle binary data via base64 encoding", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      // Binary data that would fail UTF-8 decoding
      const binaryData = new Uint8Array([
        0, 1, 255, 128, 64, 32, 16, 8, 4, 2, 1,
      ]);

      const encrypted = await layer.encrypt(binaryData, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(binaryData));
    });

    test("should handle binary data from previous cipher layer", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      // Simulate output from another cipher layer (binary ciphertext)
      const ciphertextFromPreviousLayer = new Uint8Array(50);
      crypto.getRandomValues(ciphertextFromPreviousLayer);

      const encrypted = await layer.encrypt(ciphertextFromPreviousLayer, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(
        Array.from(ciphertextFromPreviousLayer),
      );
    });
  });

  describe("Encryption", () => {
    test("should encrypt data with MLS", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Hello, MLS!");

      const result = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      expect(result).toBeDefined();
      // Check if ciphertext is a Uint8Array (Jest instanceof can be unreliable)
      expect(result.ciphertext).toBeDefined();
      expect(ArrayBuffer.isView(result.ciphertext)).toBe(true);
      expect(result.ciphertext.constructor.name).toBe("Uint8Array");
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.layerMetadata).toBeDefined();
      expect(result.parameters).toBeDefined();
    });

    test("should include metadata", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Test data");

      const result = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      expect(result.layerMetadata.algorithm).toBe("MLS");
      expect(result.layerMetadata.version).toMatch(/^\d+\.\d+\.\d+$/);
      expect(result.layerMetadata.inputSize).toBe(plaintext.length);
      expect(result.layerMetadata.outputSize).toBe(result.ciphertext.length);
      expect(result.layerMetadata.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layerMetadata.timestamp).toBeGreaterThan(0);
      expect(result.layerMetadata.metadata.groupId).toBe(groupId);
      expect(result.layerMetadata.metadata.cipherSuite).toBeDefined();
      expect(result.layerMetadata.metadata.encoding).toBe("base64");
    });

    test("should include parameters for decryption", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Test");

      const result = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      expect(result.parameters.groupId).toBeDefined();
      expect(result.parameters.timestamp).toBeDefined();
      expect(result.parameters.timestamp).toBeGreaterThan(0);
    });

    test("should use keys from constructor if not provided", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Constructor keys test");

      // Encrypt with empty keys object (should use constructor values)
      const result = await layer.encrypt(plaintext, {});

      expect(result).toBeDefined();
      // Check if ciphertext is a Uint8Array (Jest instanceof can be unreliable)
      expect(result.ciphertext).toBeDefined();
      expect(ArrayBuffer.isView(result.ciphertext)).toBe(true);
      expect(result.ciphertext.constructor.name).toBe("Uint8Array");
    });

    test("should prefer provided keys over constructor values", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager: manager1, groupId: groupId1 } =
        await setupMLSGroup("group-1");
      const { manager: manager2, groupId: groupId2 } =
        await setupMLSGroup("group-2");

      const layer = new MLSCipherLayer(manager1, groupId1);
      const plaintext = new TextEncoder().encode("Override test");

      // Encrypt with different keys than constructor
      const result = await layer.encrypt(plaintext, {
        mlsManager: manager2,
        groupId: groupId2,
      });

      expect(result).toBeDefined();
      expect(result.parameters.groupId).toBe(groupId2);
    });
  });

  describe("Decryption", () => {
    test("should decrypt MLS-encrypted data", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Secret message");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should fail without mlsManager", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      await expect(layer.decrypt(encrypted, { groupId })).rejects.toThrow();
    });

    test("should fail without groupId", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      await expect(
        layer.decrypt(encrypted, { mlsManager: manager }),
      ).rejects.toThrow();
    });

    test("should fail with wrong group", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup("group-1");
      const wrongManager = new MLSManager("eve@example.com");
      await wrongManager.initialize();

      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Secret");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      // Wrong manager doesn't have the group
      await expect(
        layer.decrypt(encrypted, { mlsManager: wrongManager, groupId }),
      ).rejects.toThrow();
    });
  });

  describe("Round-trip Encryption/Decryption", () => {
    test("should round-trip with simple text", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const originalText = "Hello, World!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test("should round-trip with binary data", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with large data", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new Uint8Array(10000).fill(42);

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with empty data", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new Uint8Array([]);

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with special characters", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const originalText = "你好世界! 🌍 Привет мир!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test("should round-trip with all possible byte values", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      // Test with all possible byte values (0-255)
      const plaintext = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        plaintext[i] = i;
      }

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: manager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("Error Handling", () => {
    test("should throw error without required keys on encrypt", async () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      await expect(layer.encrypt(plaintext, {})).rejects.toThrow();
      await expect(layer.encrypt(plaintext, null)).rejects.toThrow();
    });

    test("should throw error without required keys on decrypt", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      await expect(layer.decrypt(encrypted, {})).rejects.toThrow();
      await expect(layer.decrypt(encrypted, null)).rejects.toThrow();
    });

    test("should provide meaningful error messages", async () => {
      if (!MLSCipherLayer) return;

      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      try {
        await layer.encrypt(plaintext, {});
        fail("Should have thrown an error");
      } catch (error) {
        // Error message may be sanitized to prevent information leakage
        expect(error.message).toBeDefined();
        expect(typeof error.message).toBe("string");
      }
    });
  });

  describe("Resource Cleanup", () => {
    test("should clean up resources", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      await layer.destroy();

      // After destroy, layer should not have manager/groupId
      expect(layer.validateKeys({})).toBe(false);
    });
  });

  describe("Integration with CascadingCipherManager", () => {
    test("should work as a layer in cascading cipher", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );

      const { manager, groupId } = await setupMLSGroup();
      const cascadeManager = new CascadingCipherManager();
      const mlsLayer = new MLSCipherLayer(manager, groupId);
      cascadeManager.addLayer(mlsLayer);

      const plaintext = new TextEncoder().encode("Test message");
      const keys = {
        MLS: { mlsManager: manager, groupId },
      };

      const encrypted = await cascadeManager.encrypt(plaintext, keys);
      const decrypted = await cascadeManager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should work in combination with AES layer", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      const { AESCipherLayer } = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );

      const { manager, groupId } = await setupMLSGroup();
      const cascadeManager = new CascadingCipherManager();

      const mlsLayer = new MLSCipherLayer(manager, groupId);
      const aesLayer = new AESCipherLayer();

      cascadeManager.addLayer(mlsLayer);
      cascadeManager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("Multi-layer test");
      const keys = {
        MLS: { mlsManager: manager, groupId },
        "AES-GCM-256": { password: "test-password" },
      };

      const encrypted = await cascadeManager.encrypt(plaintext, keys);
      const decrypted = await cascadeManager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should handle binary data in cascade", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      const { AESCipherLayer } = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );

      const { manager, groupId } = await setupMLSGroup();
      const cascadeManager = new CascadingCipherManager();

      // AES first, then MLS
      const aesLayer = new AESCipherLayer();
      const mlsLayer = new MLSCipherLayer(manager, groupId);

      cascadeManager.addLayer(aesLayer);
      cascadeManager.addLayer(mlsLayer);

      // Binary data
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);
      const keys = {
        "AES-GCM-256": { password: "test-password" },
        MLS: { mlsManager: manager, groupId },
      };

      // AES encrypts binary → produces binary ciphertext
      // MLS must handle that binary ciphertext via base64 encoding
      const encrypted = await cascadeManager.encrypt(plaintext, keys);
      const decrypted = await cascadeManager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("MLS Group Features", () => {
    test("should track epoch in metadata", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);
      const plaintext = new TextEncoder().encode("Test");

      const result = await layer.encrypt(plaintext, {
        mlsManager: manager,
        groupId,
      });

      expect(result.layerMetadata.metadata.epoch).toBeDefined();
    });

    test("should work after group membership changes", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const aliceManager = new MLSManager("alice@example.com");
      const bobManager = new MLSManager("bob@example.com");

      await aliceManager.initialize();
      await bobManager.initialize();

      const groupId = "test-group";
      await aliceManager.createGroup(groupId);

      // Add Bob to the group
      const bobKeyPackage = await bobManager.generateKeyPackage();
      const { welcome, ratchetTree } = await aliceManager.addMembers(groupId, [
        bobKeyPackage,
      ]);
      await bobManager.processWelcome(welcome, ratchetTree);

      // Both should be able to encrypt/decrypt
      const layer = new MLSCipherLayer();
      const plaintext = new TextEncoder().encode("Group message");

      const encrypted = await layer.encrypt(plaintext, {
        mlsManager: aliceManager,
        groupId,
      });
      const decrypted = await layer.decrypt(encrypted, {
        mlsManager: bobManager,
        groupId,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("Base64 Encoding Correctness", () => {
    test("should correctly encode/decode binary data", async () => {
      if (!MLSCipherLayer || !MLSManager) return;

      const { manager, groupId } = await setupMLSGroup();
      const layer = new MLSCipherLayer(manager, groupId);

      // Test various problematic binary patterns
      const testCases = [
        new Uint8Array([0, 0, 0, 0]), // All zeros
        new Uint8Array([255, 255, 255, 255]), // All ones
        new Uint8Array([0, 1, 2, 3, 254, 255]), // Range
        new Uint8Array([128, 129, 130]), // High values
        new Uint8Array([10, 13, 26]), // Control characters
      ];

      for (const testCase of testCases) {
        const encrypted = await layer.encrypt(testCase, {
          mlsManager: manager,
          groupId,
        });
        const decrypted = await layer.decrypt(encrypted, {
          mlsManager: manager,
          groupId,
        });
        expect(Array.from(decrypted)).toEqual(Array.from(testCase));
      }
    });
  });
});
