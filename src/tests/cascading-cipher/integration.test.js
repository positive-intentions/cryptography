/**
 * @jest-environment jsdom
 */

/**
 * Cascading Cipher Integration Tests
 *
 * End-to-end tests for the complete cascading cipher system with real crypto operations.
 */

describe("Cascading Cipher Integration", () => {
  let CascadingCipherManager, AESCipherLayer, DHCipherLayer;
  let originalCrypto;

  beforeEach(async () => {
    // Save original crypto mock
    originalCrypto = global.crypto;

    // Setup REAL Web Crypto API (override global mocks from setupTests.js)
    const { webcrypto } = await import("crypto");
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }

    // Import modules (only real crypto modules, skip MLS/Signal which are tested separately)
    try {
      const managerModule = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      const aesModule = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );
      const dhModule = await import(
        "../../crypto/CascadingCipher/layers/DHCipherLayer.ts"
      );

      CascadingCipherManager = managerModule.CascadingCipherManager;
      AESCipherLayer = aesModule.AESCipherLayer;
      DHCipherLayer = dhModule.DHCipherLayer;
    } catch (e) {
      console.error("Failed to load modules:", e);
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

  describe("Single Layer Integration", () => {
    test("should encrypt and decrypt with AES layer", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer = new AESCipherLayer();
      manager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("Integration test message");
      const keys = {
        "AES-GCM-256": { password: "test-password-123" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe("Integration test message");
    });
  });

  describe("Multi-Layer Integration", () => {
    test("should cascade through 2 AES layers with different passwords", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer1 = new AESCipherLayer();
      const aesLayer2 = new AESCipherLayer();

      // Rename to avoid conflicts
      Object.defineProperty(aesLayer1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aesLayer2, "name", { value: "AES-Layer-2" });

      manager.addLayer(aesLayer1);
      manager.addLayer(aesLayer2);

      const plaintext = new TextEncoder().encode("Double encryption test");
      const keys = {
        "AES-Layer-1": { password: "password-one" },
        "AES-Layer-2": { password: "password-two" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe("Double encryption test");
    });

    test("should fail decryption if layer passwords are swapped", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer1 = new AESCipherLayer();
      const aesLayer2 = new AESCipherLayer();

      Object.defineProperty(aesLayer1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aesLayer2, "name", { value: "AES-Layer-2" });

      manager.addLayer(aesLayer1);
      manager.addLayer(aesLayer2);

      const plaintext = new TextEncoder().encode("Test");
      const keys = {
        "AES-Layer-1": { password: "password-one" },
        "AES-Layer-2": { password: "password-two" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Swap passwords
      const wrongKeys = {
        "AES-Layer-1": { password: "password-two" },
        "AES-Layer-2": { password: "password-one" },
      };

      await expect(manager.decrypt(encrypted, wrongKeys)).rejects.toThrow();
    });
  });

  describe("Large Data Integration", () => {
    test("should handle large data through multiple layers", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer1 = new AESCipherLayer();
      const aesLayer2 = new AESCipherLayer();

      Object.defineProperty(aesLayer1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aesLayer2, "name", { value: "AES-Layer-2" });

      manager.addLayer(aesLayer1);
      manager.addLayer(aesLayer2);

      // Create 1MB of data
      const plaintext = new Uint8Array(1024 * 1024);
      for (let i = 0; i < plaintext.length; i++) {
        plaintext[i] = i % 256;
      }

      const keys = {
        "AES-Layer-1": { password: "password1" },
        "AES-Layer-2": { password: "password2" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(decrypted.length).toBe(plaintext.length);
      expect(Array.from(decrypted.slice(0, 100))).toEqual(
        Array.from(plaintext.slice(0, 100)),
      );
    }, 30000); // 30s timeout for large data
  });

  describe("Metadata Tracking", () => {
    test("should track metadata through all layers", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer1 = new AESCipherLayer();
      const aesLayer2 = new AESCipherLayer();

      Object.defineProperty(aesLayer1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aesLayer2, "name", { value: "AES-Layer-2" });

      manager.addLayer(aesLayer1);
      manager.addLayer(aesLayer2);

      const plaintext = new TextEncoder().encode("Metadata test");
      const keys = {
        "AES-Layer-1": { password: "pass1" },
        "AES-Layer-2": { password: "pass2" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      expect(encrypted.layers).toHaveLength(2);
      expect(encrypted.layers[0].algorithm).toBe("AES-Layer-1");
      expect(encrypted.layers[1].algorithm).toBe("AES-Layer-2");

      expect(encrypted.originalSize).toBe(plaintext.length);
      expect(encrypted.finalSize).toBeGreaterThan(plaintext.length);
      expect(encrypted.totalProcessingTime).toBeGreaterThan(0);
    });
  });

  describe("Error Scenarios", () => {
    test("should report which layer failed during encryption", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer1 = new AESCipherLayer();
      const aesLayer2 = new AESCipherLayer();

      Object.defineProperty(aesLayer1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aesLayer2, "name", { value: "AES-Layer-2" });

      manager.addLayer(aesLayer1);
      manager.addLayer(aesLayer2);

      const plaintext = new TextEncoder().encode("Test");
      const keys = {
        "AES-Layer-1": { password: "pass1" },
        // Missing AES-Layer-2 password
      };

      try {
        await manager.encrypt(plaintext, keys);
        fail("Should have thrown error");
      } catch (error) {
        expect(error.message).toContain("AES-Layer-2");
        expect(error.failedAtLayer).toBe(1);
      }
    });
  });

  describe("Performance", () => {
    test("should complete encryption/decryption within reasonable time", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();
      const aesLayer = new AESCipherLayer();
      manager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("Performance test");
      const keys = {
        "AES-GCM-256": { password: "password" },
      };

      const start = performance.now();
      const encrypted = await manager.encrypt(plaintext, keys);
      await manager.decrypt(encrypted, keys);
      const end = performance.now();

      const totalTime = end - start;
      expect(totalTime).toBeLessThan(1000); // Should complete in less than 1 second
    });
  });

  describe("DH + AES Integration", () => {
    test("should cascade DH and AES layers", async () => {
      if (!CascadingCipherManager || !DHCipherLayer || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();

      // Generate DH key pairs
      const aliceKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"],
      );
      const bobKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"],
      );

      const dhLayer = new DHCipherLayer();
      const aesLayer = new AESCipherLayer();
      manager.addLayer(dhLayer);
      manager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("DH + AES test");
      const keys = {
        "DH-AES-GCM": {
          privateKey: aliceKeyPair.privateKey,
          publicKey: bobKeyPair.publicKey,
        },
        "AES-GCM-256": { password: "aes-password" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Decrypt with Bob's keys
      const decryptKeys = {
        "DH-AES-GCM": {
          privateKey: bobKeyPair.privateKey,
          publicKey: aliceKeyPair.publicKey,
        },
        "AES-GCM-256": { password: "aes-password" },
      };

      const decrypted = await manager.decrypt(encrypted, decryptKeys);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe("DH + AES test");
      expect(encrypted.layers).toHaveLength(2);
    });
  });

  describe("DH + Multi-AES Integration", () => {
    test("should cascade DH and multiple AES layers", async () => {
      if (!CascadingCipherManager || !DHCipherLayer || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();

      // Generate DH key pairs
      const aliceKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"],
      );
      const bobKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"],
      );

      const dhLayer = new DHCipherLayer();
      const aes1 = new AESCipherLayer();
      const aes2 = new AESCipherLayer();

      Object.defineProperty(aes1, "name", { value: "AES-Layer-1" });
      Object.defineProperty(aes2, "name", { value: "AES-Layer-2" });

      manager.addLayer(dhLayer);
      manager.addLayer(aes1);
      manager.addLayer(aes2);

      const plaintext = new TextEncoder().encode("DH + Multi-AES test");
      const keys = {
        "DH-AES-GCM": {
          privateKey: aliceKeyPair.privateKey,
          publicKey: bobKeyPair.publicKey,
        },
        "AES-Layer-1": { password: "password1" },
        "AES-Layer-2": { password: "password2" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Decrypt with Bob's keys
      const decryptKeys = {
        "DH-AES-GCM": {
          privateKey: bobKeyPair.privateKey,
          publicKey: aliceKeyPair.publicKey,
        },
        "AES-Layer-1": { password: "password1" },
        "AES-Layer-2": { password: "password2" },
      };

      const decrypted = await manager.decrypt(encrypted, decryptKeys);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe("DH + Multi-AES test");
      expect(encrypted.layers).toHaveLength(3);
    });
  });

  describe("Round-Robin Scenarios", () => {
    test("should apply same layer sequence multiple times", async () => {
      if (!CascadingCipherManager || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();

      // Add 3 rounds of 2 AES layers each (6 layers total)
      for (let round = 0; round < 3; round++) {
        const aes1 = new AESCipherLayer();
        const aes2 = new AESCipherLayer();
        Object.defineProperty(aes1, "name", {
          value: `AES-Round${round}-Layer1`,
        });
        Object.defineProperty(aes2, "name", {
          value: `AES-Round${round}-Layer2`,
        });
        manager.addLayer(aes1);
        manager.addLayer(aes2);
      }

      const keys = {};
      for (let round = 0; round < 3; round++) {
        keys[`AES-Round${round}-Layer1`] = {
          password: `password-r${round}-l1`,
        };
        keys[`AES-Round${round}-Layer2`] = {
          password: `password-r${round}-l2`,
        };
      }

      const plaintext = new TextEncoder().encode("Round-robin test");
      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe("Round-robin test");
      expect(encrypted.layers).toHaveLength(6);
    });

    test("should apply DH + AES sequence multiple times", async () => {
      if (!CascadingCipherManager || !DHCipherLayer || !AESCipherLayer) return;

      const manager = new CascadingCipherManager();

      // Generate DH key pairs for 2 rounds
      const keyPairs = [];
      for (let i = 0; i < 4; i++) {
        keyPairs.push(
          await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"],
          ),
        );
      }

      // Add 2 rounds of (DH + AES)
      for (let round = 0; round < 2; round++) {
        const dhLayer = new DHCipherLayer();
        const aesLayer = new AESCipherLayer();
        Object.defineProperty(dhLayer, "name", { value: `DH-Round${round}` });
        Object.defineProperty(aesLayer, "name", { value: `AES-Round${round}` });
        manager.addLayer(dhLayer);
        manager.addLayer(aesLayer);
      }

      const plaintext = new TextEncoder().encode("Round-robin DH+AES test");
      const keys = {
        "DH-Round0": {
          privateKey: keyPairs[0].privateKey,
          publicKey: keyPairs[1].publicKey,
        },
        "AES-Round0": { password: "pass0" },
        "DH-Round1": {
          privateKey: keyPairs[2].privateKey,
          publicKey: keyPairs[3].publicKey,
        },
        "AES-Round1": { password: "pass1" },
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Decrypt
      const decryptKeys = {
        "DH-Round0": {
          privateKey: keyPairs[1].privateKey,
          publicKey: keyPairs[0].publicKey,
        },
        "AES-Round0": { password: "pass0" },
        "DH-Round1": {
          privateKey: keyPairs[3].privateKey,
          publicKey: keyPairs[2].publicKey,
        },
        "AES-Round1": { password: "pass1" },
      };

      const decrypted = await manager.decrypt(encrypted, decryptKeys);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe("Round-robin DH+AES test");
      expect(encrypted.layers).toHaveLength(4);
    });
  });
});
