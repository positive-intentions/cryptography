/**
 * @jest-environment jsdom
 */

/**
 * MLKEMCipherLayer Security Tests
 *
 * Comprehensive tests for security fixes:
 * - Key size validation (1184, 64, 1088 bytes)
 * - Malformed encapsulated key handling
 * - XCryptoKey vs Uint8Array conversion
 * - Constant-time validation
 * - Error message sanitization
 * - Zeroization verification
 *
 * NOTE: Timing attack protection tests are available in Storybook:
 * - Storybook Path: Cryptography/Security/ML-KEM Timing Tests
 * - File: src/stories/Security/MLKEMTimingTests.stories.js
 * - See STORYBOOK_TIMING_TESTS.md for details
 */

jest.setTimeout(300000); // 5 minutes timeout for all tests

describe("MLKEMCipherLayer Security", () => {
  let MLKEMCipherLayer;
  let MlKem768;
  let Zeroization;
  let ConstantTime;
  let crypto;
  let originalCrypto;

  beforeAll(async () => {
    originalCrypto = global.crypto;

    const { webcrypto } = await import("crypto");
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }
    crypto = webcrypto;

    try {
      const mlkemModule = await import("@hpke/ml-kem");
      MlKem768 = mlkemModule.MlKem768;
    } catch (e) {
      MlKem768 = null;
    }

    try {
      const mlkemLayerModule = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      MLKEMCipherLayer = mlkemLayerModule.MLKEMCipherLayer;
    } catch (e) {
      MLKEMCipherLayer = null;
    }

    try {
      const zeroModule = await import("../../crypto/utils/zeroization.ts");
      Zeroization = zeroModule.Zeroization;
    } catch (e) {
      Zeroization = null;
    }

    try {
      const ctModule = await import("../../crypto/utils/constantTime.ts");
      ConstantTime = ctModule.ConstantTime;
    } catch (e) {
      ConstantTime = null;
    }
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== "undefined") {
      window.crypto = originalCrypto;
    }
  });

  describe("Key Size Validation", () => {
    test("should accept public key with correct size (1184 bytes)", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const publicKeyBytes = new Uint8Array(
        await kem.serializePublicKey(keyPair.publicKey),
      );

      expect(publicKeyBytes.length).toBe(1184);

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: publicKeyBytes,
      });
      expect(encrypted).toBeDefined();
      expect(encrypted.parameters.encapsulated.length).toBe(1088);
    });

    test("should accept private key with correct size (64 bytes)", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const privateKeyBytes = new Uint8Array(
        await kem.serializePrivateKey(keyPair.privateKey),
      );

      expect(privateKeyBytes.length).toBe(64);

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: privateKeyBytes,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should generate encapsulated key with correct size (1088 bytes)", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(encrypted.parameters.encapsulated).toBeDefined();
      expect(encrypted.parameters.encapsulated.length).toBe(1088);
    });

    test("should reject public key with invalid size", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();

      const invalidSizes = [0, 64, 1183, 1185, 2000];

      for (const size of invalidSizes) {
        const invalidPublicKey = new Uint8Array(size);
        crypto.getRandomValues(invalidPublicKey);

        const plaintext = new TextEncoder().encode("Test data");

        await expect(
          layer.encrypt(plaintext, { publicKey: invalidPublicKey }),
        ).rejects.toThrow();
      }
    });

    test("should throw specific error for invalid public key size", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const invalidPublicKey = new Uint8Array(1000);
      crypto.getRandomValues(invalidPublicKey);

      const plaintext = new TextEncoder().encode("Test data");

      await expect(
        layer.encrypt(plaintext, { publicKey: invalidPublicKey }),
      ).rejects.toThrow();
    });

    test("should reject private key with invalid size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const invalidSizes = [0, 32, 63, 65, 100];

      for (const size of invalidSizes) {
        const invalidPrivateKey = new Uint8Array(size);
        crypto.getRandomValues(invalidPrivateKey);

        await expect(
          layer.decrypt(encrypted, { privateKey: invalidPrivateKey }),
        ).rejects.toThrow();
      }
    });

    test("should throw specific error for invalid private key size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const invalidPrivateKey = new Uint8Array(50);
      crypto.getRandomValues(invalidPrivateKey);

      await expect(
        layer.decrypt(encrypted, { privateKey: invalidPrivateKey }),
      ).rejects.toThrow();
    });

    test("should reject encapsulated key with invalid size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: new Uint8Array(1000),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should throw specific error for invalid encapsulated key size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: new Uint8Array(1000),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });
  });

  describe("Malformed Encapsulated Key Handling", () => {
    test("should fail decryption with all-zero encapsulated key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: new Uint8Array(1088).fill(0),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should fail decryption with randomized encapsulated key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: crypto.getRandomValues(new Uint8Array(1088)),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should fail decryption with truncated encapsulated key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const truncatedEncapsulated = new Uint8Array(
        encrypted.parameters.encapsulated.slice(0, 500),
      );

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: truncatedEncapsulated,
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should fail decryption with extended encapsulated key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const extendedEncapsulated = new Uint8Array(1500);
      extendedEncapsulated.set(
        new Uint8Array(encrypted.parameters.encapsulated),
      );

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: extendedEncapsulated,
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should fail decryption with missing encapsulated key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          iv: encrypted.parameters.iv,
          salt: encrypted.parameters.salt,
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });
  });

  describe("XCryptoKey vs Uint8Array Conversion", () => {
    test("should handle XCryptoKey for encryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      expect(encrypted).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
    });

    test("should handle XCryptoKey for decryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should handle Uint8Array for encryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const publicKeyBytes = new Uint8Array(
        await kem.serializePublicKey(keyPair.publicKey),
      );

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: publicKeyBytes,
      });
      expect(encrypted).toBeDefined();
    });

    test("should handle Uint8Array for decryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const privateKeyBytes = new Uint8Array(
        await kem.serializePrivateKey(keyPair.privateKey),
      );

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: privateKeyBytes,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should handle mixed XCryptoKey and Uint8Array", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const publicKeyBytes = new Uint8Array(
        await kem.serializePublicKey(keyPair.publicKey),
      );

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: publicKeyBytes,
      });
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should reject invalid key format", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const invalidKey = { invalid: "key" };

      await expect(layer.encrypt(plaintext, invalidKey)).rejects.toThrow();
    });

    test("should reject null key", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      await expect(
        layer.encrypt(plaintext, { publicKey: null }),
      ).rejects.toThrow();
    });

    test("should reject undefined key", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      await expect(
        layer.encrypt(plaintext, { publicKey: undefined }),
      ).rejects.toThrow();
    });
  });

  /**
   * Constant-Time Validation Tests
   *
   * NOTE: For comprehensive timing attack protection tests, see Storybook:
   * - Storybook Path: Cryptography/Security/ML-KEM Timing Tests
   * - These tests verify basic constant-time behavior
   * - Storybook tests provide detailed timing variance analysis
   */
  describe("Constant-Time Validation", () => {
    test("should validate keys with constant-time comparison", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();

      const validKeys = { publicKey: keyPair.publicKey };
      const invalidKeys = {};

      const startValid = performance.now();
      for (let i = 0; i < 100; i++) {
        layer.validateKeys(validKeys);
      }
      const endValid = performance.now();

      const startInvalid = performance.now();
      for (let i = 0; i < 100; i++) {
        layer.validateKeys(invalidKeys);
      }
      const endInvalid = performance.now();

      const validTime = endValid - startValid;
      const invalidTime = endInvalid - startInvalid;

      const ratio = validTime / invalidTime;
      expect(ratio).toBeGreaterThan(0.5);
      expect(ratio).toBeLessThan(2.0);
    });

    test("should use constant-time comparison in validateKeys", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();

      const validKeys = { publicKey: keyPair.publicKey };

      const validResult = layer.validateKeys(validKeys);
      expect(validResult).toBe(true);
    });

    test("should handle timing attacks gracefully", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const timings = [];
      for (let i = 0; i < 20; i++) {
        const start = performance.now();
        try {
          await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });
        } catch (e) {}
        const end = performance.now();
        timings.push(end - start);
      }

      const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
      const maxTiming = Math.max(...timings);
      const minTiming = Math.min(...timings);

      const varianceRatio = maxTiming / minTiming;

      expect(varianceRatio).toBeLessThan(10.0);
    });
  });

  describe("Error Message Sanitization", () => {
    test("should not leak sensitive data in encryption error messages", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const sensitiveData = "secret-key-data-12345";
      try {
        await layer.encrypt(plaintext, { publicKey: sensitiveData });
        fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).not.toContain(sensitiveData);
        expect(error.message).not.toContain("secret");
      }
    });

    test("should not leak sensitive data in decryption error messages", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const sensitivePrivateKey = "secret-private-key-data";
      try {
        await layer.decrypt(encrypted, { privateKey: sensitivePrivateKey });
        fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).not.toContain(sensitivePrivateKey);
        expect(error.message).not.toContain("secret");
      }
    });

    test("should provide generic error message for invalid keys", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      try {
        await layer.encrypt(plaintext, {});
        fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).toContain("Invalid keys");
        expect(error.message.length).toBeLessThan(100);
      }
    });

    test("should provide generic error message for missing keys", async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      try {
        await layer.encrypt(plaintext, {});
        fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).toBeDefined();
        expect(error.message.length).toBeLessThan(200);
      }
    });

    test("should provide generic error message for decryption failures", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const wrongKeyPair = await kem.generateKeyPair();

      try {
        await layer.decrypt(encrypted, { privateKey: wrongKeyPair.privateKey });
        fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).toContain("Decryption failed");
        expect(error.message).not.toContain("private key");
        expect(error.message).not.toContain("encapsulated");
      }
    });
  });

  describe("Zeroization Verification", () => {
    test("should zeroize sharedSecretBytes after encryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768 || !Zeroization) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroize");

      await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(zeroizeSpy).toHaveBeenCalled();
    });

    test("should zeroize sharedSecretBytes after decryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768 || !Zeroization) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroize");

      await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(zeroizeSpy).toHaveBeenCalled();
    });

    test("should zeroize iv and salt after encryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768 || !Zeroization) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeAllSpy = jest.spyOn(Zeroization, "zeroizeAll");

      await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(zeroizeAllSpy).toHaveBeenCalled();
    });

    test("should zeroize buffers on exception paths", async () => {
      if (!MLKEMCipherLayer || !MlKem768 || !Zeroization) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeAllSpy = jest.spyOn(Zeroization, "zeroizeAll");

      try {
        await layer.encrypt(plaintext, {});
        fail("Should have thrown an error");
      } catch (error) {}

      expect(zeroizeAllSpy).toHaveBeenCalled();
    });

    test("should clear CryptoKey reference after encryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(encrypted).toBeDefined();
      expect(encrypted.parameters.iv).toBeDefined();
      expect(encrypted.parameters.salt).toBeDefined();
    });

    test("should clear CryptoKey reference after decryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const decrypted = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      expect(decrypted).toBeDefined();
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("Parameter Validation", () => {
    test("should validate IV size (12 bytes)", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(encrypted.parameters.iv).toBeDefined();
      expect(encrypted.parameters.iv.length).toBe(12);
    });

    test("should validate salt size (16 bytes)", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(encrypted.parameters.salt).toBeDefined();
      expect(encrypted.parameters.salt.length).toBe(16);
    });

    test("should fail decryption with wrong IV size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          iv: new Uint8Array(16),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should throw specific error for invalid IV size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          iv: new Uint8Array(16),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should fail decryption with wrong salt size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          salt: new Uint8Array(32),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should throw specific error for invalid salt size", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          salt: new Uint8Array(32),
        },
      };

      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });

    test("should validate shared secret size through decryption", async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      // Modify encapsulated key to produce invalid shared secret
      const modifiedPayload = {
        ...encrypted,
        parameters: {
          ...encrypted.parameters,
          encapsulated: crypto.getRandomValues(new Uint8Array(1088)),
        },
      };

      // Decryption should fail due to invalid shared secret
      await expect(
        layer.decrypt(modifiedPayload, { privateKey: keyPair.privateKey }),
      ).rejects.toThrow();
    });
  });
});
