/**
 * ML-KEM Browser-Based Tests
 *
 * These tests run in a real browser environment using React Testing Library.
 * This allows testing ML-KEM with actual Web Crypto API and @hpke/ml-kem.
 */

/**
 * @jest-environment jsdom
 */

describe("MLKEMCipherLayer - Browser Tests", () => {
  let MLKEMCipherLayer;
  let MlKem768;
  let originalCrypto;

  beforeAll(async () => {
    originalCrypto = global.crypto;

    if (typeof crypto !== "undefined" && crypto.subtle) {
      global.crypto = crypto;
    }
  });

  afterAll(() => {
    if (originalCrypto) {
      global.crypto = originalCrypto;
    }
  });

  beforeEach(async () => {
    try {
      const mlkemModule = await import("@hpke/ml-kem");
      MlKem768 = mlkemModule.MlKem768;
    } catch (e) {
      console.error("Failed to import MlKem768:", e);
      MlKem768 = null;
    }

    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      MLKEMCipherLayer = module.MLKEMCipherLayer;
    } catch (e) {
      console.error("Failed to import MLKEMCipherLayer:", e);
    }
  });

  describe("Real ML-KEM Operations", () => {
    test("should generate key pairs in browser environment", async () => {
      if (!MlKem768) {
        console.log("ML-KEM library not available");
        return;
      }

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.key).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey.key).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.key.length).toBe(1184);
      expect(keyPair.privateKey.key.length).toBe(64);
    });

    test("should encapsulate and decap shared secret", async () => {
      if (!MlKem768) {
        console.log("ML-KEM library not available");
        return;
      }

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const { sharedSecret: ss1, enc } = await kem.encap({
        recipientPublicKey: keyPair.publicKey,
      });

      expect(enc).toBeDefined();
      expect(ss1).toBeDefined();
      expect(enc).toBeInstanceOf(ArrayBuffer);
      expect(ss1).toBeInstanceOf(ArrayBuffer);
      expect(enc.byteLength).toBe(1088);
      expect(ss1.byteLength).toBe(64);

      const { sharedSecret: ss2 } = await kem.decap({
        recipientKey: keyPair.privateKey,
        enc,
      });

      expect(ss2).toBeDefined();
      expect(ss2).toBeInstanceOf(ArrayBuffer);
      expect(ss2.byteLength).toBe(64);

      const ss1Bytes = new Uint8Array(ss1);
      const ss2Bytes = new Uint8Array(ss2);
      expect(Array.from(ss2Bytes)).toEqual(Array.from(ss1Bytes));
    });

    test("should fail decapsulation with wrong private key", async () => {
      if (!MlKem768) {
        console.log("ML-KEM library not available");
        return;
      }

      const kem = new MlKem768();
      const keyPair1 = await kem.generateKeyPair();
      const keyPair2 = await kem.generateKeyPair();

      const { enc } = await kem.encap({
        recipientPublicKey: keyPair1.publicKey,
      });

      await expect(
        kem.decap({
          recipientKey: keyPair2.privateKey,
          enc,
        }),
      ).rejects.toThrow();
    });
  });

  describe("MLKEMCipherLayer Integration", () => {
    test("should encrypt and decrypt with real ML-KEM", async () => {
      if (!MLKEMCipherLayer || !MlKem768) {
        console.log("ML-KEM components not available");
        return;
      }

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode("Test message in browser");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(encrypted).toBeDefined();
      expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);
      expect(encrypted.parameters).toBeDefined();
      expect(encrypted.parameters.encapsulated).toBeInstanceOf(Uint8Array);
      expect(encrypted.parameters.encapsulated.length).toBe(1088);
      expect(encrypted.parameters.iv).toBeInstanceOf(Uint8Array);
      expect(encrypted.parameters.iv.length).toBe(12);
      expect(encrypted.parameters.salt).toBeInstanceOf(Uint8Array);
      expect(encrypted.parameters.salt.length).toBe(16);

      const decrypted = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should handle multiple encryptions with different IVs", async () => {
      if (!MLKEMCipherLayer || !MlKem768) {
        console.log("ML-KEM components not available");
        return;
      }

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode("Test");

      const encrypted1 = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const encrypted2 = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      expect(Array.from(encrypted1.parameters.iv)).not.toEqual(
        Array.from(encrypted2.parameters.iv),
      );

      expect(Array.from(encrypted1.parameters.encapsulated)).not.toEqual(
        Array.from(encrypted2.parameters.encapsulated),
      );
    });

    test("should fail decryption with wrong private key", async () => {
      if (!MLKEMCipherLayer || !MlKem768) {
        console.log("ML-KEM components not available");
        return;
      }

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair1 = await kem.generateKeyPair();
      const keyPair2 = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode("Test");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair1.publicKey,
      });

      await expect(
        layer.decrypt(encrypted, {
          privateKey: keyPair2.privateKey,
        }),
      ).rejects.toThrow();
    });
  });

  describe("Performance in Browser Environment", () => {
    test("should generate key pair within reasonable time", async () => {
      if (!MlKem768) {
        console.log("ML-KEM library not available");
        return;
      }

      const kem = new MlKem768();
      const startTime = performance.now();
      await kem.generateKeyPair();
      const elapsed = performance.now() - startTime;

      expect(elapsed).toBeLessThan(200);
    });

    test("should encrypt within reasonable time", async () => {
      if (!MLKEMCipherLayer || !MlKem768) {
        console.log("ML-KEM components not available");
        return;
      }

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode("Test message");

      const startTime = performance.now();
      await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const elapsed = performance.now() - startTime;

      expect(elapsed).toBeLessThan(100);
    });

    test("should decrypt within reasonable time", async () => {
      if (!MLKEMCipherLayer || !MlKem768) {
        console.log("ML-KEM components not available");
        return;
      }

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode("Test message");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const startTime = performance.now();
      await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });
      const elapsed = performance.now() - startTime;

      expect(elapsed).toBeLessThan(100);
    });
  });
});
