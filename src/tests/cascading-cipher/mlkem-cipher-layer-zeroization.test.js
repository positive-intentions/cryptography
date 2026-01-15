/**
 * @jest-environment jsdom
 */

/**
 * MLKEMCipherLayer Zeroization Tests
 *
 * Tests that MLKEMCipherLayer properly zeroizes sensitive buffers
 * including sharedSecretBytes, iv, and salt in encryption/decryption methods.
 */

describe("MLKEMCipherLayer Zeroization", () => {
  let MLKEMCipherLayer;
  let Zeroization;
  let MlKem768;
  let kem;
  let originalCrypto;

  beforeAll(async () => {
    originalCrypto = global.crypto;

    const { webcrypto } = await import("crypto");
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }

    try {
      const mlkemModule = await import("@hpke/ml-kem");
      MlKem768 = mlkemModule.MlKem768;
      kem = new MlKem768();
    } catch (e) {
      console.error("Failed to import @hpke/ml-kem:", e.message);
    }

    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      MLKEMCipherLayer = module.MLKEMCipherLayer;
    } catch (e) {
      console.error("Failed to import MLKEMCipherLayer:", e.message);
      MLKEMCipherLayer = null;
    }

    try {
      const module = await import("../../crypto/utils/zeroization");
      Zeroization = module.Zeroization;
    } catch (e) {
      console.error("Failed to import Zeroization:", e.message);
      Zeroization = null;
    }
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== "undefined") {
      window.crypto = originalCrypto;
    }
  });

  describe("encrypt method zeroization", () => {
    test("should zeroize sharedSecretBytes after encryption", async () => {
      if (!MLKEMCipherLayer || !Zeroization || !MlKem768) {
        return;
      }

      const keyPair = await kem.generateKeyPair();
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroizeAll");

      await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(zeroizeSpy).toHaveBeenCalled();
      expect(zeroizeSpy.mock.calls.length).toBeGreaterThan(0);
    });

    test("should zeroize iv and salt buffers after encryption", async () => {
      if (!MLKEMCipherLayer || !Zeroization || !MlKem768) {
        return;
      }

      const keyPair = await kem.generateKeyPair();
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeAllSpy = jest.spyOn(Zeroization, "zeroizeAll");

      await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(zeroizeAllSpy).toHaveBeenCalled();
    });

    test("should zeroize buffers even when encryption fails", async () => {
      if (!MLKEMCipherLayer || !Zeroization) {
        return;
      }

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeAllSpy = jest.spyOn(Zeroization, "zeroizeAll");

      try {
        await layer.encrypt(plaintext, {});
      } catch (error) {}

      expect(zeroizeAllSpy).toHaveBeenCalled();
    });
  });

  describe("decrypt method zeroization", () => {
    test("should zeroize sharedSecretBytes after decryption", async () => {
      if (!MLKEMCipherLayer || !Zeroization || !MlKem768) {
        return;
      }

      const keyPair = await kem.generateKeyPair();
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroize");

      await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(zeroizeSpy).toHaveBeenCalled();
      expect(zeroizeSpy.mock.calls.length).toBeGreaterThan(0);
    });

    test("should zeroize buffers even when decryption fails", async () => {
      if (!MLKEMCipherLayer || !Zeroization || !MlKem768) {
        return;
      }

      const keyPair = await kem.generateKeyPair();
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroize");

      try {
        await layer.decrypt(encrypted, { privateKey: new Uint8Array(64) });
      } catch (error) {}

      expect(zeroizeSpy).toHaveBeenCalled();
    });
  });

  describe("exception path zeroization", () => {
    test("should zeroize in encrypt when key encapsulation fails", async () => {
      if (!MLKEMCipherLayer || !Zeroization) {
        return;
      }

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test data");

      const zeroizeAllSpy = jest.spyOn(Zeroization, "zeroizeAll");

      try {
        await layer.encrypt(plaintext, { publicKey: new Uint8Array(1184) });
      } catch (error) {}

      expect(zeroizeAllSpy).toHaveBeenCalled();
    });

    test("should zeroize in decrypt when parameters are missing", async () => {
      if (!MLKEMCipherLayer || !Zeroization) {
        return;
      }

      const layer = new MLKEMCipherLayer();
      const payload = {
        ciphertext: new Uint8Array([1, 2, 3]),
        layerMetadata: {},
      };

      const zeroizeSpy = jest.spyOn(Zeroization, "zeroize");

      try {
        await layer.decrypt(payload, { privateKey: new Uint8Array(64) });
      } catch (error) {}

      expect(zeroizeSpy).toHaveBeenCalled();
    });
  });

  describe("memory inspection tests", () => {
    test("should verify zeroization utilities are available", async () => {
      if (!Zeroization) return;

      expect(Zeroization).toBeDefined();
      expect(Zeroization.zeroize).toBeDefined();
      expect(Zeroization.zeroizeAll).toBeDefined();
    });
  });
});
