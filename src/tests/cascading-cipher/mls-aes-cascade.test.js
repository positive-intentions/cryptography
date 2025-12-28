/**
 * @jest-environment jsdom
 */

/**
 * MLS-AES Cascade Unit Tests
 *
 * Isolated tests to debug and fix the cascade decryption issue
 * where AES decrypt produces corrupted data that MLS can't decrypt.
 */

describe("MLS-AES Cascade", () => {
  let MLSCipherLayer;
  let MLSManager;
  let AESCipherLayer;
  let CascadingCipherManager;

  beforeEach(async () => {
    // Setup Web Crypto API
    const { webcrypto } = await import("crypto");
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }

    // Import modules
    try {
      const mlsManagerModule = await import("../../crypto/MLS/MLSManager.tsx");
      MLSManager = mlsManagerModule.MLSManager;

      const layerModule = await import(
        "../../crypto/CascadingCipher/layers/MLSCipherLayer.ts"
      );
      MLSCipherLayer = layerModule.MLSCipherLayer;

      const aesModule = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );
      AESCipherLayer = aesModule.AESCipherLayer;

      const cascadeModule = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      CascadingCipherManager = cascadeModule.CascadingCipherManager;
    } catch (e) {
      console.error("Failed to import modules:", e);
    }
  });

  // Helper to setup a basic MLS group
  async function setupMLSGroup(groupId = "test-group") {
    const manager = new MLSManager("alice@example.com");
    await manager.initialize();
    await manager.createGroup(groupId);
    return { manager, groupId };
  }

  // Helper to convert Uint8Array to base64 string
  function uint8ArrayToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Helper to convert base64 string to Uint8Array
  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  describe("Data Format Preservation", () => {
    test("should preserve exact bytes through AES encrypt/decrypt", async () => {
      if (!AESCipherLayer) return;

      const aesLayer = new AESCipherLayer();
      const testData = new TextEncoder().encode("test-data-123");
      const keys = { password: "test-password" };

      // Encrypt
      const encrypted = await aesLayer.encrypt(testData, keys);

      // Decrypt
      const decrypted = await aesLayer.decrypt(encrypted, keys);

      // Verify exact byte preservation
      expect(Array.from(decrypted)).toEqual(Array.from(testData));
      expect(decrypted.length).toBe(testData.length);
    });

    test("should preserve MLS ciphertext format through AES encrypt/decrypt", async () => {
      if (!MLSCipherLayer || !MLSManager || !AESCipherLayer) return;

      const { manager, groupId } = await setupMLSGroup();
      const mlsLayer = new MLSCipherLayer(manager, groupId);
      const aesLayer = new AESCipherLayer();

      const plaintext = new TextEncoder().encode("test-plaintext");
      const mlsKeys = { mlsManager: manager, groupId };
      const aesKeys = { password: "test-password" };

      // MLS encrypt
      const mlsEncrypted = await mlsLayer.encrypt(plaintext, mlsKeys);
      const mlsCiphertext = mlsEncrypted.ciphertext;

      // Verify MLS ciphertext format (should be Uint8Array containing base64-encoded string)
      expect(mlsCiphertext).toBeDefined();
      expect(ArrayBuffer.isView(mlsCiphertext)).toBe(true);
      expect(mlsCiphertext.constructor.name).toBe("Uint8Array");
      expect(mlsCiphertext.length).toBeGreaterThan(0);

      // Try to decode as UTF-8 to verify it's a base64 string
      const mlsCiphertextStr = new TextDecoder().decode(mlsCiphertext);
      expect(mlsCiphertextStr).toBeTruthy();

      // AES encrypt MLS ciphertext
      const aesEncrypted = await aesLayer.encrypt(mlsCiphertext, aesKeys);

      // AES decrypt
      const aesDecrypted = await aesLayer.decrypt(aesEncrypted, aesKeys);

      // Verify exact byte preservation
      expect(aesDecrypted.length).toBe(mlsCiphertext.length);
      expect(Array.from(aesDecrypted)).toEqual(Array.from(mlsCiphertext));

      // Verify the decrypted data can be decoded as UTF-8 (base64 string)
      const decryptedStr = new TextDecoder().decode(aesDecrypted);
      expect(decryptedStr).toBe(mlsCiphertextStr);
    });
  });

  describe("MLS → AES Cascade", () => {
    test("should encrypt and decrypt MLS → AES cascade", async () => {
      if (
        !MLSCipherLayer ||
        !MLSManager ||
        !AESCipherLayer ||
        !CascadingCipherManager
      )
        return;

      const { manager, groupId } = await setupMLSGroup();
      const cascadeManager = new CascadingCipherManager();

      const mlsLayer = new MLSCipherLayer(manager, groupId);
      const aesLayer = new AESCipherLayer();

      cascadeManager.addLayer(mlsLayer);
      cascadeManager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode("MLS then AES test");
      const keys = {
        MLS: { mlsManager: manager, groupId },
        "AES-GCM-256": { password: "test-password" },
      };

      // Encrypt
      const encrypted = await cascadeManager.encrypt(plaintext, keys);

      // Verify encryption produced valid payload
      expect(encrypted).toBeDefined();
      expect(encrypted.finalCiphertext).toBeInstanceOf(Uint8Array);
      expect(encrypted.layers.length).toBe(2);
      expect(encrypted.layerParameters.length).toBe(2);

      // Decrypt
      const decrypted = await cascadeManager.decrypt(encrypted, keys);

      // Verify decryption
      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should trace data format at each step", async () => {
      if (
        !MLSCipherLayer ||
        !MLSManager ||
        !AESCipherLayer ||
        !CascadingCipherManager
      )
        return;

      const { manager, groupId } = await setupMLSGroup();
      const mlsLayer = new MLSCipherLayer(manager, groupId);
      const aesLayer = new AESCipherLayer();

      const plaintext = new TextEncoder().encode("trace-test");
      const mlsKeys = { mlsManager: manager, groupId };
      const aesKeys = { password: "test-password" };

      // Step 1: MLS encrypt
      const mlsEncrypted = await mlsLayer.encrypt(plaintext, mlsKeys);
      const mlsCiphertext = mlsEncrypted.ciphertext;
      const mlsCiphertextStr = new TextDecoder().decode(mlsCiphertext);
      console.log("MLS ciphertext length:", mlsCiphertext.length);
      console.log(
        "MLS ciphertext (first 50 chars):",
        mlsCiphertextStr.substring(0, 50),
      );

      // Step 2: AES encrypt MLS ciphertext
      const aesEncrypted = await aesLayer.encrypt(mlsCiphertext, aesKeys);
      console.log("AES ciphertext length:", aesEncrypted.ciphertext.length);

      // Step 3: AES decrypt
      const aesDecrypted = await aesLayer.decrypt(aesEncrypted, aesKeys);
      console.log("AES decrypted length:", aesDecrypted.length);
      console.log(
        "AES decrypted matches MLS ciphertext:",
        Array.from(aesDecrypted).every((byte, i) => byte === mlsCiphertext[i]),
      );

      // Step 4: Try to decode AES decrypted as UTF-8
      let aesDecryptedStr;
      try {
        aesDecryptedStr = new TextDecoder().decode(aesDecrypted);
        console.log(
          "AES decrypted as UTF-8 (first 50 chars):",
          aesDecryptedStr.substring(0, 50),
        );
      } catch (e) {
        console.log("Failed to decode AES decrypted as UTF-8:", e.message);
      }

      // Step 5: MLS decrypt
      const mlsDecrypted = await mlsLayer.decrypt(
        {
          ciphertext: aesDecrypted,
          layerMetadata: mlsEncrypted.layerMetadata,
          parameters: mlsEncrypted.parameters,
        },
        mlsKeys,
      );

      expect(Array.from(mlsDecrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe("AES → MLS Cascade", () => {
    test("should encrypt and decrypt AES → MLS cascade", async () => {
      if (
        !MLSCipherLayer ||
        !MLSManager ||
        !AESCipherLayer ||
        !CascadingCipherManager
      )
        return;

      const { manager, groupId } = await setupMLSGroup();
      const cascadeManager = new CascadingCipherManager();

      const aesLayer = new AESCipherLayer();
      const mlsLayer = new MLSCipherLayer(manager, groupId);

      cascadeManager.addLayer(aesLayer);
      cascadeManager.addLayer(mlsLayer);

      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);
      const keys = {
        "AES-GCM-256": { password: "test-password" },
        MLS: { mlsManager: manager, groupId },
      };

      // Encrypt
      const encrypted = await cascadeManager.encrypt(plaintext, keys);

      // Decrypt
      const decrypted = await cascadeManager.decrypt(encrypted, keys);

      // Verify
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });
});
