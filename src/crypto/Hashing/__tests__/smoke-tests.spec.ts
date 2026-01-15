/**
 * Smoke tests for refactored crypto modules
 */

import {
  sha256Hash,
  sha512Hash,
} from "../Hashing";

import {
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt,
} from "../Asymmetric/RSA";

import {
  generateAESKey,
  aesEncrypt,
  aesDecrypt,
} from "../Symmetric/AES";

describe("Refactored Crypto Modules - Smoke Tests", () => {
  describe("Hashing", () => {
    it("SHA-256 should hash string", async () => {
      const hash = await sha256Hash("test");
      expect(hash).toBeTruthy();
      expect(hash.length).toBe(64);
    });

    it("SHA-512 should hash string", async () => {
      const hash = await sha512Hash("test");
      expect(hash).toBeTruthy();
      expect(hash.length).toBe(128);
    });
  });

  describe("RSA", () => {
    it("should generate key pair", async () => {
      const keyPair = await generateRSAKeyPair();
      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
    });
  });
  });

  describe("AES", () => {
    it("should generate key", async () => {
      const key = await generateAESKey();
      expect(key).toBeDefined();
      expect(key.key).toBeDefined();
    });

    it("should encrypt and decrypt message", async () => {
      const key = await generateAESKey();
      const message = "Hello, World!";
      const encrypted = await aesEncrypt(message, key);
      const decrypted = await aesDecrypt(encrypted.encrypted, key, encrypted.iv);
      expect(decrypted).toBe(message);
    });

    it("should use different IV each encryption", async () => {
      const key = await generateAESKey();
      const message = "Test";
      const encrypted1 = await aesEncrypt(message, key);
      const encrypted2 = await aesEncrypt(message, key);
      expect(encrypted1.iv).not.toEqual(encrypted2.iv);
      expect(encrypted1.encrypted).not.toEqual(encrypted2.encrypted);
    });
  });
});
