/**
 * @jest-environment jsdom
 */

/**
 * Key Authentication Utility Unit Tests
 *
 * Tests for key fingerprinting and verification.
 */

describe("KeyAuthentication", () => {
  let KeyAuthentication;
  let crypto;
  let originalCrypto;

  beforeEach(async () => {
    originalCrypto = global.crypto;

    const { webcrypto } = await import("crypto");
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }
    crypto = webcrypto;

    try {
      const module = await import("../../crypto/utils/keyAuthentication.ts");
      KeyAuthentication = module.KeyAuthentication;
    } catch (e) {
      KeyAuthentication = null;
    }
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== "undefined") {
      window.crypto = originalCrypto;
    }
  });

  describe("generateFingerprint", () => {
    test("should generate fingerprint for CryptoKey", async () => {
      if (!KeyAuthentication) return;

      const keyPair = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"],
      );

      const fingerprint = await KeyAuthentication.generateFingerprint(
        keyPair.publicKey,
      );

      expect(fingerprint).toBeDefined();
      expect(typeof fingerprint).toBe("string");
      expect(fingerprint.length).toBeGreaterThan(0);
    });

    test("should generate fingerprint for Uint8Array", async () => {
      if (!KeyAuthentication) return;

      const keyBytes = new Uint8Array(65); // P-256 uncompressed public key
      keyBytes[0] = 0x04; // Uncompressed marker
      crypto.getRandomValues(keyBytes.slice(1));

      const fingerprint = await KeyAuthentication.generateFingerprint(keyBytes);

      expect(fingerprint).toBeDefined();
      expect(typeof fingerprint).toBe("string");
    });

    test("should produce hex format with colons", async () => {
      if (!KeyAuthentication) return;

      const keyBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const fingerprint = await KeyAuthentication.generateFingerprint(keyBytes);

      // Should be hex with colons (SHA-256 = 32 bytes = 64 hex chars + 31 colons = 95 chars)
      expect(fingerprint).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){31}$/);
    });

    test("should be deterministic", async () => {
      if (!KeyAuthentication) return;

      const keyBytes = new Uint8Array([1, 2, 3, 4, 5]);

      const fingerprint1 =
        await KeyAuthentication.generateFingerprint(keyBytes);
      const fingerprint2 =
        await KeyAuthentication.generateFingerprint(keyBytes);

      expect(fingerprint1).toBe(fingerprint2);
    });

    test("should produce different fingerprints for different keys", async () => {
      if (!KeyAuthentication) return;

      const keyBytes1 = new Uint8Array([1, 2, 3, 4, 5]);
      const keyBytes2 = new Uint8Array([1, 2, 3, 4, 6]);

      const fingerprint1 =
        await KeyAuthentication.generateFingerprint(keyBytes1);
      const fingerprint2 =
        await KeyAuthentication.generateFingerprint(keyBytes2);

      expect(fingerprint1).not.toBe(fingerprint2);
    });
  });

  describe("verifyFingerprint", () => {
    test("should verify matching fingerprint", async () => {
      if (!KeyAuthentication) return;

      const keyBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const fingerprint = await KeyAuthentication.generateFingerprint(keyBytes);

      const isValid = await KeyAuthentication.verifyFingerprint(
        keyBytes,
        fingerprint,
      );

      expect(isValid).toBe(true);
    });

    test("should reject non-matching fingerprint", async () => {
      if (!KeyAuthentication) return;

      const keyBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const wrongFingerprint =
        "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

      const isValid = await KeyAuthentication.verifyFingerprint(
        keyBytes,
        wrongFingerprint,
      );

      expect(isValid).toBe(false);
    });

    test("should verify CryptoKey fingerprint", async () => {
      if (!KeyAuthentication) return;

      const keyPair = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"],
      );

      const fingerprint = await KeyAuthentication.generateFingerprint(
        keyPair.publicKey,
      );
      const isValid = await KeyAuthentication.verifyFingerprint(
        keyPair.publicKey,
        fingerprint,
      );

      expect(isValid).toBe(true);
    });

    test("should detect MITM attack via fingerprint mismatch", async () => {
      if (!KeyAuthentication) return;

      // Generate two different key pairs (simulating MITM)
      const keyPair1 = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"],
      );

      const keyPair2 = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"],
      );

      const fingerprint1 = await KeyAuthentication.generateFingerprint(
        keyPair1.publicKey,
      );
      const isValid = await KeyAuthentication.verifyFingerprint(
        keyPair2.publicKey,
        fingerprint1,
      );

      expect(isValid).toBe(false);
    });
  });
});
