/**
 * @jest-environment jsdom
 */

/**
 * MLKEMCipherLayer Debug Logging Tests
 *
 * Tests for development-only debug logging functionality.
 * Verifies that debug logs are only shown in development mode.
 */

describe("MLKEMCipherLayer Debug Logging", () => {
  let MLKEMCipherLayer;
  let MlKem768;
  let originalConsoleError;

  beforeAll(async () => {
    // Save original console.error
    originalConsoleError = console.error;

    // Setup REAL Web Crypto API (override global mocks from setupTests.js)
    const { webcrypto } = await import("crypto");

    // Replace global crypto with real implementation
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== "undefined") {
      window.crypto = webcrypto;
    }

    // Import ML-KEM
    try {
      const mlkemModule = await import("@hpke/ml-kem");
      MlKem768 = mlkemModule.MlKem768;
    } catch (e) {
      MlKem768 = null;
    }

    // Dynamic import of MLKEMCipherLayer
    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      MLKEMCipherLayer = module.MLKEMCipherLayer;
    } catch (e) {
      MLKEMCipherLayer = null;
    }
  });

  beforeEach(() => {
    // Mock console.error to capture logs
    console.error = jest.fn();
  });

  afterEach(() => {
    // Restore console.error
    console.error.mockClear();
  });

  afterAll(() => {
    // Restore original console.error
    console.error = originalConsoleError;
  });

  test("should log debug information in development mode on encrypt error", async () => {
    if (!MLKEMCipherLayer || !MlKem768) {
      console.log("Skipping test: ML-KEM not available");
      return;
    }

    // Set NODE_ENV to development
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "development";

    try {
      const layer = new MLKEMCipherLayer();

      // Try to encrypt with invalid keys to trigger error
      await expect(
        layer.encrypt(new Uint8Array([1, 2, 3]), {}),
      ).rejects.toThrow();

      // Verify console.error was called
      expect(console.error).toHaveBeenCalled();

      // Verify the log contains expected fields
      const logCall = console.error.mock.calls[0];
      expect(logCall[0]).toContain("[MLKEMCipherLayer]");
      expect(logCall[1]).toHaveProperty("layer", "ML-KEM-768");
      expect(logCall[1]).toHaveProperty("operation", "encrypt");
      expect(logCall[1]).toHaveProperty("error");
      expect(logCall[1]).toHaveProperty("stack");

      // Verify no sensitive data is logged (no keys or secrets)
      const logString = JSON.stringify(logCall);
      expect(logString).not.toContain("publicKey");
      expect(logString).not.toContain("privateKey");
      expect(logString).not.toContain("sharedSecret");
    } finally {
      // Restore original NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  test("should log debug information in development mode on decrypt error", async () => {
    if (!MLKEMCipherLayer || !MlKem768) {
      console.log("Skipping test: ML-KEM not available");
      return;
    }

    // Set NODE_ENV to development
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "development";

    try {
      const layer = new MLKEMCipherLayer();

      // Try to decrypt with invalid payload to trigger error
      await expect(
        layer.decrypt(
          {
            ciphertext: new Uint8Array([1, 2, 3]),
            layerMetadata: {},
            parameters: {},
          },
          {},
        ),
      ).rejects.toThrow();

      // Verify console.error was called
      expect(console.error).toHaveBeenCalled();

      // Verify the log contains expected fields
      const logCall = console.error.mock.calls[0];
      expect(logCall[0]).toContain("[MLKEMCipherLayer]");
      expect(logCall[1]).toHaveProperty("layer", "ML-KEM-768");
      expect(logCall[1]).toHaveProperty("operation", "decrypt");
      expect(logCall[1]).toHaveProperty("error");
      expect(logCall[1]).toHaveProperty("stack");

      // Verify no sensitive data is logged (no keys or secrets)
      const logString = JSON.stringify(logCall);
      expect(logString).not.toContain("publicKey");
      expect(logString).not.toContain("privateKey");
      expect(logString).not.toContain("sharedSecret");
    } finally {
      // Restore original NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  test("should NOT log debug information in production mode on encrypt error", async () => {
    if (!MLKEMCipherLayer || !MlKem768) {
      console.log("Skipping test: ML-KEM not available");
      return;
    }

    // Set NODE_ENV to production
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    try {
      const layer = new MLKEMCipherLayer();

      // Try to encrypt with invalid keys to trigger error
      await expect(
        layer.encrypt(new Uint8Array([1, 2, 3]), {}),
      ).rejects.toThrow();

      // Verify console.error was NOT called
      expect(console.error).not.toHaveBeenCalled();
    } finally {
      // Restore original NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  test("should NOT log debug information in production mode on decrypt error", async () => {
    if (!MLKEMCipherLayer || !MlKem768) {
      console.log("Skipping test: ML-KEM not available");
      return;
    }

    // Set NODE_ENV to production
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    try {
      const layer = new MLKEMCipherLayer();

      // Try to decrypt with invalid payload to trigger error
      await expect(
        layer.decrypt(
          {
            ciphertext: new Uint8Array([1, 2, 3]),
            layerMetadata: {},
            parameters: {},
          },
          {},
        ),
      ).rejects.toThrow();

      // Verify console.error was NOT called
      expect(console.error).not.toHaveBeenCalled();
    } finally {
      // Restore original NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  test("should log error message but not sensitive data", async () => {
    if (!MLKEMCipherLayer || !MlKem768) {
      console.log("Skipping test: ML-KEM not available");
      return;
    }

    // Set NODE_ENV to development
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "development";

    try {
      const layer = new MLKEMCipherLayer();

      // Generate valid key pair
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      // Try to encrypt with malformed keys (wrong format) to trigger error
      await expect(
        layer.encrypt(new Uint8Array([1, 2, 3]), {
          publicKey: "invalid-key-format",
        }),
      ).rejects.toThrow();

      // Verify console.error was called
      expect(console.error).toHaveBeenCalled();

      // Verify the error message is logged
      const logCall = console.error.mock.calls[0];
      expect(logCall[1].error).toBeDefined();

      // Verify no sensitive data is in the logs
      const logString = JSON.stringify(logCall);
      expect(logString).not.toContain(keyPair.publicKey);
      expect(logString).not.toContain(keyPair.privateKey);
    } finally {
      // Restore original NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    }
  });
});
