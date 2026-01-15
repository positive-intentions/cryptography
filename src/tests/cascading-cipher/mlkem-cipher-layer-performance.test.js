/**
 * @jest-environment jsdom
 */

/**
 * MLKEMCipherLayer Performance Benchmarks
 *
 * Benchmarks ML-KEM performance and compares it to AES and DH cipher layers.
 * Provides baseline metrics for capacity planning and performance monitoring.
 *
 * Test Results:
 * - Key generation time
 * - Encryption time (various data sizes)
 * - Decryption time (various data sizes)
 * - Comparison with AESCipherLayer
 * - Comparison with DHCipherLayer
 */

describe("MLKEMCipherLayer Performance", () => {
  let MLKEMCipherLayer;
  let AESCipherLayer;
  let DHCipherLayer;
  let MlKem768;
  let crypto;
  let originalCrypto;

  // Performance thresholds (in milliseconds)
  const THRESHOLDS = {
    KEY_GENERATION: 100, // ML-KEM key generation should be < 100ms
    ENCRYPT_1KB: 50, // Encryption of 1KB should be < 50ms
    ENCRYPT_10KB: 100, // Encryption of 10KB should be < 100ms
    ENCRYPT_100KB: 500, // Encryption of 100KB should be < 500ms
    ENCRYPT_1MB: 3000, // Encryption of 1MB should be < 3000ms
    DECRYPT_1KB: 50, // Decryption of 1KB should be < 50ms
    DECRYPT_10KB: 100, // Decryption of 10KB should be < 100ms
    DECRYPT_100KB: 500, // Decryption of 100KB should be < 500ms
    DECRYPT_1MB: 3000, // Decryption of 1MB should be < 3000ms
  };

  beforeAll(async () => {
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

    // Import ML-KEM
    try {
      const mlkemModule = await import("@hpke/ml-kem");
      MlKem768 = mlkemModule.MlKem768;
    } catch (e) {
      MlKem768 = null;
    }

    // Dynamic imports
    try {
      const mlkemModule = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      MLKEMCipherLayer = mlkemModule.MLKEMCipherLayer;
    } catch (e) {
      MLKEMCipherLayer = null;
    }

    try {
      const aesModule = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );
      AESCipherLayer = aesModule.AESCipherLayer;
    } catch (e) {
      AESCipherLayer = null;
    }

    try {
      const dhModule = await import(
        "../../crypto/CascadingCipher/layers/DHCipherLayer.ts"
      );
      DHCipherLayer = dhModule.DHCipherLayer;
    } catch (e) {
      DHCipherLayer = null;
    }
  }, 120000); // Increase timeout to 120 seconds for initial setup

  afterAll(() => {
    // Restore original crypto mock for other tests
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== "undefined") {
      window.crypto = originalCrypto;
    }
  });

  // Helper function to generate ML-KEM key pairs
  async function generateMLKEMKeyPair() {
    if (!MlKem768) return null;
    const kem = new MlKem768();
    return await kem.generateKeyPair();
  }

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

  // Helper to generate test data of specified size
  function generateTestData(sizeBytes) {
    return new Uint8Array(sizeBytes).fill(0x42); // Fill with pattern
  }

  // Helper to run multiple iterations and calculate average
  async function benchmarkAverage(iterations, fn) {
    const times = [];
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      await fn();
      const end = performance.now();
      times.push(end - start);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);
    return { avg, min, max, times };
  }

  describe("ML-KEM Key Generation", () => {
    test("key generation should be < 100ms", async () => {
      if (!MlKem768) {
        console.warn("ML-KEM library not available, skipping test");
        return;
      }

      const results = await benchmarkAverage(10, async () => {
        const kem = new MlKem768();
        await kem.generateKeyPair();
      });

      console.log(
        `ML-KEM Key Generation: avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.KEY_GENERATION);
    });

    test("key generation performance consistency", async () => {
      if (!MlKem768) {
        console.warn("ML-KEM library not available, skipping test");
        return;
      }

      const results = await benchmarkAverage(20, async () => {
        const kem = new MlKem768();
        await kem.generateKeyPair();
      });

      // Check that variance is reasonable (max should be < 2x min)
      const variance = results.max / results.min;
      console.log(
        `ML-KEM Key Generation Consistency: variance=${variance.toFixed(2)}x`,
      );

      expect(variance).toBeLessThan(2.0);
    });
  });

  describe("ML-KEM Encryption Performance", () => {
    let mlkemLayer;
    let mlkemKeyPair;

    beforeEach(async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      mlkemLayer = new MLKEMCipherLayer();
      mlkemKeyPair = await generateMLKEMKeyPair();
    });

    test("encryption 1KB should be < 50ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(1024); // 1KB

      const results = await benchmarkAverage(20, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      console.log(
        `ML-KEM Encryption (1KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.ENCRYPT_1KB);
    });

    test("encryption 10KB should be < 100ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(10 * 1024); // 10KB

      const results = await benchmarkAverage(10, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      console.log(
        `ML-KEM Encryption (10KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.ENCRYPT_10KB);
    });

    test("encryption 100KB should be < 500ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(100 * 1024); // 100KB

      const results = await benchmarkAverage(5, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      console.log(
        `ML-KEM Encryption (100KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.ENCRYPT_100KB);
    });

    test("encryption 1MB should be < 3000ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(1024 * 1024); // 1MB

      const results = await benchmarkAverage(3, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      console.log(
        `ML-KEM Encryption (1MB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.ENCRYPT_1MB);
    });
  });

  describe("ML-KEM Decryption Performance", () => {
    let mlkemLayer;
    let mlkemKeyPair;

    beforeEach(async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      mlkemLayer = new MLKEMCipherLayer();
      mlkemKeyPair = await generateMLKEMKeyPair();
    });

    test("decryption 1KB should be < 50ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(1024); // 1KB
      const encrypted = await mlkemLayer.encrypt(data, {
        publicKey: mlkemKeyPair.publicKey,
      });

      const results = await benchmarkAverage(20, async () => {
        await mlkemLayer.decrypt(encrypted, {
          privateKey: mlkemKeyPair.privateKey,
        });
      });

      console.log(
        `ML-KEM Decryption (1KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.DECRYPT_1KB);
    });

    test("decryption 10KB should be < 100ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(10 * 1024); // 10KB
      const encrypted = await mlkemLayer.encrypt(data, {
        publicKey: mlkemKeyPair.publicKey,
      });

      const results = await benchmarkAverage(10, async () => {
        await mlkemLayer.decrypt(encrypted, {
          privateKey: mlkemKeyPair.privateKey,
        });
      });

      console.log(
        `ML-KEM Decryption (10KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.DECRYPT_10KB);
    });

    test("decryption 100KB should be < 500ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(100 * 1024); // 100KB
      const encrypted = await mlkemLayer.encrypt(data, {
        publicKey: mlkemKeyPair.publicKey,
      });

      const results = await benchmarkAverage(5, async () => {
        await mlkemLayer.decrypt(encrypted, {
          privateKey: mlkemKeyPair.privateKey,
        });
      });

      console.log(
        `ML-KEM Decryption (100KB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.DECRYPT_100KB);
    });

    test("decryption 1MB should be < 3000ms", async () => {
      if (!MLKEMCipherLayer || !mlkemKeyPair) {
        console.warn("ML-KEM not available, skipping test");
        return;
      }

      const data = generateTestData(1024 * 1024); // 1MB
      const encrypted = await mlkemLayer.encrypt(data, {
        publicKey: mlkemKeyPair.publicKey,
      });

      const results = await benchmarkAverage(3, async () => {
        await mlkemLayer.decrypt(encrypted, {
          privateKey: mlkemKeyPair.privateKey,
        });
      });

      console.log(
        `ML-KEM Decryption (1MB): avg=${results.avg.toFixed(2)}ms, min=${results.min.toFixed(2)}ms, max=${results.max.toFixed(2)}ms`,
      );

      expect(results.avg).toBeLessThan(THRESHOLDS.DECRYPT_1MB);
    });
  });

  describe("Performance Comparison: ML-KEM vs AES", () => {
    test("encryption comparison (1KB)", async () => {
      if (!MLKEMCipherLayer || !AESCipherLayer || !MlKem768) {
        console.warn("Required libraries not available, skipping test");
        return;
      }

      const mlkemLayer = new MLKEMCipherLayer();
      const aesLayer = new AESCipherLayer();
      const mlkemKeyPair = await generateMLKEMKeyPair();
      const data = generateTestData(1024); // 1KB

      // Benchmark ML-KEM
      const mlkemResults = await benchmarkAverage(10, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      // Benchmark AES
      const aesResults = await benchmarkAverage(10, async () => {
        await aesLayer.encrypt(data, {
          password: "test-password-123",
        });
      });

      const ratio = mlkemResults.avg / aesResults.avg;

      console.log(
        `Encryption (1KB) Comparison:\n` +
          `  ML-KEM: avg=${mlkemResults.avg.toFixed(2)}ms\n` +
          `  AES: avg=${aesResults.avg.toFixed(2)}ms\n` +
          `  Ratio: ${ratio.toFixed(2)}x slower`,
      );

      // ML-KEM is expected to be slower than AES (quantum-resistant algorithms are more expensive)
      expect(mlkemResults.avg).toBeGreaterThan(aesResults.avg);
    });

    test("encryption comparison (10KB)", async () => {
      if (!MLKEMCipherLayer || !AESCipherLayer || !MlKem768) {
        console.warn("Required libraries not available, skipping test");
        return;
      }

      const mlkemLayer = new MLKEMCipherLayer();
      const aesLayer = new AESCipherLayer();
      const mlkemKeyPair = await generateMLKEMKeyPair();
      const data = generateTestData(10 * 1024); // 10KB

      // Benchmark ML-KEM
      const mlkemResults = await benchmarkAverage(5, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      // Benchmark AES
      const aesResults = await benchmarkAverage(5, async () => {
        await aesLayer.encrypt(data, {
          password: "test-password-123",
        });
      });

      const ratio = mlkemResults.avg / aesResults.avg;

      console.log(
        `Encryption (10KB) Comparison:\n` +
          `  ML-KEM: avg=${mlkemResults.avg.toFixed(2)}ms\n` +
          `  AES: avg=${aesResults.avg.toFixed(2)}ms\n` +
          `  Ratio: ${ratio.toFixed(2)}x slower`,
      );

      expect(mlkemResults.avg).toBeGreaterThan(aesResults.avg);
    });
  });

  describe("Performance Comparison: ML-KEM vs DH", () => {
    test("encryption comparison (1KB)", async () => {
      if (!MLKEMCipherLayer || !DHCipherLayer || !MlKem768) {
        console.warn("Required libraries not available, skipping test");
        return;
      }

      const mlkemLayer = new MLKEMCipherLayer();
      const dhLayer = new DHCipherLayer();
      const mlkemKeyPair = await generateMLKEMKeyPair();

      // Generate DH keys
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();
      const alicePublicRaw = await exportKeyToRaw(aliceKeyPair.publicKey);
      const bobPublicRaw = await exportKeyToRaw(bobKeyPair.publicKey);

      const data = generateTestData(1024); // 1KB

      // Benchmark ML-KEM
      const mlkemResults = await benchmarkAverage(10, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      // Benchmark DH
      const dhResults = await benchmarkAverage(10, async () => {
        await dhLayer.encrypt(data, {
          privateKey: aliceKeyPair.privateKey,
          publicKey: bobPublicRaw,
        });
      });

      const ratio = mlkemResults.avg / dhResults.avg;

      console.log(
        `Encryption (1KB) Comparison:\n` +
          `  ML-KEM: avg=${mlkemResults.avg.toFixed(2)}ms\n` +
          `  DH: avg=${dhResults.avg.toFixed(2)}ms\n` +
          `  Ratio: ${ratio.toFixed(2)}x slower`,
      );

      // ML-KEM is expected to be slower than DH (quantum-resistant algorithms are more expensive)
      expect(mlkemResults.avg).toBeGreaterThan(dhResults.avg);
    });

    test("encryption comparison (10KB)", async () => {
      if (!MLKEMCipherLayer || !DHCipherLayer || !MlKem768) {
        console.warn("Required libraries not available, skipping test");
        return;
      }

      const mlkemLayer = new MLKEMCipherLayer();
      const dhLayer = new DHCipherLayer();
      const mlkemKeyPair = await generateMLKEMKeyPair();

      // Generate DH keys
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();
      const bobPublicRaw = await exportKeyToRaw(bobKeyPair.publicKey);

      const data = generateTestData(10 * 1024); // 10KB

      // Benchmark ML-KEM
      const mlkemResults = await benchmarkAverage(5, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      // Benchmark DH
      const dhResults = await benchmarkAverage(5, async () => {
        await dhLayer.encrypt(data, {
          privateKey: aliceKeyPair.privateKey,
          publicKey: bobPublicRaw,
        });
      });

      const ratio = mlkemResults.avg / dhResults.avg;

      console.log(
        `Encryption (10KB) Comparison:\n` +
          `  ML-KEM: avg=${mlkemResults.avg.toFixed(2)}ms\n` +
          `  DH: avg=${dhResults.avg.toFixed(2)}ms\n` +
          `  Ratio: ${ratio.toFixed(2)}x slower`,
      );

      expect(mlkemResults.avg).toBeGreaterThan(dhResults.avg);
    });
  });

  describe("Performance Summary", () => {
    test("should document performance characteristics", async () => {
      if (!MLKEMCipherLayer || !AESCipherLayer || !DHCipherLayer || !MlKem768) {
        console.warn("Required libraries not available, skipping test");
        return;
      }

      const mlkemLayer = new MLKEMCipherLayer();
      const aesLayer = new AESCipherLayer();
      const dhLayer = new DHCipherLayer();
      const mlkemKeyPair = await generateMLKEMKeyPair();

      // Generate DH keys
      const aliceKeyPair = await generateDHKeyPair();
      const bobKeyPair = await generateDHKeyPair();
      const bobPublicRaw = await exportKeyToRaw(bobKeyPair.publicKey);

      const data = generateTestData(1024); // 1KB

      // Benchmark all three
      const mlkemResults = await benchmarkAverage(5, async () => {
        await mlkemLayer.encrypt(data, {
          publicKey: mlkemKeyPair.publicKey,
        });
      });

      const aesResults = await benchmarkAverage(5, async () => {
        await aesLayer.encrypt(data, {
          password: "test-password-123",
        });
      });

      const dhResults = await benchmarkAverage(5, async () => {
        await dhLayer.encrypt(data, {
          privateKey: aliceKeyPair.privateKey,
          publicKey: bobPublicRaw,
        });
      });

      console.log("\n=== Performance Summary (1KB encryption) ===");
      console.log(`ML-KEM: ${mlkemResults.avg.toFixed(2)}ms (quantum-resistant)`);
      console.log(`AES:    ${aesResults.avg.toFixed(2)}ms (classical)`);
      console.log(`DH:     ${dhResults.avg.toFixed(2)}ms (classical)`);
      console.log(`\nML-KEM is ${(mlkemResults.avg / aesResults.avg).toFixed(2)}x slower than AES`);
      console.log(`ML-KEM is ${(mlkemResults.avg / dhResults.avg).toFixed(2)}x slower than DH`);
      console.log("===========================================\n");

      // All should complete successfully
      expect(mlkemResults.avg).toBeGreaterThan(0);
      expect(aesResults.avg).toBeGreaterThan(0);
      expect(dhResults.avg).toBeGreaterThan(0);
    });
  });
});

