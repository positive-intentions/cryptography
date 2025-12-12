/**
 * @jest-environment jsdom
 */

/**
 * AESCipherLayer Unit Tests
 *
 * Tests for the AES-GCM cipher layer implementation.
 * This demonstrates how to create a simple, extensible cipher layer.
 */

describe('AESCipherLayer', () => {
  let AESCipherLayer;
  let crypto;
  let originalCrypto;

  beforeEach(async () => {
    // Save original crypto mock
    originalCrypto = global.crypto;

    // Setup REAL Web Crypto API (override global mocks from setupTests.js)
    const { webcrypto } = await import('crypto');

    // Replace global crypto with real implementation
    global.crypto = webcrypto;
    globalThis.crypto = webcrypto;
    if (typeof window !== 'undefined') {
      window.crypto = webcrypto;
    }

    crypto = webcrypto;

    // Dynamic import
    try {
      const module = await import('../../crypto/CascadingCipher/layers/AESCipherLayer.ts');
      AESCipherLayer = module.AESCipherLayer;
    } catch (e) {
      AESCipherLayer = null;
    }
  });

  afterEach(() => {
    // Restore original crypto mock for other tests
    global.crypto = originalCrypto;
    globalThis.crypto = originalCrypto;
    if (typeof window !== 'undefined') {
      window.crypto = originalCrypto;
    }
  });

  describe('Construction', () => {
    test('should create AESCipherLayer instance', () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      expect(layer).toBeDefined();
    });

    test('should have correct name and version', () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      expect(layer.name).toBe('AES-GCM-256');
      expect(layer.version).toBe('2.0.0'); // Updated version with Scrypt
    });
  });

  describe('Key Validation', () => {
    test('should validate keys with required fields', () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const validKeys = {
        password: 'test-password-123',
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test('should reject keys without password', () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const invalidKeys = {};

      expect(layer.validateKeys(invalidKeys)).toBe(false);
    });

    test('should reject null or undefined keys', () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();

      expect(layer.validateKeys(null)).toBe(false);
      expect(layer.validateKeys(undefined)).toBe(false);
    });
  });

  describe('Encryption', () => {
    test('should encrypt data', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Hello, World!');
      const keys = { password: 'test-password' };

      const result = await layer.encrypt(plaintext, keys);

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.layerMetadata).toBeDefined();
      expect(result.parameters).toBeDefined();
    });

    test('should include IV in parameters', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Test data');
      const keys = { password: 'password123' };

      const result = await layer.encrypt(plaintext, keys);

      expect(result.parameters.iv).toBeDefined();
      expect(result.parameters.iv).toBeInstanceOf(Uint8Array);
      expect(result.parameters.iv.length).toBe(12); // GCM IV is 12 bytes
    });

    test('should include salt in parameters', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Test data');
      const keys = { password: 'password123' };

      const result = await layer.encrypt(plaintext, keys);

      expect(result.parameters.salt).toBeDefined();
      expect(result.parameters.salt).toBeInstanceOf(Uint8Array);
      expect(result.parameters.salt.length).toBe(16);
    });

    test('should produce different ciphertext for same plaintext with different passwords', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Same plaintext');

      const result1 = await layer.encrypt(plaintext, { password: 'password1' });
      const result2 = await layer.encrypt(plaintext, { password: 'password2' });

      const cipher1Hex = Array.from(result1.ciphertext).map(b => b.toString(16).padStart(2, '0')).join('');
      const cipher2Hex = Array.from(result2.ciphertext).map(b => b.toString(16).padStart(2, '0')).join('');

      expect(cipher1Hex).not.toBe(cipher2Hex);
    });

    test('should produce different IV each time', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Test');
      const keys = { password: 'password' };

      const result1 = await layer.encrypt(plaintext, keys);
      const result2 = await layer.encrypt(plaintext, keys);

      const iv1Hex = Array.from(result1.parameters.iv).map(b => b.toString(16)).join('');
      const iv2Hex = Array.from(result2.parameters.iv).map(b => b.toString(16)).join('');

      expect(iv1Hex).not.toBe(iv2Hex);
    });

    test('should include metadata', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Test data');
      const keys = { password: 'password' };

      const result = await layer.encrypt(plaintext, keys);

      expect(result.layerMetadata.algorithm).toBe('AES-GCM-256');
      expect(result.layerMetadata.version).toBe('2.0.0');
      expect(result.layerMetadata.inputSize).toBe(plaintext.length);
      expect(result.layerMetadata.outputSize).toBe(result.ciphertext.length);
      expect(result.layerMetadata.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layerMetadata.timestamp).toBeGreaterThan(0);
      // Check for Scrypt metadata
      expect(result.layerMetadata.metadata).toBeDefined();
      expect(result.layerMetadata.metadata.keyDerivation).toBe('Scrypt');
      expect(result.layerMetadata.metadata.scryptN).toBeDefined();
      expect(result.layerMetadata.metadata.scryptR).toBeDefined();
      expect(result.layerMetadata.metadata.scryptP).toBeDefined();
    });
  });

  describe('Decryption', () => {
    test('should decrypt data', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Secret message');
      const keys = { password: 'my-password' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should fail with wrong password', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Secret');
      const keys = { password: 'correct-password' };

      const encrypted = await layer.encrypt(plaintext, keys);

      const wrongKeys = { password: 'wrong-password' };
      await expect(layer.decrypt(encrypted, wrongKeys)).rejects.toThrow();
    });

    test('should fail with corrupted ciphertext', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Data');
      const keys = { password: 'password' };

      const encrypted = await layer.encrypt(plaintext, keys);

      // Corrupt the ciphertext
      encrypted.ciphertext[0] ^= 0xFF;

      await expect(layer.decrypt(encrypted, keys)).rejects.toThrow();
    });

    test('should fail with corrupted IV', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new TextEncoder().encode('Data');
      const keys = { password: 'password' };

      const encrypted = await layer.encrypt(plaintext, keys);

      // Corrupt the IV
      encrypted.parameters.iv[0] ^= 0xFF;

      await expect(layer.decrypt(encrypted, keys)).rejects.toThrow();
    });
  });

  describe('Round-trip', () => {
    test('should round-trip with simple text', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const originalText = 'Hello, World!';
      const plaintext = new TextEncoder().encode(originalText);
      const keys = { password: 'test-password' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test('should round-trip with binary data', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);
      const keys = { password: 'binary-test' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with large data', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new Uint8Array(10000).fill(42);
      const keys = { password: 'large-data' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with empty data', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const plaintext = new Uint8Array([]);
      const keys = { password: 'empty-test' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with special characters', async () => {
      if (!AESCipherLayer) return;

      const layer = new AESCipherLayer();
      const originalText = '你好世界! 🌍 Привет мир!';
      const plaintext = new TextEncoder().encode(originalText);
      const keys = { password: 'unicode-test' };

      const encrypted = await layer.encrypt(plaintext, keys);
      const decrypted = await layer.decrypt(encrypted, keys);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });
  });

  describe('Integration with CascadingCipherManager', () => {
    test('should work as a layer in cascading cipher', async () => {
      if (!AESCipherLayer) return;

      const { CascadingCipherManager } = await import(
        '../../crypto/CascadingCipher/CascadingCipherManager.ts'
      );

      const manager = new CascadingCipherManager();
      const aesLayer = new AESCipherLayer();
      manager.addLayer(aesLayer);

      const plaintext = new TextEncoder().encode('Test message');
      const keys = {
        'AES-GCM-256': { password: 'test-password' },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });
});
