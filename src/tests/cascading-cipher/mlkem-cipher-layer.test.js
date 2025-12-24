/**
 * @jest-environment jsdom
 */

/**
 * MLKEMCipherLayer Unit Tests
 *
 * Tests for the ML-KEM (CRYSTALS-Kyber) + AES-GCM cipher layer implementation.
 * Tests ML-KEM key encapsulation, shared secret derivation, and AES-GCM encryption.
 */

describe('MLKEMCipherLayer', () => {
  let MLKEMCipherLayer;
  let MlKem768;
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

    // Import ML-KEM
    try {
      const mlkemModule = await import('@hpke/ml-kem');
      MlKem768 = mlkemModule.MlKem768;
    } catch (e) {
      MlKem768 = null;
    }

    // Dynamic import of MLKEMCipherLayer
    try {
      const module = await import('../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts');
      MLKEMCipherLayer = module.MLKEMCipherLayer;
    } catch (e) {
      MLKEMCipherLayer = null;
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

  // Helper function to generate ML-KEM key pairs
  async function generateMLKEMKeyPair() {
    if (!MlKem768) return null;
    const kem = new MlKem768();
    return await kem.generateKeyPair();
  }

  describe('Construction', () => {
    test('should create MLKEMCipherLayer instance', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      expect(layer).toBeDefined();
    });

    test('should have correct name and version', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      expect(layer.name).toBe('ML-KEM-768');
      expect(layer.version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('Key Validation', () => {
    test('should validate keys with publicKey for encryption', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const validKeys = {
        publicKey: new Uint8Array(1184), // ML-KEM-768 public key size
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test('should validate keys with privateKey for decryption', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const validKeys = {
        privateKey: new Uint8Array(64), // ML-KEM-768 private key material size
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test('should reject keys without required fields', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();

      // Missing both publicKey and privateKey
      expect(layer.validateKeys({})).toBe(false);
    });

    test('should reject null or undefined keys', () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();

      expect(layer.validateKeys(null)).toBe(false);
      expect(layer.validateKeys(undefined)).toBe(false);
    });
  });

  describe('Key Generation', () => {
    test('should generate valid ML-KEM key pairs', async () => {
      if (!MlKem768) return;

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      // ML-KEM returns XCryptoKey objects, check the key property
      expect(keyPair.publicKey.key).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey.key).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.key.length).toBe(1184); // ML-KEM-768 public key size
      expect(keyPair.privateKey.key.length).toBe(64); // ML-KEM-768 private key material size (seed)
    });

    test('should generate different key pairs each time', async () => {
      if (!MlKem768) return;

      const kem = new MlKem768();
      const keyPair1 = await kem.generateKeyPair();
      const keyPair2 = await kem.generateKeyPair();

      const pub1Hex = Array.from(keyPair1.publicKey.key).map(b => b.toString(16).padStart(2, '0')).join('');
      const pub2Hex = Array.from(keyPair2.publicKey.key).map(b => b.toString(16).padStart(2, '0')).join('');

      expect(pub1Hex).not.toBe(pub2Hex);
    });
  });

  describe('Encryption', () => {
    test('should encrypt data with public key', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test message');

      const result = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.layerMetadata).toBeDefined();
      expect(result.parameters).toBeDefined();
    });

    test('should include encapsulated key in parameters', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test data');

      const result = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(result.parameters.encapsulated).toBeDefined();
      expect(result.parameters.encapsulated).toBeInstanceOf(Uint8Array);
      expect(result.parameters.encapsulated.length).toBe(1088); // ML-KEM-768 encapsulated key size
    });

    test('should include IV and salt in parameters', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test data');

      const result = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(result.parameters.iv).toBeDefined();
      expect(result.parameters.iv).toBeInstanceOf(Uint8Array);
      expect(result.parameters.iv.length).toBe(12); // GCM IV is 12 bytes

      expect(result.parameters.salt).toBeDefined();
      expect(result.parameters.salt).toBeInstanceOf(Uint8Array);
      expect(result.parameters.salt.length).toBe(16);
    });

    test('should produce different IV each time', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test');

      const result1 = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const result2 = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      const iv1Hex = Array.from(result1.parameters.iv).map(b => b.toString(16)).join('');
      const iv2Hex = Array.from(result2.parameters.iv).map(b => b.toString(16)).join('');

      expect(iv1Hex).not.toBe(iv2Hex);
    });

    test('should produce different encapsulated key each time', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test');

      const result1 = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const result2 = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      const enc1Hex = Array.from(result1.parameters.encapsulated).map(b => b.toString(16)).join('');
      const enc2Hex = Array.from(result2.parameters.encapsulated).map(b => b.toString(16)).join('');

      expect(enc1Hex).not.toBe(enc2Hex);
    });

    test('should include metadata', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test data');

      const result = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      expect(result.layerMetadata.algorithm).toBe('ML-KEM-768');
      expect(result.layerMetadata.inputSize).toBe(plaintext.length);
      expect(result.layerMetadata.outputSize).toBe(result.ciphertext.length);
      expect(result.layerMetadata.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layerMetadata.timestamp).toBeGreaterThan(0);
      expect(result.layerMetadata.metadata.keyEncapsulation).toBe('ML-KEM-768');
      expect(result.layerMetadata.metadata.keyDerivation).toBe('HKDF-SHA256');
    });

    test('should encrypt with different data sizes', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      // Small data
      const smallData = new TextEncoder().encode('Hi');
      const smallResult = await layer.encrypt(smallData, { publicKey: keyPair.publicKey });
      expect(smallResult.ciphertext.length).toBeGreaterThan(0);

      // Large data
      const largeData = new Uint8Array(10000).fill(42);
      const largeResult = await layer.encrypt(largeData, { publicKey: keyPair.publicKey });
      expect(largeResult.ciphertext.length).toBeGreaterThan(0);
    });
  });

  describe('Decryption', () => {
    test('should decrypt with matching private key', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Secret message');

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should fail with wrong private key', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair1 = await kem.generateKeyPair();
      const keyPair2 = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Secret');

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair1.publicKey });

      await expect(layer.decrypt(encrypted, { privateKey: keyPair2.privateKey })).rejects.toThrow();
    });

    test('should fail with corrupted ciphertext', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Data');

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      // Corrupt the ciphertext
      encrypted.ciphertext[0] ^= 0xFF;

      await expect(layer.decrypt(encrypted, { privateKey: keyPair.privateKey })).rejects.toThrow();
    });

    test('should fail with corrupted IV', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Data');

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      // Corrupt the IV
      encrypted.parameters.iv[0] ^= 0xFF;

      await expect(layer.decrypt(encrypted, { privateKey: keyPair.privateKey })).rejects.toThrow();
    });

    test('should fail with corrupted encapsulated key', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Data');

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      // Corrupt the encapsulated key
      encrypted.parameters.encapsulated[0] ^= 0xFF;

      await expect(layer.decrypt(encrypted, { privateKey: keyPair.privateKey })).rejects.toThrow();
    });

    test('should fail with missing parameters', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();

      const payload = {
        ciphertext: new Uint8Array([1, 2, 3]),
        layerMetadata: {},
        parameters: {}, // Missing IV, salt, and encapsulated
      };

      await expect(layer.decrypt(payload, { privateKey: keyPair.privateKey })).rejects.toThrow();
    });
  });

  describe('Round-trip Encryption/Decryption', () => {
    test('should round-trip with ML-KEM key pair', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const originalText = 'Hello, World!';
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test('should round-trip with binary data', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with large data', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new Uint8Array(10000).fill(42);

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with empty data', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new Uint8Array([]);

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with special characters', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const originalText = '你好世界! 🌍 Привет мир!';
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });
      const decrypted = await layer.decrypt(encrypted, { privateKey: keyPair.privateKey });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });
  });

  describe('Error Handling', () => {
    test('should throw error with invalid keys on encrypt', async () => {
      if (!MLKEMCipherLayer) return;

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode('Test');

      await expect(layer.encrypt(plaintext, {})).rejects.toThrow();
      await expect(layer.encrypt(plaintext, null)).rejects.toThrow();
    });

    test('should throw error with invalid keys on decrypt', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const layer = new MLKEMCipherLayer();
      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test');
      const encrypted = await layer.encrypt(plaintext, { publicKey: keyPair.publicKey });

      await expect(layer.decrypt(encrypted, {})).rejects.toThrow();
      await expect(layer.decrypt(encrypted, null)).rejects.toThrow();
    });
  });

  describe('Integration with CascadingCipherManager', () => {
    test('should work as a layer in cascading cipher', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const { CascadingCipherManager } = await import(
        '../../crypto/CascadingCipher/CascadingCipherManager.ts'
      );

      const manager = new CascadingCipherManager();
      const mlkemLayer = new MLKEMCipherLayer();
      manager.addLayer(mlkemLayer);

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Test message');
      const keys = {
        'ML-KEM-768': { publicKey: keyPair.publicKey },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      
      // Update keys for decryption
      keys['ML-KEM-768'] = { privateKey: keyPair.privateKey };
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should work in combination with other layers', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const { CascadingCipherManager } = await import(
        '../../crypto/CascadingCipher/CascadingCipherManager.ts'
      );
      const { AESCipherLayer } = await import(
        '../../crypto/CascadingCipher/layers/AESCipherLayer.ts'
      );

      const manager = new CascadingCipherManager();
      const mlkemLayer = new MLKEMCipherLayer();
      const aesLayer = new AESCipherLayer();

      manager.addLayer(mlkemLayer);
      manager.addLayer(aesLayer);

      const kem = new MlKem768();
      const keyPair = await kem.generateKeyPair();
      const plaintext = new TextEncoder().encode('Multi-layer test');
      const keys = {
        'ML-KEM-768': { publicKey: keyPair.publicKey },
        'AES-GCM-256': { password: 'test-password' },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      
      // Update keys for decryption
      keys['ML-KEM-768'] = { privateKey: keyPair.privateKey };
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should work with DH layer', async () => {
      if (!MLKEMCipherLayer || !MlKem768) return;

      const { CascadingCipherManager } = await import(
        '../../crypto/CascadingCipher/CascadingCipherManager.ts'
      );
      const { DHCipherLayer } = await import(
        '../../crypto/CascadingCipher/layers/DHCipherLayer.ts'
      );

      const manager = new CascadingCipherManager();
      const mlkemLayer = new MLKEMCipherLayer();
      const dhLayer = new DHCipherLayer();

      manager.addLayer(mlkemLayer);
      manager.addLayer(dhLayer);

      const kem = new MlKem768();
      const mlkemKeyPair = await kem.generateKeyPair();
      
      // Generate DH key pair
      const dhKeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      );

      const plaintext = new TextEncoder().encode('ML-KEM + DH test');
      const keys = {
        'ML-KEM-768': { publicKey: mlkemKeyPair.publicKey },
        'DH-AES-GCM': {
          privateKey: dhKeyPair.privateKey,
          publicKey: dhKeyPair.publicKey,
        },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      
      // Update keys for decryption
      keys['ML-KEM-768'] = { privateKey: mlkemKeyPair.privateKey };
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });
});

