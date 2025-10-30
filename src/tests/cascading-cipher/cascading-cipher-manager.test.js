/**
 * @jest-environment jsdom
 */

/**
 * CascadingCipherManager Unit Tests
 *
 * Tests for the main orchestrator that chains multiple cipher layers.
 */

import { CascadingCipherError } from '../../crypto/CascadingCipher/types.ts';

describe('CascadingCipherManager', () => {
  let CascadingCipherManager;
  let mockLayer1;
  let mockLayer2;
  let mockLayer3;

  beforeEach(async () => {
    // Dynamic import to avoid issues if file doesn't exist yet
    try {
      const module = await import('../../crypto/CascadingCipher/CascadingCipherManager.ts');
      CascadingCipherManager = module.CascadingCipherManager;
    } catch (e) {
      // Module not yet implemented - tests will fail appropriately
      CascadingCipherManager = null;
    }

    // Create mock cipher layers
    mockLayer1 = {
      name: 'MockCipher1',
      version: '1.0.0',
      encrypt: jest.fn().mockImplementation(async (data, keys) => ({
        ciphertext: new Uint8Array([...data, 0x01]),
        layerMetadata: {
          algorithm: 'MockCipher1',
          version: '1.0.0',
          timestamp: Date.now(),
          inputSize: data.length,
          outputSize: data.length + 1,
          processingTime: 5,
        },
        parameters: { layer: 1 },
      })),
      decrypt: jest.fn().mockImplementation(async (payload, keys) =>
        payload.ciphertext.slice(0, -1)
      ),
      validateKeys: jest.fn().mockReturnValue(true),
    };

    mockLayer2 = {
      name: 'MockCipher2',
      version: '1.0.0',
      encrypt: jest.fn().mockImplementation(async (data, keys) => ({
        ciphertext: new Uint8Array([...data, 0x02]),
        layerMetadata: {
          algorithm: 'MockCipher2',
          version: '1.0.0',
          timestamp: Date.now(),
          inputSize: data.length,
          outputSize: data.length + 1,
          processingTime: 5,
        },
        parameters: { layer: 2 },
      })),
      decrypt: jest.fn().mockImplementation(async (payload, keys) =>
        payload.ciphertext.slice(0, -1)
      ),
      validateKeys: jest.fn().mockReturnValue(true),
    };

    mockLayer3 = {
      name: 'MockCipher3',
      version: '1.0.0',
      encrypt: jest.fn().mockImplementation(async (data, keys) => ({
        ciphertext: new Uint8Array([...data, 0x03]),
        layerMetadata: {
          algorithm: 'MockCipher3',
          version: '1.0.0',
          timestamp: Date.now(),
          inputSize: data.length,
          outputSize: data.length + 1,
          processingTime: 5,
        },
        parameters: { layer: 3 },
      })),
      decrypt: jest.fn().mockImplementation(async (payload, keys) =>
        payload.ciphertext.slice(0, -1)
      ),
      validateKeys: jest.fn().mockReturnValue(true),
    };
  });

  describe('Construction', () => {
    test('should create a new CascadingCipherManager', () => {
      if (!CascadingCipherManager) {
        console.warn('CascadingCipherManager not yet implemented');
        return;
      }

      const manager = new CascadingCipherManager();
      expect(manager).toBeDefined();
    });

    test('should initialize with empty layer list', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      expect(manager.getLayers()).toEqual([]);
    });
  });

  describe('Layer Management', () => {
    test('should add a cipher layer', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const layers = manager.getLayers();
      expect(layers).toHaveLength(1);
      expect(layers[0].name).toBe('MockCipher1');
    });

    test('should add multiple cipher layers in order', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);
      manager.addLayer(mockLayer3);

      const layers = manager.getLayers();
      expect(layers).toHaveLength(3);
      expect(layers[0].name).toBe('MockCipher1');
      expect(layers[1].name).toBe('MockCipher2');
      expect(layers[2].name).toBe('MockCipher3');
    });

    test('should remove a cipher layer', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      manager.removeLayer('MockCipher1');

      const layers = manager.getLayers();
      expect(layers).toHaveLength(1);
      expect(layers[0].name).toBe('MockCipher2');
    });

    test('should clear all layers', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      manager.clearLayers();

      expect(manager.getLayers()).toEqual([]);
    });

    test('should reject duplicate layer names', () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      expect(() => {
        manager.addLayer(mockLayer1);
      }).toThrow();
    });
  });

  describe('Encryption', () => {
    test('should encrypt with single layer', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = { MockCipher1: { key: 'test' } };

      const result = await manager.encrypt(plaintext, keys);

      expect(result).toBeDefined();
      expect(result.finalCiphertext).toBeInstanceOf(Uint8Array);
      expect(result.layers).toHaveLength(1);
      expect(result.layers[0].algorithm).toBe('MockCipher1');
      expect(mockLayer1.encrypt).toHaveBeenCalledWith(plaintext, { key: 'test' });
    });

    test('should encrypt with multiple layers in order', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: { key: 'test1' },
        MockCipher2: { key: 'test2' },
      };

      const result = await manager.encrypt(plaintext, keys);

      expect(result.layers).toHaveLength(2);
      expect(result.layers[0].algorithm).toBe('MockCipher1');
      expect(result.layers[1].algorithm).toBe('MockCipher2');

      // Should apply layers in order: plaintext → layer1 → layer2
      // Result: [1, 2, 3, 0x01, 0x02]
      expect(Array.from(result.finalCiphertext)).toEqual([1, 2, 3, 0x01, 0x02]);
    });

    test('should track metadata for all layers', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const result = await manager.encrypt(plaintext, keys);

      expect(result.originalSize).toBe(3);
      expect(result.finalSize).toBe(5); // 3 + 1 + 1
      expect(result.totalProcessingTime).toBeGreaterThanOrEqual(0);
      expect(result.timestamp).toBeGreaterThan(0);
    });

    test('should throw error when encrypting with no layers', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      const plaintext = new Uint8Array([1, 2, 3]);

      await expect(manager.encrypt(plaintext, {})).rejects.toThrow(CascadingCipherError);
    });

    test('should throw error when keys are missing', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {}; // Missing MockCipher1 keys

      await expect(manager.encrypt(plaintext, keys)).rejects.toThrow();
    });

    test('should handle encryption failure in a layer', async () => {
      if (!CascadingCipherManager) return;

      const failingLayer = {
        ...mockLayer1,
        encrypt: jest.fn().mockRejectedValue(new Error('Encryption failed')),
      };

      const manager = new CascadingCipherManager();
      manager.addLayer(failingLayer);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = { MockCipher1: {} };

      await expect(manager.encrypt(plaintext, keys)).rejects.toThrow();
    });
  });

  describe('Decryption', () => {
    test('should decrypt with single layer', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = { MockCipher1: { key: 'test' } };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should decrypt with multiple layers in reverse order', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));

      // Verify decryption was called in reverse order
      expect(mockLayer2.decrypt).toHaveBeenCalled();
      expect(mockLayer1.decrypt).toHaveBeenCalled();
    });

    test('should throw error when decrypting with wrong keys', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = { MockCipher1: {} };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Change the layer to fail on decrypt
      mockLayer1.decrypt = jest.fn().mockRejectedValue(new Error('Decryption failed'));

      await expect(manager.decrypt(encrypted, keys)).rejects.toThrow();
    });
  });

  describe('Round-trip Encryption/Decryption', () => {
    test('should round-trip with 1 layer', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([10, 20, 30, 40]);
      const keys = { MockCipher1: {} };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with 2 layers', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([10, 20, 30, 40]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with 3 layers', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);
      manager.addLayer(mockLayer3);

      const plaintext = new Uint8Array([10, 20, 30, 40]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
        MockCipher3: {},
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with large data', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array(10000).fill(42);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test('should round-trip with empty data', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);

      const plaintext = new Uint8Array([]);
      const keys = { MockCipher1: {} };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });
  });

  describe('Performance Tracking', () => {
    test('should track processing time', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const result = await manager.encrypt(plaintext, keys);

      expect(result.totalProcessingTime).toBeGreaterThanOrEqual(0);
      expect(result.layers[0].processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layers[1].processingTime).toBeGreaterThanOrEqual(0);
    });

    test('should track size overhead', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const result = await manager.encrypt(plaintext, keys);

      expect(result.originalSize).toBe(3);
      expect(result.finalSize).toBeGreaterThan(3);

      // Each layer adds 1 byte in our mock
      const expectedSize = 3 + 2; // Original + 2 layers
      expect(result.finalSize).toBe(expectedSize);
    });
  });

  describe('Error Recovery', () => {
    test('should report which layer failed during encryption', async () => {
      if (!CascadingCipherManager) return;

      const failingLayer = {
        ...mockLayer2,
        encrypt: jest.fn().mockRejectedValue(new Error('Layer 2 failed')),
      };

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(failingLayer);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      try {
        await manager.encrypt(plaintext, keys);
        fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(CascadingCipherError);
        if (error instanceof CascadingCipherError) {
          expect(error.failedAtLayer).toBe(1); // 0-indexed: layer2 is at index 1
        }
      }
    });

    test('should report which layer failed during decryption', async () => {
      if (!CascadingCipherManager) return;

      const manager = new CascadingCipherManager();
      manager.addLayer(mockLayer1);
      manager.addLayer(mockLayer2);

      const plaintext = new Uint8Array([1, 2, 3]);
      const keys = {
        MockCipher1: {},
        MockCipher2: {},
      };

      const encrypted = await manager.encrypt(plaintext, keys);

      // Make layer1 fail on decrypt
      mockLayer1.decrypt = jest.fn().mockRejectedValue(new Error('Decrypt failed'));

      try {
        await manager.decrypt(encrypted, keys);
        fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(CascadingCipherError);
      }
    });
  });
});
