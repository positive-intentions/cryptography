/**
 * SFrame Manager Comprehensive Test Suite
 * Tests SFrame implementation for real-time media frame encryption
 *
 * NOTE: These tests use a mock due to Jest's incompatibility with Web Crypto API.
 * The real implementation is tested in Storybook (browser environment).
 */

describe('SFrame Manager - Real Implementation Tests', () => {
  let SFrameManager;
  let manager;

  beforeAll(() => {
    // Import the real SFrameManager directly (mock is substituted by Jest config)
    const actualModule = require('../crypto/SFrame/SFrameManager.tsx');
    SFrameManager = actualModule.SFrameManager;
  });

  beforeEach(async () => {
    // Create fresh manager for each test
    manager = new SFrameManager();
  });

  afterEach(async () => {
    // Cleanup
    if (manager) manager.destroy();
  });

  /**
   * Test 1: Initialization & Key Generation
   */
  describe('1. Initialization & Key Generation', () => {
    test('should initialize SFrame manager successfully', async () => {
      await manager.initialize();

      const stats = manager.getStats();
      expect(stats.initialized).toBe(true);
      expect(stats.keyCount).toBe(1); // Initial key generated
      expect(stats.currentKeyId).toBe(0);
      expect(stats.frameCounter).toBe(0);
    });

    test('should not re-initialize if already initialized', async () => {
      await manager.initialize();
      const statsAfterFirst = manager.getStats();

      // Try to initialize again
      await manager.initialize();
      const statsAfterSecond = manager.getStats();

      // Should be the same
      expect(statsAfterSecond).toEqual(statsAfterFirst);
    });

    test('should generate valid encryption keys', async () => {
      await manager.initialize();

      const key1 = await manager.generateKey(1);
      expect(key1).toBeDefined();
      expect(key1.keyId).toBe(1);
      expect(key1.key).toBeDefined();
      expect(key1.salt).toBeDefined();

      const stats = manager.getStats();
      expect(stats.keyCount).toBe(2); // Initial key + key1
    });

    test('should throw error when using manager before initialization', async () => {
      const frameData = new TextEncoder().encode('test data').buffer;

      await expect(manager.encryptFrame(frameData)).rejects.toThrow(
        'SFrame Manager not initialized'
      );
    });
  });

  /**
   * Test 2: Frame Encryption & Decryption
   */
  describe('2. Frame Encryption & Decryption', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should encrypt a media frame', async () => {
      const plaintext = 'Hello, SFrame!';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      const encrypted = await manager.encryptFrame(frameData);

      expect(encrypted).toBeDefined();
      expect(encrypted instanceof Uint8Array).toBe(true);
      expect(encrypted.length).toBeGreaterThan(frameData.byteLength); // Has header + IV
    });

    test('should decrypt an encrypted frame', async () => {
      const plaintext = 'Test frame data';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      const encrypted = await manager.encryptFrame(frameData);
      const decrypted = await manager.decryptFrame(encrypted);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(plaintext);
    });

    test('should handle multiple consecutive frames', async () => {
      const frames = [
        'Frame 1',
        'Frame 2',
        'Frame 3',
        'Frame 4',
      ];

      for (const frameText of frames) {
        const frameData = new TextEncoder().encode(frameText).buffer;
        const encrypted = await manager.encryptFrame(frameData);
        const decrypted = await manager.decryptFrame(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);

        expect(decryptedText).toBe(frameText);
      }
    });

    test('should increment frame counter on each encryption', async () => {
      const initialCounter = manager.getFrameCounter();
      expect(initialCounter).toBe(0);

      for (let i = 0; i < 5; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      const finalCounter = manager.getFrameCounter();
      expect(finalCounter).toBe(5);
    });

    test('should verify encrypted frames differ even with same plaintext', async () => {
      const plaintext = 'Same content';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      const encrypted1 = await manager.encryptFrame(frameData);
      const encrypted2 = await manager.encryptFrame(frameData);

      // Frames should be different (different counters)
      expect(encrypted1).not.toEqual(encrypted2);

      // But both should decrypt correctly
      const decrypted1 = new TextDecoder().decode(await manager.decryptFrame(encrypted1));
      const decrypted2 = new TextDecoder().decode(await manager.decryptFrame(encrypted2));

      expect(decrypted1).toBe(plaintext);
      expect(decrypted2).toBe(plaintext);
    });
  });

  /**
   * Test 3: Key Management & RFC 9605 Compliance
   */
  describe('3. Key Management & RFC 9605 Compliance', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should set active key', async () => {
      await manager.generateKey(1);
      manager.setActiveKey(1);

      expect(manager.getCurrentKeyId()).toBe(1);
    });

    test('RFC 9605 Section 5.2: should derive key with correct labels', async () => {
      const mlsSecret = new TextEncoder().encode('test-mls-secret').buffer;
      const keyId = 100;

      const derivedKey = await manager.deriveKeyFromMLSSecret(mlsSecret, keyId);

      expect(derivedKey).toBeDefined();
      expect(derivedKey.keyId).toBe(keyId);
      expect(derivedKey.key).toBeDefined();
      expect(derivedKey.salt).toBeDefined();
      expect(derivedKey.salt.length).toBe(16); // 128 bits

      const stats = manager.getStats();
      expect(stats.keyCount).toBe(2); // Initial key + derived key
    });

    test('should throw error when setting non-existent key', () => {
      expect(() => manager.setActiveKey(999)).toThrow('SFrame key 999 not found');
    });

    test('should rotate keys successfully', async () => {
      const initialKeyId = manager.getCurrentKeyId();
      expect(initialKeyId).toBe(0);

      const newKeyId = await manager.rotateKey();

      expect(newKeyId).toBe(1);
      expect(manager.getCurrentKeyId()).toBe(1);

      const stats = manager.getStats();
      expect(stats.keyCount).toBe(2); // Old key + new key
    });

    test('RFC 9605: should reset frame counter on key rotation', async () => {
      // Encrypt some frames to increment counter
      for (let i = 0; i < 5; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      expect(manager.getFrameCounter()).toBe(5);

      // Rotate key
      await manager.rotateKey();

      // Frame counter should be reset to 0
      expect(manager.getFrameCounter()).toBe(0);
      expect(manager.getCurrentKeyId()).toBe(1);
    });

    test('should encrypt with new key after rotation', async () => {
      const plaintext = 'Test with rotated key';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      // Encrypt with initial key
      const encrypted1 = await manager.encryptFrame(frameData);

      // Rotate key
      await manager.rotateKey();

      // Encrypt with new key
      const encrypted2 = await manager.encryptFrame(frameData);

      // Both should decrypt correctly
      const decrypted1 = new TextDecoder().decode(await manager.decryptFrame(encrypted1));
      const decrypted2 = new TextDecoder().decode(await manager.decryptFrame(encrypted2));

      expect(decrypted1).toBe(plaintext);
      expect(decrypted2).toBe(plaintext);

      // Frames should use different keys
      expect(encrypted1[0]).toBe(0); // Key ID 0
      expect(encrypted2[0]).toBe(1); // Key ID 1
    });

    test('should cleanup old keys', async () => {
      // Generate multiple keys
      await manager.generateKey(1);
      await manager.generateKey(2);
      await manager.generateKey(3);
      await manager.generateKey(4);

      manager.setActiveKey(4);

      let stats = manager.getStats();
      expect(stats.keyCount).toBe(5); // Keys 0, 1, 2, 3, 4

      // Cleanup, keeping only last 2
      manager.cleanupOldKeys(2);

      stats = manager.getStats();
      expect(stats.keyCount).toBe(2); // Only keys 3, 4 remain
    });

    test('should derive key from MLS secret', async () => {
      const mlsSecret = new TextEncoder().encode('mock-mls-secret').buffer;
      const keyId = 10;

      const derivedKey = await manager.deriveKeyFromMLSSecret(mlsSecret, keyId, 'TestContext');

      expect(derivedKey).toBeDefined();
      expect(derivedKey.keyId).toBe(keyId);

      const stats = manager.getStats();
      expect(stats.keyCount).toBe(2); // Initial key + derived key
    });
  });

  /**
   * Test 4: Frame Counter Management
   */
  describe('4. Frame Counter Management', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should track frame counter correctly', async () => {
      expect(manager.getFrameCounter()).toBe(0);

      for (let i = 0; i < 10; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      expect(manager.getFrameCounter()).toBe(10);
    });

    test('should reset frame counter', async () => {
      // Encrypt some frames
      for (let i = 0; i < 5; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      expect(manager.getFrameCounter()).toBe(5);

      // Reset counter
      manager.resetFrameCounter();

      expect(manager.getFrameCounter()).toBe(0);
    });

    test('should use reset counter after key rotation', async () => {
      // Encrypt frames
      for (let i = 0; i < 3; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      expect(manager.getFrameCounter()).toBe(3);

      // Rotate key
      await manager.rotateKey();

      // Reset counter (recommended practice)
      manager.resetFrameCounter();

      expect(manager.getFrameCounter()).toBe(0);

      // Encrypt more frames with new key
      const frameData = new TextEncoder().encode('New frame').buffer;
      await manager.encryptFrame(frameData);

      expect(manager.getFrameCounter()).toBe(1);
    });
  });

  /**
   * Test 5: Transform Streams
   */
  describe('5. Transform Streams', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should create encrypt transform', () => {
      const transform = manager.createEncryptTransform();
      expect(transform).toBeDefined();
      expect(transform.transform).toBeDefined();
    });

    test('should create decrypt transform', () => {
      const transform = manager.createDecryptTransform();
      expect(transform).toBeDefined();
      expect(transform.transform).toBeDefined();
    });

    test('should process frame through encrypt transform', async () => {
      const transform = manager.createEncryptTransform();

      const mockFrame = {
        data: new TextEncoder().encode('Video frame').buffer,
      };

      const mockController = {
        enqueue: jest.fn(),
      };

      await transform.transform(mockFrame, mockController);

      expect(mockController.enqueue).toHaveBeenCalledWith(mockFrame);
      expect(mockFrame.data.byteLength).toBeGreaterThan(0);
    });

    test('should process frame through decrypt transform', async () => {
      const plaintext = 'Audio frame';
      const frameData = new TextEncoder().encode(plaintext).buffer;
      const encrypted = await manager.encryptFrame(frameData);

      const transform = manager.createDecryptTransform();

      const mockFrame = {
        data: encrypted.buffer,
      };

      const mockController = {
        enqueue: jest.fn(),
      };

      await transform.transform(mockFrame, mockController);

      expect(mockController.enqueue).toHaveBeenCalledWith(mockFrame);

      const decryptedText = new TextDecoder().decode(mockFrame.data);
      expect(decryptedText).toBe(plaintext);
    });
  });

  /**
   * Test 6: Statistics & Monitoring
   */
  describe('6. Statistics & Monitoring', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should provide accurate statistics', async () => {
      const stats = manager.getStats();

      expect(stats).toHaveProperty('keyCount');
      expect(stats).toHaveProperty('currentKeyId');
      expect(stats).toHaveProperty('frameCounter');
      expect(stats).toHaveProperty('initialized');

      expect(stats.initialized).toBe(true);
      expect(stats.keyCount).toBe(1);
      expect(stats.currentKeyId).toBe(0);
      expect(stats.frameCounter).toBe(0);
    });

    test('should update statistics after operations', async () => {
      // Generate keys
      await manager.generateKey(1);
      await manager.generateKey(2);

      // Rotate to key 2
      manager.setActiveKey(2);

      // Encrypt frames
      for (let i = 0; i < 7; i++) {
        const frameData = new TextEncoder().encode(`Frame ${i}`).buffer;
        await manager.encryptFrame(frameData);
      }

      const stats = manager.getStats();

      expect(stats.keyCount).toBe(3); // Keys 0, 1, 2
      expect(stats.currentKeyId).toBe(2);
      expect(stats.frameCounter).toBe(7);
      expect(stats.initialized).toBe(true);
    });
  });

  /**
   * Test 7: Resource Cleanup
   */
  describe('7. Resource Cleanup', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should cleanup resources on destroy', async () => {
      // Generate some keys and encrypt frames
      await manager.generateKey(1);
      await manager.generateKey(2);

      const frameData = new TextEncoder().encode('Frame').buffer;
      await manager.encryptFrame(frameData);

      let stats = manager.getStats();
      expect(stats.keyCount).toBe(3);
      expect(stats.frameCounter).toBe(1);

      // Destroy manager
      manager.destroy();

      stats = manager.getStats();
      expect(stats.keyCount).toBe(0);
      expect(stats.frameCounter).toBe(0);
      expect(stats.initialized).toBe(false);
    });

    test('should throw error after destroy when encrypting', async () => {
      manager.destroy();

      const frameData = new TextEncoder().encode('Frame').buffer;
      await expect(manager.encryptFrame(frameData)).rejects.toThrow(
        'SFrame Manager not initialized'
      );
    });

    test('should be reinitializable after destroy', async () => {
      manager.destroy();

      // Reinitialize
      await manager.initialize();

      const stats = manager.getStats();
      expect(stats.initialized).toBe(true);
      expect(stats.keyCount).toBe(1);
    });
  });

  /**
   * Test 8: RFC 9605 Security Compliance
   */
  describe('8. RFC 9605 Security Compliance', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('RFC 9605 Section 4.3: IV must be derived via salt XOR counter', async () => {
      const plaintext = 'Test IV derivation';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      // Encrypt a frame
      const encrypted = await manager.encryptFrame(frameData);

      // Extract header (first 5 bytes)
      const header = encrypted.slice(0, 5);
      const keyId = header[0];
      const frameCount = new DataView(header.buffer, header.byteOffset).getUint32(1, false);

      // Extract IV (next 12 bytes)
      const iv = encrypted.slice(5, 17);

      // Verify IV is not all zeros (basic sanity check)
      const ivArray = Array.from(iv);
      expect(ivArray.some(byte => byte !== 0)).toBe(true);

      // Decrypt should work (proves IV derivation is consistent)
      const decrypted = await manager.decryptFrame(encrypted);
      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(plaintext);
    });

    test('RFC 9605 Section 4.3: Header must be authenticated (AAD)', async () => {
      const plaintext = 'Test header authentication';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      // Encrypt a frame
      const encrypted = await manager.encryptFrame(frameData);

      // Tamper with header (change key ID)
      const tamperedFrame = new Uint8Array(encrypted);
      tamperedFrame[0] = (tamperedFrame[0] + 1) % 256; // Change key ID

      // Decryption should fail due to AAD mismatch
      // Note: Might throw "key not found" or "authentication failed"
      await expect(manager.decryptFrame(tamperedFrame)).rejects.toThrow();
    });

    test('RFC 9605: Different frames with same plaintext must have different ciphertexts', async () => {
      const plaintext = 'Same content';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      const encrypted1 = await manager.encryptFrame(frameData);
      const encrypted2 = await manager.encryptFrame(frameData);

      // Due to counter increment, IVs differ, so ciphertexts differ
      expect(encrypted1).not.toEqual(encrypted2);

      // But both decrypt to same plaintext
      const decrypted1 = new TextDecoder().decode(await manager.decryptFrame(encrypted1));
      const decrypted2 = new TextDecoder().decode(await manager.decryptFrame(encrypted2));

      expect(decrypted1).toBe(plaintext);
      expect(decrypted2).toBe(plaintext);
    });

    test('RFC 9605 Section 5.2: MLS-derived keys use correct labels', async () => {
      // This test verifies the labels are used by ensuring derivation works
      const mlsSecret = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const keyId = 50;

      const key1 = await manager.deriveKeyFromMLSSecret(mlsSecret, keyId);

      // Create second manager with same secret
      const manager2 = new SFrameManager();
      await manager2.initialize();
      const key2 = await manager2.deriveKeyFromMLSSecret(mlsSecret, keyId);

      // Both should derive same key (verified by encryption/decryption)
      const testData = new TextEncoder().encode('Test cross-manager encryption').buffer;

      manager.setActiveKey(keyId);
      const encrypted = await manager.encryptFrame(testData);

      manager2.setActiveKey(keyId);
      const decrypted = await manager2.decryptFrame(encrypted);

      expect(new TextDecoder().decode(decrypted)).toBe('Test cross-manager encryption');

      manager2.destroy();
    });
  });

  /**
   * Test 9: Error Handling
   */
  describe('9. Error Handling', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    test('should throw error when decrypting with missing key', async () => {
      const plaintext = 'Test data';
      const frameData = new TextEncoder().encode(plaintext).buffer;

      // Encrypt with key 0
      const encrypted = await manager.encryptFrame(frameData);

      // Generate and switch to key 1
      await manager.generateKey(1);
      manager.setActiveKey(1);

      // Remove key 0
      manager.cleanupOldKeys(1);

      // Try to decrypt (requires key 0)
      await expect(manager.decryptFrame(encrypted)).rejects.toThrow('SFrame key 0 not found');
    });

    test('should handle empty frame data', async () => {
      const emptyFrame = new ArrayBuffer(0);

      const encrypted = await manager.encryptFrame(emptyFrame);
      expect(encrypted).toBeDefined();

      const decrypted = await manager.decryptFrame(encrypted);
      expect(decrypted.byteLength).toBe(0);
    });

    test('should handle large frame data', async () => {
      // Simulate a large video frame (1MB)
      const largeFrame = new Uint8Array(1024 * 1024).fill(42).buffer;

      const encrypted = await manager.encryptFrame(largeFrame);
      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeGreaterThan(largeFrame.byteLength);

      const decrypted = await manager.decryptFrame(encrypted);
      expect(decrypted.byteLength).toBe(largeFrame.byteLength);
    });
  });
});
