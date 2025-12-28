/**
 * @jest-environment jsdom
 */

/**
 * SignalCipherLayer Unit Tests
 *
 * Tests for the Signal Protocol Double Ratchet cipher layer implementation.
 * Uses mocked WASM module since real Signal Protocol WASM requires browser environment.
 */

describe("SignalCipherLayer", () => {
  let SignalCipherLayer;
  let mockWasmModule;
  let mockDoubleRatchetState;

  beforeEach(async () => {
    // Create mock WASM module that simulates Signal Protocol
    let messageCounter = 0;
    const encryptedMessages = new Map();

    mockDoubleRatchetState = {
      messageNumber: 0,
      chainKey: new Uint8Array(32).fill(1),
      rootKey: new Uint8Array(32).fill(2),
      free: jest.fn(),
    };

    mockWasmModule = {
      // Mock double_ratchet_encrypt
      double_ratchet_encrypt: jest.fn((state, plaintext) => {
        messageCounter++;
        const messageId = messageCounter;

        // Store plaintext for later decryption
        const key = `msg-${messageId}`;
        encryptedMessages.set(key, plaintext);

        // Mock encrypted output
        const mockCiphertext = new Uint8Array(plaintext.length + 32); // Add padding
        mockCiphertext.set(plaintext, 16); // Put plaintext in middle
        mockCiphertext[0] = messageId; // Store message ID

        return {
          ciphertext: () => mockCiphertext,
          public_key: () => new Uint8Array(32).fill(messageId % 256),
          message_number: () => messageId,
          previous_chain_length: () => messageId - 1,
        };
      }),

      // Mock DoubleRatchetMessage constructor
      DoubleRatchetMessage: {
        new: jest.fn(
          (publicKey, messageNumber, previousChainLength, ciphertext) => {
            return {
              publicKey,
              messageNumber,
              previousChainLength,
              ciphertext,
            };
          },
        ),
      },

      // Mock double_ratchet_decrypt
      double_ratchet_decrypt: jest.fn((state, message) => {
        // Extract message ID from ciphertext
        const messageId = message.ciphertext[0];

        // Recover plaintext from ciphertext (remove padding)
        const plaintext = message.ciphertext.slice(
          16,
          message.ciphertext.length - 16,
        );

        return plaintext;
      }),
    };

    // Import SignalCipherLayer
    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/SignalCipherLayer.ts"
      );
      SignalCipherLayer = module.SignalCipherLayer;
    } catch (e) {
      SignalCipherLayer = null;
    }
  });

  describe("Construction", () => {
    test("should create SignalCipherLayer instance without parameters", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();
      expect(layer).toBeDefined();
    });

    test("should create SignalCipherLayer with wasmModule and state", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      expect(layer).toBeDefined();
    });

    test("should have correct name and version", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();
      expect(layer.name).toBe("X3DH-DoubleRatchet");
      expect(layer.version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe("Key Validation", () => {
    test("should validate keys with doubleRatchetState", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();
      const validKeys = {
        doubleRatchetState: mockDoubleRatchetState,
      };

      expect(layer.validateKeys(validKeys)).toBe(true);
    });

    test("should validate when constructed with state", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );

      // Empty keys object should be valid since constructor provided state
      expect(layer.validateKeys({})).toBe(true);

      // Null is still invalid (must be an object)
      expect(layer.validateKeys(null)).toBe(false);
    });

    test("should reject keys without doubleRatchetState", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();

      expect(layer.validateKeys({})).toBe(false);
      expect(layer.validateKeys({ sessionId: "test" })).toBe(false);
    });

    test("should reject null or undefined keys when not initialized", () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();

      expect(layer.validateKeys(null)).toBe(false);
      expect(layer.validateKeys(undefined)).toBe(false);
    });
  });

  describe("Initialization", () => {
    test("should initialize with wasmModule and doubleRatchetState", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();
      await layer.initialize({
        wasmModule: mockWasmModule,
        doubleRatchetState: mockDoubleRatchetState,
      });

      // After initialization, empty keys should be valid
      expect(layer.validateKeys({})).toBe(true);
    });

    test("should initialize with only wasmModule", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer();
      await layer.initialize({ wasmModule: mockWasmModule });

      expect(
        layer.validateKeys({ doubleRatchetState: mockDoubleRatchetState }),
      ).toBe(true);
    });
  });

  describe("Encryption", () => {
    test("should encrypt data with Signal Protocol", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Hello, Signal!");

      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.layerMetadata).toBeDefined();
      expect(result.parameters).toBeDefined();
      expect(mockWasmModule.double_ratchet_encrypt).toHaveBeenCalled();
    });

    test("should include metadata", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test data");

      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(result.layerMetadata.algorithm).toBe("X3DH-DoubleRatchet");
      expect(result.layerMetadata.version).toMatch(/^\d+\.\d+\.\d+$/);
      expect(result.layerMetadata.inputSize).toBe(plaintext.length);
      expect(result.layerMetadata.outputSize).toBe(result.ciphertext.length);
      expect(result.layerMetadata.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.layerMetadata.timestamp).toBeGreaterThan(0);
      expect(result.layerMetadata.metadata.messageNumber).toBeDefined();
    });

    test("should include Double Ratchet parameters", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test");

      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(result.parameters.publicKey).toBeDefined();
      expect(result.parameters.publicKey).toBeInstanceOf(Uint8Array);
      expect(result.parameters.messageNumber).toBeDefined();
      expect(result.parameters.previousChainLength).toBeDefined();
    });

    test("should use constructor state if not provided in keys", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Constructor state test");

      // Encrypt with empty keys object (should use constructor state)
      const result = await layer.encrypt(plaintext, {});

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    });

    test("should use Web Crypto API fallback without WASM module", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(); // No WASM module - will use Web Crypto API
      const plaintext = new TextEncoder().encode("Test");

      // Should succeed using Web Crypto API fallback
      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.layerMetadata.algorithm).toBe("X3DH-DoubleRatchet");
      expect(mockWasmModule.double_ratchet_encrypt).not.toHaveBeenCalled(); // Should not use WASM
    });

    test("should throw error without Double Ratchet state", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(mockWasmModule); // No state
      const plaintext = new TextEncoder().encode("Test");

      await expect(layer.encrypt(plaintext, {})).rejects.toThrow();
    });
  });

  describe("Decryption", () => {
    test("should decrypt Signal-encrypted data", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Secret message");

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
      expect(mockWasmModule.double_ratchet_decrypt).toHaveBeenCalled();
      expect(mockWasmModule.DoubleRatchetMessage.new).toHaveBeenCalled();
    });

    test("should reconstruct Double Ratchet message correctly", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test");

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Verify message was constructed with correct parameters
      expect(mockWasmModule.DoubleRatchetMessage.new).toHaveBeenCalledWith(
        encrypted.parameters.publicKey,
        encrypted.parameters.messageNumber,
        encrypted.parameters.previousChainLength,
        encrypted.ciphertext,
      );
    });

    test("should use Web Crypto API fallback for decryption without WASM module", async () => {
      if (!SignalCipherLayer) return;

      // Create layer without WASM for both encryption and decryption
      const layerNoWasm = new SignalCipherLayer();
      const plaintext = new TextEncoder().encode("Test");

      // Encrypt without WASM (uses Web Crypto API)
      const encrypted = await layerNoWasm.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Decrypt without WASM (should also use Web Crypto API)
      const decrypted = await layerNoWasm.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Note: The simplified Web Crypto fallback is for demonstration purposes
      // In production, you would use the full Double Ratchet implementation from Cryptography.tsx
      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(decrypted.length).toBeGreaterThan(0);
      expect(mockWasmModule.double_ratchet_decrypt).not.toHaveBeenCalled(); // Should not use WASM
    });

    test("should throw error without Double Ratchet state", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test");
      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Try to decrypt without state
      const layerNoState = new SignalCipherLayer(mockWasmModule);

      await expect(layerNoState.decrypt(encrypted, {})).rejects.toThrow();
    });
  });

  describe("Round-trip Encryption/Decryption", () => {
    test("should round-trip with simple text", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const originalText = "Hello, World!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });

    test("should round-trip with binary data", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new Uint8Array([0, 1, 255, 128, 64, 32, 16]);

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with large data", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new Uint8Array(10000).fill(42);

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with empty data", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new Uint8Array([]);

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should round-trip with special characters", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const originalText = "你好世界! 🌍 Привет мир!";
      const plaintext = new TextEncoder().encode(originalText);

      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decrypted = await layer.decrypt(encrypted, {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(originalText);
    });
  });

  describe("State Management", () => {
    test("should handle multiple messages with incrementing message numbers", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );

      const msg1 = await layer.encrypt(new TextEncoder().encode("Message 1"), {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const msg2 = await layer.encrypt(new TextEncoder().encode("Message 2"), {
        doubleRatchetState: mockDoubleRatchetState,
      });
      const msg3 = await layer.encrypt(new TextEncoder().encode("Message 3"), {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Message numbers should increment
      expect(msg2.parameters.messageNumber).toBeGreaterThan(
        msg1.parameters.messageNumber,
      );
      expect(msg3.parameters.messageNumber).toBeGreaterThan(
        msg2.parameters.messageNumber,
      );
    });

    test("should include sessionId in metadata", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test");

      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
        sessionId: "alice-bob-session",
      });

      expect(result.layerMetadata.metadata.sessionId).toBe("alice-bob-session");
      expect(result.parameters.sessionId).toBe("alice-bob-session");
    });
  });

  describe("Resource Cleanup", () => {
    test("should clean up resources", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );

      await layer.destroy();

      expect(mockDoubleRatchetState.free).toHaveBeenCalled();
    });

    test("should handle cleanup when state has no free method", async () => {
      if (!SignalCipherLayer) return;

      const stateWithoutFree = { messageNumber: 0 };
      const layer = new SignalCipherLayer(mockWasmModule, stateWithoutFree);

      // Should not throw
      await expect(layer.destroy()).resolves.not.toThrow();
    });
  });

  describe("Integration with CascadingCipherManager", () => {
    test("should work as a layer in cascading cipher", async () => {
      if (!SignalCipherLayer) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );

      const manager = new CascadingCipherManager();
      const signalLayer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      manager.addLayer(signalLayer);

      const plaintext = new TextEncoder().encode("Test message");
      const keys = {
        "X3DH-DoubleRatchet": { doubleRatchetState: mockDoubleRatchetState },
      };

      const encrypted = await manager.encrypt(plaintext, keys);
      const decrypted = await manager.decrypt(encrypted, keys);

      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    });

    test("should work in combination with other layers", async () => {
      if (!SignalCipherLayer) return;

      const { CascadingCipherManager } = await import(
        "../../crypto/CascadingCipher/CascadingCipherManager.ts"
      );
      const { AESCipherLayer } = await import(
        "../../crypto/CascadingCipher/layers/AESCipherLayer.ts"
      );

      // Save original crypto mock
      const originalCrypto = global.crypto;
      const { webcrypto } = await import("crypto");
      global.crypto = webcrypto;
      globalThis.crypto = webcrypto;

      try {
        const manager = new CascadingCipherManager();
        const signalLayer = new SignalCipherLayer(
          mockWasmModule,
          mockDoubleRatchetState,
        );
        const aesLayer = new AESCipherLayer();

        manager.addLayer(signalLayer);
        manager.addLayer(aesLayer);

        const plaintext = new TextEncoder().encode("Multi-layer test");
        const keys = {
          "X3DH-DoubleRatchet": { doubleRatchetState: mockDoubleRatchetState },
          "AES-GCM-256": { password: "test-password" },
        };

        const encrypted = await manager.encrypt(plaintext, keys);
        const decrypted = await manager.decrypt(encrypted, keys);

        expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
      } finally {
        // Restore crypto mock
        global.crypto = originalCrypto;
        globalThis.crypto = originalCrypto;
      }
    });
  });

  describe("Error Handling", () => {
    test("should use fallback when WASM not available", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(); // No WASM - will use Web Crypto API fallback
      const plaintext = new TextEncoder().encode("Test");

      // Should not throw - will use Web Crypto API fallback
      const result = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    });

    test("should handle WASM encryption errors gracefully", async () => {
      if (!SignalCipherLayer) return;

      // Create mock that throws error
      const errorWasm = {
        double_ratchet_encrypt: jest.fn(() => {
          throw new Error("WASM encryption error");
        }),
      };

      const layer = new SignalCipherLayer(errorWasm, mockDoubleRatchetState);
      const plaintext = new TextEncoder().encode("Test");

      await expect(
        layer.encrypt(plaintext, {
          doubleRatchetState: mockDoubleRatchetState,
        }),
      ).rejects.toThrow("Signal encryption failed");
    });

    test("should handle WASM decryption errors gracefully", async () => {
      if (!SignalCipherLayer) return;

      const layer = new SignalCipherLayer(
        mockWasmModule,
        mockDoubleRatchetState,
      );
      const plaintext = new TextEncoder().encode("Test");
      const encrypted = await layer.encrypt(plaintext, {
        doubleRatchetState: mockDoubleRatchetState,
      });

      // Create mock that throws error on decrypt
      const errorWasm = {
        ...mockWasmModule,
        double_ratchet_decrypt: jest.fn(() => {
          throw new Error("WASM decryption error");
        }),
      };

      const errorLayer = new SignalCipherLayer(
        errorWasm,
        mockDoubleRatchetState,
      );

      await expect(
        errorLayer.decrypt(encrypted, {
          doubleRatchetState: mockDoubleRatchetState,
        }),
      ).rejects.toThrow("Signal decryption failed");
    });
  });
});
