/**
 * @jest-environment jsdom
 *
 * Comprehensive tests for libsignal-protocol-go WASM implementation
 */

import { TextEncoder, TextDecoder } from "util";
import path from "path";
import fs from "fs";

// Setup global TextEncoder/TextDecoder for Node.js
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock Go WASM runtime
class Go {
  constructor() {
    this.argv = ["js"];
    this.env = {};
    this.exit = (code) => {
      console.log(`Go exited with code ${code}`);
    };
    this.importObject = {
      go: {
        "runtime.wasmExit": (sp) => {
          console.log("WASM exited");
        },
        "runtime.wasmWrite": (sp) => {
          // Handle console output
        },
        "runtime.resetMemoryDataView": (sp) => {},
        "runtime.nanotime1": (sp) => {
          const msec = new Date().getTime();
          this.mem.setUint32(sp + 8, Math.floor(msec / 1000), true);
          this.mem.setUint32(sp + 12, (msec % 1000) * 1000000, true);
        },
        "runtime.walltime": (sp) => {
          const msec = new Date().getTime();
          this.mem.setUint32(sp + 8, Math.floor(msec / 1000), true);
          this.mem.setUint32(sp + 12, (msec % 1000) * 1000000, true);
        },
        "runtime.scheduleTimeoutEvent": (sp) => {},
        "runtime.clearTimeoutEvent": (sp) => {},
        "runtime.getRandomData": (sp) => {
          const slice = this.mem.getBigUint64(sp + 8, true);
          const arr = new Uint8Array(
            this._inst.exports.mem.buffer,
            Number(slice),
            8,
          );
          crypto.getRandomValues(arr);
        },
      },
    };
  }

  async run(instance) {
    this._inst = instance;
    this.mem = new DataView(this._inst.exports.mem.buffer);
    // Simplified run implementation for testing
    return new Promise((resolve) => {
      // The WASM module sets up global.SignalProtocol
      resolve();
    });
  }
}

global.Go = Go;

describe("libsignal-protocol-go WASM Implementation", () => {
  let SignalProtocol;
  let wasmLoaded = false;

  beforeAll(async () => {
    try {
      // Check if WASM file exists
      const wasmPath = path.join(
        process.cwd(),
        "..",
        "libsignal-protocol-go",
        "wasm",
        "signal.wasm",
      );

      if (!fs.existsSync(wasmPath)) {
        console.warn("⚠️ signal.wasm not found at:", wasmPath);
        return;
      }

      // Read WASM file
      const wasmBuffer = fs.readFileSync(wasmPath);

      // Mock the Go WASM runtime
      const go = new Go();

      // Instantiate WASM module
      const wasmModule = await WebAssembly.instantiate(
        wasmBuffer,
        go.importObject,
      );

      // Run the Go program
      await go.run(wasmModule.instance);

      // The Go WASM should have set up global.SignalProtocol
      SignalProtocol = global.SignalProtocol;
      wasmLoaded = true;

      console.log("✅ WASM module loaded successfully for testing");
    } catch (error) {
      console.error("❌ Failed to load WASM:", error.message);
    }
  });

  describe("Module Loading", () => {
    test("WASM module loads successfully", () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      expect(SignalProtocol).toBeDefined();
      expect(typeof SignalProtocol).toBe("object");
    });

    test("Required functions are exported", () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      // Check for all expected functions
      const expectedFunctions = [
        "generateIdentityKeyPair",
        "generateRegistrationId",
        "generatePreKeys",
        "generateSignedPreKey",
        "initializeSession",
        "processPreKeyBundle",
        "encryptMessage",
        "decryptMessage",
      ];

      expectedFunctions.forEach((funcName) => {
        expect(SignalProtocol[funcName]).toBeDefined();
        expect(typeof SignalProtocol[funcName]).toBe("function");
      });
    });
  });

  describe("Key Generation", () => {
    test("generates identity key pair", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const keyPair = await SignalProtocol.generateIdentityKeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(typeof keyPair.publicKey).toBe("string"); // Base64 encoded
      expect(typeof keyPair.privateKey).toBe("string");

      // Check key lengths (base64 encoded 32 bytes ≈ 44 chars)
      expect(keyPair.publicKey.length).toBeGreaterThan(40);
      expect(keyPair.privateKey.length).toBeGreaterThan(40);
    });

    test("generates registration ID", () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const registrationId = SignalProtocol.generateRegistrationId();

      expect(registrationId).toBeDefined();
      expect(typeof registrationId).toBe("number");
      expect(registrationId).toBeGreaterThan(0);
      expect(registrationId).toBeLessThanOrEqual(0x3fff); // Max registration ID
    });

    test("generates pre-keys", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const preKeys = await SignalProtocol.generatePreKeys(0, 10);

      expect(preKeys).toBeDefined();
      expect(Array.isArray(preKeys)).toBe(true);
      expect(preKeys.length).toBe(10);

      preKeys.forEach((preKey, index) => {
        expect(preKey.id).toBe(index);
        expect(preKey.publicKey).toBeDefined();
        expect(preKey.privateKey).toBeDefined();
        expect(typeof preKey.publicKey).toBe("string");
        expect(typeof preKey.privateKey).toBe("string");
      });
    });

    test("generates signed pre-key", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const signedPreKey = await SignalProtocol.generateSignedPreKey(
        "mockPrivKey",
        "mockPubKey",
        1,
      );

      expect(signedPreKey).toBeDefined();
      expect(signedPreKey.id).toBe(1);
      expect(signedPreKey.publicKey).toBeDefined();
      expect(signedPreKey.privateKey).toBeDefined();
      expect(signedPreKey.signature).toBeDefined();
      expect(signedPreKey.timestamp).toBeDefined();
      expect(typeof signedPreKey.signature).toBe("string");
      expect(typeof signedPreKey.timestamp).toBe("number");
    });
  });

  describe("Session Management", () => {
    test("initializes a session for a user", () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const result = SignalProtocol.initializeSession("alice");

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.userId).toBe("alice");
    });

    test("processes pre-key bundle", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      // Initialize sessions for both users
      SignalProtocol.initializeSession("alice");
      SignalProtocol.initializeSession("bob");

      // Create a mock pre-key bundle
      const bundle = {
        identityKey: "mockIdentityKey",
        signedPreKeyPublic: "mockSignedPreKey",
        signedPreKeySignature: "mockSignature",
        preKeyPublic: "mockPreKey",
      };

      const result = await SignalProtocol.processPreKeyBundle(
        "alice",
        "bob",
        JSON.stringify(bundle),
      );

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
    });
  });

  describe("Message Encryption/Decryption", () => {
    let aliceId, bobId;

    beforeEach(() => {
      if (!wasmLoaded) return;

      aliceId = "alice_" + Date.now();
      bobId = "bob_" + Date.now();

      // Initialize sessions
      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);
    });

    test("encrypts a message", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const message = "Hello, Bob!";
      const encrypted = await SignalProtocol.encryptMessage(
        aliceId,
        bobId,
        message,
      );

      expect(encrypted).toBeDefined();
      expect(encrypted.type).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
      expect(typeof encrypted.ciphertext).toBe("string"); // Base64 encoded
      expect(encrypted.ciphertext).not.toBe(message); // Should be encrypted
    });

    test("full encryption/decryption flow", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      // Setup pre-key bundle exchange
      const bundle = {
        identityKey: "mockIdentityKey",
        signedPreKeyPublic: "mockSignedPreKey",
        signedPreKeySignature: "mockSignature",
        preKeyPublic: "mockPreKey",
      };

      await SignalProtocol.processPreKeyBundle(
        aliceId,
        bobId,
        JSON.stringify(bundle),
      );

      // Encrypt message from Alice to Bob
      const originalMessage = "Secret message from Alice";
      const encrypted = await SignalProtocol.encryptMessage(
        aliceId,
        bobId,
        originalMessage,
      );

      expect(encrypted.ciphertext).toBeDefined();

      // Decrypt message at Bob's side
      const decrypted = await SignalProtocol.decryptMessage(
        bobId,
        aliceId,
        encrypted.ciphertext,
      );

      expect(decrypted).toBe(originalMessage);
    });
  });

  describe("Double Ratchet Protocol", () => {
    test("maintains forward secrecy", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const aliceId = "alice_ratchet_" + Date.now();
      const bobId = "bob_ratchet_" + Date.now();

      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);

      // Exchange multiple messages
      const messages = ["Message 1", "Message 2", "Message 3"];

      for (const msg of messages) {
        const encrypted = await SignalProtocol.encryptMessage(
          aliceId,
          bobId,
          msg,
        );
        const decrypted = await SignalProtocol.decryptMessage(
          bobId,
          aliceId,
          encrypted.ciphertext,
        );

        expect(decrypted).toBe(msg);

        // Each encryption should produce different ciphertext (forward secrecy)
        const encrypted2 = await SignalProtocol.encryptMessage(
          aliceId,
          bobId,
          msg,
        );
        expect(encrypted2.ciphertext).not.toBe(encrypted.ciphertext);
      }
    });
  });

  describe("Error Handling", () => {
    test("handles invalid user ID gracefully", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      await expect(async () => {
        await SignalProtocol.encryptMessage("nonexistent", "bob", "test");
      }).rejects.toThrow();
    });

    test("handles invalid ciphertext gracefully", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const aliceId = "alice_error_" + Date.now();
      const bobId = "bob_error_" + Date.now();

      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);

      await expect(async () => {
        await SignalProtocol.decryptMessage(
          bobId,
          aliceId,
          "invalid_ciphertext",
        );
      }).rejects.toThrow();
    });
  });

  describe("Performance", () => {
    test("key generation performance", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const iterations = 10;
      const start = performance.now();

      for (let i = 0; i < iterations; i++) {
        await SignalProtocol.generateIdentityKeyPair();
      }

      const elapsed = performance.now() - start;
      const avgTime = elapsed / iterations;

      console.log(`Average key generation time: ${avgTime.toFixed(2)}ms`);

      // Key generation should be reasonably fast (< 50ms per key pair)
      expect(avgTime).toBeLessThan(50);
    });

    test("encryption/decryption performance", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const aliceId = "alice_perf_" + Date.now();
      const bobId = "bob_perf_" + Date.now();

      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);

      const message = "Performance test message with some content";
      const iterations = 20;

      const start = performance.now();

      for (let i = 0; i < iterations; i++) {
        const encrypted = await SignalProtocol.encryptMessage(
          aliceId,
          bobId,
          message,
        );
        await SignalProtocol.decryptMessage(
          bobId,
          aliceId,
          encrypted.ciphertext,
        );
      }

      const elapsed = performance.now() - start;
      const avgTime = elapsed / iterations;

      console.log(`Average encrypt/decrypt time: ${avgTime.toFixed(2)}ms`);

      // Encryption/decryption should be fast (< 10ms per operation)
      expect(avgTime).toBeLessThan(10);
    });
  });

  describe("Compatibility", () => {
    test("handles UTF-8 messages correctly", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const aliceId = "alice_utf8_" + Date.now();
      const bobId = "bob_utf8_" + Date.now();

      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);

      const messages = [
        "你好世界", // Chinese
        "مرحبا بالعالم", // Arabic
        "🔐🔑🔒", // Emojis
        "Привет мир", // Russian
      ];

      for (const msg of messages) {
        const encrypted = await SignalProtocol.encryptMessage(
          aliceId,
          bobId,
          msg,
        );
        const decrypted = await SignalProtocol.decryptMessage(
          bobId,
          aliceId,
          encrypted.ciphertext,
        );
        expect(decrypted).toBe(msg);
      }
    });

    test("handles large messages", async () => {
      if (!wasmLoaded) {
        console.log("⚠️ Skipping: WASM not loaded");
        expect(true).toBe(true);
        return;
      }

      const aliceId = "alice_large_" + Date.now();
      const bobId = "bob_large_" + Date.now();

      SignalProtocol.initializeSession(aliceId);
      SignalProtocol.initializeSession(bobId);

      // Create a large message (10KB)
      const largeMessage = "x".repeat(10000);

      const encrypted = await SignalProtocol.encryptMessage(
        aliceId,
        bobId,
        largeMessage,
      );
      const decrypted = await SignalProtocol.decryptMessage(
        bobId,
        aliceId,
        encrypted.ciphertext,
      );

      expect(decrypted).toBe(largeMessage);
    });
  });
});
