// Jest setup file for crypto functionality tests
const { TextEncoder, TextDecoder } = require("util");
const { createHash } = require("crypto");

// Fix React testing warnings by mocking clipboard API
Object.defineProperty(navigator, "clipboard", {
  value: {
    writeText: jest.fn(() => Promise.resolve()),
    readText: jest.fn(() => Promise.resolve("test")),
  },
  writable: true,
  configurable: true,
});

// Also provide it globally for tests
global.navigator = global.navigator || {};
global.navigator.clipboard = {
  writeText: jest.fn(() => Promise.resolve()),
  readText: jest.fn(() => Promise.resolve("test")),
};

// Suppress React act warnings in tests
const originalError = console.error;
beforeAll(() => {
  console.error = (...args) => {
    if (
      typeof args[0] === "string" &&
      (args[0].includes("ReactDOMTestUtils.act is deprecated") ||
        args[0].includes("Warning: An update to") ||
        args[0].includes("not implemented: navigation") ||
        args[0].includes("Failed to copy:"))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Provide TextEncoder and TextDecoder for Jest environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Provide basic File implementation for tests
global.File = class File {
  constructor(bits, filename, options = {}) {
    this.bits = bits;
    this.name = filename;
    this.type = options.type || "";
    this.size = bits.reduce(
      (acc, bit) => acc + (bit.length || bit.byteLength || 0),
      0,
    );
  }

  async text() {
    return this.bits.join("");
  }

  async arrayBuffer() {
    const text = this.bits.join("");
    return new TextEncoder().encode(text).buffer;
  }
};

// Provide Blob implementation for tests
global.Blob = class Blob {
  constructor(bits, options = {}) {
    this.bits = bits;
    this.type = options.type || "";
  }
};

// Provide URL methods for file downloads
global.URL = {
  createObjectURL: jest.fn(() => "blob:test-url"),
  revokeObjectURL: jest.fn(),
};

// Provide document methods for file downloads
global.document = {
  createElement: jest.fn(() => ({
    href: "",
    download: "",
    click: jest.fn(),
    remove: jest.fn(),
  })),
  body: {
    appendChild: jest.fn(),
    removeChild: jest.fn(),
  },
};

// Counter for generating unique keys in tests
let keyCounter = 0;

// Mock crypto.subtle for tests
const mockSubtle = {
  digest: jest.fn(() => Promise.resolve(new ArrayBuffer(32))),
  generateKey: jest.fn((algorithm, extractable, usages) => {
    if (algorithm.name === "RSA-OAEP") {
      return Promise.resolve({
        publicKey: { type: "public", algorithm: { name: "RSA-OAEP" } },
        privateKey: { type: "private", algorithm: { name: "RSA-OAEP" } },
      });
    } else if (algorithm.name === "AES-GCM") {
      return Promise.resolve({
        type: "secret",
        algorithm: { name: "AES-GCM" },
      });
    } else if (algorithm.name === "Ed25519") {
      keyCounter++;
      return Promise.resolve({
        publicKey: {
          type: "public",
          algorithm: { name: "Ed25519" },
          usages: usages || ["verify"],
          extractable,
          _id: `ed25519-pub-${keyCounter}`,
        },
        privateKey: {
          type: "private",
          algorithm: { name: "Ed25519" },
          usages: usages || ["sign"],
          extractable,
          _id: `ed25519-priv-${keyCounter}`,
        },
      });
    } else if (algorithm.name === "X25519") {
      keyCounter++;
      return Promise.resolve({
        publicKey: {
          type: "public",
          algorithm: { name: "X25519" },
          usages: usages || [],
          extractable,
          _id: `x25519-pub-${keyCounter}`,
        },
        privateKey: {
          type: "private",
          algorithm: { name: "X25519" },
          usages: usages || ["deriveBits"],
          extractable,
          _id: `x25519-priv-${keyCounter}`,
        },
      });
    } else if (algorithm.name === "X25519") {
      return Promise.resolve({
        publicKey: {
          type: "public",
          algorithm: { name: "X25519" },
          usages: [],
        },
        privateKey: {
          type: "private",
          algorithm: { name: "X25519" },
          usages: ["deriveBits"],
        },
      });
    }
    return Promise.resolve({ type: "unknown" });
  }),
  exportKey: jest.fn((format, key) => {
    if (format === "jwk") {
      if (key.algorithm?.name === "Ed25519") {
        keyCounter++;
        return Promise.resolve({
          kty: "OKP",
          crv: "Ed25519",
          x: `test-ed25519-key-${keyCounter}`,
          use: "sig",
          key_ops: key.type === "public" ? ["verify"] : ["sign"],
        });
      } else if (key.algorithm?.name === "X25519") {
        keyCounter++;
        return Promise.resolve({
          kty: "OKP",
          crv: "X25519",
          x: `test-x25519-key-${keyCounter}`,
          use: "enc",
          key_ops: key.type === "public" ? [] : ["deriveBits"],
        });
      } else if (key.algorithm?.name === "AES-GCM") {
        keyCounter++;
        // Generate proper AES-GCM key in JWK format
        const keyValue = Buffer.from("aes-key-" + keyCounter).toString(
          "base64",
        );
        return Promise.resolve({
          kty: "oct",
          alg: "A256GCM",
          k: keyValue,
          key_ops: key.type === "secret" ? ["encrypt", "decrypt"] : ["encrypt"],
        });
      } else {
        // Use counter to generate different keys each time
        keyCounter++;
        return Promise.resolve({
          kty: key.type === "public" || key.type === "private" ? "RSA" : "oct",
          use: "enc",
          key_ops:
            key.type === "public"
              ? ["encrypt"]
              : key.type === "private"
                ? ["decrypt"]
                : ["encrypt", "decrypt"],
          alg: "RS256",
          n: "test-n-value-" + keyCounter,
          e: "AQAB",
          d:
            key.type === "private"
              ? "test-private-exponent-d-" + keyCounter
              : undefined,
        });
      }
    }
    return Promise.resolve(new ArrayBuffer(32));
  }),
  importKey: jest.fn((format, keyData) => {
    // Handle raw key data (for PBKDF2 etc.)
    if (format === "raw") {
      return Promise.resolve({ type: "imported-raw" });
    }

    // Handle JWK format
    if (format === "jwk") {
      if (typeof keyData === "string") {
        keyData = JSON.parse(keyData);
      }
      if (!keyData.kty) {
        throw new Error("Invalid JWK format");
      }

      // Return proper CryptoKey for AES
      if (
        keyData.kty === "oct" &&
        (keyData.alg === "A256GCM" || keyData.alg === "AES-GCM")
      ) {
        return Promise.resolve({
          type: "secret",
          algorithm: { name: "AES-GCM", length: 256 },
          usages: ["encrypt", "decrypt"],
          extractable: true,
        });
      }
    }

    return Promise.resolve({ type: "imported" });
  }),
  deriveKey: jest.fn(() => Promise.resolve({ type: "derived" })),
  encrypt: jest.fn((algorithm, key, data) => {
    // For AES-GCM, preserve input data and add a 16-byte authentication tag
    // This simulates real AES-GCM behavior where output = input + 16-byte tag
    const inputArray = new Uint8Array(data);
    const output = new Uint8Array(inputArray.length + 16);
    output.set(inputArray, 0);
    // Add mock tag (with some randomness to simulate different ciphertexts with different IVs)
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      tag[i] = Math.floor(Math.random() * 256);
    }
    output.set(tag, inputArray.length);
    return Promise.resolve(output.buffer);
  }),
  decrypt: jest.fn((algorithm, key, data) => {
    // For AES-GCM, remove 16-byte authentication tag and return original data
    // This preserves data format through encryption/decryption
    const inputArray = new Uint8Array(data);

    // Handle backward compatibility: if data is less than 16 bytes, it's likely old test data
    // Return it as-is (old mock behavior for very short data)
    if (inputArray.length < 16) {
      return Promise.resolve(inputArray.buffer);
    }
    // For data with tag (new format), remove last 16 bytes (authentication tag)
    const output = new Uint8Array(inputArray.length - 16);
    output.set(inputArray.subarray(0, inputArray.length - 16), 0);
    return Promise.resolve(output.buffer);
  }),
  sign: jest.fn(async (algorithm, privateKey, data) => {
    // Mock Ed25519 signature - return 64 bytes based on input
    const inputBytes = new Uint8Array(data);
    const signature = new Uint8Array(64);
    // Simple signature based on input (not cryptographically secure, just for testing)
    for (let i = 0; i < Math.min(64, inputBytes.length); i++) {
      signature[i] = inputBytes[i];
    }
    return signature.buffer;
  }),
  verify: jest.fn(async (algorithm, publicKey, signature, data) => {
    // Mock Ed25519 verification - check if signature matches data
    const signatureBytes = new Uint8Array(signature);
    const dataBytes = new Uint8Array(data);
    // Simple verification (not cryptographically secure, just for testing)
    if (signatureBytes.length !== 64) return false;
    for (let i = 0; i < Math.min(64, dataBytes.length); i++) {
      if (signatureBytes[i] !== dataBytes[i]) return false;
    }
    return true;
  }),
  deriveBits: jest.fn(() => Promise.resolve(new ArrayBuffer(32))),
};

// Set up crypto for both global and window
const mockCrypto = {
  subtle: mockSubtle,
  getRandomValues: jest.fn((arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  }),
};

// Provide crypto in multiple ways for maximum compatibility
global.crypto = mockCrypto;
globalThis.crypto = mockCrypto;
global.window = global.window || {};
global.window.crypto = mockCrypto;

// Make crypto available globally for direct access
Object.defineProperty(global, "crypto", {
  value: mockCrypto,
  writable: true,
  configurable: true,
});

// Provide btoa/atob for base64 encoding
global.btoa = (str) => Buffer.from(str, "binary").toString("base64");
global.atob = (str) => Buffer.from(str, "base64").toString("binary");
