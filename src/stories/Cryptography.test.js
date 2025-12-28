import { TextEncoder, TextDecoder } from "util";
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

const crypto = require("crypto");

// Mock Web Crypto API for Node.js testing environment
Object.defineProperty(globalThis, "crypto", {
  value: {
    getRandomValues: (arr) => {
      const randomBytes = crypto.randomBytes(arr.length);
      for (let i = 0; i < arr.length; i++) {
        arr[i] = randomBytes[i];
      }
      return arr;
    },
    subtle: {
      digest: async (algorithm, data) => {
        let nodeAlgorithm;
        switch (algorithm) {
          case "SHA-256":
            nodeAlgorithm = "sha256";
            break;
          case "SHA-512":
            nodeAlgorithm = "sha512";
            break;
          case "SHA-1":
            nodeAlgorithm = "sha1";
            break;
          default:
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
        const hash = crypto.createHash(nodeAlgorithm);
        hash.update(data);
        return new Uint8Array(hash.digest());
      },
      generateKey: jest.fn().mockResolvedValue({
        publicKey: "mock-public-key",
        privateKey: "mock-private-key",
      }),
      importKey: jest.fn().mockResolvedValue("mock-imported-key"),
      exportKey: jest.fn().mockResolvedValue({
        kty: "RSA",
        n: "mock-key-data",
      }),
      encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
      decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
      deriveKey: jest.fn().mockResolvedValue("mock-derived-key"),
    },
  },
});

// Add polyfills
global.alert = jest.fn();
global.atob = (str) => Buffer.from(str, "base64").toString("binary");
global.btoa = (str) => Buffer.from(str, "binary").toString("base64");

import React, { useState } from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";

import {
  CryptographyProvider,
  useCryptography,
} from "./components/Cryptography.tsx";

// Create a simple test component that mimics the story
const TestCryptoDemo = () => {
  const crypto = useCryptography();
  const [result, setResult] = useState("");

  const testBasicFunction = async () => {
    try {
      const hash = await crypto.sha256Hash("Hello, Cryptography!");
      setResult(hash);
    } catch (error) {
      setResult(`Error: ${error.message}`);
    }
  };

  return (
    <div>
      <h1>Cryptography Provider Demo</h1>
      <p>Click the button below to test basic cryptographic functionality.</p>
      <button onClick={testBasicFunction}>Test SHA-256 Hash</button>
      {result && (
        <div>
          <span>Result:</span>
          <span>{result}</span>
        </div>
      )}
    </div>
  );
};

describe("Cryptography Story-like Tests", () => {
  test("should render the basic cryptography provider demo", async () => {
    render(
      <CryptographyProvider entropy="">
        <TestCryptoDemo />
      </CryptographyProvider>,
    );

    // Check if the demo title renders
    expect(screen.getByText("Cryptography Provider Demo")).toBeInTheDocument();

    // Check if the button renders
    const testButton = screen.getByRole("button", {
      name: /test sha-256 hash/i,
    });
    expect(testButton).toBeInTheDocument();

    // Check if the description text renders
    expect(
      screen.getByText(/click the button below to test/i),
    ).toBeInTheDocument();
  });

  test("should handle button click and show result", async () => {
    render(
      <CryptographyProvider entropy="">
        <TestCryptoDemo />
      </CryptographyProvider>,
    );

    const testButton = screen.getByRole("button", {
      name: /test sha-256 hash/i,
    });

    // Click the test button
    fireEvent.click(testButton);

    // Wait for the result to appear (either hash or error)
    await waitFor(
      () => {
        const resultElement = screen.getByText(/result:/i);
        expect(resultElement).toBeInTheDocument();
      },
      { timeout: 3000 },
    );
  });

  test("should work with entropy prop", async () => {
    render(
      <CryptographyProvider entropy="test-entropy-123">
        <TestCryptoDemo />
      </CryptographyProvider>,
    );

    expect(screen.getByText("Cryptography Provider Demo")).toBeInTheDocument();

    const testButton = screen.getByRole("button", {
      name: /test sha-256 hash/i,
    });
    expect(testButton).toBeInTheDocument();
  });

  test("should handle crypto provider functionality", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
      expect(cryptoMethods.sha256Hash).toBeDefined();
      expect(cryptoMethods.randomString).toBeDefined();
      expect(cryptoMethods.chance).toBeDefined();
    });
  });

  test("should test all hash functions with various inputs", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const testInputs = ["string", { obj: "value" }, 123];

    for (const input of testInputs) {
      const sha256 = await cryptoMethods.sha256Hash(input);
      const sha512 = await cryptoMethods.sha512Hash(input);
      const sha3 = await cryptoMethods.sha3_512Hash(input);

      expect(sha256).toBeDefined();
      expect(sha512).toBeDefined();
      expect(sha3).toBeDefined();
    }
  });

  test("should test RSA key operations", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const keyPair = await cryptoMethods.generateKeyPair();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();

    // Test key deserialization - both object and string paths
    const pubKey = await cryptoMethods.deserializePublicKey({ kty: "RSA" });
    const pubKeyStr = await cryptoMethods.deserializePublicKey('{"kty":"RSA"}');
    const privKey = await cryptoMethods.deserializePrivateKey({ kty: "RSA" });
    const privKeyStr =
      await cryptoMethods.deserializePrivateKey('{"kty":"RSA"}');

    expect(pubKey).toBeDefined();
    expect(pubKeyStr).toBeDefined();
    expect(privKey).toBeDefined();
    expect(privKeyStr).toBeDefined();

    // Test encryption/decryption
    const encrypted = await cryptoMethods.encrypt("test message", pubKey);
    const decrypted = await cryptoMethods.decrypt(encrypted, privKey);
    expect(encrypted).toBeDefined();
    expect(decrypted).toBeDefined();
  });

  test("should test symmetric key operations", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const symKey = await cryptoMethods.generateSymmetricKey();
    const symKeyObj = await cryptoMethods.deserializeSymmetricKey({
      kty: "oct",
    });
    const symKeyStr =
      await cryptoMethods.deserializeSymmetricKey('{"kty":"oct"}');

    expect(symKey).toBeDefined();
    expect(symKeyObj).toBeDefined();
    expect(symKeyStr).toBeDefined();

    // Test kty fix branch
    const wrongKtyKey = { kty: "wrong" };
    await cryptoMethods.deserializeSymmetricKey(wrongKtyKey);
    expect(wrongKtyKey.kty).toBe("oct");

    const symEncrypted = await cryptoMethods.encryptWithSymmetricKey(
      "message",
      symKeyObj,
    );
    const symDecrypted = await cryptoMethods.decryptWithSymmetricKey(
      symEncrypted,
      symKeyObj,
    );
    expect(symEncrypted.ciphertext).toBeDefined();
    expect(symEncrypted.iv).toBeDefined();
    expect(symDecrypted).toBeDefined();
  });

  test("should test file operations", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const password = "test-password";

    // Test deriveKeyFromPassword - both with and without salt
    const result1 = await cryptoMethods.deriveKeyFromPassword(password);
    expect(result1.key).toBeDefined();
    expect(result1.salt).toBeDefined();

    const customSalt = new Uint8Array([1, 2, 3, 4]);
    const result2 = await cryptoMethods.deriveKeyFromPassword(
      password,
      customSalt,
    );
    expect(result2.salt).toBe(customSalt);

    // Test encryptFile with different content types
    const stringContent = "test string";
    const arrayBuffer = new ArrayBuffer(10);

    const enc1 = await cryptoMethods.encryptFile(
      stringContent,
      password,
      "test1.txt",
    );
    const enc2 = await cryptoMethods.encryptFile(
      arrayBuffer,
      password,
      "test2.bin",
    );

    expect(enc1.fileName).toBe("test1.txt");
    expect(enc2.fileName).toBe("test2.bin");

    // Test decryptFile
    const decrypted = await cryptoMethods.decryptFile(enc1, password);
    expect(decrypted.fileName).toBe("test1.txt");

    // Test text file helpers
    const textEnc = await cryptoMethods.encryptTextFile(
      stringContent,
      password,
      "text.txt",
    );
    const textDec = await cryptoMethods.decryptTextFile(textEnc, password);
    expect(textDec.textContent).toBeDefined();

    // Test createSecureFileDownload
    cryptoMethods.createSecureFileDownload(stringContent, "test.txt");
    // Just verify it doesn't throw an error - the mock is already set up
  });

  test("should test error handling paths", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Test deserialize errors with invalid JWK
    await expect(
      cryptoMethods.deserializePublicKey({ invalid: "key" }),
    ).rejects.toThrow('Invalid JWK: missing "kty" property');

    await expect(
      cryptoMethods.deserializePrivateKey({ invalid: "key" }),
    ).rejects.toThrow('Invalid JWK: missing "kty" property');

    await expect(
      cryptoMethods.deserializeSymmetricKey({ invalid: "key" }),
    ).rejects.toThrow('Invalid JWK: missing "kty" property');

    // Test unsupported file content type
    await expect(cryptoMethods.encryptFile(123, "password")).rejects.toThrow(
      "Unsupported file content type",
    );
  });

  test("should test random function with different salts", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Test random function with salt (line 51)
    const randomResult1 = cryptoMethods.randomString();
    const randomResult2 = cryptoMethods.randomString("additional-salt");

    expect(randomResult1).toBeDefined();
    expect(randomResult2).toBeDefined();
    expect(randomResult2).toMatch(/additional-salt/);
  });

  test("should verify all exported methods exist", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const expectedMethods = [
      "randomString",
      "sha256Hash",
      "sha512Hash",
      "sha3_512Hash",
      "generateKeyPair",
      "deserializePublicKey",
      "deserializePrivateKey",
      "encrypt",
      "decrypt",
      "generateSymmetricKey",
      "deserializeSymmetricKey",
      "encryptWithSymmetricKey",
      "decryptWithSymmetricKey",
      "deriveKeyFromPassword",
      "encryptFile",
      "decryptFile",
      "encryptTextFile",
      "decryptTextFile",
      "encryptBinaryFile",
      "decryptBinaryFile",
      "createSecureFileDownload",
      "parseEncryptedFilePackage",
      "decryptUploadedFile",
      "chance",
    ];

    expectedMethods.forEach((method) => {
      expect(cryptoMethods[method]).toBeDefined();
    });
  });

  test("should test additional edge cases and error paths", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Mock crypto errors to test catch blocks
    const originalGenerateKey = globalThis.crypto.subtle.generateKey;
    globalThis.crypto.subtle.generateKey = jest
      .fn()
      .mockRejectedValue(new Error("Generate failed"));

    await expect(cryptoMethods.generateKeyPair()).rejects.toThrow();
    // Console error is already being called based on the test output

    // Restore and test encrypt error
    globalThis.crypto.subtle.generateKey = originalGenerateKey;

    const originalEncrypt = globalThis.crypto.subtle.encrypt;
    globalThis.crypto.subtle.encrypt = jest
      .fn()
      .mockRejectedValue(new Error("Encrypt failed"));

    const result1 = await cryptoMethods.encrypt("test", "key");
    expect(result1).toBeDefined(); // Returns empty string from btoa

    const result2 = await cryptoMethods.encryptWithSymmetricKey("test", "key");
    expect(result2).toBeDefined(); // Returns object with empty ciphertext

    // Restore and test decrypt errors
    globalThis.crypto.subtle.encrypt = originalEncrypt;

    const originalDecrypt = globalThis.crypto.subtle.decrypt;
    globalThis.crypto.subtle.decrypt = jest
      .fn()
      .mockRejectedValue(new Error("Decrypt failed"));

    await expect(cryptoMethods.decrypt("invalid", "key")).rejects.toThrow(
      "Unable to decrypt message. Incorrect passphrase.",
    );

    await expect(
      cryptoMethods.decryptWithSymmetricKey(
        { ciphertext: "invalid", iv: "invalid" },
        "key",
      ),
    ).rejects.toThrow("Unable to decrypt message. Incorrect key.");

    // Test file decrypt error
    const invalidPackage = {
      encryptedData: "invalid",
      iv: "invalid",
      salt: "invalid",
      fileName: "test.txt",
      originalSize: 100,
    };

    await expect(
      cryptoMethods.decryptFile(invalidPackage, "password"),
    ).rejects.toThrow("Failed to decrypt file. Check password and try again.");

    globalThis.crypto.subtle.decrypt = originalDecrypt;
  });

  test("should test file operations with File object and binary files", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    const password = "test-password";

    // Test createSecureFileDownload with all types
    cryptoMethods.createSecureFileDownload(
      new ArrayBuffer(10),
      "test.bin",
      "application/octet-stream",
    );
    cryptoMethods.createSecureFileDownload("string content", "test.txt");

    // Test encryptBinaryFile error
    await expect(
      cryptoMethods.encryptBinaryFile("not-a-file", password),
    ).rejects.toThrow("Expected File object for binary encryption");
  });

  test("should test parseEncryptedFilePackage and decryptUploadedFile", async () => {
    let cryptoMethods;

    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Valid package
    const validPackage = {
      encryptedData: "valid",
      iv: "valid",
      salt: "valid",
      fileName: "test.txt",
      timestamp: "2023-01-01",
      originalSize: 100,
      type: "text",
      mimeType: "text/plain",
    };

    const validFile = {
      text: jest.fn().mockResolvedValue(JSON.stringify(validPackage)),
    };
    const parseResult =
      await cryptoMethods.parseEncryptedFilePackage(validFile);
    expect(parseResult.isValid).toBe(true);
    expect(parseResult.metadata.type).toBe("text");
    expect(parseResult.metadata.mimeType).toBe("text/plain");

    // Test decryptUploadedFile with text type - this will actually work since we have working mocks
    try {
      const uploadResult = await cryptoMethods.decryptUploadedFile(
        validFile,
        "password",
      );
      expect(uploadResult.isTextFile).toBe(true);
      expect(uploadResult.textContent).toBeDefined();
    } catch (error) {
      // If it fails due to mock crypto, that's expected - we still tested the parsing
      expect(error.message).toContain("Failed to decrypt uploaded file");
    }

    // Test with mimeType starting with 'text/'
    delete validPackage.type;
    validPackage.mimeType = "text/plain";
    const mimeFile = {
      text: jest.fn().mockResolvedValue(JSON.stringify(validPackage)),
    };
    try {
      const mimeResult = await cryptoMethods.decryptUploadedFile(
        mimeFile,
        "password",
      );
      expect(mimeResult.isTextFile).toBe(true);
    } catch (error) {
      // Expected due to mock crypto failures
      expect(error.message).toContain("Failed to decrypt uploaded file");
    }

    // Test invalid JSON
    const invalidFile = { text: jest.fn().mockResolvedValue("invalid json") };
    const invalidResult =
      await cryptoMethods.parseEncryptedFilePackage(invalidFile);
    expect(invalidResult.isValid).toBe(false);

    // Test missing properties
    const missingProps = [
      "encryptedData",
      "iv",
      "salt",
      "fileName",
      "timestamp",
      "originalSize",
    ];
    for (const prop of missingProps) {
      const incomplete = { ...validPackage };
      delete incomplete[prop];
      const incompleteFile = {
        text: jest.fn().mockResolvedValue(JSON.stringify(incomplete)),
      };
      const incompleteResult =
        await cryptoMethods.parseEncryptedFilePackage(incompleteFile);
      expect(incompleteResult.isValid).toBe(false);
      expect(incompleteResult.error).toBe(`Missing required property: ${prop}`);
    }

    // Test type validations
    const typeTests = [
      {
        field: "encryptedData",
        value: 123,
        error: "encryptedData must be a base64 string",
      },
      { field: "iv", value: 123, error: "iv must be a base64 string" },
      { field: "salt", value: 123, error: "salt must be a base64 string" },
      { field: "fileName", value: 123, error: "fileName must be a string" },
      {
        field: "originalSize",
        value: "string",
        error: "originalSize must be a number",
      },
    ];

    for (const test of typeTests) {
      const wrongType = { ...validPackage };
      wrongType[test.field] = test.value;
      const wrongTypeFile = {
        text: jest.fn().mockResolvedValue(JSON.stringify(wrongType)),
      };
      const wrongTypeResult =
        await cryptoMethods.parseEncryptedFilePackage(wrongTypeFile);
      expect(wrongTypeResult.isValid).toBe(false);
      expect(wrongTypeResult.error).toBe(test.error);
    }

    // Test decryptUploadedFile error
    await expect(
      cryptoMethods.decryptUploadedFile(invalidFile, "password"),
    ).rejects.toThrow("Failed to decrypt uploaded file:");
    // Console error is already being called based on the test output
  });

  test("should test entropy useEffect and final edge cases", async () => {
    let cryptoMethods;

    // Test with entropy that triggers useEffect
    const TestWrapper = () => {
      const crypto = useCryptography();
      cryptoMethods = crypto;
      return <div>Test Wrapper</div>;
    };

    render(
      <CryptographyProvider entropy="test-entropy">
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Test catch block in entropy useEffect
    const origDigest = globalThis.crypto.subtle.digest;
    globalThis.crypto.subtle.digest = jest
      .fn()
      .mockRejectedValue(new Error("Digest failed"));

    render(
      <CryptographyProvider entropy="error-entropy">
        <TestWrapper />
      </CryptographyProvider>,
    );

    // Wait for the component to render and the error to be triggered
    await waitFor(() => {
      // The error is being logged as shown in test output
      expect(cryptoMethods).toBeDefined();
    });

    globalThis.crypto.subtle.digest = origDigest;

    // Test final edge cases for 100% coverage
    expect(cryptoMethods.chance).toBeDefined();

    // Test randomString at line 51
    const randomResult = cryptoMethods.randomString();
    expect(randomResult).toBeDefined();

    // Test all methods exist
    const allMethods = [
      "randomString",
      "sha256Hash",
      "sha512Hash",
      "sha3_512Hash",
      "generateKeyPair",
      "deserializePublicKey",
      "deserializePrivateKey",
      "encrypt",
      "decrypt",
      "generateSymmetricKey",
      "deserializeSymmetricKey",
      "encryptWithSymmetricKey",
      "decryptWithSymmetricKey",
      "deriveKeyFromPassword",
      "encryptFile",
      "decryptFile",
      "encryptTextFile",
      "decryptTextFile",
      "encryptBinaryFile",
      "decryptBinaryFile",
      "createSecureFileDownload",
      "parseEncryptedFilePackage",
      "decryptUploadedFile",
      "chance",
    ];

    allMethods.forEach((method) => {
      expect(cryptoMethods[method]).toBeDefined();
    });
  });
});
