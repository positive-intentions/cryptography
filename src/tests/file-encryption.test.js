/**
 * Unit tests for password-based file encryption functionality
 * This is a simplified version that focuses on core functionality
 */

import React from "react";
import { render, waitFor } from "@testing-library/react";
import {
  CryptographyProvider,
  useCryptography,
} from "../stories/components/Cryptography";

// Test component to access crypto functions
const TestComponent = ({ testCallback }) => {
  const crypto = useCryptography();

  React.useEffect(() => {
    if (crypto && testCallback) {
      testCallback(crypto);
    }
  }, [crypto, testCallback]);

  return <div>Test Component</div>;
};

describe("Password-based File Encryption", () => {
  test("should have all file encryption methods available", async () => {
    let cryptoMethods;

    const testCallback = (crypto) => {
      cryptoMethods = crypto;
    };

    render(
      <CryptographyProvider>
        <TestComponent testCallback={testCallback} />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Check that all file encryption methods are available
    const expectedMethods = [
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
    ];

    expectedMethods.forEach((method) => {
      expect(cryptoMethods).toHaveProperty(method);
      expect(typeof cryptoMethods[method]).toBe("function");
    });
  });

  test("should provide crypto utility functions", async () => {
    let cryptoMethods;

    const testCallback = (crypto) => {
      cryptoMethods = crypto;
    };

    render(
      <CryptographyProvider>
        <TestComponent testCallback={testCallback} />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Test that basic crypto functions exist
    expect(cryptoMethods.randomString).toBeDefined();
    expect(cryptoMethods.sha256Hash).toBeDefined();
    expect(cryptoMethods.generateKeyPair).toBeDefined();
    expect(cryptoMethods.generateSymmetricKey).toBeDefined();
  });
});
