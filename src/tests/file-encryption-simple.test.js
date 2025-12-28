/**
 * Simple integration tests for file encryption functionality
 * Tests the actual functions through the React provider
 */

import React from "react";
import { render, waitFor } from "@testing-library/react";
import {
  CryptographyProvider,
  useCryptography,
} from "../stories/components/Cryptography";

// Test component to access the crypto functions
const TestComponent = ({ testCallback }) => {
  const crypto = useCryptography();

  React.useEffect(() => {
    if (crypto && testCallback) {
      testCallback(crypto);
    }
  }, [crypto, testCallback]);

  return <div>Test Component</div>;
};

describe("File Encryption Integration Tests", () => {
  test("should have encryptTextFile and decryptTextFile functions", async () => {
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

    // Check that text file encryption functions exist
    expect(cryptoMethods.encryptTextFile).toBeDefined();
    expect(typeof cryptoMethods.encryptTextFile).toBe("function");
    expect(cryptoMethods.decryptTextFile).toBeDefined();
    expect(typeof cryptoMethods.decryptTextFile).toBe("function");
  });

  test("should have password-based key derivation function", async () => {
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

    expect(cryptoMethods.deriveKeyFromPassword).toBeDefined();
    expect(typeof cryptoMethods.deriveKeyFromPassword).toBe("function");
  });

  test("should have binary file encryption functions", async () => {
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

    expect(cryptoMethods.encryptBinaryFile).toBeDefined();
    expect(typeof cryptoMethods.encryptBinaryFile).toBe("function");
    expect(cryptoMethods.decryptBinaryFile).toBeDefined();
    expect(typeof cryptoMethods.decryptBinaryFile).toBe("function");
  });

  test("should have generic encryptFile function", async () => {
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

    expect(cryptoMethods.encryptFile).toBeDefined();
    expect(typeof cryptoMethods.encryptFile).toBe("function");
    expect(cryptoMethods.decryptFile).toBeDefined();
    expect(typeof cryptoMethods.decryptFile).toBe("function");
  });

  test("should have file download function", async () => {
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

    expect(cryptoMethods.createSecureFileDownload).toBeDefined();
    expect(typeof cryptoMethods.createSecureFileDownload).toBe("function");
  });

  test("should have input validation capabilities", async () => {
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

    // Check that functions exist for validation
    expect(cryptoMethods.encryptFile).toBeDefined();
    expect(cryptoMethods.encryptBinaryFile).toBeDefined();
    // These functions should handle input validation internally
  });

  test("should have all expected crypto methods available", async () => {
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

  test("should parse and validate encrypted file packages", async () => {
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

    // Create a valid encrypted file package
    const validPackage = {
      encryptedData: "dGVzdA==",
      iv: "aXZkYXRh",
      salt: "c2FsdGRhdGE=",
      fileName: "test.txt",
      timestamp: "2023-01-01T00:00:00.000Z",
      originalSize: 100,
      type: "text",
    };

    const jsonContent = JSON.stringify(validPackage);
    const mockFile = new File([jsonContent], "test.encrypted.json", {
      type: "application/json",
    });

    const validation = await cryptoMethods.parseEncryptedFilePackage(mockFile);

    expect(validation.isValid).toBe(true);
    expect(validation.metadata.fileName).toBe("test.txt");
    expect(validation.metadata.originalSize).toBe(100);
    expect(validation.metadata.type).toBe("text");
  });

  test("should reject invalid encrypted file packages", async () => {
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

    // Create an invalid package (missing required fields)
    const invalidPackage = {
      encryptedData: "dGVzdA==",
      fileName: "test.txt",
      // Missing iv, salt, timestamp, originalSize
    };

    const jsonContent = JSON.stringify(invalidPackage);
    const mockFile = new File([jsonContent], "invalid.json", {
      type: "application/json",
    });

    const validation = await cryptoMethods.parseEncryptedFilePackage(mockFile);

    expect(validation.isValid).toBe(false);
    expect(validation.error).toContain("Missing required property");
  });

  test("should have encrypted file upload functions", async () => {
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

    // Check that encrypted file upload functions exist
    expect(cryptoMethods.parseEncryptedFilePackage).toBeDefined();
    expect(typeof cryptoMethods.parseEncryptedFilePackage).toBe("function");
    expect(cryptoMethods.decryptUploadedFile).toBeDefined();
    expect(typeof cryptoMethods.decryptUploadedFile).toBe("function");
  });
});
