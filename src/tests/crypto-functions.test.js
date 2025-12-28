/**
 * Simple unit tests for core cryptographic functions
 * Tests the crypto functions through React provider context
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

describe("Core Cryptographic Functions", () => {
  test("should provide randomString function", async () => {
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

    expect(cryptoMethods.randomString).toBeDefined();
    expect(typeof cryptoMethods.randomString).toBe("function");

    const result = cryptoMethods.randomString();
    expect(result).toBeDefined();
    expect(typeof result).toBe("string");
    expect(result.length).toBe(32); // 16 bytes * 2 hex chars per byte
  });

  test("should provide hashing functions", async () => {
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

    // Check all hash functions are available
    expect(cryptoMethods.sha256Hash).toBeDefined();
    expect(cryptoMethods.sha512Hash).toBeDefined();
    expect(cryptoMethods.sha3_512Hash).toBeDefined();

    expect(typeof cryptoMethods.sha256Hash).toBe("function");
    expect(typeof cryptoMethods.sha512Hash).toBe("function");
    expect(typeof cryptoMethods.sha3_512Hash).toBe("function");
  });

  test("should provide RSA functions", async () => {
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

    // Check RSA functions are available
    expect(cryptoMethods.generateKeyPair).toBeDefined();
    expect(cryptoMethods.deserializePublicKey).toBeDefined();
    expect(cryptoMethods.deserializePrivateKey).toBeDefined();
    expect(cryptoMethods.encrypt).toBeDefined();
    expect(cryptoMethods.decrypt).toBeDefined();
  });

  test("should provide symmetric encryption functions", async () => {
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

    // Check symmetric encryption functions are available
    expect(cryptoMethods.generateSymmetricKey).toBeDefined();
    expect(cryptoMethods.deserializeSymmetricKey).toBeDefined();
    expect(cryptoMethods.encryptWithSymmetricKey).toBeDefined();
    expect(cryptoMethods.decryptWithSymmetricKey).toBeDefined();
  });

  test("should provide file encryption functions", async () => {
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

    // Check file encryption functions are available
    expect(cryptoMethods.encryptTextFile).toBeDefined();
    expect(cryptoMethods.decryptTextFile).toBeDefined();
    expect(cryptoMethods.encryptBinaryFile).toBeDefined();
    expect(cryptoMethods.decryptBinaryFile).toBeDefined();
    expect(cryptoMethods.parseEncryptedFilePackage).toBeDefined();
    expect(cryptoMethods.decryptUploadedFile).toBeDefined();
  });

  test("should provide Chance.js instance", async () => {
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

    expect(cryptoMethods.chance).toBeDefined();
    expect(typeof cryptoMethods.chance.integer).toBe("function");
    expect(typeof cryptoMethods.chance.string).toBe("function");
  });
});
