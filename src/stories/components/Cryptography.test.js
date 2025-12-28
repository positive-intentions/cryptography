/**
 * Tests for the Cryptography React provider
 */

import React from "react";
import { render, waitFor } from "@testing-library/react";
import { CryptographyProvider, useCryptography } from "./Cryptography";

// Test component to access crypto methods
const TestComponent = ({ onMethodsReady }) => {
  const methods = useCryptography();

  React.useEffect(() => {
    if (methods && onMethodsReady) {
      onMethodsReady(methods);
    }
  }, [methods, onMethodsReady]);

  return <div>Test Component</div>;
};

describe("Cryptography Module", () => {
  describe("Provider Integration", () => {
    test("should provide all expected methods", async () => {
      let cryptoMethods;

      const handleMethodsReady = (methods) => {
        cryptoMethods = methods;
      };

      render(
        <CryptographyProvider>
          <TestComponent onMethodsReady={handleMethodsReady} />
        </CryptographyProvider>,
      );

      await waitFor(() => {
        expect(cryptoMethods).toBeDefined();
      });

      // Check core methods exist
      const expectedMethods = [
        "randomString",
        "sha256Hash",
        "sha512Hash",
        "sha3_512Hash",
        "generateKeyPair",
        "generateSymmetricKey",
        "encryptTextFile",
        "decryptTextFile",
        "parseEncryptedFilePackage",
        "decryptUploadedFile",
      ];

      expectedMethods.forEach((method) => {
        expect(cryptoMethods).toHaveProperty(method);
        expect(typeof cryptoMethods[method]).toBe("function");
      });

      // Check Chance.js integration
      expect(cryptoMethods.chance).toBeDefined();
      expect(typeof cryptoMethods.chance.integer).toBe("function");
    });

    test("should provide working randomString function", async () => {
      let cryptoMethods;

      const handleMethodsReady = (methods) => {
        cryptoMethods = methods;
      };

      render(
        <CryptographyProvider>
          <TestComponent onMethodsReady={handleMethodsReady} />
        </CryptographyProvider>,
      );

      await waitFor(() => {
        expect(cryptoMethods).toBeDefined();
      });

      const result = cryptoMethods.randomString();
      expect(typeof result).toBe("string");
      expect(result.length).toBe(32); // 16 bytes * 2 hex chars
    });
  });
});
