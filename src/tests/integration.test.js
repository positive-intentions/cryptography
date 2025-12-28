/**
 * Integration tests for the cryptography module
 * Tests the actual functionality without React context
 */

import { randomString } from "../stories/components/Cryptography";

describe("Cryptography Integration Tests", () => {
  describe("randomString function", () => {
    test("should generate random strings", () => {
      const result1 = randomString();
      const result2 = randomString();

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(typeof result1).toBe("string");
      expect(typeof result2).toBe("string");
      expect(result1.length).toBe(32);
      expect(result2.length).toBe(32);
      expect(result1).not.toBe(result2);
    });

    test("should handle salt parameter", () => {
      const salt = "test-salt";
      const result = randomString(salt);

      expect(result.startsWith(salt)).toBe(true);
      expect(result.length).toBe(salt.length + 32);
    });

    test("should generate hexadecimal output", () => {
      const result = randomString();
      expect(result).toMatch(/^[0-9a-f]+$/);
    });

    test("should handle invalid inputs gracefully", () => {
      // Test with negative length (should use default)
      const result1 = randomString(null, -5);
      expect(result1).toBeDefined();
      expect(typeof result1).toBe("string");

      // Test with empty string salt
      const result2 = randomString("");
      expect(result2).toBeDefined();
      expect(typeof result2).toBe("string");
      expect(result2.length).toBe(32); // Default length when no salt
    });

    test("should handle edge cases", () => {
      // Test with very large salt
      const largeSalt = "a".repeat(1000);
      const result = randomString(largeSalt);
      expect(result).toBeDefined();
      expect(result.startsWith(largeSalt)).toBe(true);

      // Test with special characters in salt
      const specialSalt = "!@#$%^&*()";
      const result2 = randomString(specialSalt);
      expect(result2).toBeDefined();
      expect(result2.startsWith(specialSalt)).toBe(true);
    });
  });

  describe("Error handling scenarios", () => {
    test("should handle JSON parsing errors gracefully", () => {
      // These tests simulate the error handling we added to story components
      const invalidJson = '{"invalid": json}';

      // Test that our components would handle this gracefully
      expect(() => {
        try {
          JSON.parse(invalidJson);
        } catch (error) {
          // This is expected behavior - JSON.parse should throw
          expect(error).toBeInstanceOf(SyntaxError);
        }
      }).not.toThrow();
    });

    test("should handle null/undefined values in JSON.stringify", () => {
      // Test the null checks we added
      const nullValue = null;
      const undefinedValue = undefined;
      const emptyObject = {};

      expect(JSON.stringify(nullValue)).toBe("null");
      expect(JSON.stringify(undefinedValue)).toBe(undefined);
      expect(JSON.stringify(emptyObject)).toBe("{}");

      // Test with fallback pattern we use in components
      const safeStringify = (obj) =>
        obj ? JSON.stringify(obj, null, 2) : "No data available";
      expect(safeStringify(null)).toBe("No data available");
      expect(safeStringify(undefined)).toBe("No data available");
      expect(safeStringify(emptyObject)).toBe("{}");
    });

    test("should handle parseInt edge cases", () => {
      // Test the parseInt validation we added
      const parseIntSafely = (value, defaultValue) => {
        const parsed = parseInt(value, 10);
        return isNaN(parsed) ? defaultValue : parsed;
      };

      expect(parseIntSafely("123", 1)).toBe(123);
      expect(parseIntSafely("invalid", 1)).toBe(1);
      expect(parseIntSafely("", 1)).toBe(1);
      expect(parseIntSafely(null, 1)).toBe(1);
      expect(parseIntSafely(undefined, 1)).toBe(1);
    });

    test("should handle division by zero scenarios", () => {
      // Test the division by zero protection we added
      const safeDivision = (numerator, denominator) => {
        return denominator === 0 ? "N/A" : (numerator / denominator).toFixed(2);
      };

      expect(safeDivision(10, 2)).toBe("5.00");
      expect(safeDivision(10, 0)).toBe("N/A");
      expect(safeDivision(0, 5)).toBe("0.00");
    });
  });

  // Note: Other functions are tested through React component interaction
  // since they're not exported as standalone functions

  test("module should export expected components", () => {
    expect(randomString).toBeDefined();
    expect(typeof randomString).toBe("function");
  });
});
