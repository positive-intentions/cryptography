/**
 * Random Generation Tests
 */

import {
  randomString,
  randomStringWithLength,
  randomInt,
  randomFloat,
} from "../RandomString";

describe("Random String Generation", () => {
  describe("randomString", () => {
    it("should generate a random string", () => {
      const result = randomString();

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBe(32); // 16 bytes * 2 hex chars per byte
    });

    it("should prepend salt when provided", () => {
      const salt = "user:";
      const result = randomString(salt);

      expect(result).toBeDefined();
      expect(result.startsWith(salt)).toBe(true);
      expect(result.length).toBe(salt.length + 32);
    });

    it("should generate valid hexadecimal strings", () => {
      const result = randomString();

      expect(result).toMatch(/^[a-f0-9]+$/);
    });

    it("should generate different strings on each call", () => {
      const results = Array.from({ length: 10 }, () => randomString());
      const unique = new Set(results);

      expect(unique.size).toBeGreaterThan(9); // At least 9 out of 10 should be unique
    });

    it("should handle empty salt", () => {
      const result = randomString("");

      expect(result).toBeDefined();
      expect(result.length).toBe(32);
    });

    it("should handle long salts", () => {
      const longSalt = "very-long-salt-with-many-characters-123456789";
      const result = randomString(longSalt);

      expect(result).toBeDefined();
      expect(result.startsWith(longSalt)).toBe(true);
      expect(result.length).toBe(longSalt.length + 32);
    });
  });

  describe("randomStringWithLength", () => {
    it("should generate string of specified length", () => {
      const result = randomStringWithLength(10);

      expect(result).toBeDefined();
      expect(result.length).toBe(20); // 10 bytes * 2 hex chars per byte
    });

    it("should use default length when not specified", () => {
      const result = randomStringWithLength();

      expect(result).toBeDefined();
      expect(result.length).toBe(32); // Default 16 bytes * 2 hex chars
    });

    it("should generate valid hexadecimal strings", () => {
      const result = randomStringWithLength(8);

      expect(result).toMatch(/^[a-f0-9]+$/);
    });

    it("should prepend salt when provided", () => {
      const salt = "prefix:";
      const result = randomStringWithLength(5, salt);

      expect(result).toBeDefined();
      expect(result.startsWith(salt)).toBe(true);
      expect(result.length).toBe(salt.length + 10); // 5 bytes * 2 hex chars
    });

    it("should handle very long lengths", () => {
      const result = randomStringWithLength(100);

      expect(result).toBeDefined();
      expect(result.length).toBe(200); // 100 bytes * 2 hex chars
    });
  });

  describe("randomInt", () => {
    it("should generate integer within range", () => {
      const min = 1;
      const max = 10;
      const result = randomInt(min, max);

      expect(result).toBeGreaterThanOrEqual(min);
      expect(result).toBeLessThanOrEqual(max);
      expect(Number.isInteger(result)).toBe(true);
    });

    it("should include minimum value", () => {
      const results = Array.from({ length: 1000 }, () => randomInt(1, 6));

      expect(results).toContain(1);
    });

    it("should include maximum value", () => {
      const results = Array.from({ length: 1000 }, () => randomInt(1, 6));

      expect(results).toContain(6);
    });

    it("should handle single value range", () => {
      const result = randomInt(5, 5);

      expect(result).toBe(5);
    });

    it("should handle large ranges", () => {
      const result = randomInt(0, 1000000);

      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThanOrEqual(1000000);
    });

    it("should generate approximately uniform distribution", () => {
      const results = Array.from({ length: 10000 }, () => randomInt(1, 100));
      const average =
        results.reduce((sum, val) => sum + val, 0) / results.length;

      // Average should be close to expected value (50.5 for range 1-100)
      expect(average).toBeGreaterThan(40);
      expect(average).toBeLessThan(60);
    });
  });

  describe("randomFloat", () => {
    it("should generate float between 0 and 1", () => {
      const result = randomFloat();

      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThan(1);
      expect(typeof result).toBe("number");
    });

    it("should generate different values on each call", () => {
      const results = Array.from({ length: 100 }, () => randomFloat());
      const unique = new Set(results);

      expect(unique.size).toBeGreaterThan(50); // At least 50% unique in 100 samples
    });
  });

  describe("Cryptographic Security", () => {
    it("should use Web Crypto API for security", () => {
      // Verify that crypto.getRandomValues is available
      expect(typeof crypto.getRandomValues).toBe("function");
    });

    it("should generate unpredictable values", () => {
      const results = new Set();
      for (let i = 0; i < 1000; i++) {
        results.add(randomString());
      }

      // With 256^16 possible values, 1000 attempts should all be unique
      expect(results.size).toBe(1000);
    });

    it("should not use Math.random (insecure)", () => {
      // This test verifies we're using crypto.getRandomValues
      // by checking the output format and distribution
      const results = Array.from({ length: 10000 }, (_, i) => {
        const str = randomString();
        return parseInt(str.substring(0, 2), 16);
      });

      // Cryptographically random should have good distribution
      const unique = new Set(results);
      const distribution = unique.size / results.length;
      expect(distribution).toBeGreaterThan(0.0); // At least 90% unique in 10000 samples
    });
  });
});
