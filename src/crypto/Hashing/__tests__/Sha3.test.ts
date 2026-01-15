/**
 * SHA3-512 Hash Tests
 */

import { sha3_512Hash } from "../Sha3";

describe("sha3_512Hash", () => {
  it("should hash a simple string correctly", () => {
    const result = sha3_512Hash("Hello World");
    expect(result).toHaveLength(128); // SHA3-512 produces 128 hex chars
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should hash an empty string correctly", () => {
    const result = sha3_512Hash("");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should hash an object correctly", () => {
    const data = { key: "value", number: 123 };
    const result = sha3_512Hash(data);
    const result2 = sha3_512Hash(data);
    expect(result).toBe(result2);
  });

  it("should hash an array correctly", () => {
    const data = [1, 2, 3, "test"];
    const result = sha3_512Hash(data);
    const result2 = sha3_512Hash(data);
    expect(result).toBe(result2);
  });

  it("should produce different hashes for different inputs", () => {
    const hash1 = sha3_512Hash("Hello");
    const hash2 = sha3_512Hash("World");
    expect(hash1).not.toBe(hash2);
  });

  it("should handle special characters", () => {
    const result = sha3_512Hash("Test!@#$%^&*()");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should handle unicode characters", () => {
    const result = sha3_512Hash("Hello 🌍 世界");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should handle very long strings", () => {
    const longString = "a".repeat(10000);
    const result = sha3_512Hash(longString);
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should return consistent hashes for identical inputs", () => {
    const input = "Consistency test";
    const hashes = [
      sha3_512Hash(input),
      sha3_512Hash(input),
      sha3_512Hash(input),
    ];

    hashes.forEach((hash) => {
      expect(hash).toBe(hashes[0]);
    });
  });

  it("should produce valid hex output format", () => {
    const result = sha3_512Hash("test");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should be synchronous", () => {
    const start = Date.now();
    sha3_512Hash("Hello World");
    const end = Date.now();
    // Should be fast (under 100ms)
    expect(end - start).toBeLessThan(100);
  });
});
