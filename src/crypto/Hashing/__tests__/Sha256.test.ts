/**
 * SHA-256 Hash Tests
 */

import { sha256Hash } from "../Sha256";

describe("sha256Hash", () => {
  it("should hash a simple string correctly", async () => {
    const result = await sha256Hash("Hello World");
    // Known SHA-256 hash of "Hello World"
    const expected =
      "07cf55095ef805a89c07bf3d4764b07352a8f4b2cc3df166e89d2193131536bd";
    expect(result).toBe(expected);
  });

  it("should hash an empty string correctly", async () => {
    const result = await sha256Hash("");
    // Known SHA-256 hash of empty string
    const expected =
      "12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126";
    expect(result).toBe(expected);
  });

  it("should hash an object correctly", async () => {
    const data = { key: "value", number: 123 };
    const result = await sha256Hash(data);
    // Hash should be deterministic for same input
    const result2 = await sha256Hash(data);
    expect(result).toBe(result2);
  });

  it("should hash an array correctly", async () => {
    const data = [1, 2, 3, "test"];
    const result = await sha256Hash(data);
    const result2 = await sha256Hash(data);
    expect(result).toBe(result2);
  });

  it("should produce different hashes for different inputs", async () => {
    const hash1 = await sha256Hash("Hello");
    const hash2 = await sha256Hash("World");
    expect(hash1).not.toBe(hash2);
  });

  it("should handle special characters", async () => {
    const result = await sha256Hash("Test!@#$%^&*()");
    expect(result).toHaveLength(64); // SHA-256 produces 64 hex chars
    expect(result).toMatch(/^[a-f0-9]+$/); // Should be valid hex
  });

  it("should handle unicode characters", async () => {
    const result = await sha256Hash("Hello 🌍 世界");
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should handle very long strings", async () => {
    const longString = "a".repeat(10000);
    const result = await sha256Hash(longString);
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should return consistent hashes for identical inputs", async () => {
    const input = "Consistency test";
    const hashes = await Promise.all([
      sha256Hash(input),
      sha256Hash(input),
      sha256Hash(input),
    ]);

    hashes.forEach((hash) => {
      expect(hash).toBe(hashes[0]);
    });
  });

  it("should produce valid hex output format", async () => {
    const result = await sha256Hash("test");
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });
});
