/**
 * SHA-512 Hash Tests
 */

import { sha512Hash } from "../Sha512";

describe("sha512Hash", () => {
  it("should hash a simple string correctly", async () => {
    const result = await sha512Hash("Hello World");
    // Known SHA-512 hash of "Hello World"
    const expected =
      "f31073d30f0bad9d81524ee2bbf3d9e950bda743c4313dbe38fcef421318416934565a4b31adf4558b03efd06b7ef0c3731ea0e4ba872b07bab82e816ebaebb3";
    expect(result).toBe(expected);
  });

  it("should hash an empty string correctly", async () => {
    const result = await sha512Hash("");
    // Known SHA-512 hash of empty string
    const expected =
      "64d24560970ca14d349bea0e7d2526d4754bf3283568ab4dd602bd79eb454dc3657d5bb6f9a30c90ea98d9600ebd0fb45d582f4cae3f8e3c50b0e8fb18059892";
    expect(result).toBe(expected);
  });

  it("should hash an object correctly", async () => {
    const data = { key: "value", number: 123 };
    const result = await sha512Hash(data);
    const result2 = await sha512Hash(data);
    expect(result).toBe(result2);
  });

  it("should hash an array correctly", async () => {
    const data = [1, 2, 3, "test"];
    const result = await sha512Hash(data);
    const result2 = await sha512Hash(data);
    expect(result).toBe(result2);
  });

  it("should produce different hashes for different inputs", async () => {
    const hash1 = await sha512Hash("Hello");
    const hash2 = await sha512Hash("World");
    expect(hash1).not.toBe(hash2);
  });

  it("should handle special characters", async () => {
    const result = await sha512Hash("Test!@#$%^&*()");
    expect(result).toHaveLength(128); // SHA-512 produces 128 hex chars
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should handle unicode characters", async () => {
    const result = await sha512Hash("Hello 🌍 世界");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should handle very long strings", async () => {
    const longString = "a".repeat(10000);
    const result = await sha512Hash(longString);
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should return consistent hashes for identical inputs", async () => {
    const input = "Consistency test";
    const hashes = await Promise.all([
      sha512Hash(input),
      sha512Hash(input),
      sha512Hash(input),
    ]);

    hashes.forEach((hash) => {
      expect(hash).toBe(hashes[0]);
    });
  });

  it("should produce valid hex output format", async () => {
    const result = await sha512Hash("test");
    expect(result).toHaveLength(128);
    expect(result).toMatch(/^[a-f0-9]+$/);
  });

  it("should produce different hash than SHA-256", async () => {
    const sha256Result = await sha256Hash("Hello World");
    const sha512Result = await sha512Hash("Hello World");
    expect(sha256Result).not.toBe(sha512Result);
    expect(sha256Result).toHaveLength(64);
    expect(sha512Result).toHaveLength(128);
  });
});

// Import sha256Hash for comparison
import { sha256Hash } from "../Sha256";
