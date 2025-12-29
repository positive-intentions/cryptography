/**
 * SHA-256 Hash Implementation
 * @module Hashing/Sha256
 */

/**
 * Computes SHA-256 hash of the input
 * @param input - Data to hash (any type that can be JSON stringified)
 * @returns Promise resolving to hexadecimal string of the hash
 *
 * @example
 * ```typescript
 * const hash = await sha256Hash("Hello World");
 * console.log(hash); // "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
 * ```
 *
 * @example
 * ```typescript
 * const hash = await sha256Hash({ key: "value" });
 * ```
 */
export async function sha256Hash(input: unknown): Promise<string> {
  const inputString = JSON.stringify(input);
  const encoder = new TextEncoder();
  const data = encoder.encode(inputString);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}
