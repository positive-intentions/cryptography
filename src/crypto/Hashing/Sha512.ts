/**
 * SHA-512 Hash Implementation
 * @module Hashing/Sha512
 */

/**
 * Computes SHA-512 hash of the input
 * @param input - Data to hash (any type that can be JSON stringified)
 * @returns Promise resolving to hexadecimal string of the hash
 *
 * @example
 * ```typescript
 * const hash = await sha512Hash("Hello World");
 * console.log(hash); // "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
 * ```
 *
 * @example
 * ```typescript
 * const hash = await sha512Hash({ key: "value" });
 * ```
 */
export async function sha512Hash(input: unknown): Promise<string> {
  const inputString = JSON.stringify(input);
  const encoder = new TextEncoder();
  const data = encoder.encode(inputString);

  const hashBuffer = await crypto.subtle.digest("SHA-512", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}
