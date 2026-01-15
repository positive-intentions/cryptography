/**
 * SHA3-512 Hash Implementation
 * @module Hashing/Sha3
 */

import { sha3_512 } from "js-sha3";

/**
 * Computes SHA3-512 hash of the input
 * @param input - Data to hash (any type that can be JSON stringified)
 * @returns Hexadecimal string of the hash
 *
 * @example
 * ```typescript
 * const hash = sha3_512Hash("Hello World");
 * console.log(hash); // "83799497d7db7144054d8e9d0c3e8f6e7b6b2d9c6a5b4d3f2e1c9b8a7f6e5d4c"
 * ```
 *
 * @example
 * ```typescript
 * const hash = sha3_512Hash({ key: "value" });
 * ```
 */
export function sha3_512Hash(input: unknown): string {
  const inputString = JSON.stringify(input);
  const hashHex = sha3_512(inputString);

  return hashHex;
}
