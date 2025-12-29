/**
 * Hashing Module Index
 * Exports all hashing functions
 * @module Hashing
 */

export { sha256Hash } from "./Sha256";
export { sha512Hash } from "./Sha512";
export { sha3_512Hash } from "./Sha3";

/**
 * Hashing module providing multiple secure hash algorithms
 *
 * @example
 * ```typescript
 * import { sha256Hash, sha512Hash, sha3_512Hash } from '@/crypto/Hashing';
 *
 * const sha256 = await sha256Hash("data");
 * const sha512 = await sha512Hash("data");
 * const sha3 = sha3_512Hash("data");
 * ```
 */
