/**
 * Random Generation Module Index
 * Exports random generation functions
 * @module RandomGeneration
 */

export {
  randomString,
  randomStringWithLength,
  randomInt,
  randomFloat,
} from "./RandomString";

/**
 * Cryptographically secure random generation module
 *
 * @example
 * ```typescript
 * import { randomString, randomInt, randomFloat } from '@/crypto/RandomGeneration';
 *
 * const id = randomString();
 * const dice = randomInt(1, 6);
 * const probability = randomFloat();
 * ```
 */
