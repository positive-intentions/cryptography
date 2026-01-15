/**
 * Random String Generation Module
 * Cryptographically secure random string generation
 * @module RandomGeneration
 */

/**
 * Default length for random strings (16 bytes = 32 hex characters)
 */
const DEFAULT_RANDOM_LENGTH = 16;

/**
 * Generates a cryptographically secure random string
 * @param additionalSalt - Optional prefix to prepend to the random string
 * @returns Hexadecimal string of random bytes with optional prefix
 *
 * Uses Web Crypto API's getRandomValues() for cryptographic security
 *
 * @example
 * ```typescript
 * const random1 = randomString(); // e.g., "a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
 * const random2 = randomString("user:"); // e.g., "user:a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
 * ```
 */
export function randomString(additionalSalt = ""): string {
  const randomStringLength = DEFAULT_RANDOM_LENGTH;

  // Generate cryptographically secure random bytes
  const randomValues = crypto.getRandomValues(
    new Uint8Array(randomStringLength),
  );

  // Convert random bytes to hexadecimal string
  const randomHex = Array.from(randomValues)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  // Append salt if provided
  return additionalSalt ? additionalSalt + randomHex : randomHex;
}

/**
 * Generates a random string of specified length
 * @param length - Number of random bytes to generate (default: 16)
 * @param additionalSalt - Optional prefix to prepend
 * @returns Hexadecimal string of specified length (in bytes)
 *
 * @example
 * ```typescript
 * const random32 = randomStringWithLength(32); // 64 hex characters
 * const random8 = randomStringWithLength(8); // 16 hex characters
 * ```
 */
export function randomStringWithLength(
  length: number = DEFAULT_RANDOM_LENGTH,
  additionalSalt = "",
): string {
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  const randomHex = Array.from(randomValues)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return additionalSalt ? additionalSalt + randomHex : randomHex;
}

/**
 * Generates a random integer within a range
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (inclusive)
 * @returns Random integer between min and max
 *
 * Uses rejection sampling for uniform distribution
 *
 * @example
 * ```typescript
 * const dice = randomInt(1, 6); // 1-6 (like dice)
 * const percentage = randomInt(0, 100); // 0-100
 * ```
 */
export function randomInt(min: number, max: number): number {
  const range = max - min + 1;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const cutoff = Math.floor(256 ** bytesNeeded / range) * range;

  let value;
  do {
    const randomBytes = crypto.getRandomValues(new Uint8Array(bytesNeeded));
    value = 0;
    for (let i = 0; i < bytesNeeded; i++) {
      value = (value << 8) + randomBytes[i];
    }
  } while (value >= cutoff);

  return min + (value % range);
}

/**
 * Generates a random floating-point number between 0 and 1
 * @returns Random float between 0 (inclusive) and 1 (exclusive)
 *
 * @example
 * ```typescript
 * const chance = randomFloat(); // e.g., 0.723481...
 * if (randomFloat() > 0.5) {
 *   console.log("50% chance event occurred");
 * }
 * ```
 */
export function randomFloat(): number {
  // Generate 52 bits of randomness (double precision)
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  // Mask to get 52 bits (IEEE 754 mantissa)
  bytes[7] = bytes[7] & 0x0f;

  // Convert to double
  const view = new DataView(bytes.buffer);
  const randomDouble = view.getFloat64(0, false);

  // Convert from [0, 1] to [0, 1) by dividing by max
  return Math.abs(randomDouble / Number.MAX_VALUE);
}
