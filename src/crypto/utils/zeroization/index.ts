/**
 * Zeroization Utilities Module Index
 * Exports zeroization functions for secure memory management
 * @module utils/Zeroization
 */

export {
  zeroize,
  zeroizeString,
  zeroizeCopy,
  isZeroized,
} from "./zeroization.ts";

/**
 * Secure memory clearing utilities
 *
 * @example
 * ```typescript
 * import { zeroize, zeroizeCopy } from '@/crypto/utils/zeroization';
 *
 * const passwordBytes = new TextEncoder().encode("password");
 * // Use passwordBytes
 * zeroize(passwordBytes); // Securely clear memory
 * ```
 */
