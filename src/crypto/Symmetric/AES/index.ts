/**
 * AES-GCM Symmetric Encryption Module Index
 * Exports AES-GCM encryption/decryption functions
 * @module Symmetric/AES
 */

export {
  generateAESKey,
  importAESKey,
  aesEncrypt,
  aesDecrypt,
  type AESKey,
  type AEGCSEncryptedData,
} from "./AES";

/**
 * AES-GCM symmetric encryption module using 256-bit keys
 *
 * @example
 * ```typescript
 * import { generateAESKey, aesEncrypt, aesDecrypt } from '@/crypto/Symmetric/AES';
 *
 * // Generate key
 * const { key } = await generateAESKey();
 * const cryptoKey = await importAESKey(key);
 *
 * // Encrypt message
 * const encrypted = await aesEncrypt("Hello", cryptoKey);
 *
 * // Decrypt message
 * const decrypted = await aesDecrypt(encrypted.encrypted, cryptoKey, encrypted.iv);
 * ```
 */
