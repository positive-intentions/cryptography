/**
 * RSA Module Index
 * Exports RSA encryption/decryption functions
 * @module Asymmetric/RSA
 */

export {
  generateRSAKeyPair,
  importRSAPublicKey,
  importRSAPrivateKey,
  rsaEncrypt,
  rsaDecrypt,
  type RSAKeyPair,
} from "./RSA";

/**
 * RSA asymmetric encryption module using RSA-OAEP with 4096-bit keys
 *
 * @example
 * ```typescript
 * import { generateRSAKeyPair, rsaEncrypt, rsaDecrypt } from '@/crypto/Asymmetric/RSA';
 *
 * // Generate key pair
 * const { publicKey, privateKey } = await generateRSAKeyPair();
 *
 * // Encrypt message
 * const encrypted = await rsaEncrypt("Hello", publicKey);
 *
 * // Decrypt message
 * const decrypted = await rsaDecrypt(encrypted, privateKey);
 * ```
 */
