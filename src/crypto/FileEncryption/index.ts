/**
 * File Encryption Module Index
 * Exports file encryption/decryption functions
 * @module FileEncryption
 */

export {
  deriveKeyFromPassword,
  encryptFile,
  decryptFile,
  encryptTextFile,
  decryptTextFile,
  encryptBinaryFile,
  decryptBinaryFile,
  type EncryptedFilePackage,
  type DecryptedFileResult,
  type DecryptedFileWithMetadata,
} from "./PasswordEncryption";

export {
  createSecureFileDownload,
  parseEncryptedFilePackage,
  decryptUploadedFile,
  type FilePackageValidation,
} from "./FileHandler";

/**
 * Password-based file encryption using Scrypt + AES-GCM
 *
 * @example
 * ```typescript
 * import { encryptTextFile, decryptTextFile } from '@/crypto/FileEncryption';
 *
 * // Encrypt
 * const encrypted = await encryptTextFile("Hello, World!", "myPassword", "message.txt");
 *
 * // Decrypt
 * const decrypted = await decryptTextFile(encrypted, "myPassword");
 * console.log(decrypted.textContent); // "Hello, World!"
 * ```
 */
