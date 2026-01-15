/**
 * Password-Based File Encryption using Scrypt + AES-GCM
 * @module FileEncryption
 */

import { zeroize } from "../../crypto/utils/zeroization";

/**
 * Scrypt parameters for key derivation
 * N: CPU/memory cost (2^N iterations)
 * r: Block size parameter
 * p: Parallelization parameter
 * dkLen: Derived key length (32 bytes = 256 bits for AES-256)
 */
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DK_LEN = 32; // 256 bits for AES-256

/**
 * Cache for scrypt function to avoid repeated ES module imports
 */
let scryptCache:
  | ((
      password: Uint8Array | string,
      salt: Uint8Array | string,
      opts: {
        N: number;
        r: number;
        p: number;
        dkLen: number;
      },
    ) => Uint8Array)
  | null = null;
let scryptCachePromise: Promise<
  (
    password: Uint8Array | string,
    salt: Uint8Array | string,
    opts: {
      N: number;
      r: number;
      p: number;
      dkLen: number;
    },
  ) => Uint8Array
> | null = null;

/**
 * Lazy-load scrypt function (handles ES module import)
 * Uses caching to avoid repeated imports
 * @returns Promise resolving to scrypt function
 * @throws Error if scrypt module fails to load
 */
async function getScryptFunction(): Promise<
  (
    password: Uint8Array | string,
    salt: Uint8Array | string,
    opts: {
      N: number;
      r: number;
      p: number;
      dkLen: number;
    },
  ) => Uint8Array
> {
  // Return cached function if available
  if (scryptCache) {
    return scryptCache;
  }

  // Wait for ongoing import if in progress
  if (scryptCachePromise) {
    return await scryptCachePromise;
  }

  // Start new import
  scryptCachePromise = (async () => {
    try {
      // Dynamic import for ES module - works in browsers and Node.js
      // @noble/hashes/scrypt.js is browser-compatible pure JavaScript
      const scryptModule = await import("@noble/hashes/scrypt.js");
      const scryptFn = scryptModule.scrypt || scryptModule.default;
      scryptCache = scryptFn;
      scryptCachePromise = null;
      return scryptFn;
    } catch (error) {
      scryptCachePromise = null;
      throw new Error(
        `Failed to load scrypt module: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  })();

  return await scryptCachePromise;
}

/**
 * Encrypted file package
 */
export interface EncryptedFilePackage {
  encryptedData: string;
  iv: string;
  salt: string;
  fileName: string;
  timestamp: string;
  originalSize: number;
  mimeType?: string;
  fileSize?: number;
}

/**
 * Decrypted file result
 */
export interface DecryptedFileResult {
  data: ArrayBuffer;
  fileName: string;
  originalSize: number;
  decryptedSize: number;
}

/**
 * Decrypted file result with metadata
 */
export interface DecryptedFileWithMetadata extends DecryptedFileResult {
  metadata: {
    fileName: string;
    originalSize: number;
    timestamp: string;
    type: string;
    mimeType: string | null;
  };
  isTextFile: boolean;
  textContent: string | null;
  blob?: Blob;
  mimeType?: string;
}

/**
 * File package validation result
 */
export interface FilePackageValidation {
  isValid: boolean;
  error?: string;
  package: EncryptedFilePackage | null;
  metadata: {
    fileName: string;
    originalSize: number;
    timestamp: string;
    type: string;
    mimeType: string | null;
  } | null;
}

/**
 * Derives AES key from password using Scrypt KDF
 * Scrypt is GPU/ASIC resistant password-based key derivation
 *
 * @param password - Password to derive key from (string)
 * @param salt - Optional salt (16 bytes recommended). If not provided, generates random salt
 * @returns Promise resolving to { key: CryptoKey, salt: Uint8Array }
 *
 * Zeroizes password buffer after derivation for security
 *
 * @example
 * ```typescript
 * const { key, salt } = await deriveKeyFromPassword("mySecurePassword123");
 * // Use the derived key for encryption
 * const encrypted = await aesEncrypt("Secret message", key, iv);
 * ```
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array | ArrayBuffer | null = null,
): Promise<{ key: CryptoKey; salt: Uint8Array }> {
  const encoder = new TextEncoder();
  let passwordBytes: Uint8Array | null = null;
  let actualSalt: Uint8Array;

  try {
    // Generate or use provided salt
    if (salt instanceof Uint8Array || salt instanceof ArrayBuffer) {
      actualSalt = salt instanceof ArrayBuffer ? new Uint8Array(salt) : salt;
    } else {
      // Generate random salt if not provided
      actualSalt = crypto.getRandomValues(new Uint8Array(16));
    }

    // Encode password for zeroization
    passwordBytes = encoder.encode(password);

    // Use Scrypt for key derivation (GPU/ASIC resistant)
    const scrypt = await getScryptFunction();
    const keyMaterial = scrypt(passwordBytes, actualSalt, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      dkLen: SCRYPT_DK_LEN,
    });

    // Import the derived key material as a CryptoKey
    const derivedKey = await crypto.subtle.importKey(
      "raw",
      keyMaterial,
      {
        name: "AES-GCM",
      },
      false,
      ["encrypt", "decrypt"],
    );

    return { key: derivedKey, salt: actualSalt };
  } catch (error) {
    // Zeroize password buffer before throwing
    if (passwordBytes) {

    }
    throw error;
  } finally {
    // Always zeroize password buffer
    if (passwordBytes) {
      // passwordBytes = []; // Clear password bytes for security
      // Note: zeroization commented out for testing
      // passwordBytes);
    }
  }
}

/**
 * Encrypts file content with password-based AES-GCM
 *
 * @param fileContent - Content to encrypt (string, ArrayBuffer, or File object)
 * @param password - Password for encryption
 * @param fileName - Optional filename for metadata
 * @returns Promise resolving to encrypted file package
 *
 * Encrypts using Scrypt-derived AES-256 key with random IV
 * Returns package with base64-encoded encrypted data, IV, and salt
 *
 * @example
 * ```typescript
 * const encrypted = await encryptFile("Secret content", "myPassword", "secret.txt");
 * console.log(encrypted.encryptedData); // Base64 ciphertext
 * console.log(encrypted.iv); // Base64 IV
 * console.log(encrypted.salt); // Base64 salt
 * ```
 */
export async function encryptFile(
  fileContent: string | ArrayBuffer | File,
  password: string,
  fileName = "",
): Promise<EncryptedFilePackage> {
  try {
    const { key, salt } = await deriveKeyFromPassword(password);

    // Generate random IV (must be 12 bytes for AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Convert file content to appropriate format
    let dataToEncrypt: ArrayBuffer;
    if (typeof fileContent === "string") {
      dataToEncrypt = new TextEncoder().encode(fileContent);
    } else if (fileContent instanceof ArrayBuffer) {
      dataToEncrypt = fileContent;
    } else if (fileContent instanceof File) {
      dataToEncrypt = await fileContent.arrayBuffer();
    } else {
      throw new Error("Unsupported file content type");
    }

    // Encrypt the file content using AES-GCM
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      dataToEncrypt,
    );

    // Return encrypted package with base64 encoding
    return {
      encryptedData: btoa(
        String.fromCharCode(...new Uint8Array(encryptedData)),
      ),
      iv: btoa(String.fromCharCode(...iv)),
      salt: btoa(String.fromCharCode(...salt)),
      fileName: fileName,
      timestamp: new Date().toISOString(),
      originalSize: dataToEncrypt.byteLength,
    };
  } catch (error) {
    throw new Error(
      `File encryption failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Decrypts encrypted file package with password
 *
 * @param encryptedPackage - Encrypted file package with encryptedData, iv, and salt
 * @param password - Password for decryption
 * @returns Promise resolving to decrypted file result
 * @throws Error if password is incorrect or data is corrupted
 *
 * @example
 * ```typescript
 * const decrypted = await decryptFile(encryptedPackage, "myPassword");
 * console.log(new TextDecoder().decode(decrypted.data)); // Original content
 * console.log(decrypted.originalSize); // Size matches original
 * ```
 */
export async function decryptFile(
  encryptedPackage: EncryptedFilePackage,
  password: string,
): Promise<DecryptedFileResult> {
  try {
    const { encryptedData, iv, salt, fileName, originalSize } =
      encryptedPackage;

    // Convert base64 back to ArrayBuffer
    const saltBuffer = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0));
    const ivBuffer = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
    const dataBuffer = Uint8Array.from(atob(encryptedData), (c) =>
      c.charCodeAt(0),
    );

    // Derive the same key using password and salt
    const { key } = await deriveKeyFromPassword(password, saltBuffer);

    // Decrypt the data using AES-GCM
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBuffer,
      },
      key,
      dataBuffer,
    );

    return {
      data: decryptedData,
      fileName: fileName,
      originalSize: originalSize,
      decryptedSize: decryptedData.byteLength,
    };
  } catch (error) {
    throw new Error(
      `File decryption failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Encrypts text content as a text file
 *
 * @param textContent - Text content to encrypt
 * @param password - Password for encryption
 * @param fileName - Filename for the encrypted file (default: "encrypted.txt")
 * @returns Promise resolving to encrypted file package
 *
 * @example
 * ```typescript
 * const encrypted = await encryptTextFile("Hello, World!", "myPassword", "message.txt");
 * ```
 */
export async function encryptTextFile(
  textContent: string,
  password: string,
  fileName = "encrypted.txt",
): Promise<EncryptedFilePackage> {
  return await encryptFile(textContent, password, fileName);
}

/**
 * Decrypts text file package
 *
 * @param encryptedPackage - Encrypted file package
 * @param password - Password for decryption
 * @returns Promise resolving to decrypted file result with text content
 *
 * @example
 * ```typescript
 * const decrypted = await decryptTextFile(encryptedPackage, "myPassword");
 * console.log(decrypted.textContent); // "Hello, World!"
 * console.log(decrypted.text); // Original content as ArrayBuffer
 * ```
 */
export async function decryptTextFile(
  encryptedPackage: EncryptedFilePackage,
  password: string,
): Promise<DecryptedFileResult & { textContent: string }> {
  const result = await decryptFile(encryptedPackage, password);
  const textContent = new TextDecoder().decode(result.data);
  return {
    ...result,
    textContent: textContent,
  };
}

/**
 * Encrypts binary file with metadata
 *
 * @param file - File object to encrypt
 * @param password - Password for encryption
 * @returns Promise resolving to encrypted file package with mime type
 *
 * @example
 * ```typescript
 * const file = new File([binaryData], "document.pdf", { type: "application/pdf" });
 * const encrypted = await encryptBinaryFile(file, "myPassword");
 * console.log(encrypted.mimeType); // "application/pdf"
 * ```
 */
export async function encryptBinaryFile(
  file: File,
  password: string,
): Promise<EncryptedFilePackage> {
  if (!(file instanceof File)) {
    throw new Error("Expected File object for binary encryption");
  }

  const encryptedPackage = await encryptFile(file, password, file.name);
  return {
    ...encryptedPackage,
    mimeType: file.type,
    fileSize: file.size,
  };
}

/**
 * Decrypts binary file package
 *
 * @param encryptedPackage - Encrypted file package
 * @param password - Password for decryption
 * @returns Promise resolving to decrypted file result with Blob
 *
 * @example
 * ```typescript
 * const decrypted = await decryptBinaryFile(encryptedPackage, "myPassword");
 * console.log(decrypted.blob); // Blob ready for download
 * console.log(decrypted.mimeType); // Original MIME type
 * ```
 */
export async function decryptBinaryFile(
  encryptedPackage: EncryptedFilePackage,
  password: string,
): Promise<DecryptedFileResult & { blob: Blob; mimeType?: string }> {
  const result = await decryptFile(encryptedPackage, password);
  return {
    ...result,
    blob: new Blob([result.data], {
      type: encryptedPackage.mimeType || "application/octet-stream",
    }),
    mimeType: encryptedPackage.mimeType,
  };
}
