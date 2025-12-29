/**
 * AES-GCM Symmetric Encryption
 * @module Symmetric/AES
 */

/**
 * Generated AES-GCM key pair in JWK format
 */
export interface AESKey {
  key: JsonWebKey;
}

/**
 * Encrypted message with AES-GCM
 */
export interface AEGCSEncryptedData {
  encrypted: ArrayBuffer;
  iv: Uint8Array;
}

/**
 * AES-GCM key generation parameters
 */
const AES_GCM_KEY_PARAMS: AesKeyGenParams = {
  name: "AES-GCM",
  length: 256, // 256-bit key (can be 128, 192, or 256)
};

/**
 * Validates JWK symmetric key
 * @param jwkKey - Key to validate (JWK object or JSON string)
 * @returns Validated JWK object
 * @throws Error if JWK is invalid
 */
function validateAESJWK(key: JsonWebKey | string): JsonWebKey {
  const jwkKey = typeof key === "string" ? JSON.parse(key) : key;

  if (!jwkKey.kty) {
    throw new Error('Invalid JWK: missing "kty" property');
  }

  // Ensure symmetric key type is correct
  if (jwkKey.kty !== "oct") {
    jwkKey.kty = "oct";
  }

  return jwkKey;
}

/**
 * Generates a new AES-GCM symmetric key
 * @returns Promise resolving to key in JWK format
 *
 * @example
 * ```typescript
 * const key = await generateAESKey();
 * console.log(key.key); // JWK format symmetric key
 * ```
 */
export async function generateAESKey(): Promise<AESKey> {
  const cryptoKey = (await window.crypto.subtle.generateKey(
    AES_GCM_KEY_PARAMS,
    true, // Extractable
    ["encrypt", "decrypt"],
  )) as CryptoKey;

  const keyJWK = await crypto.subtle.exportKey("jwk", cryptoKey);
  return { key: keyJWK };
}

/**
 * Imports a symmetric key from JWK format
 * @param key - Key in JWK format (object or JSON string)
 * @returns Promise resolving to CryptoKey for encryption/decryption
 *
 * @example
 * ```typescript
 * const cryptoKey = await importAESKey(jwkKey);
 * const encrypted = await aesEncrypt("Hello", cryptoKey);
 * ```
 */
export async function importAESKey(
  key: JsonWebKey | string,
): Promise<CryptoKey> {
  const jwkKey = validateAESJWK(key);

  return await window.crypto.subtle.importKey(
    "jwk",
    jwkKey,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypts a message using AES-GCM
 * @param message - Plaintext message to encrypt
 * @param key - CryptoKey symmetric key
 * @returns Promise resolving to encrypted data with IV
 *
 * Uses a random 12-byte IV for each encryption (AES-GCM standard)
 *
 * @example
 * ```typescript
 * const cryptoKey = await importAESKey(jwkKey);
 * const result = await aesEncrypt("Secret message", cryptoKey);
 * console.log(result.encrypted); // Encrypted ArrayBuffer
 * console.log(result.iv); // 12-byte IV
 * ```
 */
export async function aesEncrypt(
  message: string,
  key: CryptoKey,
): Promise<AEGCSEncryptedData> {
  const encodedMessage = new TextEncoder().encode(message);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Must be 12 bytes

  const encrypted = await window.crypto.subtle
    .encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      encodedMessage,
    )
    .catch((error) => {
      console.error("AES-GCM encryption error:", error);
      throw error;
    });

  return { encrypted, iv };
}

/**
 * Decrypts a message using AES-GCM
 * @param buffer - Encrypted ArrayBuffer
 * @param key - CryptoKey symmetric key
 * @param iv - 12-byte initialization vector
 * @returns Promise resolving to decrypted plaintext string
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 *
 * @example
 * ```typescript
 * const cryptoKey = await importAESKey(jwkKey);
 * const decrypted = await aesDecrypt(encryptedData.encrypted, cryptoKey, encryptedData.iv);
 * console.log(decrypted); // "Secret message"
 * ```
 */
export async function aesDecrypt(
  buffer: ArrayBuffer,
  key: CryptoKey,
  iv: Uint8Array,
): Promise<string> {
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      buffer,
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("AES-GCM decryption error:", error);
    throw new Error(
      "Unable to decrypt message. Incorrect key or corrupted data.",
    );
  }
}
