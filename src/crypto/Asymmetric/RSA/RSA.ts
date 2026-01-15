/**
 * RSA Encryption/Decryption Module
 * Provides RSA-OAEP encryption with 4096-bit keys
 * @module Asymmetric/RSA
 */

/**
 * Generated RSA key pair in JWK format
 */
export interface RSAKeyPair {
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}

/**
 * RSA algorithm parameters for import/export
 */
const RSA_ALGORITHM: RsaHashedImportParams = {
  name: "RSA-OAEP",
  hash: "SHA-256",
};

/**
 * RSA key generation parameters
 */
const RSA_KEY_PARAMS: RsaKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 4096, // High security: can be 1024, 2048, or 4096
  publicExponent: new Uint8Array([1, 0, 1]), // 65537 in bytes
};

/**
 * Validates JWK key object
 * @param jwkKey - Key to validate (JWK object or JSON string)
 * @returns Validated JWK object
 * @throws Error if JWK is invalid
 */
function validateJWK(key: JsonWebKey | string): JsonWebKey {
  const jwkKey = typeof key === "string" ? JSON.parse(key) : key;

  if (!jwkKey.kty) {
    throw new Error('Invalid JWK: missing "kty" property');
  }

  return jwkKey;
}

/**
 * Generates a new RSA-OAEP key pair
 * @returns Promise resolving to key pair with public and private keys in JWK format
 *
 * @example
 * ```typescript
 * const keyPair = await generateRSAKeyPair();
 * console.log(keyPair.publicKey); // Public key for encryption
 * console.log(keyPair.privateKey); // Private key for decryption
 * ```
 */
export async function generateRSAKeyPair(): Promise<RSAKeyPair> {
  const keyPair = (await crypto.subtle.generateKey(
    RSA_KEY_PARAMS,
    true, // Extractable
    ["encrypt", "decrypt"],
  )) as CryptoKeyPair;

  const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJWK = await crypto.subtle.exportKey(
    "jwk",
    keyPair.privateKey,
  );

  return {
    publicKey: publicKeyJWK,
    privateKey: privateKeyJWK,
  };
}

/**
 * Imports a public key from JWK format
 * @param key - Public key in JWK format (object or JSON string)
 * @returns Promise resolving to CryptoKey for encryption
 *
 * @example
 * ```typescript
 * const publicKey = await importRSAPublicKey(jwkPublicKey);
 * const encrypted = await encrypt("Hello", publicKey);
 * ```
 */
export async function importRSAPublicKey(
  key: JsonWebKey | string,
): Promise<CryptoKey> {
  const jwkKey = validateJWK(key);

  return await crypto.subtle.importKey("jwk", jwkKey, RSA_ALGORITHM, true, [
    "encrypt",
  ]);
}

/**
 * Imports a private key from JWK format
 * @param key - Private key in JWK format (object or JSON string)
 * @returns Promise resolving to CryptoKey for decryption
 *
 * @example
 * ```typescript
 * const privateKey = await importRSAPrivateKey(jwkPrivateKey);
 * const decrypted = await decrypt(encryptedData, privateKey);
 * ```
 */
export async function importRSAPrivateKey(
  key: JsonWebKey | string,
): Promise<CryptoKey> {
  const jwkKey = validateJWK(key);

  return await crypto.subtle.importKey("jwk", jwkKey, RSA_ALGORITHM, true, [
    "decrypt",
  ]);
}

/**
 * Encrypts a message using RSA-OAEP
 * @param message - Plaintext message to encrypt
 * @param publicKey - CryptoKey public key
 * @returns Promise resolving to encrypted ArrayBuffer
 *
 * @example
 * ```typescript
 * const publicKey = await importRSAPublicKey(jwkPublicKey);
 * const encrypted = await rsaEncrypt("Secret message", publicKey);
 * ```
 */
export async function rsaEncrypt(
  message: string,
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  const encodedMessage = new TextEncoder().encode(message);

  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    encodedMessage,
  );

  return encrypted;
}

/**
 * Decrypts a message using RSA-OAEP
 * @param buffer - Encrypted ArrayBuffer
 * @param privateKey - CryptoKey private key
 * @returns Promise resolving to decrypted plaintext string
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 *
 * @example
 * ```typescript
 * const privateKey = await importRSAPrivateKey(jwkPrivateKey);
 * const decrypted = await rsaDecrypt(encryptedData, privateKey);
 * console.log(decrypted); // "Secret message"
 * ```
 */
export async function rsaDecrypt(
  buffer: ArrayBuffer,
  privateKey: CryptoKey,
): Promise<string> {
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      buffer,
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("RSA decryption error:", error);
    throw new Error(
      "Unable to decrypt message. Incorrect key or corrupted data.",
    );
  }
}
