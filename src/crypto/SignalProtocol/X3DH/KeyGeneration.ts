/**
 * X3DH Key Exchange Module
 * Implements X25519 key generation and key exchange for Signal Protocol
 * @module SignalProtocol/X3DH
 */

/**
 * Signal key pair with identity and signing keys
 */
export interface SignalKeyPair {
  identityKeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
  signedPrekeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
}

/**
 * X3DH DH result
 */
export interface X3DHResult {
  sharedSecret: ArrayBuffer;
  publicKey: CryptoKey;
}

/**
 * Parameters for X25519 key generation
 */
const X25519_KEY_PARAMS = {
  name: "X25519",
};

/**
 * Parameters for Ed25519 signing key generation
 */
const ED25519_SIGNING_KEY_PARAMS = {
  name: "Ed25519",
};

/**
 * Error messages
 */
const ERROR_MESSAGES = {
  KEY_GENERATION_FAILED: "Key generation failed",
  DH_DERIVATION_FAILED: "Failed to derive shared secret",
  KEY_EXPORT_FAILED: "Failed to export public key",
  KEY_IMPORT_FAILED: "Failed to import public key",
};

/**
 * Generates a new X25519 key pair for Signal Protocol
 * @returns Promise resolving to key pair with publicKey and privateKey
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalKeyPair();
 * console.log(keyPair.publicKey); // CryptoKey for DH operations
 * console.log(keyPair.privateKey); // CryptoKey for DH operations
 * ```
 */
export async function generateSignalKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}> {
  try {
    const keyPair: any = await crypto.subtle.generateKey(
      X25519_KEY_PARAMS,
      true,
      ["deriveBits"],
    );

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_GENERATION_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Generates a new Ed25519 signing key pair for Signal Protocol
 * @returns Promise resolving to signing key pair with publicKey and privateKey
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalSigningKeyPair();
 * console.log(keyPair.publicKey); // CryptoKey for verification
 * console.log(keyPair.privateKey); // CryptoKey for signing
 * ```
 */
export async function generateSignalSigningKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}> {
  try {
    const keyPair: any = await crypto.subtle.generateKey(
      ED25519_SIGNING_KEY_PARAMS,
      true,
      ["sign", "verify"],
    );

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_GENERATION_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Performs X25519 Diffie-Hellman key exchange
 * @param privateKey - Local private key
 * @param publicKey - Remote public key
 * @returns Promise resolving to shared secret (32 bytes)
 *
 * @example
 * ```typescript
 * const myKeyPair = await generateSignalKeyPair();
 * const remotePublicKey = await importSignalPublicKey(remoteBytes);
 * const sharedSecret = await performSignalDH(myKeyPair.privateKey, remotePublicKey);
 * console.log(sharedSecret); // 32-byte shared secret
 * ```
 */
export async function performSignalDH(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  try {
    return await crypto.subtle.deriveBits(
      {
        name: "X25519",
        public: publicKey,
      },
      privateKey,
      256,
    );
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.DH_DERIVATION_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Exports an X25519 public key in raw format
 * @param publicKey - CryptoKey public key to export
 * @returns Promise resolving to ArrayBuffer of public key (32 bytes)
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalKeyPair();
 * const publicKeyBuffer = await exportSignalPublicKey(keyPair.publicKey);
 * // Send publicKeyBuffer to other party
 * ```
 */
export async function exportSignalPublicKey(
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  try {
    return await crypto.subtle.exportKey("raw", publicKey);
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_EXPORT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Exports an Ed25519 signing public key in raw format
 * @param publicKey - Ed25519 public key to export
 * @returns Promise resolving to ArrayBuffer of public key (32 bytes)
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalSigningKeyPair();
 * const publicKeyBuffer = await exportSignalSigningPublicKey(keyPair.publicKey);
 * ```
 */
export async function exportSignalSigningPublicKey(
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  try {
    return await crypto.subtle.exportKey("raw", publicKey);
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_EXPORT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Imports an X25519 public key from raw bytes
 * @param keyBytes - Raw bytes of public key
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```typescript
 * const publicKeyBuffer = new Uint8Array([...]); // Received from other party
 * const publicKey = await importSignalPublicKey(publicKeyBuffer);
 * ```
 */
export async function importSignalPublicKey(
  keyBytes: ArrayBuffer | Uint8Array,
): Promise<CryptoKey> {
  try {
    const arrayBuffer =
      keyBytes instanceof Uint8Array ? keyBytes.buffer : keyBytes;

    return await crypto.subtle.importKey(
      "raw",
      arrayBuffer,
      X25519_KEY_PARAMS,
      true,
      [],
    );
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_IMPORT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Imports an Ed25519 signing public key from raw bytes
 * @param keyBytes - Raw bytes of public key
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```typescript
 * const publicKeyBuffer = new Uint8Array([...]); // Received from other party
 * const publicKey = await importSignalSigningPublicKey(publicKeyBuffer);
 * ```
 */
export async function importSignalSigningPublicKey(
  keyBytes: ArrayBuffer | Uint8Array,
): Promise<CryptoKey> {
  try {
    const arrayBuffer =
      keyBytes instanceof Uint8Array ? keyBytes.buffer : keyBytes;

    return await crypto.subtle.importKey(
      "raw",
      arrayBuffer,
      ED25519_SIGNING_KEY_PARAMS,
      true,
      ["verify"],
    );
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.KEY_IMPORT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Backward compatibility alias for generateSignalKeyPair
 * @deprecated Use generateSignalKeyPair instead
 */
export async function generateIdentityKeyPair(): Promise<SignalKeyPair> {
  const keyPair = await generateSignalKeyPair();
  return {
    identityKeyPair: keyPair,
    signedPrekeyPair: undefined as any,
  };
}

/**
 * Backward compatibility alias for generateSignalSigningKeyPair
 * @deprecated Use generateSignalSigningKeyPair instead
 */
export async function generateSigningKeyPair(): Promise<SignalKeyPair> {
  const keyPair = await generateSignalSigningKeyPair();
  return {
    identityKeyPair: undefined as any,
    signedPrekeyPair: keyPair,
  };
}
