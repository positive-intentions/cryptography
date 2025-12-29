/**
 * Signal Protocol Signature Module
 * Implements Ed25519 signing and verification for Signal Protocol
 * @module SignalProtocol/X3DH
 */

/**
 * Error messages
 */
const ERROR_MESSAGES = {
  SIGN_FAILED: "Failed to sign data",
  VERIFY_FAILED: "Failed to verify signature",
};

/**
 * Signs data using Ed25519 private key
 * @param privateKey - Ed25519 private key for signing
 * @param data - Data to sign (ArrayBuffer or Uint8Array)
 * @returns Promise resolving to signature (64 bytes)
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalSigningKeyPair();
 * const message = new TextEncoder().encode("Hello, Signal!");
 * const signature = await signSignalData(keyPair.privateKey, message);
 * console.log(signature); // 64-byte signature
 * ```
 */
export async function signSignalData(
  privateKey: CryptoKey,
  data: ArrayBuffer | Uint8Array,
): Promise<ArrayBuffer> {
  try {
    const arrayBuffer = data instanceof Uint8Array ? data.buffer : data;
    return await crypto.subtle.sign(
      {
        name: "Ed25519",
      },
      privateKey,
      arrayBuffer,
    );
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.SIGN_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Verifies a signature using Ed25519 public key
 * @param publicKey - Ed25519 public key for verification
 * @param signature - Signature to verify (64 bytes)
 * @param data - Original data that was signed
 * @returns Promise resolving to true if signature is valid, false otherwise
 *
 * @example
 * ```typescript
 * const keyPair = await generateSignalSigningKeyPair();
 * const message = new TextEncoder().encode("Hello, Signal!");
 * const signature = await signSignalData(keyPair.privateKey, message);
 *
 * const isValid = await verifySignalSignature(keyPair.publicKey, signature, message);
 * console.log(isValid); // true
 * ```
 */
export async function verifySignalSignature(
  publicKey: CryptoKey,
  signature: ArrayBuffer | Uint8Array,
  data: ArrayBuffer | Uint8Array,
): Promise<boolean> {
  try {
    const signatureBuffer =
      signature instanceof Uint8Array ? signature.buffer : signature;
    const dataArrayBuffer = data instanceof Uint8Array ? data.buffer : data;

    return await crypto.subtle.verify(
      {
        name: "Ed25519",
      },
      publicKey,
      signatureBuffer,
      dataArrayBuffer,
    );
  } catch (error) {
    return false;
  }
}
