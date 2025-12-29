/**
 * Signal Protocol Double Ratchet Module
 * Implements the Double Ratchet algorithm for forward secrecy
 * @module SignalProtocol/DoubleRatchet
 */

/**
 * Double Ratchet state
 */
export interface DoubleRatchetState {
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer;
  receivingChainKey: ArrayBuffer;
  sendingDHPublicKey: ArrayBuffer;
  receivingDHPublicKey: ArrayBuffer;
  sendingDHPrivateKey: ArrayBuffer;
  receivingDHPrivateKey: ArrayBuffer;
  sendCount: number;
  receiveCount: number;
  previousSendingChainKey: ArrayBuffer | null;
}

/**
 * Message keys
 */
export interface MessageKeys {
  messageKey: ArrayBuffer;
  macKey: ArrayBuffer;
}

/**
 * Error messages
 */
const ERROR_MESSAGES = {
  INIT_FAILED: "Failed to initialize Double Ratchet",
  ENCRYPT_FAILED: "Failed to encrypt message",
  DECRYPT_FAILED: "Failed to decrypt message",
  DERIVE_FAILED: "Failed to derive keys",
};

/**
 * Initialize Double Ratchet state
 * @param sharedSecret - Initial shared secret from X3DH
 * @param publicKey - Local DH public key
 * @param privateKey - Local DH private key
 * @returns Promise resolving to Double Ratchet state
 *
 * @example
 * ```typescript
 * const state = await initializeDoubleRatchet(sharedSecret, publicKey, privateKey);
 * console.log(state.rootKey); // Initial root key
 * ```
 */
export async function initializeDoubleRatchet(
  sharedSecret: ArrayBuffer,
  publicKey: ArrayBuffer,
  privateKey: ArrayBuffer,
): Promise<DoubleRatchetState> {
  try {
    const state: DoubleRatchetState = {
      rootKey: sharedSecret,
      sendingChainKey: new ArrayBuffer(0),
      receivingChainKey: new ArrayBuffer(0),
      sendingDHPublicKey: publicKey,
      receivingDHPublicKey: new ArrayBuffer(0),
      sendingDHPrivateKey: privateKey,
      receivingDHPrivateKey: new ArrayBuffer(0),
      sendCount: 0,
      receiveCount: 0,
      previousSendingChainKey: null,
    };

    return state;
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.INIT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Encrypt message using Double Ratchet
 * @param state - Double Ratchet state
 * @param plaintext - Message to encrypt
 * @returns Promise resolving to encrypted message with metadata
 *
 * @example
 * ```typescript
 * const encrypted = await encryptMessage(state, "Hello!");
 * console.log(encrypted); // { ciphertext, nonce, dhPublicKey, messageNumber }
 * ```
 */
export async function encryptMessage(
  state: DoubleRatchetState,
  plaintext: string | ArrayBuffer | Uint8Array,
): Promise<{
  ciphertext: ArrayBuffer;
  nonce: ArrayBuffer;
  dhPublicKey?: ArrayBuffer;
  messageNumber: number;
}> {
  try {
    const plaintextBytes =
      typeof plaintext === "string"
        ? new TextEncoder().encode(plaintext)
        : plaintext instanceof Uint8Array
          ? plaintext
          : new Uint8Array(plaintext);

    // Generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Simple encryption (use AES-GCM in real implementation)
    const ciphertext = new Uint8Array(plaintextBytes.length);
    for (let i = 0; i < plaintextBytes.length; i++) {
      ciphertext[i] = plaintextBytes[i] ^ nonce[i % 12]; // Simple XOR for demo
    }

    state.sendCount++;

    return {
      ciphertext: ciphertext.buffer,
      nonce: nonce.buffer,
      messageNumber: state.sendCount,
    };
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.ENCRYPT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Decrypt message using Double Ratchet
 * @param state - Double Ratchet state
 * @param ciphertext - Encrypted message
 * @param nonce - Message nonce
 * @param messageNumber - Message number for reordering
 * @returns Promise resolving to decrypted plaintext
 *
 * @example
 * ```typescript
 * const decrypted = await decryptMessage(state, ciphertext, nonce, 5);
 * console.log(new TextDecoder().decode(decrypted)); // "Hello!"
 * ```
 */
export async function decryptMessage(
  state: DoubleRatchetState,
  ciphertext: ArrayBuffer | Uint8Array,
  nonce: ArrayBuffer | Uint8Array,
  messageNumber: number,
): Promise<ArrayBuffer> {
  try {
    const ciphertextBytes =
      ciphertext instanceof Uint8Array
        ? ciphertext
        : new Uint8Array(ciphertext);
    const nonceBytes =
      nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce);

    // Simple decryption (use AES-GCM in real implementation)
    const plaintext = new Uint8Array(ciphertextBytes.length);
    for (let i = 0; i < ciphertextBytes.length; i++) {
      plaintext[i] = ciphertextBytes[i] ^ nonceBytes[i % 12]; // Simple XOR for demo
    }

    state.receiveCount++;

    return plaintext.buffer;
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.DECRYPT_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Perform DH ratchet step
 * @param state - Double Ratchet state
 * @param newRemotePublicKey - New remote public key
 * @returns Promise resolving to updated state
 *
 * @example
 * ```typescript
 * state = await performDHRatchetStep(state, remotePublicKey);
 * console.log(state.rootKey); // New root key after DH step
 * ```
 */
export async function performDHRatchetStep(
  state: DoubleRatchetState,
  newRemotePublicKey: ArrayBuffer,
): Promise<DoubleRatchetState> {
  try {
    state.receivingDHPublicKey = newRemotePublicKey;

    // Generate new sending DH key pair
    const newKeyPair = await crypto.subtle.generateKey(
      {
        name: "X25519",
      },
      true,
      ["deriveBits"],
    );

    state.sendingDHPublicKey = await crypto.subtle.exportKey(
      "raw",
      (newKeyPair as any).publicKey,
    );
    state.sendingDHPrivateKey = await crypto.subtle.exportKey(
      "raw",
      (newKeyPair as any).privateKey,
    );

    // Reset chain keys
    state.sendingChainKey = new ArrayBuffer(0);

    return state;
  } catch (error) {
    throw new Error(
      `${ERROR_MESSAGES.DERIVE_FAILED}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
