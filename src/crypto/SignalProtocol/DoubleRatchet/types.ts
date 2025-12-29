/**
 * Signal Protocol Shared Utilities Types
 * @module SignalProtocol/Shared
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
 * Encrypted message format
 */
export interface EncryptedMessage {
  ciphertext: ArrayBuffer;
  nonce: ArrayBuffer;
  dhPublicKey?: ArrayBuffer;
  messageNumber: number;
}
