/**
 * X3DH Module Types
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
  publicKey?: CryptoKey;
}
