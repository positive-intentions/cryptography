/**
 * X3DH Module Index
 * Exports all X3DH functions
 * @module SignalProtocol/X3DH
 */

export {
  generateIdentityKeyPair,
  generateSigningKeyPair,
  generateSignalKeyPair,
  generateSignalSigningKeyPair,
  performSignalDH,
  exportSignalPublicKey,
  exportSignalSigningPublicKey,
  importSignalPublicKey,
  importSignalSigningPublicKey,
  type SignalKeyPair,
  type X3DHResult,
} from "./KeyGeneration";

export { signSignalData, verifySignalSignature } from "./Signature";

/**
 * X3DH key exchange module
 * Provides X25519-based Diffie-Hellman key exchange for Signal Protocol
 *
 * @example
 * ```typescript
 * import { generateSignalKeyPair, performSignalDH } from '@/crypto/SignalProtocol/X3DH';
 *
 * // Generate key pair
 * const keyPair = await generateSignalKeyPair();
 *
 * // Perform DH exchange with other party's public key
 * const sharedSecret = await performSignalDH(keyPair.privateKey, remotePublicKey);
 * console.log(sharedSecret); // 32-byte shared secret
 * ```
 */
