/**
 * Cascading Cipher System
 *
 * Extensible middleware for daisy-chaining multiple encryption algorithms.
 * Supports MLS, Signal Protocol, Diffie-Hellman, and AES-GCM encryption layers.
 *
 * @example
 * ```typescript
 * import {
 *   CascadingCipherManager,
 *   MLSCipherLayer,
 *   SignalCipherLayer,
 *   DHCipherLayer,
 *   AESCipherLayer,
 *   MLKEMCipherLayer
 * } from 'cryptography/CascadingCipher';
 *
 * const cascader = new CascadingCipherManager();
 * cascader.addLayer(new MLSCipherLayer(mlsManager, groupId));
 * cascader.addLayer(new SignalCipherLayer(wasmModule, state));
 * cascader.addLayer(new DHCipherLayer());
 * cascader.addLayer(new MLKEMCipherLayer());
 * cascader.addLayer(new AESCipherLayer());
 *
 * const encrypted = await cascader.encrypt(plaintext, keys);
 * const decrypted = await cascader.decrypt(encrypted, keys);
 * ```
 */

// Core types and interfaces
export type {
  CipherLayer,
  EncryptedPayload,
  CascadedPayload,
  LayerMetadata,
  CipherLayerConfig,
  CipherKeys,
  CascadeEncryptOptions,
  CascadeDecryptOptions,
} from "./types";

export { CipherLayerError, CascadingCipherError } from "./types";

// Main manager
export { CascadingCipherManager } from "./CascadingCipherManager";

// Cipher layers
export { AESCipherLayer } from "./layers/AESCipherLayer";
export type { AESKeys } from "./layers/AESCipherLayer";

export { MLSCipherLayer } from "./layers/MLSCipherLayer";
export type { MLSKeys } from "./layers/MLSCipherLayer";

export { SignalCipherLayer } from "./layers/SignalCipherLayer";
export type { SignalKeys } from "./layers/SignalCipherLayer";

export { DHCipherLayer } from "./layers/DHCipherLayer";
export type { DHKeys } from "./layers/DHCipherLayer";

export { MLKEMCipherLayer } from "./layers/MLKEMCipherLayer";
export type { MLKEMKeys } from "./layers/MLKEMCipherLayer";

// Export ML-KEM utilities for direct use
// Import and re-export from MLKEMUtils to ensure proper module federation exposure
// Note: Direct re-export may not work with module federation, so we import and re-export explicitly
import {
  getMLKEMInstance as _getMLKEMInstance,
  getMlKem768Class as _getMlKem768Class,
  MlKem768 as _MlKem768,
} from "../MLKEMUtils";

export const getMLKEMInstance = _getMLKEMInstance;
export const getMlKem768Class = _getMlKem768Class;
export { _MlKem768 as MlKem768 };

/**
 * Create a basic cascading cipher with common layers
 *
 * @returns Pre-configured CascadingCipherManager with AES layer
 */
export function createBasicCascadingCipher(): CascadingCipherManager {
  const manager = new CascadingCipherManager();
  const aesLayer = new AESCipherLayer();
  manager.addLayer(aesLayer);
  return manager;
}

/**
 * Create a cascading cipher with multiple AES layers
 *
 * @param count - Number of AES layers to add
 * @returns Pre-configured CascadingCipherManager
 */
export function createMultiLayerAESCipher(
  count: number = 2,
): CascadingCipherManager {
  const manager = new CascadingCipherManager();
  for (let i = 0; i < count; i++) {
    const layer = new AESCipherLayer();
    // Give each layer a unique name
    Object.defineProperty(layer, "name", {
      value: `AES-GCM-256-Layer-${i + 1}`,
    });
    manager.addLayer(layer);
  }
  return manager;
}
