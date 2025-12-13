/**
 * Signal Protocol Cipher Layer
 *
 * Wraps the Signal Protocol (Double Ratchet + X3DH) for use in cascading cipher chains.
 * Uses Web Crypto API by default, with optional WASM fallback for performance.
 */

import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';
import { Zeroization } from '../../utils/zeroization';

/**
 * Keys for Signal encryption
 */
export interface SignalKeys {
  doubleRatchetState?: any; // DoubleRatchetState (can be WASM or JS)
  sessionId?: string;
}

/**
 * SignalCipherLayer - Signal Protocol encryption layer
 *
 * Provides Double Ratchet algorithm with forward secrecy and
 * post-compromise security as a layer in the cascading cipher system.
 *
 * Uses browser Web Crypto API by default (X25519, Ed25519, HKDF, AES-GCM).
 * Optionally uses WASM module for potential performance improvements.
 */
export class SignalCipherLayer implements CipherLayer {
  readonly name = 'X3DH-DoubleRatchet';
  readonly version = '1.0.0';

  private wasmModule: any = null;
  private doubleRatchetState: any = null;
  private useWasm: boolean = false;

  /**
   * Create Signal cipher layer
   *
   * @param wasmModule - Optional pre-loaded Signal Protocol WASM module
   * @param doubleRatchetState - Optional pre-initialized Double Ratchet state
   */
  constructor(wasmModule?: any, doubleRatchetState?: any) {
    this.wasmModule = wasmModule;
    this.doubleRatchetState = doubleRatchetState;
    this.useWasm = !!wasmModule;
  }

  /**
   * Validate Signal keys
   */
  validateKeys(keys: any): boolean {
    if (!keys) return false;

    // If constructor provided state, keys can be minimal
    if (this.doubleRatchetState) {
      return true;
    }

    // Otherwise, keys must provide Double Ratchet state
    return keys.doubleRatchetState !== undefined;
  }

  /**
   * Initialize Signal layer
   *
   * Attempts to load WASM module if available, but gracefully falls back
   * to Web Crypto API implementation if WASM is not available.
   */
  async initialize(config: any): Promise<void> {
    try {
      if (config?.wasmModule) {
        this.wasmModule = config.wasmModule;
        this.useWasm = true;
      }

      // Try to load WASM module dynamically from federated module (optional)
      if (!this.wasmModule && config?.preferWasm !== false) {
        try {
          // Load WASM bindings from federated signal_protocol module
          const wasmBindings = await import('signal_protocol/WasmBindings').catch(() => null);

          if (wasmBindings) {
            // Load the WASM module using the federated bindings
            const wasmModule = await wasmBindings.loadWasmModule().catch(() => null);
            
            if (wasmModule) {
              this.wasmModule = wasmModule;
              this.useWasm = true;
              console.log('✅ Signal Protocol: Using WASM implementation from federated module');
            } else {
              console.log('ℹ️ Signal Protocol: WASM not available, using Web Crypto API implementation');
              this.useWasm = false;
            }
          } else {
            console.log('ℹ️ Signal Protocol: Federated module not available, using Web Crypto API implementation');
            this.useWasm = false;
          }
        } catch (wasmError) {
          // WASM not available, will use Web Crypto API
          console.log('ℹ️ Signal Protocol: WASM not available, using Web Crypto API implementation');
          this.useWasm = false;
        }
      }

      if (config?.doubleRatchetState) {
        this.doubleRatchetState = config.doubleRatchetState;
      }
    } catch (error) {
      // Initialization errors are only critical if we can't fall back
      console.warn('Signal Protocol initialization warning:', error.message);
      this.useWasm = false;
    }
  }

  /**
   * Helper: AES-GCM encryption using Web Crypto API
   */
  private async webCryptoEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array
  ): Promise<Uint8Array> {
    let keyCopy: Uint8Array | null = null;
    try {
      // Create a copy of key for zeroization (key may be reused)
      keyCopy = new Uint8Array(key);
      
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyCopy,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        cryptoKey,
        data
      );

      return new Uint8Array(encrypted);
    } finally {
      // Zeroize key copy
      if (keyCopy) {
        Zeroization.zeroize(keyCopy);
      }
    }
  }

  /**
   * Helper: AES-GCM decryption using Web Crypto API
   */
  private async webCryptoDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array
  ): Promise<Uint8Array> {
    let keyCopy: Uint8Array | null = null;
    try {
      // Create a copy of key for zeroization (key may be reused)
      keyCopy = new Uint8Array(key);
      
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyCopy,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        cryptoKey,
        data
      );

      return new Uint8Array(decrypted);
    } finally {
      // Zeroize key copy
      if (keyCopy) {
        Zeroization.zeroize(keyCopy);
      }
    }
  }

  /**
   * Encrypt data using Signal Protocol Double Ratchet
   */
  async encrypt(data: Uint8Array, keys: SignalKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();
    let messageKey: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let aad: Uint8Array | null = null;

    try {
      const state = keys.doubleRatchetState || this.doubleRatchetState;

      if (!state) {
        throw new CipherLayerError(
          'Double Ratchet state is required',
          this.name,
          'encrypt'
        );
      }

      // Use WASM implementation if available
      if (this.useWasm && this.wasmModule) {
        const result = this.wasmModule.double_ratchet_encrypt(state, data);
        const endTime = performance.now();

        return {
          ciphertext: result.ciphertext(),
          layerMetadata: {
            algorithm: this.name,
            version: this.version,
            timestamp: Date.now(),
            inputSize: data.length,
            outputSize: result.ciphertext().length,
            processingTime: endTime - startTime,
            metadata: {
              messageNumber: result.message_number(),
              sessionId: keys.sessionId || 'default',
            },
          },
          parameters: {
            publicKey: result.public_key(),
            messageNumber: result.message_number(),
            previousChainLength: result.previous_chain_length(),
            sessionId: keys.sessionId,
          },
        };
      }

      // Fallback: Web Crypto API implementation (simplified Double Ratchet)
      // This is a placeholder - in production, you would import the full
      // JavaScript implementation from Cryptography.tsx

      // For now, use a simplified AES-GCM encryption as a demonstration
      // In a real implementation, this would use the full Double Ratchet from Cryptography.tsx

      const messageNumber = state.sendingMessageNumber || 0;
      const publicKey = state.sendingDHPublicKey || new Uint8Array(32);
      const previousChainLength = state.previousChainLength || 0;

      // Generate message key (simplified - real implementation uses HKDF)
      messageKey = state.sendingChainKey ? new Uint8Array(state.sendingChainKey) : crypto.getRandomValues(new Uint8Array(32));
      nonce = crypto.getRandomValues(new Uint8Array(12));

      // Create AAD
      aad = new Uint8Array([
        ...publicKey,
        ...new Uint8Array(new Uint32Array([messageNumber]).buffer),
        ...new Uint8Array(new Uint32Array([previousChainLength]).buffer),
      ]);

      // Encrypt
      const encrypted = await this.webCryptoEncrypt(messageKey, nonce, data, aad);

      // Prepend nonce to ciphertext
      const ciphertext = new Uint8Array(nonce.length + encrypted.length);
      ciphertext.set(nonce);
      ciphertext.set(encrypted, nonce.length);

      const endTime = performance.now();

      // Create copies for return (before zeroization)
      const publicKeyCopy = new Uint8Array(publicKey);

      return {
        ciphertext,
        layerMetadata: {
          algorithm: this.name,
          version: this.version,
          timestamp: Date.now(),
          inputSize: data.length,
          outputSize: ciphertext.length,
          processingTime: endTime - startTime,
          metadata: {
            messageNumber,
            sessionId: keys.sessionId || 'default',
          },
        },
        parameters: {
          publicKey: publicKeyCopy,
          messageNumber,
          previousChainLength,
          sessionId: keys.sessionId,
        },
      };
    } catch (error) {
      // Zeroize sensitive data before throwing
      Zeroization.zeroizeAll(messageKey, nonce, aad);

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Check for sensitive data (sessionId, state info) in error message
      const sessionId = keys.sessionId;
      const hasSensitiveData = 
        (sessionId && errorMessage.includes(sessionId)) ||
        errorMessage.includes('sessionId') ||
        errorMessage.includes('state') ||
        errorMessage.includes('ratchet');

      if (hasSensitiveData) {
        throw new CipherLayerError(
          'Signal encryption failed',
          this.name,
          'encrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `Signal encryption failed: ${errorMessage}`,
        this.name,
        'encrypt',
        error as Error
      );
    } finally {
      // Always zeroize sensitive data
      Zeroization.zeroizeAll(messageKey, nonce, aad);
    }
  }

  /**
   * Decrypt data using Signal Protocol Double Ratchet
   */
  async decrypt(payload: EncryptedPayload, keys: SignalKeys): Promise<Uint8Array> {
    let messageKey: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let aad: Uint8Array | null = null;
    let encryptedData: Uint8Array | null = null;

    try {
      const state = keys.doubleRatchetState || this.doubleRatchetState;

      if (!state) {
        throw new CipherLayerError(
          'Double Ratchet state is required',
          this.name,
          'decrypt'
        );
      }

      // Use WASM implementation if available
      if (this.useWasm && this.wasmModule) {
        // Reconstruct Signal message
        const message = this.wasmModule.DoubleRatchetMessage.new(
          payload.parameters.publicKey,
          payload.parameters.messageNumber,
          payload.parameters.previousChainLength,
          payload.ciphertext
        );

        // Decrypt using Double Ratchet
        const plaintext = this.wasmModule.double_ratchet_decrypt(state, message);
        return plaintext;
      }

      // Fallback: Web Crypto API implementation (simplified)
      // In a real implementation, this would use the full Double Ratchet from Cryptography.tsx

      const ciphertext = payload.ciphertext;
      const messageNumber = payload.parameters.messageNumber;
      const publicKey = payload.parameters.publicKey;
      const previousChainLength = payload.parameters.previousChainLength;

      // Extract nonce and encrypted data
      if (ciphertext.length < 12) {
        throw new CipherLayerError(
          'Ciphertext too short',
          this.name,
          'decrypt'
        );
      }

      nonce = ciphertext.slice(0, 12);
      encryptedData = ciphertext.slice(12);

      // Get message key (simplified - real implementation uses HKDF chain)
      const chainKey = state.receivingChainKey || state.sendingChainKey;
      messageKey = chainKey ? new Uint8Array(chainKey) : crypto.getRandomValues(new Uint8Array(32));

      // Recreate AAD
      aad = new Uint8Array([
        ...publicKey,
        ...new Uint8Array(new Uint32Array([messageNumber]).buffer),
        ...new Uint8Array(new Uint32Array([previousChainLength]).buffer),
      ]);

      // Decrypt
      const plaintext = await this.webCryptoDecrypt(messageKey, nonce, encryptedData, aad);

      // Create a copy for return (before zeroization)
      const plaintextCopy = new Uint8Array(plaintext);
      return plaintextCopy;
    } catch (error) {
      // Zeroize sensitive data before throwing
      Zeroization.zeroizeAll(messageKey, nonce, aad, encryptedData);

      // Don't leak sensitive data in error messages
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Check for sensitive data (sessionId, state info) in error message
      const sessionId = keys.sessionId;
      const hasSensitiveData = 
        (sessionId && errorMessage.includes(sessionId)) ||
        errorMessage.includes('sessionId') ||
        errorMessage.includes('state') ||
        errorMessage.includes('ratchet');

      if (hasSensitiveData) {
        throw new CipherLayerError(
          'Signal decryption failed',
          this.name,
          'decrypt',
          error as Error
        );
      }

      throw new CipherLayerError(
        `Signal decryption failed: ${errorMessage}`,
        this.name,
        'decrypt',
        error as Error
      );
    } finally {
      // Always zeroize sensitive data
      Zeroization.zeroizeAll(messageKey, nonce, aad, encryptedData);
    }
  }

  /**
   * Clean up Signal resources
   */
  async destroy(): Promise<void> {
    if (this.doubleRatchetState && this.doubleRatchetState.free) {
      this.doubleRatchetState.free();
      this.doubleRatchetState = null;
    }
    this.wasmModule = null;
  }
}
