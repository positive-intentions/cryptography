/**
 * Signal Protocol Cipher Layer
 *
 * Wraps the Signal Protocol (Double Ratchet + X3DH) for use in cascading cipher chains.
 */

import {
  CipherLayer,
  EncryptedPayload,
  CipherLayerError,
} from '../types';

/**
 * Keys for Signal encryption
 */
export interface SignalKeys {
  doubleRatchetState?: any; // DoubleRatchetState from WASM
  sessionId?: string;
}

/**
 * SignalCipherLayer - Signal Protocol encryption layer
 *
 * Provides Double Ratchet algorithm with forward secrecy and
 * post-compromise security as a layer in the cascading cipher system.
 *
 * Note: This layer requires the Signal Protocol WASM module to be loaded.
 */
export class SignalCipherLayer implements CipherLayer {
  readonly name = 'Signal-DoubleRatchet';
  readonly version = '1.0.0';

  private wasmModule: any = null;
  private doubleRatchetState: any = null;

  /**
   * Create Signal cipher layer
   *
   * @param wasmModule - Optional pre-loaded Signal Protocol WASM module
   * @param doubleRatchetState - Optional pre-initialized Double Ratchet state
   */
  constructor(wasmModule?: any, doubleRatchetState?: any) {
    this.wasmModule = wasmModule;
    this.doubleRatchetState = doubleRatchetState;
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
   * Initialize Signal layer with WASM module
   */
  async initialize(config: any): Promise<void> {
    try {
      if (config?.wasmModule) {
        this.wasmModule = config.wasmModule;
      }

      if (!this.wasmModule) {
        // Try to load WASM module dynamically
        const signalWasm = await import('../../../pkg/signal_protocol_wasm.js');
        await signalWasm.default(); // Initialize WASM
        this.wasmModule = signalWasm;
      }

      if (config?.doubleRatchetState) {
        this.doubleRatchetState = config.doubleRatchetState;
      }
    } catch (error) {
      throw new CipherLayerError(
        `Failed to initialize Signal Protocol: ${error.message}`,
        this.name,
        'initialize',
        error as Error
      );
    }
  }

  /**
   * Encrypt data using Signal Protocol Double Ratchet
   */
  async encrypt(data: Uint8Array, keys: SignalKeys): Promise<EncryptedPayload> {
    const startTime = performance.now();

    try {
      if (!this.wasmModule) {
        throw new CipherLayerError(
          'Signal Protocol WASM module not loaded. Call initialize() first.',
          this.name,
          'encrypt'
        );
      }

      const state = keys.doubleRatchetState || this.doubleRatchetState;

      if (!state) {
        throw new CipherLayerError(
          'Double Ratchet state is required',
          this.name,
          'encrypt'
        );
      }

      // Use Double Ratchet encrypt
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
    } catch (error) {
      throw new CipherLayerError(
        `Signal encryption failed: ${error.message}`,
        this.name,
        'encrypt',
        error as Error
      );
    }
  }

  /**
   * Decrypt data using Signal Protocol Double Ratchet
   */
  async decrypt(payload: EncryptedPayload, keys: SignalKeys): Promise<Uint8Array> {
    try {
      if (!this.wasmModule) {
        throw new CipherLayerError(
          'Signal Protocol WASM module not loaded. Call initialize() first.',
          this.name,
          'decrypt'
        );
      }

      const state = keys.doubleRatchetState || this.doubleRatchetState;

      if (!state) {
        throw new CipherLayerError(
          'Double Ratchet state is required',
          this.name,
          'decrypt'
        );
      }

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
    } catch (error) {
      throw new CipherLayerError(
        `Signal decryption failed: ${error.message}`,
        this.name,
        'decrypt',
        error as Error
      );
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
