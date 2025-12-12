/**
 * Cascading Cipher Manager
 *
 * Main orchestrator for chaining multiple encryption layers.
 * Applies cipher layers in sequence for encryption and reverses for decryption.
 */

import {
  CipherLayer,
  CascadedPayload,
  CipherKeys,
  CascadeEncryptOptions,
  CascadeDecryptOptions,
  CascadingCipherError,
  LayerMetadata,
} from './types';

/**
 * CascadingCipherManager - Chains multiple cipher layers for layered encryption
 *
 * Example:
 * ```typescript
 * const manager = new CascadingCipherManager();
 * manager.addLayer(new MLSCipherLayer(mlsManager, groupId));
 * manager.addLayer(new SignalCipherLayer(signalState));
 *
 * const encrypted = await manager.encrypt(plaintext, keys);
 * const decrypted = await manager.decrypt(encrypted, keys);
 * ```
 */
export class CascadingCipherManager {
  private layers: CipherLayer[] = [];
  private layerMap: Map<string, CipherLayer> = new Map();

  /**
   * Convert Uint8Array to base64 string for consistent format between layers
   */
  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to Uint8Array
   */
  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Add a cipher layer to the chain
   *
   * @param layer - The cipher layer to add
   * @throws Error if a layer with the same name already exists
   */
  addLayer(layer: CipherLayer): void {
    if (this.layerMap.has(layer.name)) {
      throw new CascadingCipherError(
        `Layer with name "${layer.name}" already exists`,
        undefined
      );
    }

    this.layers.push(layer);
    this.layerMap.set(layer.name, layer);
  }

  /**
   * Remove a cipher layer by name
   *
   * @param layerName - Name of the layer to remove
   */
  removeLayer(layerName: string): void {
    const index = this.layers.findIndex((l) => l.name === layerName);
    if (index !== -1) {
      this.layers.splice(index, 1);
      this.layerMap.delete(layerName);
    }
  }

  /**
   * Get all cipher layers in order
   *
   * @returns Array of cipher layers
   */
  getLayers(): CipherLayer[] {
    return [...this.layers];
  }

  /**
   * Clear all cipher layers
   */
  clearLayers(): void {
    this.layers = [];
    this.layerMap.clear();
  }

  /**
   * Encrypt data through all cipher layers in sequence
   *
   * Applies layers in order: plaintext → layer1 → layer2 → ... → finalCiphertext
   *
   * @param plaintext - Data to encrypt
   * @param keys - Keys for each layer
   * @param options - Encryption options
   * @returns Cascaded encrypted payload with metadata
   */
  async encrypt(
    plaintext: Uint8Array,
    keys: CipherKeys,
    options?: Partial<CascadeEncryptOptions>
  ): Promise<CascadedPayload> {
    if (this.layers.length === 0) {
      throw new CascadingCipherError('No cipher layers configured', undefined);
    }

    const startTime = performance.now();
    const originalSize = plaintext.length;

    let currentData = plaintext;
    const layerMetadataList: LayerMetadata[] = [];
    const layerParametersList: Record<string, any>[] = [];

    try {
      for (let i = 0; i < this.layers.length; i++) {
        const layer = this.layers[i];
        const layerKeys = keys[layer.name];

        if (!layerKeys && !options?.skipValidation) {
          throw new CascadingCipherError(
            `Missing keys for layer: ${layer.name}`,
            i
          );
        }

        // Validate keys if layer supports it
        if (layer.validateKeys && !layer.validateKeys(layerKeys)) {
          throw new CascadingCipherError(
            `Invalid keys for layer: ${layer.name}`,
            i
          );
        }

        try {
          // Convert currentData from base64 string to Uint8Array if needed (for layers after the first)
          let inputData: Uint8Array;
          if (i === 0) {
            // First layer receives plaintext as Uint8Array
            inputData = currentData;
          } else {
            // Subsequent layers receive base64 string from previous layer
            if (typeof currentData === 'string') {
              inputData = this.base64ToArrayBuffer(currentData);
            } else {
              inputData = currentData;
            }
          }

          const encrypted = await layer.encrypt(inputData, layerKeys);

          layerMetadataList.push(encrypted.layerMetadata);
          layerParametersList.push(encrypted.parameters);

          // Debug: Log data format after encrypt
          if (process.env.DEBUG_CASCADE) {
            console.log(`[Cascade Encrypt] Layer ${i} (${layer.name}) output:`, {
              ciphertextType: typeof encrypted.ciphertext,
              ciphertextConstructor: encrypted.ciphertext?.constructor?.name,
              ciphertextLength: encrypted.ciphertext?.length,
              isUint8Array: encrypted.ciphertext instanceof Uint8Array,
            });
          }

          // Convert ciphertext to base64 string for consistent format between layers
          // This ensures all layers receive data in the same format
          currentData = this.arrayBufferToBase64(encrypted.ciphertext);
        } catch (error) {
          throw new CascadingCipherError(
            `Encryption failed at layer ${i} (${layer.name}): ${error.message}`,
            i,
            error as Error
          );
        }
      }

      const endTime = performance.now();
      const totalProcessingTime = endTime - startTime;

      // Debug: Log final ciphertext format
      if (process.env.DEBUG_CASCADE) {
        console.log(`[Cascade Encrypt] Final ciphertext:`, {
          type: typeof currentData,
          constructor: currentData?.constructor?.name,
          length: currentData?.length,
          isUint8Array: currentData instanceof Uint8Array,
        });
      }

      // Store final ciphertext as Uint8Array (convert from base64 string if needed)
      // currentData is base64 string after last layer, convert back to Uint8Array for storage
      const finalCiphertextBytes = typeof currentData === 'string' 
        ? this.base64ToArrayBuffer(currentData)
        : currentData;

      return {
        finalCiphertext: finalCiphertextBytes,
        layers: layerMetadataList,
        layerParameters: layerParametersList,
        totalProcessingTime,
        originalSize,
        finalSize: finalCiphertextBytes.length,
        timestamp: Date.now(),
      };
    } catch (error) {
      if (error instanceof CascadingCipherError) {
        throw error;
      }
      throw new CascadingCipherError(
        `Cascading encryption failed: ${error.message}`,
        undefined,
        error as Error
      );
    }
  }

  /**
   * Decrypt data by reversing through all cipher layers
   *
   * Applies layers in reverse: ciphertext → layerN → ... → layer2 → layer1 → plaintext
   *
   * @param cascadedPayload - Encrypted cascaded payload
   * @param keys - Keys for each layer
   * @param options - Decryption options
   * @returns Decrypted plaintext
   */
  async decrypt(
    cascadedPayload: CascadedPayload,
    keys: CipherKeys,
    options?: Partial<CascadeDecryptOptions>
  ): Promise<Uint8Array> {
    if (this.layers.length === 0) {
      throw new CascadingCipherError('No cipher layers configured', undefined);
    }

    if (this.layers.length !== cascadedPayload.layers.length) {
      throw new CascadingCipherError(
        `Layer count mismatch: manager has ${this.layers.length} layers, ` +
          `payload has ${cascadedPayload.layers.length} layers`,
        undefined
      );
    }

    // Convert finalCiphertext to base64 string for consistent format
    // All data between layers is stored as base64 strings
    let currentData: string | Uint8Array = this.arrayBufferToBase64(cascadedPayload.finalCiphertext);

    try {
      // Decrypt in reverse order (last layer first)
      for (let i = this.layers.length - 1; i >= 0; i--) {
        const layer = this.layers[i];
        const layerKeys = keys[layer.name];
        const layerMetadata = cascadedPayload.layers[i];
        const layerParameters = cascadedPayload.layerParameters[i];

        if (!layerKeys && !options?.skipValidation) {
          throw new CascadingCipherError(
            `Missing keys for layer: ${layer.name}`,
            i
          );
        }

        // Validate keys if layer supports it
        if (layer.validateKeys && !layer.validateKeys(layerKeys)) {
          throw new CascadingCipherError(
            `Invalid keys for layer: ${layer.name}`,
            i
          );
        }

        // Verify layer metadata matches
        if (options?.verifyIntegrity) {
          if (layerMetadata.algorithm !== layer.name) {
            throw new CascadingCipherError(
              `Layer mismatch at position ${i}: expected ${layer.name}, ` +
                `got ${layerMetadata.algorithm}`,
              i
            );
          }
        }

        try {
          // Convert currentData from base64 string to Uint8Array for the layer
          let ciphertextBytes: Uint8Array;
          if (typeof currentData === 'string') {
            ciphertextBytes = this.base64ToArrayBuffer(currentData);
          } else if (currentData instanceof Uint8Array) {
            ciphertextBytes = currentData;
          } else {
            // Fallback: try to convert to Uint8Array
            ciphertextBytes = new Uint8Array(currentData as any);
          }

          const payload = {
            ciphertext: ciphertextBytes,
            layerMetadata,
            parameters: layerParameters,
          };

          // Debug: Log data format before decrypt
          if (process.env.DEBUG_CASCADE) {
            console.log(`[Cascade Decrypt] Layer ${i} (${layer.name}):`, {
              ciphertextType: typeof payload.ciphertext,
              ciphertextConstructor: payload.ciphertext?.constructor?.name,
              ciphertextLength: payload.ciphertext?.length,
              isUint8Array: payload.ciphertext instanceof Uint8Array,
              isArrayBuffer: payload.ciphertext instanceof ArrayBuffer,
              isArray: Array.isArray(payload.ciphertext),
            });
          }

          const decrypted = await layer.decrypt(payload, layerKeys);

          // Convert decrypted data to base64 string for next layer
          // For the last layer (i === 0), we'll return Uint8Array directly
          if (i > 0) {
            // Convert to base64 for next layer
            currentData = this.arrayBufferToBase64(decrypted);
          } else {
            // Last layer - return Uint8Array directly
            currentData = decrypted;
          }

          // Debug: Log data format after decrypt
          if (process.env.DEBUG_CASCADE) {
            console.log(`[Cascade Decrypt] Layer ${i} (${layer.name}) output:`, {
              dataType: typeof currentData,
              dataConstructor: currentData?.constructor?.name,
              dataLength: currentData?.length,
              isUint8Array: currentData instanceof Uint8Array,
            });
          }
        } catch (error) {
          throw new CascadingCipherError(
            `Decryption failed at layer ${i} (${layer.name}): ${error.message}`,
            i,
            error as Error
          );
        }
      }

      // Return the decrypted plaintext as Uint8Array
      // After the last layer (i === 0), currentData is already Uint8Array
      return currentData as Uint8Array;
    } catch (error) {
      if (error instanceof CascadingCipherError) {
        throw error;
      }
      throw new CascadingCipherError(
        `Cascading decryption failed: ${error.message}`,
        undefined,
        error as Error
      );
    }
  }

  /**
   * Get information about the configured layers
   *
   * @returns Array of layer information
   */
  getLayerInfo(): Array<{ name: string; version: string }> {
    return this.layers.map((layer) => ({
      name: layer.name,
      version: layer.version,
    }));
  }

  /**
   * Initialize all layers that support initialization
   *
   * @param configs - Configuration for each layer (keyed by layer name)
   */
  async initializeLayers(configs: Record<string, any>): Promise<void> {
    for (const layer of this.layers) {
      if (layer.initialize) {
        const config = configs[layer.name];
        await layer.initialize(config);
      }
    }
  }

  /**
   * Destroy all layers that support cleanup
   */
  async destroyLayers(): Promise<void> {
    for (const layer of this.layers) {
      if (layer.destroy) {
        await layer.destroy();
      }
    }
  }

  /**
   * Get the total number of layers
   */
  get layerCount(): number {
    return this.layers.length;
  }
}
