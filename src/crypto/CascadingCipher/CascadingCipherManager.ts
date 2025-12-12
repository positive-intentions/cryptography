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
          const encrypted = await layer.encrypt(currentData, layerKeys);

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

          currentData = encrypted.ciphertext;
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

      return {
        finalCiphertext: currentData,
        layers: layerMetadataList,
        layerParameters: layerParametersList,
        totalProcessingTime,
        originalSize,
        finalSize: currentData.length,
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

    let currentData = cascadedPayload.finalCiphertext;

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
          const payload = {
            ciphertext: currentData,
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

          currentData = await layer.decrypt(payload, layerKeys);

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

      return currentData;
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
