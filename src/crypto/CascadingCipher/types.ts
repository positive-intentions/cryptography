/**
 * Cascading Cipher Types and Interfaces
 *
 * This module defines the core types and interfaces for the cascading cipher system.
 * It provides an extensible architecture for chaining multiple encryption algorithms.
 */

/**
 * Metadata for each encryption layer
 */
export interface LayerMetadata {
  /** Name of the cipher algorithm used */
  algorithm: string;

  /** Version of the algorithm implementation */
  version: string;

  /** Timestamp when encryption was performed */
  timestamp: number;

  /** Size of the payload before this layer */
  inputSize: number;

  /** Size of the payload after this layer */
  outputSize: number;

  /** Time taken to process this layer (ms) */
  processingTime: number;

  /** Additional algorithm-specific metadata */
  metadata?: Record<string, any>;
}

/**
 * Encrypted payload from a single cipher layer
 */
export interface EncryptedPayload {
  /** The encrypted data */
  ciphertext: Uint8Array;

  /** Metadata about this layer */
  layerMetadata: LayerMetadata;

  /** Algorithm-specific parameters needed for decryption */
  parameters: Record<string, any>;
}

/**
 * Result of cascading encryption with all layers
 */
export interface CascadedPayload {
  /** Final encrypted data after all layers */
  finalCiphertext: Uint8Array;

  /** Ordered list of layer metadata (outermost first) */
  layers: LayerMetadata[];

  /** Parameters for each layer (indexed by layer order) */
  layerParameters: Record<string, any>[];

  /** Total processing time for all layers */
  totalProcessingTime: number;

  /** Original plaintext size */
  originalSize: number;

  /** Final encrypted size */
  finalSize: number;

  /** Timestamp of the cascaded encryption */
  timestamp: number;
}

/**
 * Configuration for initializing a cipher layer
 */
export interface CipherLayerConfig {
  /** Any initialization parameters needed */
  [key: string]: any;
}

/**
 * Keys required for encryption/decryption
 */
export interface CipherKeys {
  /** Layer-specific keys and parameters */
  [layerName: string]: any;
}

/**
 * Abstract interface for a single cipher layer
 *
 * All cipher implementations must implement this interface to be
 * compatible with the cascading cipher system.
 */
export interface CipherLayer {
  /**
   * Unique name identifier for this cipher layer
   */
  readonly name: string;

  /**
   * Version of this cipher implementation
   */
  readonly version: string;

  /**
   * Initialize the cipher layer (optional)
   *
   * @param config - Configuration parameters for initialization
   */
  initialize?(config: CipherLayerConfig): Promise<void>;

  /**
   * Encrypt data using this cipher layer
   *
   * @param data - Plaintext data to encrypt
   * @param keys - Keys and parameters for encryption
   * @returns Encrypted payload with metadata
   */
  encrypt(data: Uint8Array, keys: any): Promise<EncryptedPayload>;

  /**
   * Decrypt data using this cipher layer
   *
   * @param payload - Encrypted payload to decrypt
   * @param keys - Keys and parameters for decryption
   * @returns Decrypted plaintext data
   */
  decrypt(payload: EncryptedPayload, keys: any): Promise<Uint8Array>;

  /**
   * Validate that the required keys are present
   *
   * @param keys - Keys to validate
   * @returns True if keys are valid
   */
  validateKeys?(keys: any): boolean;

  /**
   * Clean up resources (optional)
   */
  destroy?(): Promise<void>;
}

/**
 * Options for cascading encryption
 */
export interface CascadeEncryptOptions {
  /** Keys for each layer */
  keys: CipherKeys;

  /** Skip validation of keys (not recommended) */
  skipValidation?: boolean;

  /** Include detailed metadata */
  includeDetailedMetadata?: boolean;
}

/**
 * Options for cascading decryption
 */
export interface CascadeDecryptOptions {
  /** Keys for each layer */
  keys: CipherKeys;

  /** Skip validation of keys (not recommended) */
  skipValidation?: boolean;

  /** Verify layer integrity */
  verifyIntegrity?: boolean;
}

/**
 * Error thrown by cipher layers
 */
export class CipherLayerError extends Error {
  constructor(
    message: string,
    public readonly layerName: string,
    public readonly operation: 'encrypt' | 'decrypt' | 'initialize',
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'CipherLayerError';
  }
}

/**
 * Error thrown by the cascading cipher manager
 */
export class CascadingCipherError extends Error {
  constructor(
    message: string,
    public readonly failedAtLayer?: number,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'CascadingCipherError';
  }
}
