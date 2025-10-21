/**
 * Mock SFrame Manager for Jest tests
 * This mock simulates the SFrame protocol behavior for unit testing
 * Real implementation is tested in Storybook (browser environment with Web Crypto API)
 *
 * This mock avoids ES module import issues during Jest testing
 */

export class SFrameManager {
  private keys: Map<number, any> = new Map();
  private currentKeyId: number = 0;
  private frameCounter: number = 0;
  private initialized: boolean = false;

  constructor() {
    // Mock constructor
  }

  /**
   * Initialize the SFrame manager
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Generate initial key (key ID 0)
    await this.generateKey(0);
    this.initialized = true;
  }

  /**
   * Generate a new SFrame encryption key
   */
  async generateKey(keyId: number): Promise<any> {
    const mockKey = {
      keyId,
      key: new Uint8Array(16).fill(keyId), // Mock AES-128 key
      salt: new Uint8Array(16).fill(Math.random() * 255),
    };

    this.keys.set(keyId, mockKey);
    return mockKey;
  }

  /**
   * Derive an SFrame key from MLS shared secret
   */
  async deriveKeyFromMLSSecret(
    mlsSecret: ArrayBuffer,
    keyId: number,
    context: string = 'SFrame'
  ): Promise<any> {
    const mockKey = {
      keyId,
      key: new Uint8Array(16).fill(keyId + 100), // Mock derived key
      salt: new Uint8Array(16).fill(Math.random() * 255),
    };

    this.keys.set(keyId, mockKey);
    return mockKey;
  }

  /**
   * Set the active encryption key
   */
  setActiveKey(keyId: number): void {
    if (!this.keys.has(keyId)) {
      throw new Error(`SFrame key ${keyId} not found`);
    }
    this.currentKeyId = keyId;
  }

  /**
   * Encrypt a media frame using SFrame
   */
  async encryptFrame(frameData: ArrayBuffer): Promise<Uint8Array> {
    if (!this.initialized) {
      throw new Error('SFrame Manager not initialized. Call initialize() first.');
    }

    const sframeKey = this.keys.get(this.currentKeyId);
    if (!sframeKey) {
      throw new Error(`SFrame key ${this.currentKeyId} not found`);
    }

    // Mock encryption: prefix with header + counter + nonce
    const plaintext = new Uint8Array(frameData);
    const header = new Uint8Array(5);
    header[0] = this.currentKeyId;
    new DataView(header.buffer).setUint32(1, this.frameCounter, false);

    const iv = new Uint8Array(12).fill(Math.random() * 255);
    const encrypted = new Uint8Array(header.length + iv.length + plaintext.length);
    encrypted.set(header, 0);
    encrypted.set(iv, header.length);
    encrypted.set(plaintext, header.length + iv.length);

    this.frameCounter++;
    return encrypted;
  }

  /**
   * Decrypt a media frame using SFrame
   */
  async decryptFrame(encryptedFrame: Uint8Array): Promise<ArrayBuffer> {
    if (!this.initialized) {
      throw new Error('SFrame Manager not initialized. Call initialize() first.');
    }

    // Parse header
    const keyId = encryptedFrame[0];
    const frameCount = new DataView(encryptedFrame.buffer).getUint32(1, false);

    const sframeKey = this.keys.get(keyId);
    if (!sframeKey) {
      throw new Error(`SFrame key ${keyId} not found`);
    }

    // Extract plaintext (skip header + IV)
    const plaintext = encryptedFrame.slice(17);
    return plaintext.buffer;
  }

  /**
   * Create encrypt transform for Insertable Streams
   */
  createEncryptTransform(): any {
    const manager = this;
    return {
      transform: async (encodedFrame: any, controller: any) => {
        const encrypted = await manager.encryptFrame(encodedFrame.data);
        encodedFrame.data = encrypted.buffer;
        controller.enqueue(encodedFrame);
      },
    };
  }

  /**
   * Create decrypt transform for Insertable Streams
   */
  createDecryptTransform(): any {
    const manager = this;
    return {
      transform: async (encodedFrame: any, controller: any) => {
        const decrypted = await manager.decryptFrame(new Uint8Array(encodedFrame.data));
        encodedFrame.data = decrypted;
        controller.enqueue(encodedFrame);
      },
    };
  }

  /**
   * Rotate encryption keys
   * RFC 9605: Frame counter should be reset on key rotation
   */
  async rotateKey(): Promise<number> {
    const newKeyId = this.currentKeyId + 1;
    await this.generateKey(newKeyId);
    this.setActiveKey(newKeyId);
    this.resetFrameCounter(); // RFC 9605: Reset counter on rotation
    return newKeyId;
  }

  /**
   * Get current key ID
   */
  getCurrentKeyId(): number {
    return this.currentKeyId;
  }

  /**
   * Get frame counter
   */
  getFrameCounter(): number {
    return this.frameCounter;
  }

  /**
   * Reset frame counter
   */
  resetFrameCounter(): void {
    this.frameCounter = 0;
  }

  /**
   * Remove old keys
   */
  cleanupOldKeys(keepLast: number = 2): void {
    const keyIds = Array.from(this.keys.keys()).sort((a, b) => b - a);

    if (keyIds.length > keepLast) {
      const toDelete = keyIds.slice(keepLast);
      toDelete.forEach((keyId) => {
        this.keys.delete(keyId);
      });
    }
  }

  /**
   * Get statistics
   */
  getStats(): {
    keyCount: number;
    currentKeyId: number;
    frameCounter: number;
    initialized: boolean;
  } {
    return {
      keyCount: this.keys.size,
      currentKeyId: this.currentKeyId,
      frameCounter: this.frameCounter,
      initialized: this.initialized,
    };
  }

  /**
   * Clean up resources
   */
  destroy(): void {
    this.keys.clear();
    this.initialized = false;
    this.frameCounter = 0;
  }
}

export default SFrameManager;
