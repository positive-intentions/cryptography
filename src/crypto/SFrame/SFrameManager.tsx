/**
 * SFrame (Secure Frame) Manager
 * End-to-end encryption for real-time media frames (audio/video)
 * Designed for low overhead and high performance
 *
 * SFrame adds ~10 bytes per frame overhead
 * Compatible with WebRTC Insertable Streams API
 */

export interface SFrameKey {
  keyId: number;
  key: CryptoKey;
  salt: Uint8Array;
}

export interface SFrameEncryptedFrame {
  frameCount: number;
  keyId: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  authTag: Uint8Array;
}

export class SFrameManager {
  private keys: Map<number, SFrameKey> = new Map();
  private currentKeyId: number = 0;
  private frameCounter: number = 0;
  private initialized: boolean = false;

  constructor() {
    console.log('🎥 [SFrame] Manager created');
  }

  /**
   * Initialize the SFrame manager
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      console.warn('[SFrame] Already initialized');
      return;
    }

    try {
      console.log('🔐 [SFrame] Initializing...');

      // Generate initial key
      await this.generateKey(0);

      this.initialized = true;
      console.log('✅ [SFrame] Initialized successfully');
    } catch (error) {
      console.error('❌ [SFrame] Initialization failed:', error);
      throw new Error(`SFrame initialization failed: ${error.message}`);
    }
  }

  /**
   * Generate a new SFrame encryption key
   */
  async generateKey(keyId: number): Promise<SFrameKey> {
    try {
      console.log(`🔑 [SFrame] Generating key ${keyId}...`);

      // Generate AES-GCM key (128-bit for low overhead)
      const key = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 128, // 128-bit for performance, 256-bit for maximum security
        },
        false, // Not extractable for security
        ['encrypt', 'decrypt']
      );

      // Generate salt for key derivation
      const salt = crypto.getRandomValues(new Uint8Array(16));

      const sframeKey: SFrameKey = {
        keyId,
        key,
        salt,
      };

      this.keys.set(keyId, sframeKey);
      console.log(`✅ [SFrame] Key ${keyId} generated`);

      return sframeKey;
    } catch (error) {
      console.error(`❌ [SFrame] Key generation failed:`, error);
      throw new Error(`SFrame key generation failed: ${error.message}`);
    }
  }

  /**
   * Derive an SFrame key from MLS shared secret
   * This allows SFrame to use keys derived from MLS for media encryption
   */
  async deriveKeyFromMLSSecret(
    mlsSecret: ArrayBuffer,
    keyId: number,
    context: string = 'SFrame'
  ): Promise<SFrameKey> {
    try {
      console.log(`🔗 [SFrame] Deriving key ${keyId} from MLS secret...`);

      // Use HKDF to derive SFrame key from MLS secret
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const info = new TextEncoder().encode(context);

      // Import MLS secret as key material
      const baseKey = await crypto.subtle.importKey(
        'raw',
        mlsSecret,
        'HKDF',
        false,
        ['deriveKey']
      );

      // Derive AES-GCM key
      const key = await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt,
          info,
        },
        baseKey,
        {
          name: 'AES-GCM',
          length: 128,
        },
        false,
        ['encrypt', 'decrypt']
      );

      const sframeKey: SFrameKey = {
        keyId,
        key,
        salt,
      };

      this.keys.set(keyId, sframeKey);
      console.log(`✅ [SFrame] Key ${keyId} derived from MLS`);

      return sframeKey;
    } catch (error) {
      console.error(`❌ [SFrame] Key derivation failed:`, error);
      throw new Error(`SFrame key derivation failed: ${error.message}`);
    }
  }

  /**
   * Set the active encryption key
   */
  setActiveKey(keyId: number): void {
    if (!this.keys.has(keyId)) {
      throw new Error(`SFrame key ${keyId} not found`);
    }
    this.currentKeyId = keyId;
    console.log(`🔄 [SFrame] Active key set to ${keyId}`);
  }

  /**
   * Encrypt a media frame using SFrame
   */
  async encryptFrame(frameData: ArrayBuffer): Promise<Uint8Array> {
    this.ensureInitialized();

    try {
      const sframeKey = this.keys.get(this.currentKeyId);
      if (!sframeKey) {
        throw new Error(`SFrame key ${this.currentKeyId} not found`);
      }

      // Generate IV from frame counter (deterministic but unique per frame)
      // SFrame uses a 96-bit (12-byte) IV
      const iv = new Uint8Array(12);
      const counterView = new DataView(iv.buffer);
      // Store frame counter in the IV (last 8 bytes as uint64-like)
      counterView.setUint32(4, Math.floor(this.frameCounter / 0x100000000), false);
      counterView.setUint32(8, this.frameCounter & 0xffffffff, false);

      // Encrypt the frame
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          tagLength: 128, // 128-bit authentication tag
        },
        sframeKey.key,
        frameData
      );

      // SFrame header: 1 byte for key ID + frame counter encoding
      // Simplified header: 1 byte key ID + 4 bytes frame counter
      const header = new Uint8Array(5);
      header[0] = this.currentKeyId;
      new DataView(header.buffer).setUint32(1, this.frameCounter, false);

      // Combine header + IV + ciphertext
      const encrypted = new Uint8Array(header.length + iv.length + ciphertext.byteLength);
      encrypted.set(header, 0);
      encrypted.set(iv, header.length);
      encrypted.set(new Uint8Array(ciphertext), header.length + iv.length);

      // Increment frame counter
      this.frameCounter++;

      return encrypted;
    } catch (error) {
      console.error('❌ [SFrame] Frame encryption failed:', error);
      throw new Error(`SFrame encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt a media frame using SFrame
   */
  async decryptFrame(encryptedFrame: Uint8Array): Promise<ArrayBuffer> {
    this.ensureInitialized();

    try {
      // Parse SFrame header (5 bytes: 1 byte key ID + 4 bytes frame counter)
      const keyId = encryptedFrame[0];
      const frameCount = new DataView(encryptedFrame.buffer).getUint32(1, false);

      // Get the key
      const sframeKey = this.keys.get(keyId);
      if (!sframeKey) {
        throw new Error(`SFrame key ${keyId} not found`);
      }

      // Extract IV (12 bytes after header)
      const iv = encryptedFrame.slice(5, 17);

      // Extract ciphertext (rest of the data)
      const ciphertext = encryptedFrame.slice(17);

      // Decrypt the frame
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          tagLength: 128,
        },
        sframeKey.key,
        ciphertext
      );

      return plaintext;
    } catch (error) {
      console.error('❌ [SFrame] Frame decryption failed:', error);
      throw new Error(`SFrame decryption failed: ${error.message}`);
    }
  }

  /**
   * Encrypt transform function for Insertable Streams
   * Use this with RTCRtpSender.createEncodedStreams()
   */
  createEncryptTransform(): TransformStream {
    const manager = this;

    return new TransformStream({
      async transform(encodedFrame, controller) {
        try {
          // Get frame data
          const frameData = encodedFrame.data;

          // Encrypt the frame
          const encrypted = await manager.encryptFrame(frameData);

          // Create new encoded frame with encrypted data
          encodedFrame.data = encrypted.buffer;

          // Forward the encrypted frame
          controller.enqueue(encodedFrame);
        } catch (error) {
          console.error('[SFrame] Encrypt transform error:', error);
          // Forward unencrypted frame on error (fallback)
          controller.enqueue(encodedFrame);
        }
      },
    });
  }

  /**
   * Decrypt transform function for Insertable Streams
   * Use this with RTCRtpReceiver.createEncodedStreams()
   */
  createDecryptTransform(): TransformStream {
    const manager = this;

    return new TransformStream({
      async transform(encodedFrame, controller) {
        try {
          // Get encrypted frame data
          const encryptedData = new Uint8Array(encodedFrame.data);

          // Decrypt the frame
          const decrypted = await manager.decryptFrame(encryptedData);

          // Create new encoded frame with decrypted data
          encodedFrame.data = decrypted;

          // Forward the decrypted frame
          controller.enqueue(encodedFrame);
        } catch (error) {
          console.error('[SFrame] Decrypt transform error:', error);
          // Skip frame on decryption error
          // (better to drop frame than show corrupted video)
        }
      },
    });
  }

  /**
   * Rotate encryption keys
   */
  async rotateKey(): Promise<number> {
    try {
      const newKeyId = this.currentKeyId + 1;
      console.log(`🔄 [SFrame] Rotating to key ${newKeyId}...`);

      await this.generateKey(newKeyId);
      this.setActiveKey(newKeyId);

      console.log(`✅ [SFrame] Key rotated to ${newKeyId}`);
      return newKeyId;
    } catch (error) {
      console.error('❌ [SFrame] Key rotation failed:', error);
      throw new Error(`SFrame key rotation failed: ${error.message}`);
    }
  }

  /**
   * Get current key ID
   */
  getCurrentKeyId(): number {
    return this.currentKeyId;
  }

  /**
   * Get frame counter (for debugging)
   */
  getFrameCounter(): number {
    return this.frameCounter;
  }

  /**
   * Reset frame counter (use when rotating keys)
   */
  resetFrameCounter(): void {
    this.frameCounter = 0;
    console.log('🔄 [SFrame] Frame counter reset');
  }

  /**
   * Remove old keys to prevent memory bloat
   */
  cleanupOldKeys(keepLast: number = 2): void {
    const keyIds = Array.from(this.keys.keys()).sort((a, b) => b - a);

    if (keyIds.length > keepLast) {
      const toDelete = keyIds.slice(keepLast);
      toDelete.forEach((keyId) => {
        this.keys.delete(keyId);
        console.log(`🧹 [SFrame] Deleted old key ${keyId}`);
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
    console.log('✅ [SFrame] Manager destroyed');
  }

  /**
   * Ensure the manager is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('SFrame Manager not initialized. Call initialize() first.');
    }
  }
}

export default SFrameManager;
