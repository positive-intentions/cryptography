/**
 * Key Authentication Utility
 *
 * Provides key fingerprinting for MITM attack prevention.
 * Generates SHA-256 fingerprints of public keys for verification.
 */

import { ConstantTime } from './constantTime';

/**
 * Key authentication utility for fingerprinting public keys
 */
export class KeyAuthentication {
  /**
   * Generate a fingerprint for a public key
   *
   * @param publicKey - The public key (CryptoKey or Uint8Array)
   * @returns Hex string fingerprint with colons (e.g., "aa:bb:cc:dd:...")
   */
  static async generateFingerprint(publicKey: CryptoKey | Uint8Array): Promise<string> {
    let keyBytes: Uint8Array;

    // Check if it's a CryptoKey by checking for Web Crypto API key properties
    if (publicKey && typeof publicKey === 'object' && 'type' in publicKey && 'algorithm' in publicKey) {
      const exported = await crypto.subtle.exportKey('raw', publicKey as CryptoKey);
      keyBytes = new Uint8Array(exported);
    } else {
      keyBytes = publicKey as Uint8Array;
    }

    // Hash the key to create fingerprint
    const hash = await crypto.subtle.digest('SHA-256', keyBytes);
    const hashArray = Array.from(new Uint8Array(hash));

    // Format as hex string with colons
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  /**
   * Verify key fingerprint matches expected value
   *
   * @param publicKey - The public key to verify
   * @param expectedFingerprint - The expected fingerprint
   * @returns True if fingerprint matches
   */
  static async verifyFingerprint(
    publicKey: CryptoKey | Uint8Array,
    expectedFingerprint: string
  ): Promise<boolean> {
    const fingerprint = await this.generateFingerprint(publicKey);
    // Use constant-time comparison to prevent timing attacks
    return ConstantTime.constantTimeCompareStrings(fingerprint, expectedFingerprint);
  }
}

