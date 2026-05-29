/**
 * @jest-environment jsdom
 *
 * Golden vector conformance tests — frozen hex for Enkrypted Chat Appendix A.
 */

import { CascadingCipherManager } from '../../crypto/CascadingCipher/CascadingCipherManager.ts';
import {
  GOLDEN_VECTOR_PROFILE,
  V1_PLAINTEXT_HEX,
  V1_FINAL_CIPHERTEXT_HEX,
  V2_PLAINTEXT_HEX,
  V2_FINAL_CIPHERTEXT_HEX,
  PROFILE_MOCK_LAYER_NAMES,
  bytesToHex,
  hexToBytes,
  createGoldenMockLayers,
} from './golden-vectors.fixtures.js';

describe('Golden vectors (Appendix A)', () => {
  test('V1 — plaintext "Hi" three-layer mock cascade', async () => {
    const manager = new CascadingCipherManager();
    createGoldenMockLayers(['MockCipher1', 'MockCipher2', 'MockCipher3']).forEach(
      (layer) => manager.addLayer(layer)
    );

    const plaintext = hexToBytes(V1_PLAINTEXT_HEX);
    const keys = {
      MockCipher1: {},
      MockCipher2: {},
      MockCipher3: {},
    };

    const encrypted = await manager.encrypt(plaintext, keys);
    expect(bytesToHex(encrypted.finalCiphertext)).toBe(V1_FINAL_CIPHERTEXT_HEX);

    const decrypted = await manager.decrypt(encrypted, keys);
    expect(bytesToHex(decrypted)).toBe(V1_PLAINTEXT_HEX);
  });

  test('V2 — four-byte plaintext four-layer profile-order mock cascade', async () => {
    const manager = new CascadingCipherManager();
    createGoldenMockLayers(PROFILE_MOCK_LAYER_NAMES).forEach((layer) =>
      manager.addLayer(layer)
    );

    const plaintext = hexToBytes(V2_PLAINTEXT_HEX);
    const keys = Object.fromEntries(
      PROFILE_MOCK_LAYER_NAMES.map((name) => [name, {}])
    );

    const encrypted = await manager.encrypt(plaintext, keys);
    expect(bytesToHex(encrypted.finalCiphertext)).toBe(V2_FINAL_CIPHERTEXT_HEX);

    const decrypted = await manager.decrypt(encrypted, keys);
    expect(bytesToHex(decrypted)).toBe(V2_PLAINTEXT_HEX);
  });

  test('exports frozen profile id for spec cross-reference', () => {
    expect(GOLDEN_VECTOR_PROFILE).toBe('EnkryptedChat-Profile-v0-golden-mock');
  });
});
