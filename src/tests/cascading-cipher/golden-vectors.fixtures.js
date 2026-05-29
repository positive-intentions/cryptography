/**
 * EnkryptedChat-Profile-v0 golden vectors (cascade layer chain).
 * Source of truth for website/docs/technical/whitepaper/appendix-a-test-vectors.mdx
 *
 * These use deterministic mock cipher layers (append 0x01..0x04 per layer).
 * Live MLS/Signal/ML-KEM/AES vectors are deferred until Profile-v1 key freeze.
 */

export const GOLDEN_VECTOR_PROFILE = 'EnkryptedChat-Profile-v0-golden-mock';

/** @param {Uint8Array | number[]} bytes */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** @param {string} hex */
export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Plaintext UTF-8 "Hi" */
export const V1_PLAINTEXT_HEX = '4869';

/** After MockCipher1..3 append 0x01, 0x02, 0x03 */
export const V1_FINAL_CIPHERTEXT_HEX = '4869010203';

/** Four-byte plaintext */
export const V2_PLAINTEXT_HEX = '0a141e28';

/** After four mock layers append 0x01..0x04 (simulates MLS→Signal→ML-KEM→AES depth) */
export const V2_FINAL_CIPHERTEXT_HEX = '0a141e2801020304';

/** Mock layer names aligned with product cascade order */
export const PROFILE_MOCK_LAYER_NAMES = ['MLS', 'Signal', 'ML-KEM', 'AES'];

/**
 * Build mock layers that append one byte each (deterministic, no Date.now in ciphertext).
 * @param {string[]} names
 */
export function createGoldenMockLayers(names) {
  return names.map((name, index) => {
    const tag = index + 1;
    return {
      name,
      version: '1.0.0-golden',
      encrypt: async (data) => ({
        ciphertext: new Uint8Array([...data, tag]),
        layerMetadata: {
          algorithm: name,
          version: '1.0.0-golden',
          timestamp: 1717000000000,
          inputSize: data.length,
          outputSize: data.length + 1,
          processingTime: 0,
        },
        parameters: { goldenTag: tag },
      }),
      decrypt: async (payload) => payload.ciphertext.slice(0, -1),
      validateKeys: () => true,
    };
  });
}
