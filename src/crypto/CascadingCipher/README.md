# Cascading Cipher System

An extensible encryption middleware that daisy-chains multiple encryption algorithms for layered security. Supports MLS, Signal Protocol, Diffie-Hellman, and AES-GCM encryption layers.

## Overview

The Cascading Cipher System provides a flexible architecture for combining multiple encryption algorithms in sequence. Data flows through each cipher layer during encryption and reverses through them during decryption.

```
Plaintext → Layer1 → Layer2 → Layer3 → Ciphertext
Ciphertext → Layer3⁻¹ → Layer2⁻¹ → Layer1⁻¹ → Plaintext
```

## Features

- ✅ **Extensible Architecture**: Easy to add new cipher layers
- ✅ **Multiple Protocols**: MLS, Signal, DH, AES-GCM support
- ✅ **Metadata Tracking**: Full visibility into each layer's processing
- ✅ **Error Recovery**: Detailed error reporting with layer identification
- ✅ **Performance Monitoring**: Track processing time and size overhead
- ✅ **Module Federation**: Export via webpack for use in other apps
- ✅ **TypeScript**: Full type safety and IntelliSense support

## Quick Start

### Basic Example

```typescript
import {
  CascadingCipherManager,
  AESCipherLayer,
  DHCipherLayer,
} from "cryptography/CascadingCipher";

// Create manager
const manager = new CascadingCipherManager();

// Add layers (applied in order during encryption)
manager.addLayer(new DHCipherLayer());
manager.addLayer(new AESCipherLayer());

// Prepare plaintext and keys
const plaintext = new TextEncoder().encode("Secret message");
const keys = {
  "DH-AES-GCM": {
    privateKey: dhPrivateKey,
    publicKey: dhPublicKey,
  },
  "AES-GCM-256": {
    password: "my-secure-password",
  },
};

// Encrypt
const encrypted = await manager.encrypt(plaintext, keys);

// Decrypt (layers applied in reverse)
const decrypted = await manager.decrypt(encrypted, keys);
```

### MLS + Signal + DH + AES Example

```typescript
import {
  CascadingCipherManager,
  MLSCipherLayer,
  SignalCipherLayer,
  DHCipherLayer,
  AESCipherLayer,
} from "cryptography/CascadingCipher";

const manager = new CascadingCipherManager();

// Add all layers (innermost to outermost)
manager.addLayer(new MLSCipherLayer(mlsManager, groupId));
manager.addLayer(new SignalCipherLayer(wasmModule, doubleRatchetState));
manager.addLayer(new DHCipherLayer());
manager.addLayer(new AESCipherLayer());

const keys = {
  MLS: { mlsManager, groupId },
  "X3DH-DoubleRatchet": { doubleRatchetState },
  "DH-AES-GCM": { privateKey, publicKey },
  "AES-GCM-256": { password: "password" },
};

const encrypted = await manager.encrypt(plaintext, keys);
// Result flows: plaintext → MLS → Signal → DH → AES → ciphertext

const decrypted = await manager.decrypt(encrypted, keys);
// Result flows: ciphertext → AES⁻¹ → DH⁻¹ → Signal⁻¹ → MLS⁻¹ → plaintext
```

## Available Cipher Layers

### 1. AESCipherLayer

Password-based AES-GCM-256 encryption with Scrypt key derivation (GPU/ASIC resistant).

```typescript
const aesLayer = new AESCipherLayer();
const keys = { password: "secure-password" };
```

**Features:**

- AES-GCM-256 authenticated encryption
- Scrypt key derivation (N=32768, r=8, p=1) - GPU/ASIC resistant
- Random salt and IV per encryption
- IV reuse protection
- Protocol version in AAD
- Zeroization of sensitive buffers
- Compatible with Web Crypto API

### 2. DHCipherLayer

Diffie-Hellman ECDH-P256 key exchange with AES-GCM encryption.

```typescript
const dhLayer = new DHCipherLayer();

// Option 1: Provide DH keys
const keys = {
  privateKey: dhPrivateKey, // CryptoKey or Uint8Array
  publicKey: dhPublicKey, // CryptoKey or Uint8Array
};

// Option 2: Provide pre-derived shared secret
const keys = {
  sharedSecret: sharedSecretBytes,
};
```

**Features:**

- ECDH-P256 key exchange
- HKDF-SHA256 key derivation
- AES-GCM-256 encryption
- Compatible with ../chat app's DH implementation

### 3. MLSCipherLayer

RFC 9420 compliant MLS (Message Layer Security) group encryption.

```typescript
import { MLSManager } from "../../crypto/MLS/MLSManager";

const mlsManager = new MLSManager("user@example.com");
await mlsManager.initialize();
await mlsManager.createGroup("my-group");

const mlsLayer = new MLSCipherLayer(mlsManager, "my-group");
const keys = { mlsManager, groupId: "my-group" };
```

**Features:**

- End-to-end encrypted group messaging
- Forward secrecy
- MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
- Group member management

### 4. SignalCipherLayer

Signal Protocol with Double Ratchet algorithm via WASM from federated module.

```typescript
// Load WASM bindings from federated signal_protocol module
const wasmBindings = await import("signal_protocol/WasmBindings");
const signalWasm = await wasmBindings.loadWasmModule();

const signalLayer = new SignalCipherLayer(signalWasm, doubleRatchetState);
const keys = { doubleRatchetState };
```

**Note:** The Signal Protocol WASM module is now provided via module federation from the `signal_protocol` remote module. The `SignalCipherLayer` will automatically load it if not provided.

**Features:**

- Double Ratchet algorithm
- Forward secrecy
- Post-compromise security
- Out-of-order message handling

## Creating Custom Cipher Layers

Implement the `CipherLayer` interface:

```typescript
import { CipherLayer, EncryptedPayload, CipherLayerError } from "./types";

class MyCustomCipherLayer implements CipherLayer {
  readonly name = "MyCustomCipher";
  readonly version = "1.0.0";

  validateKeys(keys: any): boolean {
    // Validate required keys
    return keys && keys.myKey !== undefined;
  }

  async encrypt(data: Uint8Array, keys: any): Promise<EncryptedPayload> {
    const startTime = performance.now();

    // Your encryption logic here
    const ciphertext = await this.myEncryptionAlgorithm(data, keys);

    return {
      ciphertext,
      layerMetadata: {
        algorithm: this.name,
        version: this.version,
        timestamp: Date.now(),
        inputSize: data.length,
        outputSize: ciphertext.length,
        processingTime: performance.now() - startTime,
      },
      parameters: {
        // Parameters needed for decryption
      },
    };
  }

  async decrypt(payload: EncryptedPayload, keys: any): Promise<Uint8Array> {
    // Your decryption logic here
    return await this.myDecryptionAlgorithm(payload.ciphertext, keys);
  }
}
```

## API Reference

### CascadingCipherManager

Main orchestrator for managing cipher layers.

#### Methods

- `addLayer(layer: CipherLayer): void` - Add a cipher layer to the chain
- `removeLayer(layerName: string): void` - Remove a layer by name
- `getLayers(): CipherLayer[]` - Get all configured layers
- `clearLayers(): void` - Remove all layers
- `encrypt(plaintext: Uint8Array, keys: CipherKeys): Promise<CascadedPayload>` - Encrypt data
- `decrypt(payload: CascadedPayload, keys: CipherKeys): Promise<Uint8Array>` - Decrypt data
- `initializeLayers(configs: Record<string, any>): Promise<void>` - Initialize all layers
- `destroyLayers(): Promise<void>` - Clean up all layers

### CascadedPayload

Result of cascading encryption with full metadata.

```typescript
interface CascadedPayload {
  finalCiphertext: Uint8Array;
  layers: LayerMetadata[];
  layerParameters: Record<string, any>[];
  totalProcessingTime: number;
  originalSize: number;
  finalSize: number;
  timestamp: number;
}
```

### LayerMetadata

Metadata for each encryption layer.

```typescript
interface LayerMetadata {
  algorithm: string;
  version: string;
  timestamp: number;
  inputSize: number;
  outputSize: number;
  processingTime: number;
  metadata?: Record<string, any>;
}
```

## Module Federation Usage

In your webpack config:

```javascript
// webpack.config.js
module.exports = {
  plugins: [
    new ModuleFederationPlugin({
      remotes: {
        cryptography: "cryptography@http://localhost:8083/remoteEntry.js",
      },
    }),
  ],
};
```

In your app:

```typescript
// Dynamically import
const { CascadingCipherManager, AESCipherLayer, DHCipherLayer } = await import(
  "cryptography/CascadingCipher"
);

// Use as normal
const manager = new CascadingCipherManager();
manager.addLayer(new DHCipherLayer());
```

## Testing

Run the comprehensive test suite:

```bash
# All cascading cipher tests
npm test -- src/tests/cascading-cipher --no-coverage

# Specific test files
npm test -- src/tests/cascading-cipher/cipher-layer-interface.test.js
npm test -- src/tests/cascading-cipher/cascading-cipher-manager.test.js
npm test -- src/tests/cascading-cipher/aes-cipher-layer.test.js
npm test -- src/tests/cascading-cipher/integration.test.js
```

## Storybook Demo

View the interactive demo:

```bash
npm start
# Navigate to: Cascading Cipher / Interactive Demo
```

The demo includes:

- Live encryption/decryption
- Multiple layer configuration
- DH key generation
- Performance metrics
- Detailed operation logs

## Performance Considerations

Each layer adds:

- **Processing time**: ~5-50ms per layer (depends on algorithm)
- **Size overhead**: Varies by algorithm (AES-GCM: +28 bytes, DH: +32 bytes, etc.)
- **Memory**: Temporary buffers for intermediate results

For optimal performance:

- Use fewer layers when possible
- Consider layer order (faster layers first)
- Reuse key derivation when encrypting multiple messages
- Profile with large datasets

## Security Notes

⚠️ **Important Security Considerations:**

1. **Key Management**: Secure storage of keys is critical
2. **Random Number Generation**: Uses `crypto.getRandomValues()` - ensure proper entropy
3. **Layer Independence**: Each layer's security is independent; compromise of one doesn't affect others
4. **Protocol Compliance**: MLS and Signal layers follow their respective RFCs
5. **Forward Secrecy**: MLS and Signal provide forward secrecy; AES and DH do not

## Architecture

```
┌─────────────────────────────────────────────────┐
│         CascadingCipherManager                  │
│  (Orchestrates layer chain)                     │
└────────┬────────────────────────────────────────┘
         │
         ├─> Layer 1 (e.g., MLS)
         │   └─> encrypt/decrypt
         │
         ├─> Layer 2 (e.g., Signal)
         │   └─> encrypt/decrypt
         │
         ├─> Layer 3 (e.g., DH)
         │   └─> encrypt/decrypt
         │
         └─> Layer 4 (e.g., AES)
             └─> encrypt/decrypt
```

## Files Created

### Core

- `src/crypto/CascadingCipher/types.ts` - Type definitions
- `src/crypto/CascadingCipher/CascadingCipherManager.ts` - Main manager
- `src/crypto/CascadingCipher/index.ts` - Exports

### Layers

- `src/crypto/CascadingCipher/layers/AESCipherLayer.ts`
- `src/crypto/CascadingCipher/layers/DHCipherLayer.ts`
- `src/crypto/CascadingCipher/layers/MLSCipherLayer.ts`
- `src/crypto/CascadingCipher/layers/SignalCipherLayer.ts`

### Tests

- `src/tests/cascading-cipher/cipher-layer-interface.test.js` - ✅ 25/25 passing
- `src/tests/cascading-cipher/cascading-cipher-manager.test.js` - ✅ 25/25 passing
- `src/tests/cascading-cipher/aes-cipher-layer.test.js` - ⚠️ 10/21 passing (integration refinement needed)
- `src/tests/cascading-cipher/integration.test.js` - Full integration tests

### Demo

- `src/stories/CascadingCipher/CascadingCipherDemo.stories.js` - Interactive Storybook demo

## Contributing

To add a new cipher layer:

1. Create `src/crypto/CascadingCipher/layers/YourCipherLayer.ts`
2. Implement the `CipherLayer` interface
3. Add tests in `src/tests/cascading-cipher/your-cipher-layer.test.js`
4. Export from `src/crypto/CascadingCipher/index.ts`
5. Update this README

## License

Same as parent project.
