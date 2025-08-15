# Signal Protocol WASM Build

This directory contains a WebAssembly (WASM) build of the Signal Protocol implementation.

## ✅ WASM Compatibility

**Yes, this library can be built as WASM!** The implementation uses only:
- Pure Go cryptographic libraries (crypto/aes, crypto/sha256)
- golang.org/x/crypto (Curve25519, HKDF)
- No CGO dependencies
- No system calls that would block WASM

## Building

```bash
cd wasm
./build.sh
```

This will create:
- `signal.wasm` - The compiled WASM module (~2-3MB)
- `wasm_exec.js` - Go's WASM support file (copied from Go installation)

## Usage

### Browser Integration

```javascript
// Load the WASM module
const go = new Go();
const result = await WebAssembly.instantiateStreaming(
    fetch("signal.wasm"), 
    go.importObject
);
go.run(result.instance);

// Use the Signal Protocol
const identityKeys = await SignalProtocol.generateIdentityKeyPair();
const registrationId = SignalProtocol.generateRegistrationId();
const preKeys = await SignalProtocol.generatePreKeys(0, 100);
```

### Node.js Integration

```javascript
const fs = require('fs');
const Go = require('./wasm_exec.js');

const go = new Go();
const wasmBuffer = fs.readFileSync('./signal.wasm');
const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
go.run(result.instance);
```

## API Functions

The WASM module exposes these functions:

- `generateIdentityKeyPair()` - Generate identity key pair
- `generateRegistrationId()` - Generate registration ID  
- `generatePreKeys(start, count)` - Generate prekeys
- `generateSignedPreKey(privKey, pubKey, id)` - Generate signed prekey
- `initializeSession(userId)` - Initialize a session for a user
- `processPreKeyBundle(userId, remoteUserId, bundle)` - Process prekey bundle
- `encryptMessage(userId, recipientId, message)` - Encrypt a message
- `decryptMessage(userId, senderId, ciphertext)` - Decrypt a message

## Testing

1. Start a local web server:
```bash
python3 -m http.server 8080
```

2. Open http://localhost:8080/index.html

## Performance

WASM performance is generally good for cryptographic operations:
- Key generation: ~5-10ms
- Message encryption: ~1-2ms  
- Message decryption: ~1-2ms

Note: First operation may be slower due to WASM initialization.

## Limitations

- In-memory storage only (implement IndexedDB for persistence)
- No web workers support in example (can be added)
- Bundle size is ~2-3MB (can be optimized with wasm-opt)

## Production Considerations

For production use:
1. Implement persistent storage (IndexedDB/localStorage)
2. Add proper error handling and recovery
3. Optimize WASM size with `wasm-opt`
4. Consider using Web Workers for crypto operations
5. Implement proper session management
6. Add TypeScript definitions for better DX