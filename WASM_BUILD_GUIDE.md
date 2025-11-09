# WASM Build Guide - Signal Protocol Cryptography

## ⚠️ Important: Signal Protocol WASM Migration

**The Signal Protocol WASM implementation has been moved to a separate repository (`signal-protocol`) and is now provided via Module Federation.**

### Current Architecture

The Signal Protocol WASM is now loaded from the `signal_protocol` remote module:

```typescript
// Load WASM bindings from federated signal_protocol module
const wasmBindings = await import("signal_protocol/WasmBindings");
const signalWasmModule = await wasmBindings.loadWasmModule();
```

**Module Federation Configuration:**

- Remote name: `signal_protocol`
- Local development: `http://localhost:8084/remoteEntry.js`
- Exposed modules:
  - `./SignalProtocol` - SignalProtocolDemo component
  - `./WasmBindings` - WASM bindings module

**Note:** This guide documents the historical build process. For current development, see the `signal-protocol` repository.

---

## 🚨 Historical Context: Critical Security Update Required

**The WASM currently deployed to p2p contains BROKEN cryptography that was fixed in the Rust source code but NOT yet compiled!**

### The Problem (Historical)

The p2p application previously imported Signal Protocol WASM at:

```typescript
// MLSProvider.tsx:196 (OLD - no longer used)
const signalWasmModule = await import(
  "cryptography/pkg/signal_protocol_wasm.js"
);
```

**Current WASM Status:**

- ❌ Built: October 29, 2025 15:19 (BEFORE security fixes)
- ❌ Contains fake SHA-256 "cryptography"
- ❌ Contains broken ECDH implementation
- ❌ Logs all cryptographic secrets
- ❌ Provides ZERO security

**Fixed Rust Source:**

- ✅ Real X25519 elliptic curve cryptography
- ✅ Real Ed25519 digital signatures
- ✅ No information leakage
- ✅ Production-ready security

**Impact on p2p Cascading Cipher:**

```
Plaintext → [MLS: Secure ✅] → [Signal: BROKEN ❌] → [AES: Secure ✅] → Ciphertext
```

The Signal layer in the cascading cipher is compromised until WASM is rebuilt!

---

## Quick Start: Rebuild WASM

### One-Line Rebuild (Recommended)

```bash
npm run build:wasm:with-security-fixes
```

This will:

1. Build production WASM with security fixes
2. Validate the build succeeded
3. Output the fixed WASM to `pkg/`

### Deploy to p2p

```bash
npm run deploy:p2p
```

Or manually:

```bash
npm run build:wasm:production
cp -r pkg/* ../p2p/node_modules/cryptography/pkg/
```

---

## Build Commands Reference

### Production Builds

| Command                                  | Description                         |
| ---------------------------------------- | ----------------------------------- |
| `npm run build:wasm:production`          | Production build with optimizations |
| `npm run build:wasm:with-security-fixes` | Production build + validation       |
| `npm run build:wasm:quick`               | Fast development build              |
| `npm run build:wasm:all-targets`         | Build for web, node, and bundler    |

### Development

| Command                               | Description                                         |
| ------------------------------------- | --------------------------------------------------- |
| `npm run build:wasm:dev`              | Development build (faster, larger)                  |
| `npm run watch:rust`                  | Auto-rebuild on Rust changes (requires cargo-watch) |
| `npm run check:crypto-implementation` | Validate Rust code compiles                         |

### Validation

| Command                      | Description               |
| ---------------------------- | ------------------------- |
| `npm run validate:wasm`      | Check if WASM file exists |
| `npm run validate:wasm:size` | Show WASM file size       |
| `npm run status:wasm`        | Full WASM status report   |

### Information

| Command                         | Description                     |
| ------------------------------- | ------------------------------- |
| `npm run info:security-changes` | Show what was fixed             |
| `npm run check-rust`            | Verify Rust toolchain installed |

---

## Build Targets

### Web (Default - Used by p2p)

```bash
npm run build:wasm:production
```

**Output:** `pkg/signal_protocol_wasm.js` + `pkg/signal_protocol_wasm_bg.wasm`
**Used by:** Browsers, Storybook, p2p application

### Node.js

```bash
npm run build:wasm:node
```

**Output:** `pkg-node/`
**Used by:** Node.js applications, backend services

### Bundler

```bash
npm run build:wasm:bundler
```

**Output:** `pkg-bundler/`
**Used by:** Webpack, Rollup, Vite

---

## Security Fixes in Detail

### 1. Real X25519 ECDH

**Before (BROKEN):**

```rust
// crypto.rs - FAKE ECDH using lexicographic ordering + SHA-256
let (key1, key2) = if private_key <= public_key {
    (private_key, public_key)
} else {
    (public_key, private_key)
};
let mut hasher = Sha256::new();
hasher.update(key1);
hasher.update(key2);
hasher.finalize().to_vec() // ❌ This is NOT Diffie-Hellman!
```

**After (FIXED):**

```rust
// crypto.rs - Real X25519 scalar multiplication
let secret = X25519StaticSecret::from(private_bytes);
let public = X25519PublicKey::from(public_bytes);
secret.diffie_hellman(&public) // ✅ Real elliptic curve DH
```

### 2. Real Ed25519 Signatures

**Before (BROKEN):**

```rust
// crypto.rs - Fake signature using HMAC
pub(crate) fn simple_sign(private_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    hasher.update(data);
    hasher.finalize().to_vec() // ❌ Not a real signature!
}
```

**After (FIXED):**

```rust
// crypto.rs - Real Ed25519 signatures
let signing_key = SigningKey::from_bytes(&key_bytes);
let signature: Signature = signing_key.sign(&data_bytes);
// ✅ Real elliptic curve signature
```

### 3. No Information Leakage

**Before (CRITICAL VULNERABILITY):**

```rust
// x3dh.rs - Logging all secrets!
log(&format!("Alice DH1: {:?}", hex::encode(&dh1)));
log(&format!("Alice shared secret: {}", hex::encode(&shared_secret)));
// ❌ All cryptographic secrets exposed in logs!
```

**After (FIXED):**

```rust
// x3dh.rs - Only operational logging
// SECURITY: Never log DH results - they are cryptographic secrets
log("X3DH initiation completed successfully");
// ✅ No sensitive data in logs
```

### 4. Production-Ready Crypto Libraries

**Before:**

- Custom "simplified" implementations
- Educational-only code
- Zero security

**After:**

- `x25519-dalek 2.0` - Audited X25519 implementation
- `ed25519-dalek 2.0` - Audited Ed25519 implementation
- `curve25519-dalek 4.0` - Industry-standard ECC
- `subtle 2.5` - Constant-time operations

---

## Verification Steps

### 1. Check Current WASM Status

```bash
npm run status:wasm
```

Expected output:

```
📊 WASM Status:
-rw-rw-r-- 1 user user 96K Jan XX XX:XX pkg/signal_protocol_wasm_bg.wasm

📅 Last modified:
2025-10-29 15:19:30 (or newer after rebuild)
```

### 2. Verify Security Fixes

```bash
npm run info:security-changes
```

### 3. Validate Rust Code

```bash
npm run check:crypto-implementation
```

Expected: `✅ Rust crypto implementation valid`

### 4. Build and Validate

```bash
npm run build:wasm:with-security-fixes
```

Expected:

```
🔐 Building WASM with security fixes (real X25519, Ed25519)...
[info]: Checking for the Wasm target...
[info]: Compiling to Wasm...
   Compiling signal-protocol-wasm v0.1.0
    Finished `release` profile [optimized] target(s) in X.XXs
✅ Production WASM built
✅ WASM file exists
```

---

## p2p Integration

### How p2p Consumes WASM (Updated for Module Federation)

The p2p application should now load Signal Protocol WASM from the federated module:

```typescript
// Updated approach using module federation
const wasmBindings = await import("signal_protocol/WasmBindings");
const signalWasmModule = await wasmBindings.loadWasmModule();
```

**Module Federation Path:**

```
p2p imports "signal_protocol/WasmBindings"
  ↓
Resolves to: http://localhost:8084/remoteEntry.js (or production URL)
  ↓
Loads: signal_protocol's pkg/signal_protocol_wasm.js
  ↓
Initializes: signal_protocol_wasm_bg.wasm
```

**Note:** Ensure the `signal_protocol` remote is configured in p2p's webpack config.

### Update p2p to Use Fixed WASM

**Option 1: Automatic Deploy**

```bash
cd /path/to/cryptography
npm run deploy:p2p
```

**Option 2: Manual Deploy**

```bash
cd /path/to/cryptography
npm run build:wasm:production
cp -r pkg/* ../p2p/node_modules/cryptography/pkg/
```

**Option 3: Update via npm/module federation**

- Publish fixed cryptography package
- Update p2p's package.json dependency
- Run `npm install` in p2p

### Verify p2p Has Updated WASM

```bash
cd ../p2p
ls -lh node_modules/cryptography/pkg/signal_protocol_wasm_bg.wasm
stat node_modules/cryptography/pkg/signal_protocol_wasm_bg.wasm
```

The timestamp should match your rebuild time.

---

## Build Performance

### Expected Build Times

| Build Type                             | Time     | Size   |
| -------------------------------------- | -------- | ------ |
| Development (`build:wasm:dev`)         | ~15-30s  | ~150KB |
| Production (`build:wasm:production`)   | ~30-60s  | ~95KB  |
| All targets (`build:wasm:all-targets`) | ~90-180s | -      |

### Build Size Comparison

```bash
npm run validate:wasm:size
```

**Before fixes:** ~80KB
**After fixes:** ~95KB (+19% due to real crypto libraries)

The size increase is acceptable for production-grade security.

---

## Troubleshooting

### Build Fails: "cargo not found"

```bash
npm run install-rust
source $HOME/.cargo/env
```

### Build Fails: "wasm-pack not found"

```bash
npm run install-wasm-pack
```

### Build Fails: "error: linker `rust-lld` not found"

```bash
rustup target add wasm32-unknown-unknown
```

### p2p Still Uses Old WASM

1. Clear p2p's node_modules: `rm -rf ../p2p/node_modules/cryptography`
2. Reinstall: `cd ../p2p && npm install`
3. Or manual copy: `npm run deploy:p2p`

### Verify Crypto Libraries Loaded

Check Cargo.lock for:

```
x25519-dalek 2.0
ed25519-dalek 2.0
curve25519-dalek 4.0
```

---

## Development Workflow

### Making Crypto Changes (Updated for Module Federation)

**Note:** Signal Protocol Rust source code is now in the `signal-protocol` repository.

1. **Edit Rust source** in `../signal-protocol/src/rust/*.rs`
2. **Build WASM in signal-protocol repo:**
   ```bash
   cd ../signal-protocol
   npm run build:wasm:production
   ```
3. **Start signal-protocol dev server:**
   ```bash
   npm run start:webpack  # Runs on port 8084
   ```
4. **Test in cryptography Storybook:**
   ```bash
   cd ../cryptography
   npm start  # Storybook will load from signal_protocol remote
   ```
5. **Hot reloading:** Changes in signal-protocol will automatically reload in cryptography via module federation

### Watch Mode (Auto-rebuild)

Install cargo-watch:

```bash
cargo install cargo-watch
```

Run watch mode:

```bash
npm run watch:rust
```

This will auto-rebuild when Rust files change (but note: this builds native, not WASM).

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build WASM
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown

      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

      - name: Build WASM
        run: npm run build:wasm:production

      - name: Validate WASM
        run: npm run validate:wasm

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: wasm-build
          path: pkg/
```

---

## Security Audit Summary

**Audit Date:** January 2025
**Status:** CRITICAL vulnerabilities fixed in Rust source
**Action Required:** Rebuild WASM to deploy fixes

### Risk Assessment

| Component           | Before Fix                       | After Fix               |
| ------------------- | -------------------------------- | ----------------------- |
| Key Generation      | 🔴 CRITICAL (fake crypto)        | 🟢 SECURE (real X25519) |
| ECDH                | 🔴 CRITICAL (broken)             | 🟢 SECURE (real DH)     |
| Signatures          | 🔴 CRITICAL (forgeable)          | 🟢 SECURE (Ed25519)     |
| Information Leakage | 🔴 CRITICAL (all secrets logged) | 🟢 SECURE (no leakage)  |
| **Overall**         | 🔴 **SEVERE RISK**               | 🟢 **PRODUCTION READY** |

**Full audit report:** `../website/docs/research/signal-protocol-security-audit/README.md`

---

## Next Steps

1. **Rebuild WASM immediately:**

   ```bash
   npm run build:wasm:with-security-fixes
   ```

2. **Deploy to p2p:**

   ```bash
   npm run deploy:p2p
   ```

3. **Verify in p2p:**

   - Restart p2p dev server
   - Test message encryption/decryption
   - Check browser console for WASM load success

4. **Update production deployment**
   - Build production version of p2p
   - Deploy with updated WASM
   - Verify cryptographic operations work

---

## Additional Resources

- **Security Audit:** `docs/research/signal-protocol-security-audit/README.md`
- **Signal Protocol Spec:** https://signal.org/docs/
- **wasm-pack Documentation:** https://rustwasm.github.io/docs/wasm-pack/
- **Dalek Cryptography:** https://github.com/dalek-cryptography

---

**Last Updated:** January 2025
**WASM Version:** 0.1.0
**Rust Toolchain:** stable
**Security Status:** ✅ **Fixed (awaiting WASM rebuild)**
