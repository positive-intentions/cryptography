# WASM Build Quick Reference

## 🚨 **CRITICAL: Current WASM is BROKEN!**

The p2p app uses WASM built **BEFORE** security fixes were applied.

**Rebuild immediately:** `npm run build:wasm:with-security-fixes`

---

## Essential Commands

### Build WASM with Security Fixes
```bash
npm run build:wasm:with-security-fixes
```
Builds production WASM with real X25519, Ed25519, no logging.

### Deploy to p2p
```bash
npm run deploy:p2p
```
Builds and copies WASM to `../p2p/node_modules/cryptography/pkg/`

### Check Status
```bash
npm run status:wasm
```
Shows WASM file size and last modified date.

---

## Common Workflows

### After Editing Rust Code
```bash
npm run check:crypto-implementation  # Validate syntax
npm run build:wasm:with-security-fixes  # Build WASM
npm run deploy:p2p  # Deploy to p2p
```

### Quick Development Build
```bash
npm run build:wasm:quick
```

### View Security Changes
```bash
npm run info:security-changes
```

---

## What Was Fixed?

| Component | Before | After |
|-----------|--------|-------|
| **ECDH** | Fake SHA-256 hash | Real X25519 curve25519 |
| **Signatures** | HMAC (forgeable) | Ed25519 (unforgeable) |
| **Logging** | All secrets logged | No secret logging |
| **Security** | 🔴 ZERO | 🟢 128-bit |

---

## Verification

### 1. Rebuild
```bash
npm run build:wasm:with-security-fixes
```

### 2. Check File
```bash
ls -lh pkg/signal_protocol_wasm_bg.wasm
```
Should show recent timestamp (~95KB)

### 3. Deploy
```bash
npm run deploy:p2p
```

### 4. Test in p2p
```bash
cd ../p2p
npm start
# Open browser, test messaging
```

---

## Build Scripts Reference

| Script | Purpose |
|--------|---------|
| `build:wasm:with-security-fixes` | **Production build + validate** |
| `build:wasm:production` | Production build (optimized) |
| `build:wasm:quick` | Fast development build |
| `build:wasm:dev` | Development build (faster) |
| `build:wasm:all-targets` | Build web, node, bundler |
| `deploy:p2p` | Build + copy to p2p |
| `status:wasm` | Show WASM info |
| `validate:wasm` | Check WASM exists |
| `check:crypto-implementation` | Validate Rust code |
| `info:security-changes` | Show what was fixed |

---

## Troubleshooting

### "cargo not found"
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### "wasm-pack not found"
```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

### "p2p still uses old WASM"
```bash
rm -rf ../p2p/node_modules/cryptography
cd ../p2p && npm install
```

---

**For detailed documentation, see:** `WASM_BUILD_GUIDE.md`
