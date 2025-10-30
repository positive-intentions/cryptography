# Test Quick Reference Card

## Essential Test Commands

### 🔐 Security Tests (Run Before Committing)
```bash
npm run test:all:security
```
Tests X25519 ECDH, Ed25519 signatures, X3DH

### 🧪 All Tests
```bash
npm run test:all
```
Rust + JavaScript tests

### ⚡ Quick Tests (Fast)
```bash
npm run test:rust:quick
```
Quiet mode for rapid feedback

---

## Component-Specific

| Command | What It Tests |
|---------|---------------|
| `npm run test:rust:crypto` | **X25519 ECDH + Ed25519 signatures** |
| `npm run test:rust:keys` | Key generation (X25519) |
| `npm run test:rust:x3dh` | X3DH key exchange |
| `npm run test:rust:messages` | Message encryption/decryption |

---

## Full Test Suites

### Crypto Suite
```bash
npm run test:suite:crypto
```
All cryptographic primitive tests

### Full Suite
```bash
npm run test:suite:full
```
Everything (Rust + WASM + JS)

---

## WASM Testing

```bash
npm run test:wasm:node     # Node.js environment
npm run test:wasm          # Chrome headless
npm run test:wasm:browser  # Chrome with DevTools
```

---

## After Changes

### 1. Changed crypto code
```bash
npm run test:rust:security
npm run test:rust:all
```

### 2. Before building WASM
```bash
npm run test:rust
npm run build:wasm:quick
npm run test:wasm:node
```

### 3. Before commit
```bash
npm run test:ci
```

---

## Debugging

### Verbose output
```bash
npm run test:rust:verbose
```

### Single test
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --lib test_name -- --nocapture
```

---

## Coverage

```bash
npm run test:rust:coverage
# Opens: coverage-rust/index.html
```

---

**See TESTING_GUIDE.md for full documentation**
