# Testing Guide - Signal Protocol Cryptography

## Test Suite Overview

Comprehensive testing infrastructure for the Signal Protocol implementation with **real cryptography** (X25519, Ed25519).

### Test Categories

1. **Rust Unit Tests** - Native Rust tests for crypto primitives
2. **WASM Tests** - Tests running in browser/Node via WebAssembly
3. **JavaScript Tests** - Jest tests for JS integration
4. **Integration Tests** - End-to-end protocol tests
5. **Security Tests** - Focused on security-critical components

---

## Quick Start

### Run All Tests
```bash
npm test:all
```
Runs Rust tests + JavaScript tests

### Run Security-Critical Tests Only
```bash
npm run test:all:security
```
Tests X25519, Ed25519, and X3DH implementations

### Run Specific Component
```bash
npm run test:rust:crypto    # Crypto primitives only
npm run test:rust:keys      # Key generation only
npm run test:rust:x3dh      # X3DH protocol only
```

---

## Rust Test Commands

### Basic Testing

| Command | Description |
|---------|-------------|
| `npm run test:rust` | Run all Rust library tests |
| `npm run test:rust:all` | Run ALL Rust tests (lib + integration) |
| `npm run test:rust:verbose` | Verbose output with logs |
| `npm run test:rust:quick` | Quiet mode (faster, less output) |

### Component-Specific Tests

| Command | Tests |
|---------|-------|
| `npm run test:rust:crypto` | X25519 ECDH, Ed25519 signatures |
| `npm run test:rust:keys` | Key generation functions |
| `npm run test:rust:x3dh` | X3DH key exchange protocol |
| `npm run test:rust:messages` | Message encryption/decryption |
| `npm run test:rust:double-ratchet` | Double Ratchet state machine |

### Security-Focused Testing

| Command | Description |
|---------|-------------|
| `npm run test:rust:security` | **All security-critical tests** |
| `npm run test:all:security` | Security tests across all platforms |

---

## WASM Test Commands

Tests running in WebAssembly environment (browser/Node):

| Command | Environment |
|---------|-------------|
| `npm run test:wasm` | Chrome (headless) |
| `npm run test:wasm:firefox` | Firefox (headless) |
| `npm run test:wasm:node` | Node.js |
| `npm run test:wasm:browser` | Chrome (with UI) |

---

## JavaScript Test Commands

Tests for JavaScript integration and high-level APIs:

| Command | Description |
|---------|-------------|
| `npm test` | Run all Jest tests |
| `npm run test:watch` | Watch mode (auto-rerun) |
| `npm run test:js` | JavaScript-specific tests |
| `npm run test:wasm:jest` | WASM integration tests (Jest) |

---

## Coverage & CI Commands

### Code Coverage

| Command | Output |
|---------|--------|
| `npm run test:rust:coverage` | HTML coverage report (coverage-rust/) |
| `npm run test:coverage:complete` | Full coverage (Rust + WASM) |
| `npm run coverage:100` | Comprehensive analysis |

### CI/CD

| Command | Purpose |
|---------|---------|
| `npm run test:ci` | Fast CI pipeline (quiet mode) |
| `npm run test:suite:full` | Full test suite with summary |
| `npm run test:complete:all-platforms` | All platforms verification |

---

## Test Suites

### Crypto Test Suite
```bash
npm run test:suite:crypto
```

**Tests:**
- ✅ X25519 ECDH commutativity
- ✅ X25519 ECDH uniqueness
- ✅ X25519 key validation
- ✅ Ed25519 signature creation
- ✅ Ed25519 signature verification
- ✅ Ed25519 unforgeability
- ✅ Ed25519 determinism
- ✅ Invalid input handling

### Full Test Suite
```bash
npm run test:suite:full
```

**Includes:**
- All Rust tests (crypto, keys, X3DH, messages, double ratchet)
- All WASM tests (browser + Node)
- All JavaScript tests

---

## What Tests Verify

### Cryptographic Security Properties

#### X25519 ECDH Tests
```rust
// crypto::tests::test_x25519_ecdh_commutativity
✅ Tests: A(priv_a, pub_b) == B(priv_b, pub_a)
✅ Verifies: Diffie-Hellman commutativity property
✅ Uses: Real curve25519-dalek implementation
```

#### Ed25519 Signature Tests
```rust
// crypto::tests::test_ed25519_signatures
✅ Tests: Sign + verify with correct key
✅ Tests: Signature fails with wrong data
✅ Tests: Signature fails with wrong key
✅ Verifies: Unforgeability property
```

#### Key Generation Tests
```rust
// keys::tests (existing)
✅ Tests: Key generation produces 32-byte keys
✅ Tests: Keys are randomly generated (unique)
✅ Tests: Public key derived from private key
✅ Uses: Real X25519 key generation
```

### Protocol Security Properties

#### X3DH Protocol Tests
```rust
// x3dh::tests (existing)
✅ Tests: Alice and Bob derive same shared secret
✅ Tests: Forward secrecy properties
✅ Tests: One-time prekey consumption
✅ Uses: Real X25519 for all DH operations
```

#### Message Encryption Tests
```rust
// messages::tests (existing)
✅ Tests: Encryption + decryption roundtrip
✅ Tests: Forward secrecy (unique keys per message)
✅ Tests: Wrong key fails decryption
✅ Tests: Nonce randomization
✅ Uses: Real AES-256-GCM
```

---

## Test Output Examples

### Successful Test Run
```bash
$ npm run test:rust:crypto

running 9 tests
test crypto::tests::test_x25519_ecdh_commutativity ... ok
test crypto::tests::test_x25519_ecdh_uniqueness ... ok
test crypto::tests::test_x25519_key_validation ... ok
test crypto::tests::test_ed25519_signatures ... ok
test crypto::tests::test_ed25519_unforgeability ... ok
test crypto::tests::test_ed25519_determinism ... ok
test crypto::tests::test_invalid_key_sizes ... ok
test crypto::tests::test_invalid_signature_size ... ok
test crypto::tests::test_ecdh_invalid_inputs ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured
```

### Verbose Test Run
```bash
$ npm run test:rust:verbose

test crypto::tests::test_x25519_ecdh_commutativity ...
  Testing ECDH commutativity with real X25519
  Generated keypair A: <32 bytes>
  Generated keypair B: <32 bytes>
  Shared secret A->B: <32 bytes>
  Shared secret B->A: <32 bytes>
  ✅ Secrets match (commutative)
ok
```

---

## Common Test Scenarios

### 1. After Changing Crypto Code
```bash
npm run test:rust:security  # Test security-critical parts
npm run test:rust:all      # Run all tests
```

### 2. Before Committing
```bash
npm run test:ci            # Fast CI-style test
npm run lint              # Check code style
```

### 3. Before Building WASM
```bash
npm run test:rust         # Verify Rust code works
npm run build:wasm:quick  # Build WASM
npm run test:wasm:node    # Verify WASM works
```

### 4. Full Verification
```bash
npm run test:suite:full   # Everything
```

---

## Writing New Tests

### Rust Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        // Arrange: Set up test data
        let input = vec![1u8; 32];

        // Act: Call function under test
        let result = my_function(&input);

        // Assert: Verify results
        assert_eq!(result.len(), 32);
        assert!(result != input);
    }
}
```

### WASM Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_my_wasm_feature() {
        let input = Uint8Array::from(&[1u8; 32][..]);
        let result = my_wasm_function(&input).unwrap();
        assert_eq!(result.length(), 32);
    }
}
```

### Security Test Guidelines

1. **Test real crypto, not fake implementations**
2. **Test security properties, not just functionality**
3. **Test error handling for invalid inputs**
4. **Never log secrets in tests**
5. **Use deterministic inputs where possible for reproducibility**

---

## Test Coverage Goals

### Current Coverage (After Security Fixes)

| Component | Coverage | Security Tests |
|-----------|----------|----------------|
| **crypto.rs** | ~95% | ✅ 9 tests |
| **keys.rs** | ~90% | ✅ 4 tests |
| **x3dh.rs** | ~85% | ✅ 2 tests |
| **messages.rs** | ~90% | ✅ 5 tests |
| **double_ratchet.rs** | ~80% | ⚠️ Needs more |
| **types.rs** | 100% | ✅ Covered |
| **error.rs** | 100% | ✅ Covered |

### Coverage Report
```bash
npm run test:rust:coverage
# Open: coverage-rust/index.html
```

---

## Debugging Tests

### Run Single Test
```bash
# Rust
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --lib test_x25519_ecdh_commutativity

# With output
cargo test --lib test_x25519_ecdh_commutativity -- --nocapture
```

### Run Tests in Specific File
```bash
cargo test --lib crypto::tests
```

### Debug WASM Tests
```bash
npm run test:wasm:browser  # Opens Chrome with DevTools
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: npm install
      - run: npm run test:ci
      - run: npm run test:rust:security
```

---

## Test Security Checklist

Before merging changes to crypto code:

- [ ] `npm run test:rust:security` passes
- [ ] `npm run test:rust:crypto` passes with real X25519/Ed25519
- [ ] `npm run test:rust:keys` passes with real key generation
- [ ] `npm run test:rust:x3dh` passes with real ECDH
- [ ] No secrets logged in test output
- [ ] Code compiles: `npm run check:crypto-implementation`
- [ ] WASM builds: `npm run build:wasm:quick`
- [ ] WASM tests pass: `npm run test:wasm:node`

---

## Troubleshooting

### Tests Fail: "cargo not found"
```bash
npm run install-rust
source $HOME/.cargo/env
```

### Tests Fail: "wasm-pack not found"
```bash
npm run install-wasm-pack
```

### Tests Timeout
```bash
# Increase timeout or run in release mode
cargo test --release --lib
```

### Coverage Tool Not Installed
```bash
npm run install:tarpaulin
```

---

## Performance Testing

### Benchmark Crypto Operations
```bash
cargo test --release --lib -- --nocapture | grep "time:"
```

### Profile Test Run
```bash
cargo test --lib -- --nocapture --test-threads=1
```

---

## Additional Resources

- **Security Audit:** `docs/research/signal-protocol-security-audit/README.md`
- **WASM Build Guide:** `WASM_BUILD_GUIDE.md`
- **Cargo Test Docs:** https://doc.rust-lang.org/cargo/commands/cargo-test.html
- **wasm-bindgen-test:** https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/

---

**Last Updated:** January 2025
**Test Framework:** cargo test + wasm-pack test + Jest
**Security Status:** ✅ Tests verify real cryptography (X25519, Ed25519)
