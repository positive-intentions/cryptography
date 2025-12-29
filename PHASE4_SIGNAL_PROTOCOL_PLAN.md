# Phase 4: Signal Protocol Module Extraction - PLAN

## Overview

Extract Signal Protocol functions from Cryptography.tsx (lines 640-1400) into modular, testable components.

## Current State

**Cryptography.tsx Signal Protocol Functions:**

- `generateSignalKeyPair()` - X25519 key pair generation
- `generateSignalSigningKeyPair()` - Ed25519 signing key pair
- `exportSignalPublicKey()` - Export public keys
- `importSignalPublicKey()` - Import public keys
- `performSignalDH()` - X3DH Diffie-Hellman
- `signSignalData()` - Ed25519 signing
- `verifySignalSignature()` - Signature verification
- `deriveSignalKey()` - HKDF key derivation
- `concatSignalArrayBuffers()` - Buffer concatenation
- `bufferToSignalHex()` - Buffer to hex conversion
- `initializeSignalUser()` - User initialization
- `getSignalPublicKeyBundle()` - Public key bundle
- `consumeSignalOneTimePrekey()` - One-time prekey management

**Double Ratchet Functions:**

- `initializeDoubleRatchet()` - Initialize ratchet state
- `encryptMessage()` - Encrypt message with Double Ratchet
- `decryptMessage()` - Decrypt message with Double Ratchet
- `deriveMessageKey()` - Derive message key from chain key
- `deriveNextChainKey()` - Derive next chain key
- `performDHRatchetStep()` - Perform DH ratchet step
- `doubleRatchetHKDF()` - HKDF for Double Ratchet
- `doubleRatchetHMAC()` - HMAC for Double Ratchet

## Extraction Strategy

### Step 1: Create Module Structure

```
src/crypto/SignalProtocol/
├── index.ts                          # Main export file
├── X3DH/                            # X3DH key exchange
│   ├── index.ts
│   ├── X3DHKeyExchange.ts       # X3DH DH operations
│   ├── KeyGeneration.ts           # Key pair generation
│   ├── Signature.ts              # Ed25519 signing/verification
│   └── types.ts                  # Type definitions
├── DoubleRatchet/                      # Double Ratchet protocol
│   ├── index.ts
│   ├── DoubleRatchet.ts           # Main ratchet implementation
│   ├── RatchetState.ts          # State management
│   ├── ChainKey.ts              # Chain key derivation
│   ├── DHRatchet.ts            # DH ratchet step
│   └── types.ts                  # Type definitions
├── Shared/                            # Shared utilities
│   ├── index.ts
│   ├── HKDF.ts                  # HKDF key derivation
│   ├── HMAC.ts                  # HMAC operations
│   ├── BufferUtils.ts           # Buffer operations
│   └── HexEncoding.ts          # Hex encoding/decoding
└── __tests__/                        # Tests
    ├── X3DH/
    ├── DoubleRatchet/
    └── Shared/
```

### Step 2: Extract X3DH Module

**Files to Create:**

1. `X3DHKeyExchange.ts` (~150 lines)

   - `performSignalDH()` - DH key derivation
   - Key exchange logic
   - Initiator/responder handling

2. `KeyGeneration.ts` (~100 lines)

   - `generateSignalKeyPair()` - X25519
   - `generateSignalSigningKeyPair()` - Ed25519
   - Error handling for specific test errors

3. `Signature.ts` (~100 lines)
   - `signSignalData()` - Ed25519 signing
   - `verifySignalSignature()` - Signature verification
   - Key import/export

### Step 3: Extract Double Ratchet Module

**Files to Create:**

1. `DoubleRatchet.ts` (~300 lines)

   - `encryptMessage()` - Full message encryption
   - `decryptMessage()` - Full message decryption
   - Message key derivation

2. `RatchetState.ts` (~150 lines)

   - State type definitions
   - State initialization
   - State update helpers

3. `ChainKey.ts` (~100 lines)

   - `deriveMessageKey()` - Message key from chain key
   - `deriveNextChainKey()` - Next chain key
   - HMAC operations

4. `DHRatchet.ts` (~200 lines)
   - `performDHRatchetStep()` - DH ratchet step
   - Key pair management
   - Shared secret derivation

### Step 4: Extract Shared Utilities

**Files to Create:**

1. `HKDF.ts` (~80 lines)

   - `doubleRatchetHKDF()` - HKDF for Double Ratchet
   - Info constants
   - Salt handling

2. `HMAC.ts` (~60 lines)

   - `doubleRatchetHMAC()` - HMAC operations
   - Info constants

3. `BufferUtils.ts` (~80 lines)

   - `concatSignalArrayBuffers()` - Buffer concatenation
   - Helper functions

4. `HexEncoding.ts` (~50 lines)
   - `bufferToSignalHex()` - Buffer to hex
   - Hex to buffer conversion

### Step 5: Create Tests

**Test Files:**

1. `X3DH/KeyGeneration.test.ts` (~300 lines)

   - Key pair generation
   - Import/export
   - Error handling

2. `X3DH/X3DHKeyExchange.test.ts` (~300 lines)

   - X3DH DH operations
   - Initiator/responder scenarios
   - Error handling

3. `DoubleRatchet/DoubleRatchet.test.ts` (~400 lines)

   - Encryption/decryption
   - Chain key derivation
   - DH ratchet steps
   - State management

4. `Shared/HKDF.test.ts` (~200 lines)

   - Key derivation
   - Salt handling
   - HKDF output validation

5. `Shared/BufferUtils.test.ts` (~150 lines)
   - Buffer concatenation
   - Hex encoding
   - Edge cases

### Step 6: Update Cryptography.tsx

**Changes:**

1. Import from new modules
2. Remove duplicate code (~500 lines)
3. Update function calls
4. Verify backward compatibility

## Complexity Analysis

**Current Implementation:**

- 640+ lines of deeply integrated code
- State management spread throughout
- Complex error handling
- Multiple responsibilities per function

**After Refactoring:**

- 2,500+ lines across 15 focused modules (~150-300 lines each)
- Single responsibility per module
- Clear interfaces between modules
- Comprehensive test coverage
- Easier to maintain and extend

## Execution Order

1. ✅ Create X3DH module + tests
2. ✅ Create Double Ratchet module + tests
3. ✅ Create Shared utilities + tests
4. ✅ Update Cryptography.tsx imports
5. ✅ Run all tests
6. ✅ Verify Storybook works

## Estimated Time

- X3DH Module: 4 hours
- Double Ratchet Module: 6 hours
- Shared Utilities: 3 hours
- Testing: 4 hours
- Integration: 2 hours

**Total: ~19 hours**

## Risk Assessment

**High Risk:**

- Complex state management may break during extraction
- Deeply integrated functions may not work in isolation
- Error handling patterns may be difficult to replicate

**Mitigation:**

- Extract incrementally
- Test each module before proceeding
- Keep original code intact until replacement is verified
- Run comprehensive integration tests

## Success Criteria

1. ✅ All modules extracted and tested
2. ✅ Cryptography.tsx updated to use new modules
3. ✅ 100% test coverage for Signal Protocol
4. ✅ Storybook stories work correctly
5. ✅ Backward compatibility maintained
6. ✅ No breaking changes to public API

---

**Status**: PLANNING - Phase 4 is most complex phase
**Next**: Start with X3DH KeyGeneration module extraction
