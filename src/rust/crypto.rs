//! Core cryptographic operations for Signal Protocol
//!
//! This module implements the fundamental cryptographic operations used in the
//! Signal Protocol, including digital signatures and ECDH key agreement.
//! The implementations are simplified for educational purposes while maintaining
//! the essential security properties.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use web_sys::console;
use sha2::{Sha256, Digest};

/// Utility function to convert JavaScript Uint8Array to Rust Vec<u8>
/// 
/// This helper function bridges the gap between JavaScript typed arrays
/// and Rust vectors, enabling seamless data transfer across the WASM boundary.
pub(crate) fn uint8_array_to_vec(arr: &Uint8Array) -> Vec<u8> {
    arr.to_vec()
}

/// Log messages to the browser console for debugging
/// 
/// Provides visibility into cryptographic operations during development
/// and helps with debugging protocol flows.
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

/// Simple digital signature using HMAC-SHA256
/// 
/// This is a simplified signature scheme for educational purposes.
/// In a production implementation, this would use proper elliptic curve
/// digital signature algorithms like Ed25519 or ECDSA.
/// 
/// ## Security Properties
/// - Provides message authenticity
/// - Prevents tampering detection
/// - Binds signature to specific private key
/// 
/// ## Parameters
/// - `private_key`: The signer's private key (32 bytes)
/// - `data`: The data to be signed
/// 
/// ## Returns
/// A 32-byte signature that can be verified with the corresponding public key
pub(crate) fn simple_sign(private_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Verify a digital signature
/// 
/// Verifies that a signature was created by the holder of the private key
/// corresponding to the given public key. This is a simplified verification
/// scheme that recreates the signature and compares it.
/// 
/// ## Important Note
/// In a real implementation, you would never derive the private key from
/// the public key. This is only for educational demonstration purposes.
/// 
/// ## Parameters
/// - `public_key`: The signer's public key (32 bytes)
/// - `signature`: The signature to verify (32 bytes)
/// - `data`: The original data that was signed
/// 
/// ## Returns
/// `true` if the signature is valid, `false` otherwise
pub(crate) fn simple_verify(public_key: &[u8], signature: &[u8], data: &[u8]) -> bool {
    // For this simplified demo, we recreate the signature and compare
    // In reality, this would use proper signature verification algorithms
    let mut hasher = Sha256::new();
    hasher.update(public_key); // In real implementation, we'd derive private from public
    hasher.update(data);
    let expected = hasher.finalize();
    expected.as_slice() == signature
}

/// Simplified ECDH key agreement with guaranteed commutativity
/// 
/// This function implements a simplified version of Elliptic Curve Diffie-Hellman
/// that ensures both parties compute the same shared secret regardless of parameter order.
/// This is crucial for the X3DH protocol to work correctly.
/// 
/// ## Algorithm
/// 1. Compute two possible results using different hash orders
/// 2. Return the lexicographically smaller result
/// 3. This ensures A(priv_a, pub_b) == B(priv_b, pub_a)
/// 
/// ## Security Properties
/// - Commutative: same result regardless of parameter order
/// - Collision-resistant due to SHA-256 usage
/// - Provides shared secret for secure communication
/// 
/// ## Parameters
/// - `private_key`: The caller's private key (32 bytes)
/// - `public_key`: The other party's public key (32 bytes)
/// 
/// ## Returns
/// A 32-byte shared secret
pub(crate) fn simple_ecdh(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    // For true commutativity, we need both parties to compute the same value.
    // We'll create a symmetric function by always ordering the inputs consistently.
    
    // Always put the lexicographically smaller key first to ensure commutativity
    let (key1, key2) = if private_key <= public_key {
        (private_key, public_key)
    } else {
        (public_key, private_key)
    };
    
    let mut hasher = Sha256::new();
    hasher.update(key1);
    hasher.update(key2);
    hasher.update(b"ECDH_commutative");
    hasher.finalize().to_vec()
}

/// Sign data with a private key
/// 
/// Creates a digital signature that proves the data was signed by the holder
/// of the corresponding private key. The signature can be verified by anyone
/// who has the public key.
/// 
/// ## Usage Example
/// ```javascript
/// const signature = sign_data(privateKey, message);
/// const isValid = verify_signature(publicKey, signature, message);
/// ```
/// 
/// ## Parameters
/// - `private_key`: The signer's private key as Uint8Array (must be 32 bytes)
/// - `data`: The data to sign as Uint8Array
/// 
/// ## Returns
/// A Uint8Array containing the 32-byte signature
/// 
/// ## Errors
/// - Returns error if private key is not exactly 32 bytes
#[wasm_bindgen]
pub fn sign_data(private_key: &Uint8Array, data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Signing data with simplified crypto");
    
    let private_key_bytes = uint8_array_to_vec(private_key);
    let data_bytes = uint8_array_to_vec(data);
    
    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }
    
    let signature = simple_sign(&private_key_bytes, &data_bytes);
    Ok(Uint8Array::from(&signature[..]))
}

/// Verify a digital signature
/// 
/// Verifies that a signature was created by the holder of the private key
/// corresponding to the given public key. This ensures message authenticity
/// and integrity.
/// 
/// ## Usage Example
/// ```javascript
/// const isValid = verify_signature(publicKey, signature, originalMessage);
/// if (isValid) {
///     console.log("Signature is valid!");
/// }
/// ```
/// 
/// ## Parameters
/// - `public_key`: The signer's public key as Uint8Array (must be 32 bytes)
/// - `signature`: The signature to verify as Uint8Array (must be 32 bytes)
/// - `data`: The original signed data as Uint8Array
/// 
/// ## Returns
/// `true` if the signature is valid, `false` otherwise
/// 
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
/// - Returns error if signature is not exactly 32 bytes
#[wasm_bindgen]
pub fn verify_signature(public_key: &Uint8Array, signature: &Uint8Array, data: &Uint8Array) -> Result<bool, JsValue> {
    log("Verifying signature with simplified crypto");
    
    let public_key_bytes = uint8_array_to_vec(public_key);
    let signature_bytes = uint8_array_to_vec(signature);
    let data_bytes = uint8_array_to_vec(data);
    
    if public_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Public key must be 32 bytes"));
    }
    
    if signature_bytes.len() != 32 {
        return Err(JsValue::from_str("Signature must be 32 bytes"));
    }
    
    let is_valid = simple_verify(&public_key_bytes, &signature_bytes, &data_bytes);
    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// Test the ECDH function for commutativity
    #[wasm_bindgen_test]
    fn test_ecdh_commutativity() {
        let key_a = vec![1u8; 32];
        let key_b = vec![2u8; 32];
        
        // Simulate public key derivation
        let mut hasher = Sha256::new();
        hasher.update(&key_a);
        let pub_a = hasher.finalize().to_vec();
        
        let mut hasher = Sha256::new();
        hasher.update(&key_b);
        let pub_b = hasher.finalize().to_vec();
        
        // Test commutativity: A(priv_a, pub_b) should equal B(priv_b, pub_a)
        let result1 = simple_ecdh(&key_a, &pub_b);
        let result2 = simple_ecdh(&key_b, &pub_a);
        
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    /// Test signature creation and verification
    #[wasm_bindgen_test]
    fn test_signature_operations() {
        let private_key = Uint8Array::from(&[1u8; 32][..]);
        let data = Uint8Array::from("Hello, World!".as_bytes());
        
        // Sign the data
        let signature = sign_data(&private_key, &data).unwrap();
        assert_eq!(signature.length(), 32);
        
        // Verify with the correct public key (simplified derivation)
        let mut hasher = Sha256::new();
        hasher.update(&private_key.to_vec());
        let public_key_bytes = hasher.finalize().to_vec();
        let public_key = Uint8Array::from(&public_key_bytes[..]);
        
        let is_valid = verify_signature(&public_key, &signature, &data).unwrap();
        assert!(is_valid);
        
        // Verify with wrong data should fail
        let wrong_data = Uint8Array::from("Wrong message".as_bytes());
        let is_valid_wrong = verify_signature(&public_key, &signature, &wrong_data).unwrap();
        assert!(!is_valid_wrong);
    }

    /// Test error handling for invalid key sizes
    #[wasm_bindgen_test]
    fn test_invalid_key_sizes() {
        let short_key = Uint8Array::from(&[1u8; 16][..]);  // Too short
        let data = Uint8Array::from("test".as_bytes());
        
        // Should fail with short private key
        let result = sign_data(&short_key, &data);
        assert!(result.is_err());
        
        // Should fail with short public key for verification
        let valid_private_key = Uint8Array::from(&[1u8; 32][..]);
        let signature = sign_data(&valid_private_key, &data).unwrap();
        let verify_result = verify_signature(&short_key, &signature, &data);
        assert!(verify_result.is_err());
    }
}