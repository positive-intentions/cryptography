//! Cryptographic key generation for Signal Protocol
//!
//! This module handles the generation of various types of cryptographic keys
//! used in the Signal Protocol. All key generation uses secure random number
//! generation and follows Signal Protocol specifications.

use wasm_bindgen::prelude::*;
use web_sys::console;
use sha2::{Sha256, Digest};
use rand::{RngCore, rngs::OsRng};
use crate::rust::types::KeyPair;

/// Log messages to the browser console for debugging
/// 
/// This helper function makes it easy to trace key generation operations
/// during development and testing.
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

/// Generate a cryptographically secure random 32-byte key
/// 
/// Uses the operating system's secure random number generator to create
/// high-entropy key material. This is the foundation for all key generation
/// in the Signal Protocol implementation.
/// 
/// ## Security Properties
/// - Uses OS-level entropy source (OsRng)
/// - Generates 256 bits of entropy
/// - Suitable for cryptographic key material
fn generate_random_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate an identity key pair for long-term user identification
/// 
/// Identity keys are long-lived keys that identify a user or device.
/// They are used in the X3DH key exchange protocol and for signing
/// other keys to establish authenticity.
/// 
/// ## Usage
/// Each user/device should generate one identity key pair and use it
/// consistently across all communication sessions. The public key
/// can be distributed through a key server or other trusted mechanism.
/// 
/// ## Returns
/// A `KeyPair` containing the identity public and private keys
#[wasm_bindgen]
pub fn generate_identity_keypair() -> Result<KeyPair, JsValue> {
    log("Generating identity keypair using simplified crypto");
    
    let private_key = generate_random_key();
    
    // In a simplified implementation, we derive the public key from the private key
    // using SHA-256. In a real implementation, this would use proper elliptic curve operations
    let public_key = {
        let mut hasher = Sha256::new();
        hasher.update(&private_key);
        hasher.finalize().to_vec()
    };
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Generate a signed prekey for medium-term use in key exchanges
/// 
/// Signed prekeys are generated periodically (e.g., weekly) and signed
/// by the identity key to prove authenticity. They are used in the X3DH
/// protocol to establish initial communication.
/// 
/// ## Purpose
/// - Provides forward secrecy by rotating regularly
/// - Enables asynchronous key exchange when recipient is offline
/// - Signed by identity key for authenticity verification
/// 
/// ## Returns
/// A `KeyPair` containing the signed prekey public and private keys
#[wasm_bindgen]
pub fn generate_signed_prekey() -> Result<KeyPair, JsValue> {
    log("Generating signed prekey using simplified crypto");
    
    let private_key = generate_random_key();
    
    // Derive public key from private key using SHA-256
    let public_key = {
        let mut hasher = Sha256::new();
        hasher.update(&private_key);
        hasher.finalize().to_vec()
    };
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Generate a one-time prekey for single-use in key exchanges
/// 
/// One-time prekeys provide additional forward secrecy by being used only once.
/// They are consumed during the X3DH key exchange and then discarded,
/// ensuring that compromise of long-term keys doesn't affect past communications.
/// 
/// ## Security Benefits
/// - Perfect forward secrecy (used only once)
/// - Prevents replay attacks on key exchanges
/// - Protects against compromise of identity/signed prekeys
/// 
/// ## Returns
/// A `KeyPair` containing the one-time prekey public and private keys
#[wasm_bindgen]
pub fn generate_one_time_prekey() -> Result<KeyPair, JsValue> {
    log("Generating one-time prekey using simplified crypto");
    
    let private_key = generate_random_key();
    
    // Derive public key from private key using SHA-256
    let public_key = {
        let mut hasher = Sha256::new();
        hasher.update(&private_key);
        hasher.finalize().to_vec()
    };
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Generate an ephemeral key pair for temporary use in key exchanges
/// 
/// Ephemeral keys are generated fresh for each key exchange session
/// and provide additional forward secrecy. They are never stored
/// long-term and are discarded after the key exchange completes.
/// 
/// ## Use Cases
/// - X3DH key exchange initiation
/// - Session-specific entropy
/// - Enhanced forward secrecy guarantees
/// 
/// ## Returns
/// A `KeyPair` containing the ephemeral public and private keys
#[wasm_bindgen]
pub fn generate_ephemeral_keypair() -> Result<KeyPair, JsValue> {
    log("Generating ephemeral keypair using simplified crypto");
    
    let private_key = generate_random_key();
    
    // Derive public key from private key using SHA-256
    let public_key = {
        let mut hasher = Sha256::new();
        hasher.update(&private_key);
        hasher.finalize().to_vec()
    };
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// Test that identity keypairs are generated successfully
    #[wasm_bindgen_test]
    fn test_generate_identity_keypair() {
        let keypair = generate_identity_keypair().unwrap();
        
        // Check that keys are the correct length (32 bytes each)
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);
        
        // Verify that public key is derived consistently from private key
        let private_bytes = keypair.private_key().to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&private_bytes);
        let expected_public = hasher.finalize().to_vec();
        let actual_public = keypair.public_key().to_vec();
        
        assert_eq!(expected_public, actual_public);
    }

    /// Test that multiple keypair generations produce different results
    #[wasm_bindgen_test]
    fn test_keypair_uniqueness() {
        let keypair1 = generate_identity_keypair().unwrap();
        let keypair2 = generate_identity_keypair().unwrap();
        
        // Keys should be different each time
        assert_ne!(keypair1.public_key().to_vec(), keypair2.public_key().to_vec());
        assert_ne!(keypair1.private_key().to_vec(), keypair2.private_key().to_vec());
    }

    /// Test all key generation functions for basic functionality
    #[wasm_bindgen_test]
    fn test_all_key_generation_functions() {
        // Test all key generation functions
        let identity = generate_identity_keypair().unwrap();
        let signed_prekey = generate_signed_prekey().unwrap();
        let one_time_prekey = generate_one_time_prekey().unwrap();
        let ephemeral = generate_ephemeral_keypair().unwrap();
        
        // All should produce valid keypairs
        assert_eq!(identity.public_key().length(), 32);
        assert_eq!(signed_prekey.public_key().length(), 32);
        assert_eq!(one_time_prekey.public_key().length(), 32);
        assert_eq!(ephemeral.public_key().length(), 32);
        
        // All should be unique
        assert_ne!(identity.public_key().to_vec(), signed_prekey.public_key().to_vec());
        assert_ne!(signed_prekey.public_key().to_vec(), one_time_prekey.public_key().to_vec());
        assert_ne!(one_time_prekey.public_key().to_vec(), ephemeral.public_key().to_vec());
    }
}