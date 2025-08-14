//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol
//!
//! This module implements the X3DH key agreement protocol used by Signal
//! to establish shared secrets between two parties. X3DH provides forward
//! secrecy and authentication without requiring both parties to be online
//! simultaneously.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use web_sys::console;
use sha2::Sha256;
use hkdf::Hkdf;
use crate::rust::crypto::{uint8_array_to_vec, simple_ecdh};
use crate::rust::types::X3DHResult;

/// Log messages to the browser console for debugging
/// 
/// Helps trace the X3DH protocol execution and debug issues
/// during key exchange operations.
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

/// Initiate X3DH key exchange (Alice's side)
/// 
/// This function performs the X3DH key agreement from the initiator's perspective.
/// Alice combines her keys with Bob's prekeys to compute a shared secret that
/// both parties can independently derive.
/// 
/// ## X3DH Protocol Overview
/// The X3DH protocol performs multiple Diffie-Hellman computations:
/// 1. DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
/// 2. DH2: Alice_Ephemeral_Private × Bob_Identity_Public  
/// 3. DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
/// 4. DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (optional)
/// 
/// The results are concatenated and fed into HKDF to derive the final shared secret.
/// 
/// ## Security Properties
/// - **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
/// - **Authentication**: Both parties prove their identity through key ownership
/// - **Asynchronous**: Bob doesn't need to be online during key exchange
/// - **Deniability**: No long-term proof of participation in conversations
/// 
/// ## Parameters
/// - `alice_identity_private`: Alice's long-term identity private key (32 bytes)
/// - `alice_ephemeral_private`: Alice's session-specific ephemeral private key (32 bytes)
/// - `bob_identity_public`: Bob's identity public key (32 bytes)
/// - `bob_signed_prekey_public`: Bob's signed prekey public key (32 bytes)
/// - `bob_one_time_prekey_public`: Optional one-time prekey for additional forward secrecy
/// 
/// ## Returns
/// An `X3DHResult` containing the shared secret and associated data
/// 
/// ## Example Usage
/// ```rust
/// let result = x3dh_initiate(
///     &alice_identity_private,
///     &alice_ephemeral_private,
///     &bob_identity_public,
///     &bob_signed_prekey_public,
///     Some(bob_one_time_prekey_public)
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
#[wasm_bindgen]
pub fn x3dh_initiate(
    alice_identity_private: &Uint8Array,
    alice_ephemeral_private: &Uint8Array,
    bob_identity_public: &Uint8Array,
    bob_signed_prekey_public: &Uint8Array,
    bob_one_time_prekey_public: Option<Uint8Array>,
) -> Result<X3DHResult, JsValue> {
    log("Initiating X3DH key exchange (Alice side)");
    
    // Convert JavaScript arrays to Rust vectors
    let alice_identity_private_bytes = uint8_array_to_vec(alice_identity_private);
    let alice_ephemeral_private_bytes = uint8_array_to_vec(alice_ephemeral_private);
    let bob_identity_public_bytes = uint8_array_to_vec(bob_identity_public);
    let bob_signed_prekey_public_bytes = uint8_array_to_vec(bob_signed_prekey_public);
    
    // Perform the three mandatory DH operations (X3DH protocol standard order)
    
    // DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
    // This proves Alice knows her identity key and authenticates Bob's signed prekey
    let dh1 = simple_ecdh(&alice_identity_private_bytes, &bob_signed_prekey_public_bytes);
    
    // DH2: Alice_Ephemeral_Private × Bob_Identity_Public
    // This provides forward secrecy through Alice's ephemeral key
    let dh2 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_identity_public_bytes);
    
    // DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
    // This combines ephemeral forward secrecy with Bob's medium-term key
    let dh3 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_signed_prekey_public_bytes);
    
    log(&format!("Alice DH1: {:?}", hex::encode(&dh1)));
    log(&format!("Alice DH2: {:?}", hex::encode(&dh2)));
    log(&format!("Alice DH3: {:?}", hex::encode(&dh3)));
    
    // Concatenate the DH results in the standard order
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    
    // Optional fourth DH with one-time prekey for additional forward secrecy
    if let Some(bob_one_time_prekey) = bob_one_time_prekey_public {
        let bob_one_time_prekey_bytes = uint8_array_to_vec(&bob_one_time_prekey);
        
        // DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public
        // This provides perfect forward secrecy as the one-time key is used only once
        let dh4 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_one_time_prekey_bytes);
        dh_concat.extend_from_slice(&dh4);
        
        log(&format!("Alice DH4: {:?}", hex::encode(&dh4)));
    }
    
    // Derive the final shared secret using HKDF (HMAC-based Key Derivation Function)
    // HKDF provides cryptographic strength and domain separation
    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &dh_concat);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(info, &mut shared_secret)
        .map_err(|e| JsValue::from_str(&format!("HKDF expand failed: {}", e)))?;
    
    log(&format!("Alice final shared secret: {}", hex::encode(&shared_secret)));
    
    // Create associated data for additional protocol context
    // This can be used for protocol versioning or additional authentication
    let associated_data = b"X3DH_Key_Exchange";
    
    Ok(X3DHResult {
        shared_secret: shared_secret.to_vec(),
        associated_data: associated_data.to_vec(),
    })
}

/// Respond to X3DH key exchange (Bob's side)
/// 
/// This function performs the X3DH key agreement from the responder's perspective.
/// Bob uses his prekeys and Alice's ephemeral key to compute the same shared secret
/// that Alice derived on her side.
/// 
/// ## Protocol Symmetry
/// Bob performs the exact same DH computations as Alice, but uses his private keys
/// instead of Alice's. The commutativity property of our simplified ECDH ensures
/// that both parties compute identical shared secrets.
/// 
/// ## Key Derivation Order
/// Bob must perform the DH computations in the same order as Alice:
/// 1. DH1: Bob_SignedPrekey_Private × Alice_Identity_Public (= Alice's DH1)
/// 2. DH2: Bob_Identity_Private × Alice_Ephemeral_Public (= Alice's DH2)
/// 3. DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public (= Alice's DH3)
/// 4. DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (= Alice's DH4, optional)
/// 
/// ## Parameters
/// - `bob_identity_private`: Bob's long-term identity private key (32 bytes)
/// - `bob_signed_prekey_private`: Bob's signed prekey private key (32 bytes)
/// - `bob_one_time_prekey_private`: Optional one-time prekey private key (32 bytes)
/// - `alice_identity_public`: Alice's identity public key (32 bytes)
/// - `alice_ephemeral_public`: Alice's ephemeral public key from the key exchange (32 bytes)
/// 
/// ## Returns
/// An `X3DHResult` containing the same shared secret Alice computed
/// 
/// ## Example Usage
/// ```rust
/// let result = x3dh_respond(
///     &bob_identity_private,
///     &bob_signed_prekey_private,
///     Some(bob_one_time_prekey_private),
///     &alice_identity_public,
///     &alice_ephemeral_public
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
#[wasm_bindgen]
pub fn x3dh_respond(
    bob_identity_private: &Uint8Array,
    bob_signed_prekey_private: &Uint8Array,
    bob_one_time_prekey_private: Option<Uint8Array>,
    alice_identity_public: &Uint8Array,
    alice_ephemeral_public: &Uint8Array,
) -> Result<X3DHResult, JsValue> {
    log("Responding to X3DH key exchange (Bob side)");
    
    // Convert JavaScript arrays to Rust vectors
    let bob_identity_private_bytes = uint8_array_to_vec(bob_identity_private);
    let bob_signed_prekey_private_bytes = uint8_array_to_vec(bob_signed_prekey_private);
    let alice_identity_public_bytes = uint8_array_to_vec(alice_identity_public);
    let alice_ephemeral_public_bytes = uint8_array_to_vec(alice_ephemeral_public);
    
    // Perform the same DH operations as Alice (must be equivalent due to ECDH commutativity)
    
    // DH1: Alice_Identity_Private × Bob_SignedPrekey_Public = Bob_SignedPrekey_Private × Alice_Identity_Public
    let dh1 = simple_ecdh(&bob_signed_prekey_private_bytes, &alice_identity_public_bytes);
    
    // DH2: Alice_Ephemeral_Private × Bob_Identity_Public = Bob_Identity_Private × Alice_Ephemeral_Public  
    let dh2 = simple_ecdh(&bob_identity_private_bytes, &alice_ephemeral_public_bytes);
    
    // DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public = Bob_SignedPrekey_Private × Alice_Ephemeral_Public
    let dh3 = simple_ecdh(&bob_signed_prekey_private_bytes, &alice_ephemeral_public_bytes);
    
    log(&format!("Bob DH1: {:?}", hex::encode(&dh1)));
    log(&format!("Bob DH2: {:?}", hex::encode(&dh2)));
    log(&format!("Bob DH3: {:?}", hex::encode(&dh3)));
    
    // Concatenate the DH results in the same order as Alice
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    
    // Optional fourth DH with one-time prekey  
    if let Some(bob_one_time_prekey_private) = bob_one_time_prekey_private {
        let bob_one_time_prekey_private_bytes = uint8_array_to_vec(&bob_one_time_prekey_private);
        
        // DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public = Bob_OneTimePrekey_Private × Alice_Ephemeral_Public
        let dh4 = simple_ecdh(&bob_one_time_prekey_private_bytes, &alice_ephemeral_public_bytes);
        dh_concat.extend_from_slice(&dh4);
        
        log(&format!("Bob DH4: {:?}", hex::encode(&dh4)));
    }
    
    // Derive the same shared secret using HKDF with identical parameters
    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &dh_concat);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(info, &mut shared_secret)
        .map_err(|e| JsValue::from_str(&format!("HKDF expand failed: {}", e)))?;
    
    log(&format!("Bob final shared secret: {}", hex::encode(&shared_secret)));
    
    // Create the same associated data as Alice
    let associated_data = b"X3DH_Key_Exchange";
    
    Ok(X3DHResult {
        shared_secret: shared_secret.to_vec(),
        associated_data: associated_data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rust::keys::*;
    use wasm_bindgen_test::*;

    /// Test complete X3DH key exchange without one-time prekey
    #[wasm_bindgen_test]
    fn test_x3dh_without_one_time_prekey() {
        // Generate keys for Alice
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();
        
        // Generate keys for Bob
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();
        
        // Alice initiates X3DH
        let alice_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            None
        ).unwrap();
        
        // Bob responds to X3DH
        let bob_result = x3dh_respond(
            &bob_identity.private_key(),
            &bob_signed_prekey.private_key(),
            None,
            &alice_identity.public_key(),
            &alice_ephemeral.public_key()
        ).unwrap();
        
        // Both parties should derive the same shared secret
        assert_eq!(alice_result.shared_secret().to_vec(), bob_result.shared_secret().to_vec());
        assert_eq!(alice_result.shared_secret().length(), 32);
        assert_eq!(alice_result.associated_data().to_vec(), bob_result.associated_data().to_vec());
    }

    /// Test complete X3DH key exchange with one-time prekey
    #[wasm_bindgen_test]
    fn test_x3dh_with_one_time_prekey() {
        // Generate keys for Alice
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();
        
        // Generate keys for Bob
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();
        let bob_one_time_prekey = generate_one_time_prekey().unwrap();
        
        // Alice initiates X3DH with one-time prekey
        let alice_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            Some(bob_one_time_prekey.public_key())
        ).unwrap();
        
        // Bob responds to X3DH with one-time prekey
        let bob_result = x3dh_respond(
            &bob_identity.private_key(),
            &bob_signed_prekey.private_key(),
            Some(bob_one_time_prekey.private_key()),
            &alice_identity.public_key(),
            &alice_ephemeral.public_key()
        ).unwrap();
        
        // Both parties should derive the same shared secret
        assert_eq!(alice_result.shared_secret().to_vec(), bob_result.shared_secret().to_vec());
        assert_eq!(alice_result.shared_secret().length(), 32);
        assert_eq!(alice_result.associated_data().to_vec(), bob_result.associated_data().to_vec());
    }

    /// Test that different key sets produce different shared secrets
    #[wasm_bindgen_test]
    fn test_x3dh_uniqueness() {
        // First key exchange
        let alice_identity1 = generate_identity_keypair().unwrap();
        let alice_ephemeral1 = generate_ephemeral_keypair().unwrap();
        let bob_identity1 = generate_identity_keypair().unwrap();
        let bob_signed_prekey1 = generate_signed_prekey().unwrap();
        
        let result1 = x3dh_initiate(
            &alice_identity1.private_key(),
            &alice_ephemeral1.private_key(),
            &bob_identity1.public_key(),
            &bob_signed_prekey1.public_key(),
            None
        ).unwrap();
        
        // Second key exchange with different keys
        let alice_identity2 = generate_identity_keypair().unwrap();
        let alice_ephemeral2 = generate_ephemeral_keypair().unwrap();
        let bob_identity2 = generate_identity_keypair().unwrap();
        let bob_signed_prekey2 = generate_signed_prekey().unwrap();
        
        let result2 = x3dh_initiate(
            &alice_identity2.private_key(),
            &alice_ephemeral2.private_key(),
            &bob_identity2.public_key(),
            &bob_signed_prekey2.public_key(),
            None
        ).unwrap();
        
        // Different keys should produce different shared secrets
        assert_ne!(result1.shared_secret().to_vec(), result2.shared_secret().to_vec());
    }
}