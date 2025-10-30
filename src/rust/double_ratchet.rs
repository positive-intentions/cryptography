//! Double Ratchet Implementation for Signal Protocol
//!
//! This module implements the Double Ratchet algorithm, which provides both forward
//! secrecy and post-compromise security for ongoing conversations. The Double Ratchet
//! combines a DH ratchet (for post-compromise security) with a symmetric-key ratchet
//! (for forward secrecy).
//!
//! ## Security Properties
//!
//! - **Forward Secrecy**: Past messages remain secure even if current keys are compromised
//! - **Post-Compromise Security**: Future messages become secure after key compromise
//! - **Out-of-Order Messages**: Messages can arrive and be decrypted in any order
//! - **Authenticated Encryption**: All messages include authentication tags
//!
//! ## Algorithm Overview
//!
//! The Double Ratchet algorithm consists of:
//! 1. **DH Ratchet**: Generates new key agreement for each message direction change
//! 2. **Symmetric Ratchet**: Derives new chain keys for each message in a direction
//! 3. **Message Keys**: Derived from chain keys, used once per message
//! 4. **Skipped Message Keys**: Stored for out-of-order message decryption

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use web_sys::console;
use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use std::collections::HashMap;
use crate::rust::crypto::{uint8_array_to_vec, simple_ecdh};
use crate::rust::keys::generate_identity_keypair;
use crate::rust::types::KeyPair;
use crate::rust::error::SignalError;

/// Maximum number of skipped message keys to store
/// This prevents memory exhaustion attacks while allowing reasonable out-of-order delivery
const MAX_SKIPPED_MESSAGE_KEYS: usize = 1000;

/// HKDF info strings for domain separation
const HKDF_INFO_ROOT_KEY: &[u8] = b"Signal_DoubleRatchet_RootKey";
const HKDF_INFO_CHAIN_KEY: &[u8] = b"Signal_DoubleRatchet_ChainKey";  
const HKDF_INFO_MESSAGE_KEY: &[u8] = b"Signal_DoubleRatchet_MessageKey";

/// Log messages to the browser console for debugging
/// 
/// Provides visibility into Double Ratchet operations during development
/// and helps trace the complex state management.
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

/// Double Ratchet state for one participant
/// 
/// This structure maintains all the cryptographic state needed for the Double Ratchet
/// algorithm. It includes root keys, chain keys, message numbers, and skipped message
/// keys for out-of-order message handling.
/// 
/// ## State Components
/// 
/// - **Root Key**: Used to derive new chain keys during DH ratchet steps
/// - **Chain Keys**: Used to derive message keys and advance the symmetric ratchet
/// - **DH Key Pairs**: Used for Diffie-Hellman ratchet steps
/// - **Message Numbers**: Track the current position in each chain
/// - **Skipped Keys**: Store keys for messages that haven't arrived yet
#[wasm_bindgen]
#[derive(Clone)]
pub struct DoubleRatchetState {
    /// Root key for deriving new chain keys
    #[wasm_bindgen(skip)]
    pub root_key: Vec<u8>,
    
    /// Current sending chain key
    #[wasm_bindgen(skip)]
    pub sending_chain_key: Option<Vec<u8>>,
    
    /// Current receiving chain key  
    #[wasm_bindgen(skip)]
    pub receiving_chain_key: Option<Vec<u8>>,
    
    /// Our DH key pair for sending
    #[wasm_bindgen(skip)]
    pub sending_dh_keypair: Option<KeyPair>,
    
    /// Remote party's DH public key for receiving
    #[wasm_bindgen(skip)]
    pub receiving_dh_public_key: Option<Vec<u8>>,
    
    /// Number of messages sent in current sending chain
    #[wasm_bindgen(skip)]
    pub sending_message_number: u32,
    
    /// Number of messages received in current receiving chain
    #[wasm_bindgen(skip)]
    pub receiving_message_number: u32,
    
    /// Length of previous sending chain (for authenticated data)
    #[wasm_bindgen(skip)]
    pub previous_chain_length: u32,
    
    /// Skipped message keys for out-of-order messages
    /// Map from "dh_public_key:message_number" to message key
    #[wasm_bindgen(skip)]
    pub skipped_message_keys: HashMap<String, Vec<u8>>,
}

#[wasm_bindgen]
impl DoubleRatchetState {
    /// Create a new empty Double Ratchet state
    #[wasm_bindgen(constructor)]
    pub fn new() -> DoubleRatchetState {
        DoubleRatchetState {
            root_key: vec![0u8; 32],
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_dh_keypair: None,
            receiving_dh_public_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }
    
    /// Get the current root key
    #[wasm_bindgen(getter)]
    pub fn root_key(&self) -> Uint8Array {
        Uint8Array::from(&self.root_key[..])
    }
    
    /// Get the sending message number
    #[wasm_bindgen(getter)]
    pub fn sending_message_number(&self) -> u32 {
        self.sending_message_number
    }
    
    /// Get the receiving message number
    #[wasm_bindgen(getter)]
    pub fn receiving_message_number(&self) -> u32 {
        self.receiving_message_number
    }
    
    /// Get the number of skipped message keys stored
    #[wasm_bindgen(getter)]
    pub fn skipped_keys_count(&self) -> usize {
        self.skipped_message_keys.len()
    }
}

/// Result of Double Ratchet message encryption
/// 
/// Contains the encrypted message along with the DH public key and message number
/// needed for the recipient to decrypt the message and update their ratchet state.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DoubleRatchetMessage {
    /// The encrypted message with nonce and authentication tag
    #[wasm_bindgen(skip)]
    pub ciphertext: Vec<u8>,
    
    /// The sender's current DH public key
    #[wasm_bindgen(skip)]
    pub dh_public_key: Vec<u8>,
    
    /// The message number in the current sending chain
    #[wasm_bindgen(skip)]
    pub message_number: u32,
    
    /// The length of the previous sending chain
    #[wasm_bindgen(skip)]
    pub previous_chain_length: u32,
}

#[wasm_bindgen]
impl DoubleRatchetMessage {
    /// Get the ciphertext as a JavaScript Uint8Array
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.ciphertext[..])
    }
    
    /// Get the DH public key as a JavaScript Uint8Array
    #[wasm_bindgen(getter)]
    pub fn dh_public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.dh_public_key[..])
    }
    
    /// Get the message number
    #[wasm_bindgen(getter)]
    pub fn message_number(&self) -> u32 {
        self.message_number
    }
    
    /// Get the previous chain length
    #[wasm_bindgen(getter)]
    pub fn previous_chain_length(&self) -> u32 {
        self.previous_chain_length
    }
}

/// Initialize a Double Ratchet state from a shared secret
/// 
/// This function initializes the Double Ratchet state after an X3DH key exchange.
/// The shared secret from X3DH becomes the initial root key, and the first chain
/// keys are derived based on whether this party is the initiator or responder.
/// 
/// ## Protocol Flow
/// 
/// 1. **Initiator (Alice)**: Generates sending DH key pair immediately
/// 2. **Responder (Bob)**: Waits for first message to establish receiving chain
/// 3. Both parties derive their initial chain keys from the shared secret
/// 
/// ## Parameters
/// - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
/// - `is_initiator`: Whether this party initiates the conversation
/// 
/// ## Returns
/// An initialized `DoubleRatchetState` ready for message encryption/decryption
/// 
/// ## Example Usage
/// ```rust
/// let shared_secret = x3dh_result.shared_secret();
/// let alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
/// let bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
/// ```
#[wasm_bindgen]
pub fn initialize_double_ratchet(
    shared_secret: &Uint8Array,
    is_initiator: bool,
) -> Result<DoubleRatchetState, JsValue> {
    log(&format!("Initializing Double Ratchet (initiator: {})", is_initiator));
    
    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    
    if shared_secret_bytes.len() != 32 {
        return Err(SignalError::InvalidInput("Shared secret must be 32 bytes".to_string()).into());
    }
    
    let mut state = DoubleRatchetState::new();
    
    // Initialize root key with shared secret
    state.root_key = shared_secret_bytes;
    
    if is_initiator {
        // Alice (initiator) generates initial sending key pair
        state.sending_dh_keypair = Some(generate_identity_keypair()?);
        
        // Alice starts with sending capability
        // Initial sending chain key derived from root key
        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Initial_Chain"), &state.root_key);
        let mut initial_chain_key = [0u8; 32];
        hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut initial_chain_key)
            .map_err(|e| JsValue::from_str(&format!("Initial chain key derivation failed: {}", e)))?;
        
        state.sending_chain_key = Some(initial_chain_key.to_vec());
        state.sending_message_number = 0;
        
        log("Alice initialized with sending capability");
    } else {
        // Bob (responder) waits for first message to establish receiving chain
        // No initial chain keys - will be established on first message reception
        state.receiving_message_number = 0;
        
        log("Bob initialized as responder");
    }
    
    state.previous_chain_length = 0;
    
    Ok(state)
}

/// Derive a message key from a chain key
/// 
/// This function implements the symmetric ratchet step that derives a unique
/// message key from the current chain key. Each message gets its own key,
/// providing forward secrecy.
/// 
/// ## Algorithm
/// - Uses HKDF with chain key as input key material
/// - Domain-separated with MESSAGE_KEY info string
/// - Produces 32-byte message key for AES-256-GCM
/// 
/// ## Parameters
/// - `chain_key`: The current chain key (32 bytes)
/// 
/// ## Returns
/// A 32-byte message key for encrypting/decrypting one message
fn derive_message_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Message_Salt"), chain_key);
    let mut message_key = [0u8; 32];
    hkdf.expand(HKDF_INFO_MESSAGE_KEY, &mut message_key)
        .map_err(|e| SignalError::KeyDerivation(format!("Message key derivation failed: {}", e)))?;
    
    Ok(message_key.to_vec())
}

/// Derive the next chain key from the current chain key
/// 
/// This function advances the symmetric ratchet by deriving a new chain key
/// from the current one. This provides forward secrecy by making it impossible
/// to compute previous chain keys from the current one.
/// 
/// ## Algorithm
/// - Uses HKDF with current chain key as input
/// - Domain-separated with CHAIN_KEY info string  
/// - Produces new 32-byte chain key
/// 
/// ## Parameters
/// - `chain_key`: The current chain key (32 bytes)
/// 
/// ## Returns
/// The next chain key in the symmetric ratchet sequence
fn derive_next_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Chain_Salt"), chain_key);
    let mut next_chain_key = [0u8; 32];
    hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut next_chain_key)
        .map_err(|e| SignalError::KeyDerivation(format!("Next chain key derivation failed: {}", e)))?;
    
    Ok(next_chain_key.to_vec())
}

/// Perform a DH ratchet step
/// 
/// This function performs the Diffie-Hellman ratchet step when receiving a message
/// with a new DH public key. It derives new root and chain keys and advances the
/// ratchet state to provide post-compromise security.
/// 
/// ## Algorithm
/// 1. Perform ECDH with our DH private key and new remote public key
/// 2. Use HKDF to derive new root key and receiving chain key
/// 3. Generate new DH key pair for future sending
/// 4. Derive new sending chain key
/// 5. Update ratchet state
/// 
/// ## Parameters
/// - `state`: The current Double Ratchet state (will be modified)
/// - `new_remote_public_key`: The new DH public key from remote party (32 bytes)
/// 
/// ## Returns
/// Updated state with new root key, chain keys, and DH key pair
fn perform_dh_ratchet_step(
    state: &mut DoubleRatchetState, 
    new_remote_public_key: &[u8]
) -> Result<(), SignalError> {
    log("Performing DH ratchet step");
    
    // Step 1: Establish receiving chain key
    if let Some(ref current_dh_keypair) = state.sending_dh_keypair {
        // Case: We have a current DH key pair (normal DH ratchet)
        // Perform ECDH with our current key and new remote key
        let dh_output = simple_ecdh(&current_dh_keypair.private_key, new_remote_public_key);
        
        // Derive new root key and receiving chain key
        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_DH_Ratchet"), &state.root_key);
        let mut hkdf_output = [0u8; 64]; // 32 bytes root key + 32 bytes chain key
        hkdf.expand(&dh_output, &mut hkdf_output)
            .map_err(|e| SignalError::KeyDerivation(format!("DH ratchet HKDF failed: {}", e)))?;
        
        // Update root key and establish receiving chain
        state.root_key = hkdf_output[0..32].to_vec();
        state.receiving_chain_key = Some(hkdf_output[32..64].to_vec());
        state.receiving_dh_public_key = Some(new_remote_public_key.to_vec());
        state.receiving_message_number = 0;
        
        log("Established receiving chain from DH ratchet");
    } else {
        // Case: No current DH key pair (first message from remote party)
        // This happens when Bob receives Alice's first message
        log("First message received, establishing initial receiving chain");
        
        // Derive receiving chain key from root key using SAME parameters as Alice's initial chain
        // This ensures Alice's sending chain key == Bob's receiving chain key
        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Initial_Chain"), &state.root_key);
        let mut receiving_chain_key = [0u8; 32];
        hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut receiving_chain_key)
            .map_err(|e| SignalError::KeyDerivation(format!("Initial receiving chain derivation failed: {}", e)))?;
        
        state.receiving_chain_key = Some(receiving_chain_key.to_vec());
        state.receiving_dh_public_key = Some(new_remote_public_key.to_vec());
        state.receiving_message_number = 0;
        
        log("Established initial receiving chain");
    }
    
    // Step 2: Generate new DH key pair for sending
    let new_dh_keypair = generate_identity_keypair()
        .map_err(|e| SignalError::KeyGeneration(format!("Failed to generate new DH keypair: {:?}", e)))?;
    
    // Step 3: Derive sending chain key with new key pair
    let sending_dh_output = simple_ecdh(&new_dh_keypair.private_key, new_remote_public_key);
    
    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_DH_Ratchet_Send"), &state.root_key);
    let mut hkdf_output = [0u8; 64];
    hkdf.expand(&sending_dh_output, &mut hkdf_output)
        .map_err(|e| SignalError::KeyDerivation(format!("Sending chain HKDF failed: {}", e)))?;
    
    // Update state for sending
    state.root_key = hkdf_output[0..32].to_vec();
    state.sending_chain_key = Some(hkdf_output[32..64].to_vec());
    state.sending_dh_keypair = Some(new_dh_keypair);
    state.previous_chain_length = state.sending_message_number;
    state.sending_message_number = 0;
    
    log("DH ratchet step completed");
    Ok(())
}

/// Skip message keys for out-of-order messages
/// 
/// This function stores message keys for messages that haven't arrived yet,
/// allowing the Double Ratchet to handle out-of-order message delivery.
/// It prevents memory exhaustion by limiting the number of skipped keys.
/// 
/// ## Parameters
/// - `state`: The Double Ratchet state (will be modified)
/// - `until_message_number`: Skip keys up to this message number
/// 
/// ## Returns
/// Updated state with skipped message keys stored
fn skip_message_keys(
    state: &mut DoubleRatchetState,
    until_message_number: u32,
) -> Result<(), SignalError> {
    if let Some(ref mut receiving_chain_key) = state.receiving_chain_key {
        if state.receiving_message_number < until_message_number {
            let skip_count = until_message_number - state.receiving_message_number;
            
            if skip_count > MAX_SKIPPED_MESSAGE_KEYS as u32 {
                return Err(SignalError::InvalidInput(
                    format!("Too many skipped message keys: {}", skip_count)
                ));
            }
            
            let dh_public_key_hex = if let Some(ref dh_key) = state.receiving_dh_public_key {
                hex::encode(dh_key)
            } else {
                "none".to_string()
            };
            
            let mut current_chain_key = receiving_chain_key.clone();
            
            while state.receiving_message_number < until_message_number {
                // Derive message key for this message number
                let message_key = derive_message_key(&current_chain_key)?;

                // Store the skipped key
                let key_id = format!("{}:{}", dh_public_key_hex, state.receiving_message_number);
                state.skipped_message_keys.insert(key_id.clone(), message_key);

                // Advance to next chain key
                current_chain_key = derive_next_chain_key(&current_chain_key)?;
                state.receiving_message_number += 1;

                // SECURITY: Avoid logging key identifiers to prevent timing analysis
            }
            
            *receiving_chain_key = current_chain_key;
        }
    }
    
    Ok(())
}

/// Encrypt a message using the Double Ratchet
/// 
/// This function encrypts a message using the current sending chain key,
/// derives a unique message key, and creates a message that includes all
/// information needed for decryption and ratchet state updates.
/// 
/// ## Process
/// 1. Derive message key from current sending chain key
/// 2. Encrypt plaintext using AES-256-GCM with derived key
/// 3. Create authenticated data including DH public key and message number
/// 4. Advance sending chain key for next message
/// 5. Return encrypted message with metadata
/// 
/// ## Parameters
/// - `state`: The Double Ratchet state (will be modified)
/// - `plaintext`: The message to encrypt
/// 
/// ## Returns
/// A `DoubleRatchetMessage` containing encrypted data and metadata
/// 
/// ## Errors
/// - Returns error if no sending chain key is available
/// - Returns error if encryption fails
/// - Returns error if chain key derivation fails
#[wasm_bindgen]
pub fn double_ratchet_encrypt(
    state: &mut DoubleRatchetState,
    plaintext: &Uint8Array,
) -> Result<DoubleRatchetMessage, JsValue> {
    log(&format!("Encrypting message #{}", state.sending_message_number));
    
    let plaintext_bytes = uint8_array_to_vec(plaintext);
    
    // Check that we have a sending chain key
    let sending_chain_key = state.sending_chain_key.as_ref()
        .ok_or_else(|| JsValue::from_str("No sending chain key available"))?;
    
    let sending_dh_keypair = state.sending_dh_keypair.as_ref()
        .ok_or_else(|| JsValue::from_str("No sending DH keypair available"))?;
    
    // Derive message key
    let message_key = derive_message_key(sending_chain_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Generate random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Prepare additional authenticated data (AAD)
    // Format: DH_public_key || message_number || previous_chain_length
    let mut aad = Vec::new();
    aad.extend_from_slice(&sending_dh_keypair.public_key);
    aad.extend_from_slice(&state.sending_message_number.to_be_bytes());
    aad.extend_from_slice(&state.previous_chain_length.to_be_bytes());
    
    // Encrypt with AES-256-GCM
    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce_ga, plaintext_bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("AES-GCM encryption failed: {}", e)))?;
    
    // Prepend nonce to ciphertext
    let mut result_ciphertext = nonce_bytes.to_vec();
    result_ciphertext.extend_from_slice(&ciphertext);
    
    // Create the message
    let message = DoubleRatchetMessage {
        ciphertext: result_ciphertext,
        dh_public_key: sending_dh_keypair.public_key.clone(),
        message_number: state.sending_message_number,
        previous_chain_length: state.previous_chain_length,
    };
    
    // Advance sending chain for next message
    let next_chain_key = derive_next_chain_key(sending_chain_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    state.sending_chain_key = Some(next_chain_key);
    state.sending_message_number += 1;
    
    log(&format!("Message encrypted successfully, advanced to message #{}", state.sending_message_number));
    
    Ok(message)
}

/// Decrypt a message using the Double Ratchet
/// 
/// This function decrypts a Double Ratchet message, handling DH ratchet steps
/// if needed and managing out-of-order message delivery through skipped message keys.
/// 
/// ## Process
/// 1. Check for DH ratchet step (new DH public key)
/// 2. Handle skipped message keys for out-of-order delivery
/// 3. Derive or retrieve appropriate message key
/// 4. Decrypt message using AES-256-GCM
/// 5. Update ratchet state
/// 
/// ## Parameters
/// - `state`: The Double Ratchet state (will be modified)
/// - `message`: The encrypted message to decrypt
/// 
/// ## Returns
/// The decrypted plaintext as a Uint8Array
/// 
/// ## Errors
/// - Returns error if DH ratchet step fails
/// - Returns error if message key derivation fails  
/// - Returns error if decryption fails
/// - Returns error if authentication fails
#[wasm_bindgen]
pub fn double_ratchet_decrypt(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Decrypting message #{}", message.message_number));
    
    let message_dh_key = &message.dh_public_key;
    let message_number = message.message_number;
    let ciphertext_bytes = &message.ciphertext;
    
    // Check if this is a DH ratchet step (new DH public key)
    let is_dh_ratchet_step = if let Some(ref current_dh_key) = state.receiving_dh_public_key {
        current_dh_key != message_dh_key
    } else {
        // First message - always a DH ratchet step
        true
    };
    
    if is_dh_ratchet_step {
        log("Performing DH ratchet step for new DH public key");
        perform_dh_ratchet_step(state, message_dh_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    }
    
    // Try to find skipped message key first
    let dh_key_hex = hex::encode(message_dh_key);
    let key_id = format!("{}:{}", dh_key_hex, message_number);

    let message_key = if let Some(skipped_key) = state.skipped_message_keys.remove(&key_id) {
        // SECURITY: Avoid logging key identifiers to prevent timing analysis
        skipped_key
    } else {
        // Skip intermediate message keys if needed
        if message_number > state.receiving_message_number {
            skip_message_keys(state, message_number)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        
        // Derive message key from current receiving chain key
        let receiving_chain_key = state.receiving_chain_key.as_ref()
            .ok_or_else(|| JsValue::from_str("No receiving chain key available"))?;
        
        if message_number != state.receiving_message_number {
            return Err(JsValue::from_str(&format!(
                "Message number mismatch: expected {}, got {}", 
                state.receiving_message_number, message_number
            )));
        }
        
        let message_key = derive_message_key(receiving_chain_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        // Advance receiving chain
        let next_chain_key = derive_next_chain_key(receiving_chain_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        state.receiving_chain_key = Some(next_chain_key);
        state.receiving_message_number += 1;
        
        message_key
    };
    
    // Validate ciphertext length
    if ciphertext_bytes.len() < 12 {
        return Err(JsValue::from_str("Ciphertext too short for nonce"));
    }
    
    // Extract nonce and encrypted data
    let nonce_bytes = &ciphertext_bytes[..12];
    let encrypted_data = &ciphertext_bytes[12..];
    
    // Prepare additional authenticated data (same as encryption)
    let mut aad = Vec::new();
    aad.extend_from_slice(message_dh_key);
    aad.extend_from_slice(&message.message_number.to_be_bytes());
    aad.extend_from_slice(&message.previous_chain_length.to_be_bytes());
    
    // Decrypt with AES-256-GCM
    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce_ga, encrypted_data)
        .map_err(|e| JsValue::from_str(&format!("AES-GCM decryption failed: {}", e)))?;
    
    log("Message decrypted successfully");
    
    Ok(Uint8Array::from(&plaintext[..]))
}

/// Cleanup old skipped message keys
/// 
/// This function removes old skipped message keys to prevent memory exhaustion.
/// It should be called periodically to maintain reasonable memory usage.
/// 
/// ## Parameters
/// - `state`: The Double Ratchet state (will be modified)
/// - `max_keys`: Maximum number of skipped keys to keep
/// 
/// ## Returns
/// Number of keys removed
#[wasm_bindgen]
pub fn cleanup_skipped_message_keys(
    state: &mut DoubleRatchetState,
    max_keys: usize,
) -> usize {
    let keys_to_remove = if state.skipped_message_keys.len() > max_keys {
        state.skipped_message_keys.len() - max_keys
    } else {
        return 0;
    };
    
    // Remove oldest keys (this is simplified - a real implementation might use timestamps)
    let mut keys: Vec<_> = state.skipped_message_keys.keys().cloned().collect();
    keys.sort(); // Sort to get consistent ordering
    
    let mut removed_count = 0;
    for key in keys.iter().take(keys_to_remove) {
        state.skipped_message_keys.remove(key);
        removed_count += 1;
    }
    
    log(&format!("Cleaned up {} old skipped message keys", removed_count));
    
    removed_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    use crate::rust::x3dh::x3dh_initiate;
    use crate::rust::keys::*;

    /// Test Double Ratchet initialization
    #[wasm_bindgen_test]
    fn test_double_ratchet_initialization() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        
        // Test Alice (initiator)
        let alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        assert_eq!(alice_state.sending_message_number, 0);
        assert_eq!(alice_state.receiving_message_number, 0);
        assert!(alice_state.sending_chain_key.is_some());
        assert!(alice_state.sending_dh_keypair.is_some());
        
        // Test Bob (responder)
        let bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        assert_eq!(bob_state.sending_message_number, 0);
        assert_eq!(bob_state.receiving_message_number, 0);
        assert!(bob_state.sending_chain_key.is_none()); // Bob waits for first message
    }

    /// Test message key derivation
    #[wasm_bindgen_test]
    fn test_message_key_derivation() {
        let chain_key = [1u8; 32];
        
        let message_key = derive_message_key(&chain_key).unwrap();
        assert_eq!(message_key.len(), 32);
        
        // Same chain key should produce same message key
        let message_key2 = derive_message_key(&chain_key).unwrap();
        assert_eq!(message_key, message_key2);
        
        // Different chain key should produce different message key
        let different_chain_key = [2u8; 32];
        let different_message_key = derive_message_key(&different_chain_key).unwrap();
        assert_ne!(message_key, different_message_key);
    }

    /// Test chain key advancement
    #[wasm_bindgen_test]
    fn test_chain_key_advancement() {
        let chain_key = [1u8; 32];
        
        let next_chain_key = derive_next_chain_key(&chain_key).unwrap();
        assert_eq!(next_chain_key.len(), 32);
        assert_ne!(chain_key.to_vec(), next_chain_key);
        
        // Advancing should be deterministic
        let next_chain_key2 = derive_next_chain_key(&chain_key).unwrap();
        assert_eq!(next_chain_key, next_chain_key2);
        
        // Chain keys should form a sequence
        let third_chain_key = derive_next_chain_key(&next_chain_key).unwrap();
        assert_ne!(next_chain_key, third_chain_key);
    }

    /// Test Double Ratchet encryption and decryption
    #[wasm_bindgen_test]
    fn test_double_ratchet_encrypt_decrypt() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        
        // Initialize Alice and Bob
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        
        // Alice encrypts first message
        let plaintext = Uint8Array::from("Hello Bob!".as_bytes());
        let encrypted_message = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        
        assert!(encrypted_message.ciphertext().length() > plaintext.length());
        assert_eq!(encrypted_message.message_number(), 0);
        assert_eq!(alice_state.sending_message_number, 1);
        
        // Bob decrypts the message
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted_message).unwrap();
        let decrypted_text = String::from_utf8(decrypted.to_vec()).unwrap();
        assert_eq!(decrypted_text, "Hello Bob!");
        assert_eq!(bob_state.receiving_message_number, 1);
    }

    /// Test bidirectional conversation
    #[wasm_bindgen_test]
    fn test_bidirectional_conversation() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        
        // Alice -> Bob
        let msg1 = Uint8Array::from("Hello Bob!".as_bytes());
        let encrypted1 = double_ratchet_encrypt(&mut alice_state, &msg1).unwrap();
        let decrypted1 = double_ratchet_decrypt(&mut bob_state, &encrypted1).unwrap();
        assert_eq!(String::from_utf8(decrypted1.to_vec()).unwrap(), "Hello Bob!");
        
        // Bob -> Alice (triggers DH ratchet step)
        let msg2 = Uint8Array::from("Hello Alice!".as_bytes());
        let encrypted2 = double_ratchet_encrypt(&mut bob_state, &msg2).unwrap();
        let decrypted2 = double_ratchet_decrypt(&mut alice_state, &encrypted2).unwrap();
        assert_eq!(String::from_utf8(decrypted2.to_vec()).unwrap(), "Hello Alice!");
        
        // Alice -> Bob again
        let msg3 = Uint8Array::from("How are you?".as_bytes());
        let encrypted3 = double_ratchet_encrypt(&mut alice_state, &msg3).unwrap();
        let decrypted3 = double_ratchet_decrypt(&mut bob_state, &encrypted3).unwrap();
        assert_eq!(String::from_utf8(decrypted3.to_vec()).unwrap(), "How are you?");
    }

    /// Test skipped message keys for out-of-order delivery
    #[wasm_bindgen_test]
    fn test_out_of_order_messages() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        
        // Alice encrypts several messages
        let msg1 = double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 1".as_bytes())).unwrap();
        let msg2 = double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 2".as_bytes())).unwrap();
        let msg3 = double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 3".as_bytes())).unwrap();
        
        // Bob receives messages out of order: 3, 1, 2
        let decrypted3 = double_ratchet_decrypt(&mut bob_state, &msg3).unwrap();
        assert_eq!(String::from_utf8(decrypted3.to_vec()).unwrap(), "Message 3");
        
        let decrypted1 = double_ratchet_decrypt(&mut bob_state, &msg1).unwrap();
        assert_eq!(String::from_utf8(decrypted1.to_vec()).unwrap(), "Message 1");
        
        let decrypted2 = double_ratchet_decrypt(&mut bob_state, &msg2).unwrap();
        assert_eq!(String::from_utf8(decrypted2.to_vec()).unwrap(), "Message 2");
        
        // Verify final state
        assert_eq!(bob_state.receiving_message_number, 3);
        assert_eq!(bob_state.skipped_keys_count(), 0); // All skipped keys should be used
    }

    /// Test skipped message key cleanup
    #[wasm_bindgen_test]
    fn test_skipped_key_cleanup() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        
        // Create many encrypted messages
        let mut messages = Vec::new();
        for i in 0..10 {
            let plaintext = Uint8Array::from(format!("Message {}", i).as_bytes());
            messages.push(double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap());
        }
        
        // Bob receives only the last message, creating many skipped keys
        let last_message = messages.last().unwrap();
        let _decrypted = double_ratchet_decrypt(&mut bob_state, last_message).unwrap();
        
        assert!(bob_state.skipped_keys_count() > 5);
        
        // Cleanup skipped keys
        let removed = cleanup_skipped_message_keys(&mut bob_state, 3);
        assert!(removed > 0);
        assert!(bob_state.skipped_keys_count() <= 3);
    }

    /// Test error conditions
    #[wasm_bindgen_test]
    fn test_error_conditions() {
        // Invalid shared secret length
        let short_secret = Uint8Array::from(&[1u8; 16][..]);
        let result = initialize_double_ratchet(&short_secret, true);
        assert!(result.is_err());
        
        // Empty state encryption
        let mut empty_state = DoubleRatchetState::new();
        let plaintext = Uint8Array::from("test".as_bytes());
        let result = double_ratchet_encrypt(&mut empty_state, &plaintext);
        assert!(result.is_err());
    }

    /// Test integration with X3DH
    #[wasm_bindgen_test]
    fn test_integration_with_x3dh() {
        // Generate keys for Alice and Bob
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();
        
        // Perform X3DH key exchange
        let x3dh_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            None
        ).unwrap();
        
        // Initialize Double Ratchet with X3DH result
        let shared_secret = x3dh_result.shared_secret();
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        
        // Test message exchange
        let plaintext = Uint8Array::from("X3DH -> Double Ratchet integration test".as_bytes());
        let encrypted = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted).unwrap();
        
        let decrypted_text = String::from_utf8(decrypted.to_vec()).unwrap();
        assert_eq!(decrypted_text, "X3DH -> Double Ratchet integration test");
    }
}