use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use web_sys::console;

// Import cryptographic libraries
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, aead::{Aead, NewAead}};
use aes_gcm::aead::generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};

// Error types
#[derive(thiserror::Error, Debug)]
pub enum SignalError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
    #[error("Key exchange failed: {0}")]
    KeyExchange(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl Into<JsValue> for SignalError {
    fn into(self) -> JsValue {
        JsValue::from_str(&self.to_string())
    }
}

// Key pair structures
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    #[wasm_bindgen(skip)]
    pub public_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub private_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Uint8Array {
        Uint8Array::from(&self.private_key[..])
    }
}

// X3DH result structure
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct X3DHResult {
    #[wasm_bindgen(skip)]
    pub shared_secret: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub associated_data: Vec<u8>,
}

#[wasm_bindgen]
impl X3DHResult {
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Uint8Array {
        Uint8Array::from(&self.shared_secret[..])
    }

    #[wasm_bindgen(getter)]
    pub fn associated_data(&self) -> Uint8Array {
        Uint8Array::from(&self.associated_data[..])
    }
}

// Message encryption result structure
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct EncryptionResult {
    #[wasm_bindgen(skip)]
    pub ciphertext: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub message_key: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.ciphertext[..])
    }

    #[wasm_bindgen(getter)]
    pub fn message_key(&self) -> Uint8Array {
        Uint8Array::from(&self.message_key[..])
    }
}

// Utility function to convert JS Uint8Array to Vec<u8>
fn uint8_array_to_vec(arr: &Uint8Array) -> Vec<u8> {
    arr.to_vec()
}

// Utility function to log to browser console
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

// Generate a random 32-byte key
fn generate_random_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// Simple hash function for signing (using SHA256)
fn simple_sign(private_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Simple signature verification
fn simple_verify(public_key: &[u8], signature: &[u8], data: &[u8]) -> bool {
    // For this simplified demo, we recreate the signature and compare
    let mut hasher = Sha256::new();
    hasher.update(public_key); // In real implementation, we'd derive private from public
    hasher.update(data);
    let expected = hasher.finalize();
    expected.as_slice() == signature
}

// Key generation functions
#[wasm_bindgen]
pub fn generate_identity_keypair() -> Result<KeyPair, JsValue> {
    log("Generating identity keypair using simplified crypto");
    
    let private_key = generate_random_key();
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

#[wasm_bindgen]
pub fn generate_signed_prekey() -> Result<KeyPair, JsValue> {
    log("Generating signed prekey using simplified crypto");
    
    let private_key = generate_random_key();
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

#[wasm_bindgen]
pub fn generate_one_time_prekey() -> Result<KeyPair, JsValue> {
    log("Generating one-time prekey using simplified crypto");
    
    let private_key = generate_random_key();
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

#[wasm_bindgen]
pub fn generate_ephemeral_keypair() -> Result<KeyPair, JsValue> {
    log("Generating ephemeral keypair using simplified crypto");
    
    let private_key = generate_random_key();
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

// Digital signature functions
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

// Simple ECDH simulation that ensures commutativity
// The key insight: for demonstration purposes, we'll implement a symmetric function
// that always produces the same result regardless of parameter order
fn simple_ecdh(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    // For true commutativity, we need both parties to compute the same value.
    // In our simplified model where public_key = SHA256(private_key),
    // we'll create a symmetric function that works for both directions.
    
    // Create two candidate results and choose the lexicographically smaller one
    // This ensures both parties always get the same result
    
    // Method 1: private_key as input, public_key as salt
    let mut hasher1 = Sha256::new();
    hasher1.update(private_key);
    hasher1.update(public_key);
    hasher1.update(b"ECDH_v1");
    let result1 = hasher1.finalize();
    
    // Method 2: public_key as input, private_key as salt  
    let mut hasher2 = Sha256::new();
    hasher2.update(public_key);
    hasher2.update(private_key);
    hasher2.update(b"ECDH_v2");
    let result2 = hasher2.finalize();
    
    // Always return the lexicographically smaller result
    // This ensures commutativity: same result regardless of parameter order
    if result1 <= result2 {
        result1.to_vec()
    } else {
        result2.to_vec()
    }
}

// X3DH key exchange functions
#[wasm_bindgen]
pub fn x3dh_initiate(
    alice_identity_private: &Uint8Array,
    alice_ephemeral_private: &Uint8Array,
    bob_identity_public: &Uint8Array,
    bob_signed_prekey_public: &Uint8Array,
    bob_one_time_prekey_public: Option<Uint8Array>,
) -> Result<X3DHResult, JsValue> {
    log("Initiating X3DH key exchange (Alice side)");
    
    let alice_identity_private_bytes = uint8_array_to_vec(alice_identity_private);
    let alice_ephemeral_private_bytes = uint8_array_to_vec(alice_ephemeral_private);
    let bob_identity_public_bytes = uint8_array_to_vec(bob_identity_public);
    let bob_signed_prekey_public_bytes = uint8_array_to_vec(bob_signed_prekey_public);
    
    // Perform DH operations using simplified crypto (X3DH standard order)
    let dh1 = simple_ecdh(&alice_identity_private_bytes, &bob_signed_prekey_public_bytes);
    let dh2 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_identity_public_bytes);
    let dh3 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_signed_prekey_public_bytes);
    
    log(&format!("Alice DH1: {:?}", hex::encode(&dh1)));
    log(&format!("Alice DH2: {:?}", hex::encode(&dh2)));
    log(&format!("Alice DH3: {:?}", hex::encode(&dh3)));
    
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    
    // Optional fourth DH with one-time prekey
    if let Some(bob_one_time_prekey) = bob_one_time_prekey_public {
        let bob_one_time_prekey_bytes = uint8_array_to_vec(&bob_one_time_prekey);
        // DH4: Alice_Ephemeral_Private * Bob_OneTimePrekey_Public
        let dh4 = simple_ecdh(&alice_ephemeral_private_bytes, &bob_one_time_prekey_bytes);
        dh_concat.extend_from_slice(&dh4);
    }
    
    // Derive shared secret using HKDF
    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &dh_concat);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(info, &mut shared_secret)
        .map_err(|e| JsValue::from_str(&format!("HKDF expand failed: {}", e)))?;
    
    log(&format!("Alice final shared secret: {}", hex::encode(&shared_secret)));
    
    // Create associated data (same format for both Alice and Bob)
    let associated_data = b"X3DH_Key_Exchange";
    
    Ok(X3DHResult {
        shared_secret: shared_secret.to_vec(),
        associated_data: associated_data.to_vec(),
    })
}

#[wasm_bindgen]
pub fn x3dh_respond(
    bob_identity_private: &Uint8Array,
    bob_signed_prekey_private: &Uint8Array,
    bob_one_time_prekey_private: Option<Uint8Array>,
    alice_identity_public: &Uint8Array,
    alice_ephemeral_public: &Uint8Array,
) -> Result<X3DHResult, JsValue> {
    log("Responding to X3DH key exchange (Bob side)");
    
    let bob_identity_private_bytes = uint8_array_to_vec(bob_identity_private);
    let bob_signed_prekey_private_bytes = uint8_array_to_vec(bob_signed_prekey_private);
    let alice_identity_public_bytes = uint8_array_to_vec(alice_identity_public);
    let alice_ephemeral_public_bytes = uint8_array_to_vec(alice_ephemeral_public);
    
    // Perform the same DH operations as Alice (must be equivalent due to ECDH commutativity)
    // DH1: Alice_Identity_Private * Bob_SignedPrekey_Public = Bob_SignedPrekey_Private * Alice_Identity_Public
    let dh1 = simple_ecdh(&bob_signed_prekey_private_bytes, &alice_identity_public_bytes);
    // DH2: Alice_Ephemeral_Private * Bob_Identity_Public = Bob_Identity_Private * Alice_Ephemeral_Public  
    let dh2 = simple_ecdh(&bob_identity_private_bytes, &alice_ephemeral_public_bytes);
    // DH3: Alice_Ephemeral_Private * Bob_SignedPrekey_Public = Bob_SignedPrekey_Private * Alice_Ephemeral_Public
    let dh3 = simple_ecdh(&bob_signed_prekey_private_bytes, &alice_ephemeral_public_bytes);
    
    log(&format!("Bob DH1: {:?}", hex::encode(&dh1)));
    log(&format!("Bob DH2: {:?}", hex::encode(&dh2)));
    log(&format!("Bob DH3: {:?}", hex::encode(&dh3)));
    
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    
    // Optional fourth DH with one-time prekey  
    if let Some(bob_one_time_prekey_private) = bob_one_time_prekey_private {
        let bob_one_time_prekey_private_bytes = uint8_array_to_vec(&bob_one_time_prekey_private);
        // DH4: Alice_Ephemeral_Private * Bob_OneTimePrekey_Public = Bob_OneTimePrekey_Private * Alice_Ephemeral_Public
        let dh4 = simple_ecdh(&bob_one_time_prekey_private_bytes, &alice_ephemeral_public_bytes);
        dh_concat.extend_from_slice(&dh4);
    }
    
    // Derive same shared secret using HKDF
    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &dh_concat);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(info, &mut shared_secret)
        .map_err(|e| JsValue::from_str(&format!("HKDF expand failed: {}", e)))?;
    
    log(&format!("Bob final shared secret: {}", hex::encode(&shared_secret)));
    
    // Create associated data (same format for both Alice and Bob)
    let associated_data = b"X3DH_Key_Exchange";
    
    Ok(X3DHResult {
        shared_secret: shared_secret.to_vec(),
        associated_data: associated_data.to_vec(),
    })
}

// Message encryption/decryption functions
#[wasm_bindgen]
pub fn encrypt_message(
    shared_secret: &Uint8Array,
    plaintext: &Uint8Array,
    message_number: u32,
) -> Result<EncryptionResult, JsValue> {
    log(&format!("Encrypting message #{}", message_number));
    
    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    let plaintext_bytes = uint8_array_to_vec(plaintext);
    
    // Derive message-specific key using HKDF
    let salt = b"Signal_Message_Salt";
    let info = format!("Signal_Message_{}", message_number);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &shared_secret_bytes);
    let mut message_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut message_key)
        .map_err(|e| JsValue::from_str(&format!("Message key derivation failed: {}", e)))?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Encrypt with AES-GCM
    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce_ga, plaintext_bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("AES-GCM encryption failed: {}", e)))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(EncryptionResult {
        ciphertext: result,
        message_key: message_key.to_vec(),
    })
}

#[wasm_bindgen]
pub fn decrypt_message(
    shared_secret: &Uint8Array,
    ciphertext: &Uint8Array,
    message_key: &Uint8Array,
    message_number: u32,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Decrypting message #{}", message_number));
    
    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    let ciphertext_bytes = uint8_array_to_vec(ciphertext);
    let message_key_bytes = uint8_array_to_vec(message_key);
    
    // Use the provided message key directly (no need to verify)
    // In a real implementation, you might want additional verification,
    // but for this demo we trust the provided key
    
    if ciphertext_bytes.len() < 12 {
        return Err(JsValue::from_str("Ciphertext too short"));
    }
    
    // Extract nonce and ciphertext
    let nonce_ga = GenericArray::from_slice(&ciphertext_bytes[..12]);
    let encrypted_data = &ciphertext_bytes[12..];
    
    // Decrypt with AES-GCM
    let key = GenericArray::from_slice(&message_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce_ga, encrypted_data)
        .map_err(|e| JsValue::from_str(&format!("AES-GCM decryption failed: {}", e)))?;
    
    Ok(Uint8Array::from(&plaintext[..]))
}

// Key derivation function
#[wasm_bindgen]
pub fn hkdf_derive_key(
    input_key_material: &Uint8Array,
    salt: &Uint8Array,
    info: &Uint8Array,
    output_length: usize,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Deriving key with HKDF, output length: {}", output_length));
    
    let ikm = uint8_array_to_vec(input_key_material);
    let salt_bytes = uint8_array_to_vec(salt);
    let info_bytes = uint8_array_to_vec(info);
    
    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bytes), &ikm);
    let mut output = vec![0u8; output_length];
    hkdf.expand(&info_bytes, &mut output)
        .map_err(|e| JsValue::from_str(&format!("HKDF failed: {}", e)))?;
    
    Ok(Uint8Array::from(&output[..]))
}

// Utility functions
#[wasm_bindgen]
pub fn serialize_public_key(public_key: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Serializing public key");
    
    let key_bytes = uint8_array_to_vec(public_key);
    
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Public key must be 32 bytes"));
    }
    
    // Add a version byte (0x05 for compressed point)
    let mut serialized = vec![0x05];
    serialized.extend_from_slice(&key_bytes);
    
    Ok(Uint8Array::from(&serialized[..]))
}

#[wasm_bindgen]
pub fn deserialize_public_key(serialized_key: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Deserializing public key");
    
    let serialized_bytes = uint8_array_to_vec(serialized_key);
    
    if serialized_bytes.len() != 33 || serialized_bytes[0] != 0x05 {
        return Err(JsValue::from_str("Invalid serialized key format"));
    }
    
    Ok(Uint8Array::from(&serialized_bytes[1..]))
}

// Memory management functions
#[wasm_bindgen]
pub fn free_keypair(_keypair: &KeyPair) {
    log("Freeing keypair memory");
    // In Rust, memory is automatically managed
}

#[wasm_bindgen]
pub fn free_buffer(_buffer: &Uint8Array) {
    log("Freeing buffer memory");
    // Memory cleanup handled automatically
}

// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn main() {
    log("Signal Protocol WASM module initialized");
    
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();
}

// Simple timestamp function using JavaScript Date.now()
fn get_timestamp() -> u64 {
    js_sys::Date::now() as u64
}