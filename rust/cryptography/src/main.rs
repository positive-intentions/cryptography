use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme};
use rsa::pkcs8::{EncodePrivateKey}; // For private key encoding
use rand::rngs::OsRng;
use pem::{Pem, encode};
use rsa_der::public_key_to_der;

fn main() {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");

    // Encoding the private key to PKCS#8 PEM
    let private_key_der = private_key.to_pkcs8_der().unwrap();
    let private_pem = encode(&Pem {
        tag: String::from("PRIVATE KEY"),
        contents: private_key_der.as_ref().to_vec(),
    });

    // Get the public key from the private key
    let public_key = RsaPublicKey::from(&private_key);

    // Serialize the public key to DER format using rsa_der
    let public_key_der = public_key_to_der(
        public_key.n(), // modulus
        public_key.e()  // public exponent
    );

    // Encode the DER-formatted public key to PEM
    let public_pem = encode(&Pem {
        tag: String::from("PUBLIC KEY"),
        contents: public_key_der,
    });

    println!("Private Key PEM:\n{}", private_pem);
    println!("Public Key PEM:\n{}", public_pem);
}
