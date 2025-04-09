// ====================================================
// CRYPTOGRAPHIC ALGORITHMS DEMONSTRATION PROGRAM
// ====================================================
// This program demonstrates various encryption, hashing, and signature 
// algorithms used in computer security and cryptocurrencies.
// 
// Author: Henri Le Bras
// License: MIT

extern crate base64;
extern crate hex;
extern crate aes_gcm;
extern crate chacha20poly1305;
extern crate sha2;
extern crate ed25519_dalek;
extern crate secp256k1;
extern crate blake2;
extern crate blake3;

use aes_gcm::{AesGcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hex::FromHex;
use std::env;
use aes_gcm::aes::Aes256;
use generic_array::typenum::U12;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Key as ChaChaKey;
use chacha20poly1305::Nonce as ChaChaNonce;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use secp256k1::{Secp256k1, Message as Secp256k1Message};
use blake2::{Blake2b512, Blake2s256, Digest as Blake2Digest};
use blake3::Hasher as Blake3Hasher;

// Converts a hex string to a byte array
// Example: "0A1B2C" becomes [10, 27, 44]
fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s).unwrap()
}

// ====================================================
// SYMMETRIC ENCRYPTION: AES-GCM
// ====================================================
// AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) is a 
// popular symmetric encryption algorithm providing both confidentiality and authenticity.
// 
// How it works:
// 1. Uses the same key for encryption and decryption
// 2. Needs a nonce (number used once) for security
// 3. Produces ciphertext and an authentication tag
// 4. Used in TLS, SSH, and other secure protocols
fn encrypt_aes_gcm(message: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Convert bytes to structures suitable for AES-GCM API
    let key = Key::<Aes256>::from_slice(key);  // AES-256 bit key
    let nonce = Nonce::<U12>::from_slice(nonce);  // 12 byte nonce (96 bits)
    
    // Initialize AES-GCM cipher
    let cipher = AesGcm::<Aes256, U12>::new(key);
    
    // Encrypt the message (auth tag automatically added)
    cipher.encrypt(nonce, message).expect("Encryption failure")
}

fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Convert bytes to structures suitable for AES-GCM API
    let key = Key::<Aes256>::from_slice(key);
    let nonce = Nonce::<U12>::from_slice(nonce);
    
    // Initialize AES-GCM cipher
    let cipher = AesGcm::<Aes256, U12>::new(key);
    
    // Decrypt message and verify auth tag
    cipher.decrypt(nonce, ciphertext).expect("Decryption failure")
}

// ====================================================
// SYMMETRIC ENCRYPTION: ChaCha20-Poly1305
// ====================================================
// ChaCha20-Poly1305 is a modern AEAD (Authenticated Encryption with Associated Data)
// that combines ChaCha20 stream cipher with Poly1305 authentication.
// 
// Advantages:
// - Fast in software (no hardware acceleration needed)
// - Resistant to timing attacks
// - Used in TLS 1.3, IETF, Wireguard, etc.
fn encrypt_chacha20poly1305(message: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Prepare key and nonce
    let key = ChaChaKey::from_slice(key);  // 256-bit key
    let nonce = ChaChaNonce::from_slice(nonce);  // 96-bit nonce
    
    // Initialize cipher
    let cipher = ChaCha20Poly1305::new(key);
    
    // Encrypt message (includes auth tag)
    cipher.encrypt(nonce, message).expect("ChaCha20Poly1305 encryption failure")
}

fn decrypt_chacha20poly1305(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Prepare key and nonce
    let key = ChaChaKey::from_slice(key);
    let nonce = ChaChaNonce::from_slice(nonce);
    
    // Initialize cipher
    let cipher = ChaCha20Poly1305::new(key);
    
    // Decrypt and verify authenticity
    cipher.decrypt(nonce, ciphertext).expect("ChaCha20Poly1305 decryption failure")
}

// ====================================================
// HASHING: SHA-256
// ====================================================
// SHA-256 (Secure Hash Algorithm 256 bits) is a cryptographic hash function
// that produces a 256-bit (32 byte) digest from any data.
// 
// Properties:
// - Deterministic: same input → same output
// - Collision resistant: hard to find two inputs with same output
// - Avalanche effect: small input change → large output change
// - Used in Bitcoin, SSL certs, digital signatures, etc.
fn hash_sha256(message: &[u8]) -> Vec<u8> {
    // Initialize SHA-256 hasher
    let mut hasher = Sha256::new();
    
    // Update hasher with input data
    hasher.update(message);
    
    // Finalize and get 256-bit (32 byte) hash
    hasher.finalize().to_vec()
}

// ====================================================
// HASHING: Double SHA-256
// ====================================================
// Double SHA-256 is used in Bitcoin for extra security.
// Process: apply SHA-256 twice: SHA-256(SHA-256(message))
// 
// Used in:
// - Bitcoin transactions
// - Blockchain structure
// - Proof of work (mining)
fn hash_double_sha256(message: &[u8]) -> Vec<u8> {
    // First pass of SHA-256
    let hash1 = hash_sha256(message);
    
    // Second pass of SHA-256 on first result
    hash_sha256(&hash1)
}

// ====================================================
// HASHING: Blake2b
// ====================================================
// Blake2b is a cryptographic hash function optimized for 64-bit platforms
// with configurable output size up to 512 bits.
// 
// Features:
// - Faster than MD5, SHA-1, SHA-2, and SHA-3
// - Highly secure against collision attacks
// - Parameterizable output (variable size)
// - Can function as a MAC (Message Authentication Code)
// - Used in projects like Argon2 and for file hashing
fn hash_blake2b(message: &[u8]) -> Vec<u8> {
    // Initialize Blake2b hasher with 512-bit output
    let mut hasher = Blake2b512::new();
    
    // Update hasher with input data
    hasher.update(message);
    
    // Finalize and get 512-bit (64 byte) hash
    hasher.finalize().to_vec()
}

// ====================================================
// HASHING: Blake2s
// ====================================================
// Blake2s is a variant of Blake2 optimized for 32-bit platforms
// with output size up to 256 bits.
// 
// Features:
// - More efficient on resource-constrained devices
// - Ideal for embedded environments or IoT
// - Good performance on 32-bit processors
// - Suitable for memory-constrained applications
fn hash_blake2s(message: &[u8]) -> Vec<u8> {
    // Initialize Blake2s hasher with 256-bit output
    let mut hasher = Blake2s256::new();
    
    // Update hasher with input data
    hasher.update(message);
    
    // Finalize and get 256-bit (32 byte) hash
    hasher.finalize().to_vec()
}

// ====================================================
// HASHING: Blake3
// ====================================================
// Blake3 is the latest evolution in the Blake family, designed to be
// extremely fast with enhanced security.
// 
// Features:
// - Much faster than Blake2 and other algorithms
// - Parallelizable (efficiently uses multiple cores)
// - Ideal for hashing large files
// - Extendable output size (XOF - Extendable Output Function)
// - Resistant to side-channel attacks
fn hash_blake3(message: &[u8]) -> Vec<u8> {
    // Initialize Blake3 hasher
    let mut hasher = Blake3Hasher::new();
    
    // Update hasher with input data
    hasher.update(message);
    
    // Finalize and get hash (32 bytes by default)
    let mut output = [0u8; 32]; // 256 bits
    hasher.finalize_xof().fill(&mut output);
    
    output.to_vec()
}

// ====================================================
// DIGITAL SIGNATURE: Ed25519
// ====================================================
// Ed25519 is an elliptic curve signature algorithm that offers
// high security with compact keys and signatures.
// 
// Features:
// - 32-byte public keys
// - 64-byte signatures
// - Very fast
// - Used in Solana, SSH, TLS, and other modern protocols
fn ed25519_example(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Box<dyn std::error::Error>> {
    // Create deterministic key to reproduce same result each time
    // In real use, this key should be randomly generated and kept secret
    let seed = [1u8; 32]; // Fixed 32-byte seed
    
    // Create signing key from seed
    let signing_key = SigningKey::from_bytes(&seed);
    
    // Derive verifying key (public key) from signing key
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Sign message with private key
    let signature = signing_key.sign(message);
    
    // Verify signature with public key
    let verification = ed25519_dalek::Verifier::verify(&verifying_key, message, &signature).is_ok();
    
    // Return public key, signature and verification result
    Ok((verifying_key.to_bytes().to_vec(), signature.to_bytes().to_vec(), verification))
}

// ====================================================
// DIGITAL SIGNATURE: Secp256k1
// ====================================================
// Secp256k1 is the elliptic curve used by Bitcoin for signatures.
// It's a well-established standard for cryptocurrency systems.
// 
// Features:
// - Elliptic curve with special properties making it efficient
// - Used by Bitcoin, Ethereum, and other blockchains
// - More complex but equally secure as Ed25519
fn secp256k1_example(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Box<dyn std::error::Error>> {
    // Initialize Secp256k1 context
    let secp = Secp256k1::new();
    
    // Create deterministic key (for reproducibility)
    // In real use, this key would be randomly generated
    let secret_key_bytes = [42u8; 32]; // Deterministic 32-byte private key
    
    // Create private key from bytes
    let secret_key = secp256k1::SecretKey::from_slice(&secret_key_bytes)?;
    
    // Derive public key from private key
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    
    // For signing, we need a 32-byte hash of the message
    let hash = hash_sha256(message);
    
    // Create Secp256k1 message from hash
    let secp_msg = Secp256k1Message::from_digest_slice(&hash)?;
    
    // Sign the message
    let signature = secp.sign_ecdsa(&secp_msg, &secret_key);
    
    // Verify signature
    let verification = secp.verify_ecdsa(&secp_msg, &signature, &public_key).is_ok();
    
    // Return private key, public key and verification result
    Ok((secret_key.secret_bytes().to_vec(), 
        public_key.serialize().to_vec(), 
        verification))
}

// ====================================================
// Main Program
// ====================================================
fn main() {
    // Default values (don't use in production!)
    let default_key = "0000000000000000000000000000070080000000000000000000000000000000";
    let default_iv = "000000000000000000000000";
    let default_msg = "Hello World";
    
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Determine message and method
    let (msg, method) = if args.len() > 2 {
        // If two or more arguments, first is message, second is method
        (args[1].as_str(), args[2].as_str())
    } else if args.len() > 1 {
        // If only one argument, it's the message, default method is AES
        (args[1].as_str(), "aes")
    } else {
        // If no arguments, use default values
        (default_msg, "aes")
    };

    println!("== Encryption/Decryption/Hashing ==");
    println!("Method: {}", method);
    println!("Message: {:?}", msg);
    
    // Convert strings to bytes
    let key_bytes = hex_to_bytes(default_key);
    let nonce_bytes = hex_to_bytes(default_iv);
    let plain = msg.as_bytes();

    // If method is "all", run all algorithms
    if method == "all" {
        run_aes_gcm(plain, &key_bytes, &nonce_bytes);
        run_chacha20poly1305(plain, &key_bytes, &nonce_bytes);
        run_sha256(plain);
        run_double_sha256(plain);
        run_blake2b(plain);
        run_blake2s(plain);
        run_blake3(plain);
        run_ed25519(plain);
        run_secp256k1(plain);
        return;
    }

    // Otherwise, choose specified processing method
    match method {
        "aes" => run_aes_gcm(plain, &key_bytes, &nonce_bytes),
        "chacha" => run_chacha20poly1305(plain, &key_bytes, &nonce_bytes),
        "sha256" => run_sha256(plain),
        "double-sha256" => run_double_sha256(plain),
        "blake2b" => run_blake2b(plain),
        "blake2s" => run_blake2s(plain),
        "blake3" => run_blake3(plain),
        "ed25519" => run_ed25519(plain),
        "secp256k1" => run_secp256k1(plain),
        _ => {
            println!("\nUnrecognized algorithm. Available options:");
            println!("  aes: AES-GCM (default)");
            println!("  chacha: ChaCha20-Poly1305");
            println!("  sha256: SHA-256 (Bitcoin)");
            println!("  double-sha256: Double SHA-256 (Bitcoin)");
            println!("  blake2b: Blake2b (512 bits)");
            println!("  blake2s: Blake2s (256 bits)");
            println!("  blake3: Blake3 (256 bits by default)");
            println!("  ed25519: Ed25519 (Solana)");
            println!("  secp256k1: Secp256k1 (Bitcoin)");
            println!("  all: Run all algorithms");
        }
    }
}

// Dedicated execution functions for each algorithm to simplify "all" mode handling

fn run_aes_gcm(plain: &[u8], key_bytes: &[u8], nonce_bytes: &[u8]) {
    println!("\n== AES-GCM ==");
    println!("Description: AES-GCM is a symmetric encryption algorithm used for both encryption");
    println!("and authentication of data. It's used in TLS, IPsec and other protocols.");
    
    let ciphertext = encrypt_aes_gcm(plain, key_bytes, nonce_bytes);
    let decrypted_text = decrypt_aes_gcm(&ciphertext, key_bytes, nonce_bytes);
    
    println!("Encrypted: {}", hex::encode(&ciphertext));
    println!("Successful decryption");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_text));
}

fn run_chacha20poly1305(plain: &[u8], key_bytes: &[u8], nonce_bytes: &[u8]) {
    println!("\n== ChaCha20-Poly1305 ==");
    println!("Description: ChaCha20-Poly1305 is a modern encryption algorithm");
    println!("that performs well in software and resists timing attacks.");
    println!("It's used in TLS 1.3, Wireguard and other modern protocols.");
    
    let ciphertext = encrypt_chacha20poly1305(plain, key_bytes, nonce_bytes);
    let decrypted_text = decrypt_chacha20poly1305(&ciphertext, key_bytes, nonce_bytes);
    
    println!("Encrypted: {}", hex::encode(&ciphertext));
    println!("Successful decryption");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_text));
}

fn run_sha256(plain: &[u8]) {
    println!("\n== SHA-256 (Bitcoin) ==");
    println!("Description: SHA-256 is a cryptographic hash function that produces");
    println!("a 256-bit digest. It's used in Bitcoin, SSL and many");
    println!("security protocols.");
    
    let hash = hash_sha256(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_double_sha256(plain: &[u8]) {
    println!("\n== Double SHA-256 (Bitcoin) ==");
    println!("Description: Double SHA-256 means applying SHA-256 twice");
    println!("SHA-256(SHA-256(message)). This method is used in Bitcoin");
    println!("for transactions and proof of work.");
    
    let hash = hash_double_sha256(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_blake2b(plain: &[u8]) {
    println!("\n== Blake2b ==");
    println!("Description: Blake2b is a cryptographic hash function");
    println!("optimized for 64-bit platforms with a 512-bit output.");
    println!("It's faster than MD5, SHA-1, SHA-2, and SHA-3, while offering");
    println!("high security.");
    
    let hash = hash_blake2b(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_blake2s(plain: &[u8]) {
    println!("\n== Blake2s ==");
    println!("Description: Blake2s is a variant of Blake2 optimized for");
    println!("32-bit platforms with a 256-bit output.");
    println!("Ideal for embedded systems and resource-constrained devices.");
    
    let hash = hash_blake2s(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_blake3(plain: &[u8]) {
    println!("\n== Blake3 ==");
    println!("Description: Blake3 is the latest algorithm in the Blake family,");
    println!("designed to be extremely fast with enhanced security.");
    println!("It's parallelizable and ideal for hashing large files.");
    
    let hash = hash_blake3(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_ed25519(plain: &[u8]) {
    println!("\n== Ed25519 (Solana) ==");
    println!("Description: Ed25519 is an elliptic curve signature algorithm");
    println!("with compact keys and signatures. It's used in Solana,");
    println!("SSH, and many modern protocols.");
    
    match ed25519_example(plain) {
        Ok((public_key, signature, verification)) => {
            println!("Public key: {}", hex::encode(&public_key));
            println!("Signature: {}", hex::encode(&signature));
            println!("Verification: {}", if verification { "Success" } else { "Failed" });
        },
        Err(e) => {
            println!("Ed25519 operation failed: {}", e);
        }
    }
}

fn run_secp256k1(plain: &[u8]) {
    println!("\n== Secp256k1 (Bitcoin) ==");
    println!("Description: Secp256k1 is the elliptic curve used by Bitcoin");
    println!("for signatures. It's also used by Ethereum and");
    println!("other blockchains.");
    
    match secp256k1_example(plain) {
        Ok((secret_key, public_key, verification)) => {
            println!("Secret key: {}", hex::encode(&secret_key));
            println!("Public key: {}", hex::encode(&public_key));
            println!("Verification: {}", if verification { "Success" } else { "Failed" });
        },
        Err(e) => {
            println!("Secp256k1 operation failed: {}", e);
        }
    }
}