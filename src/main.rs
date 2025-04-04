// ====================================================
// PROGRAMME DE DÉMONSTRATION D'ALGORITHMES CRYPTOGRAPHIQUES
// ====================================================
// Ce programme démontre plusieurs algorithmes de chiffrement, hachage et signature
// utilisés dans la sécurité informatique et les cryptomonnaies.
// 
// Auteurs: Henri & Claude
// Licence: MIT

extern crate base64;
extern crate hex;
extern crate aes_gcm;
extern crate chacha20poly1305;
extern crate sha2;
extern crate ed25519_dalek;
extern crate secp256k1;

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

// Convertit une chaîne hexadécimale en tableau d'octets
// Exemple: "0A1B2C" devient [10, 27, 44]
fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s).unwrap()
}

// ====================================================
// CHIFFREMENT SYMÉTRIQUE: AES-GCM
// ====================================================
// AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) est un algorithme
// de chiffrement symétrique populaire qui offre à la fois confidentialité et authenticité.
// 
// Fonctionnement:
// 1. Utilise la même clé pour chiffrer et déchiffrer
// 2. Requiert un nonce (nombre utilisé une seule fois) pour assurer la sécurité
// 3. Produit un texte chiffré et un tag d'authentification
// 4. Utilisé dans TLS, SSH, et d'autres protocoles sécurisés
fn encrypt_aes_gcm(message: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Convertir les bytes en structures adaptées à l'API AES-GCM
    let key = Key::<Aes256>::from_slice(key);  // Clé AES-256 bits
    let nonce = Nonce::<U12>::from_slice(nonce);  // Nonce de 12 bytes (96 bits)
    
    // Initialiser le chiffreur AES-GCM
    let cipher = AesGcm::<Aes256, U12>::new(key);
    
    // Chiffrer le message (le tag d'authentification est automatiquement ajouté)
    cipher.encrypt(nonce, message).expect("Encryption failure")
}

fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Convertir les bytes en structures adaptées à l'API AES-GCM
    let key = Key::<Aes256>::from_slice(key);
    let nonce = Nonce::<U12>::from_slice(nonce);
    
    // Initialiser le chiffreur AES-GCM
    let cipher = AesGcm::<Aes256, U12>::new(key);
    
    // Déchiffrer le message et vérifier le tag d'authentification
    cipher.decrypt(nonce, ciphertext).expect("Decryption failure")
}

// ====================================================
// CHIFFREMENT SYMÉTRIQUE: ChaCha20-Poly1305
// ====================================================
// ChaCha20-Poly1305 est un AEAD (Authenticated Encryption with Associated Data)
// moderne qui combine le chiffrement par flux ChaCha20 avec l'authentification Poly1305.
// 
// Avantages:
// - Performant en logiciel (pas besoin d'accélération matérielle)
// - Résistant aux attaques temporelles (timing attacks)
// - Utilisé dans TLS 1.3, IETF, Wireguard, etc.
fn encrypt_chacha20poly1305(message: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Préparer la clé et le nonce
    let key = ChaChaKey::from_slice(key);  // Clé de 256 bits
    let nonce = ChaChaNonce::from_slice(nonce);  // Nonce de 96 bits
    
    // Initialiser le chiffreur
    let cipher = ChaCha20Poly1305::new(key);
    
    // Chiffrer le message (inclut un tag d'authentification)
    cipher.encrypt(nonce, message).expect("ChaCha20Poly1305 encryption failure")
}

fn decrypt_chacha20poly1305(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Préparer la clé et le nonce
    let key = ChaChaKey::from_slice(key);
    let nonce = ChaChaNonce::from_slice(nonce);
    
    // Initialiser le chiffreur
    let cipher = ChaCha20Poly1305::new(key);
    
    // Déchiffrer et vérifier l'authenticité
    cipher.decrypt(nonce, ciphertext).expect("ChaCha20Poly1305 decryption failure")
}

// ====================================================
// HACHAGE: SHA-256
// ====================================================
// SHA-256 (Secure Hash Algorithm 256 bits) est une fonction de hachage cryptographique
// qui produit une empreinte de 256 bits (32 octets) à partir de n'importe quelle donnée.
// 
// Propriétés:
// - Déterministe: même entrée → même sortie
// - Résistant aux collisions: difficile de trouver deux entrées avec même sortie
// - Effet avalanche: un petit changement cause un grand changement dans le hash
// - Utilisé dans Bitcoin, certificats SSL, signatures numériques, etc.
fn hash_sha256(message: &[u8]) -> Vec<u8> {
    // Initialiser le hasher SHA-256
    let mut hasher = Sha256::new();
    
    // Mettre à jour le hasher avec les données d'entrée
    hasher.update(message);
    
    // Finaliser et obtenir le hash de 256 bits (32 bytes)
    hasher.finalize().to_vec()
}

// ====================================================
// HACHAGE: Double SHA-256
// ====================================================
// Double SHA-256 est utilisé dans Bitcoin pour renforcer la sécurité.
// Le processus consiste à appliquer SHA-256 deux fois: SHA-256(SHA-256(message))
// 
// Utilisé dans:
// - Les transactions Bitcoin
// - La structure de la blockchain
// - La preuve de travail (mining)
fn hash_double_sha256(message: &[u8]) -> Vec<u8> {
    // Première passe de SHA-256
    let hash1 = hash_sha256(message);
    
    // Seconde passe de SHA-256 sur le résultat de la première
    hash_sha256(&hash1)
}

// ====================================================
// SIGNATURE NUMÉRIQUE: Ed25519
// ====================================================
// Ed25519 est un algorithme de signature à courbe elliptique qui offre
// un haut niveau de sécurité avec des clés et signatures compactes.
// 
// Caractéristiques:
// - Clés publiques de 32 bytes
// - Signatures de 64 bytes
// - Très rapide
// - Utilisé dans Solana, SSH, TLS, et d'autres protocoles modernes
fn ed25519_example(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Box<dyn std::error::Error>> {
    // Créer une clé déterministe pour reproduire le même résultat à chaque fois
    // Dans un cas réel, cette clé devrait être générée aléatoirement et conservée secrète
    let seed = [1u8; 32]; // Seed fixe de 32 bytes
    
    // Créer la clé de signature à partir de la seed
    let signing_key = SigningKey::from_bytes(&seed);
    
    // Dériver la clé de vérification (clé publique) à partir de la clé de signature
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Signer le message avec la clé privée
    let signature = signing_key.sign(message);
    
    // Vérifier la signature avec la clé publique
    let verification = ed25519_dalek::Verifier::verify(&verifying_key, message, &signature).is_ok();
    
    // Retourner la clé publique, la signature et le résultat de vérification
    Ok((verifying_key.to_bytes().to_vec(), signature.to_bytes().to_vec(), verification))
}

// ====================================================
// SIGNATURE NUMÉRIQUE: Secp256k1
// ====================================================
// Secp256k1 est la courbe elliptique utilisée par Bitcoin pour les signatures.
// C'est un standard bien établi pour les systèmes de cryptocurrencies.
// 
// Caractéristiques:
// - Courbe elliptique aux propriétés spéciales qui la rendent efficace
// - Utilisée par Bitcoin, Ethereum, et d'autres blockchains
// - Plus complexe mais tout aussi sécurisée que Ed25519
fn secp256k1_example(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Box<dyn std::error::Error>> {
    // Initialiser le contexte Secp256k1
    let secp = Secp256k1::new();
    
    // Créer une clé déterministe (pour reproductibilité)
    // Dans un cas réel, cette clé serait générée aléatoirement
    let secret_key_bytes = [42u8; 32]; // Clé privée déterministe de 32 bytes
    
    // Créer la clé privée à partir des bytes
    let secret_key = secp256k1::SecretKey::from_slice(&secret_key_bytes)?;
    
    // Dériver la clé publique à partir de la clé privée
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    
    // Pour signer, on a besoin d'un hash de 32 bytes du message
    let hash = hash_sha256(message);
    
    // Créer le message Secp256k1 à partir du hash
    let secp_msg = Secp256k1Message::from_digest_slice(&hash)?;
    
    // Signer le message
    let signature = secp.sign_ecdsa(&secp_msg, &secret_key);
    
    // Vérifier la signature
    let verification = secp.verify_ecdsa(&secp_msg, &signature, &public_key).is_ok();
    
    // Retourner la clé privée, la clé publique et le résultat de vérification
    Ok((secret_key.secret_bytes().to_vec(), 
        public_key.serialize().to_vec(), 
        verification))
}

// ====================================================
// Programme principal
// ====================================================
fn main() {
    // Valeurs par défaut (ne pas utiliser en production!)
    let default_key = "0000000000000000000000000000070080000000000000000000000000000000";
    let default_iv = "000000000000000000000000";
    let default_msg = "test for Lili & Arya";
    
    // Récupérer les arguments de la ligne de commande
    let args: Vec<String> = env::args().collect();
    
    // Déterminer le message et la méthode
    let (msg, method) = if args.len() > 2 {
        // Si deux arguments ou plus, le premier est le message, le second est la méthode
        (args[1].as_str(), args[2].as_str())
    } else if args.len() > 1 {
        // Si un seul argument, c'est le message, méthode par défaut est AES
        (args[1].as_str(), "aes")
    } else {
        // Si aucun argument, utiliser les valeurs par défaut
        (default_msg, "aes")
    };

    println!("== Encryption/Decryption/Hashing ==");
    println!("Method: {}", method);
    println!("Message: {:?}", msg);
    
    // Convertir les chaînes en bytes
    let key_bytes = hex_to_bytes(default_key);
    let nonce_bytes = hex_to_bytes(default_iv);
    let plain = msg.as_bytes();

    // Si la méthode est "all", exécuter tous les algorithmes
    if method == "all" {
        run_aes_gcm(plain, &key_bytes, &nonce_bytes);
        run_chacha20poly1305(plain, &key_bytes, &nonce_bytes);
        run_sha256(plain);
        run_double_sha256(plain);
        run_ed25519(plain);
        run_secp256k1(plain);
        return;
    }

    // Sinon, choisir la méthode de traitement spécifiée
    match method {
        "aes" => run_aes_gcm(plain, &key_bytes, &nonce_bytes),
        "chacha" => run_chacha20poly1305(plain, &key_bytes, &nonce_bytes),
        "sha256" => run_sha256(plain),
        "double-sha256" => run_double_sha256(plain),
        "ed25519" => run_ed25519(plain),
        "secp256k1" => run_secp256k1(plain),
        _ => {
            println!("\nAlgorithme non reconnu. Options disponibles :");
            println!("  aes: AES-GCM (par défaut)");
            println!("  chacha: ChaCha20-Poly1305");
            println!("  sha256: SHA-256 (Bitcoin)");
            println!("  double-sha256: Double SHA-256 (Bitcoin)");
            println!("  ed25519: Ed25519 (Solana)");
            println!("  secp256k1: Secp256k1 (Bitcoin)");
            println!("  all: Exécuter tous les algorithmes");
        }
    }
}

// Fonctions d'exécution dédiées à chaque algorithme pour simplifier la gestion du mode "all"

fn run_aes_gcm(plain: &[u8], key_bytes: &[u8], nonce_bytes: &[u8]) {
    println!("\n== AES-GCM ==");
    println!("Description: AES-GCM est un algorithme de chiffrement symétrique utilisé pour le chiffrement");
    println!("et l'authentification simultanée des données. Il est utilisé dans TLS, IPsec et d'autres protocoles.");
    
    let ciphertext = encrypt_aes_gcm(plain, key_bytes, nonce_bytes);
    let decrypted_text = decrypt_aes_gcm(&ciphertext, key_bytes, nonce_bytes);
    
    println!("Encrypted: {}", hex::encode(&ciphertext));
    println!("Successful decryption");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_text));
}

fn run_chacha20poly1305(plain: &[u8], key_bytes: &[u8], nonce_bytes: &[u8]) {
    println!("\n== ChaCha20-Poly1305 ==");
    println!("Description: ChaCha20-Poly1305 est un algorithme de chiffrement moderne");
    println!("performant en logiciel et résistant aux attaques temporelles.");
    println!("Il est utilisé dans TLS 1.3, Wireguard et d'autres protocoles modernes.");
    
    let ciphertext = encrypt_chacha20poly1305(plain, key_bytes, nonce_bytes);
    let decrypted_text = decrypt_chacha20poly1305(&ciphertext, key_bytes, nonce_bytes);
    
    println!("Encrypted: {}", hex::encode(&ciphertext));
    println!("Successful decryption");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_text));
}

fn run_sha256(plain: &[u8]) {
    println!("\n== SHA-256 (Bitcoin) ==");
    println!("Description: SHA-256 est une fonction de hachage cryptographique qui produit");
    println!("une empreinte de 256 bits. Elle est utilisée dans Bitcoin, SSL et de nombreux");
    println!("protocoles de sécurité.");
    
    let hash = hash_sha256(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_double_sha256(plain: &[u8]) {
    println!("\n== Double SHA-256 (Bitcoin) ==");
    println!("Description: Double SHA-256 consiste à appliquer SHA-256 deux fois");
    println!("SHA-256(SHA-256(message)). Cette méthode est utilisée dans Bitcoin");
    println!("pour les transactions et la preuve de travail.");
    
    let hash = hash_double_sha256(plain);
    println!("Hash: {}", hex::encode(&hash));
}

fn run_ed25519(plain: &[u8]) {
    println!("\n== Ed25519 (Solana) ==");
    println!("Description: Ed25519 est un algorithme de signature à courbe elliptique");
    println!("offrant des clés et signatures compactes. Il est utilisé dans Solana,");
    println!("SSH, et de nombreux protocoles modernes.");
    
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
    println!("Description: Secp256k1 est la courbe elliptique utilisée par Bitcoin");
    println!("pour les signatures. Elle est également utilisée par Ethereum et");
    println!("d'autres blockchains.");
    
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