Rust Cryptography Demonstration
A command-line tool demonstrating various cryptographic algorithms implemented in Rust, including encryption, hashing, and digital signatures. This project showcases common cryptographic operations used in computer security and cryptocurrencies.
Features

Symmetric Encryption

AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
ChaCha20-Poly1305


Hashing

SHA-256
Double SHA-256 (used in Bitcoin)


Digital Signatures

Ed25519 (used in Solana and other modern protocols)
Secp256k1 (used in Bitcoin, Ethereum, and other blockchains)



Installation
Make sure you have Rust and Cargo installed. If not, install them using rustup.
bashCopier# Clone the repository
git clone https://github.com/yourusername/rust-cryptography.git
cd rust-cryptography

# Build the project
cargo build --release
Usage
bashCopier# Run with default values (AES-GCM on "Hello World")
cargo run

# Specify a message
cargo run "My secret message"

# Specify a message and algorithm
cargo run "My secret message" aes
cargo run "My secret message" chacha
cargo run "My secret message" sha256
cargo run "My secret message" double-sha256
cargo run "My secret message" ed25519
cargo run "My secret message" secp256k1

# Run all algorithms on a message
cargo run "My secret message" all
Example Output
When running with the all option, you'll see output like this:
Copier== Encryption/Decryption/Hashing ==
Method: all
Message: "My secret message"

== AES-GCM ==
Description: AES-GCM is a symmetric encryption algorithm used for both encryption
and authentication of data. It's used in TLS, IPsec and other protocols.
Encrypted: a3b4c5d6...
Successful decryption
Decrypted: My secret message

== ChaCha20-Poly1305 ==
...
Security Note
This code is for educational purposes only. It uses fixed keys and nonces for reproducibility, which is not secure for actual applications. In production:

Use secure random number generators for keys and nonces
Do not reuse nonces with the same key
Implement proper key management
Consider additional security measures like key rotation

Dependencies

aes-gcm: AES-GCM implementation
chacha20poly1305: ChaCha20-Poly1305 implementation
sha2: SHA-2 hash functions
ed25519-dalek: Ed25519 digital signatures
secp256k1: Secp256k1 digital signatures
hex: Hex encoding/decoding
base64: Base64 encoding/decoding

License
MIT License

Démonstration de Cryptographie en Rust
Un outil en ligne de commande démontrant divers algorithmes cryptographiques implémentés en Rust, incluant le chiffrement, le hachage et les signatures numériques. Ce projet présente des opérations cryptographiques courantes utilisées dans la sécurité informatique et les cryptomonnaies.
Fonctionnalités

Chiffrement Symétrique

AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
ChaCha20-Poly1305


Hachage

SHA-256
Double SHA-256 (utilisé dans Bitcoin)


Signatures Numériques

Ed25519 (utilisé dans Solana et d'autres protocoles modernes)
Secp256k1 (utilisé dans Bitcoin, Ethereum, et d'autres blockchains)



Installation
Assurez-vous d'avoir Rust et Cargo installés. Si ce n'est pas le cas, installez-les via rustup.
bashCopier# Cloner le dépôt
git clone https://github.com/votreutilisateur/rust-cryptography.git
cd rust-cryptography

# Compiler le projet
cargo build --release
Utilisation
bashCopier# Exécuter avec les valeurs par défaut (AES-GCM sur "Hello World")
cargo run

# Spécifier un message
cargo run "Mon message secret"

# Spécifier un message et un algorithme
cargo run "Mon message secret" aes
cargo run "Mon message secret" chacha
cargo run "Mon message secret" sha256
cargo run "Mon message secret" double-sha256
cargo run "Mon message secret" ed25519
cargo run "Mon message secret" secp256k1

# Exécuter tous les algorithmes sur un message
cargo run "Mon message secret" all
Exemple de Sortie
Lors de l'exécution avec l'option all, vous verrez une sortie comme celle-ci:
Copier== Encryption/Decryption/Hashing ==
Method: all
Message: "Mon message secret"

== AES-GCM ==
Description: AES-GCM is a symmetric encryption algorithm used for both encryption
and authentication of data. It's used in TLS, IPsec and other protocols.
Encrypted: a3b4c5d6...
Successful decryption
Decrypted: Mon message secret

== ChaCha20-Poly1305 ==
...
Note de Sécurité
Ce code est à des fins éducatives uniquement. Il utilise des clés et des nonces fixes pour la reproductibilité, ce qui n'est pas sécurisé pour des applications réelles. En production:

Utilisez des générateurs de nombres aléatoires sécurisés pour les clés et les nonces
Ne réutilisez pas les nonces avec la même clé
Implémentez une gestion appropriée des clés
Envisagez des mesures de sécurité supplémentaires comme la rotation des clés

Dépendances

aes-gcm: Implémentation d'AES-GCM
chacha20poly1305: Implémentation de ChaCha20-Poly1305
sha2: Fonctions de hachage SHA-2
ed25519-dalek: Signatures numériques Ed25519
secp256k1: Signatures numériques Secp256k1
hex: Encodage/décodage Hex
base64: Encodage/décodage Base64

Licence
Licence MIT
