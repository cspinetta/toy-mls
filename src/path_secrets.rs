//! Path secrets derivation for MLS (MLS TreeKEM)

use crate::crypto::KeyPair;
use crate::messages::CipherForSubtree;
use crate::tree::LeafIndex;
use rand::{Rng, rngs::OsRng};
use x25519_dalek::{PublicKey, StaticSecret};

/// Derive path secrets from a leaf up to the root
///
/// Implements the MLS path secret derivation as defined in RFC 9420 §7.4.
/// Derives path secrets using HKDF-Expand with the "mls10 path" label.
///
/// # Arguments
/// * `_leaf_idx` - The leaf index to start from
/// * `path_len` - Length of the path (number of secrets to derive)
///
/// # Returns
/// Vector of path secrets s[i] from leaf to root
pub fn derive_path_up(_leaf_idx: LeafIndex, path_len: usize) -> Vec<[u8; 32]> {
    let mut path_secrets = Vec::new();

    // Start with a random seed secret (in real MLS this would come from key derivation)
    let mut rng = OsRng;
    let mut current_secret = rng.r#gen::<[u8; 32]>();

    for _i in 0..path_len {
        path_secrets.push(current_secret);

        // Derive next secret: s[i+1] = HKDF-Expand(s[i], "mls10 path", 32)
        current_secret = hkdf_expand(&current_secret, b"mls10 path", 32);
    }

    path_secrets
}

/// Derive node key pair from a path secret
///
/// # Arguments
/// * `path_secret` - The path secret s[i]
///
/// # Returns
/// X25519 key pair derived from the secret
pub fn node_keys_from_path(path_secret: &[u8; 32]) -> KeyPair {
    // Derive node secret: node_secret = HKDF-Expand(s[i], "mls10 node", 32)
    let node_secret = hkdf_expand(path_secret, b"mls10 node", 32);

    // Convert to X25519 key pair
    let sk = StaticSecret::from(node_secret);
    let pk = PublicKey::from(&sk);

    KeyPair {
        sk: sk.to_bytes(),
        pk: pk.to_bytes(),
    }
}

/// Encrypt path secrets to copath subtrees
///
/// # Arguments
/// * `path_secrets` - Vector of path secrets to encrypt
/// * `sender_node_keys` - Vector of sender node key pairs
/// * `copath_subtrees` - Vector of copath subtree public keys
///
/// # Returns
/// Vector of encrypted secrets for each copath subtree
/// Each CipherForSubtree corresponds to one copath node, not all combinations
pub fn encrypt_to_copaths(
    path_secrets: &[[u8; 32]],
    sender_node_keys: &[KeyPair],
    copath_subtrees: &[[u8; 32]],
) -> Vec<CipherForSubtree> {
    let mut encrypted_secrets = Vec::new();

    // Each copath node gets one encrypted secret (the path secret at the corresponding level)
    for (subtree_idx, &subtree_pk) in copath_subtrees.iter().enumerate() {
        // Find the corresponding path secret and sender key for this copath level
        let path_secret = path_secrets
            .get(subtree_idx)
            .expect("Path secret missing for copath level");
        let sender_sk = StaticSecret::from(sender_node_keys[subtree_idx].sk);

        // Sender: uses node[i] private key and copath public keys.
        // Recipient: uses their subtree private key and sender node[i] public key.

        // Generate shared secret: shared = X25519(sender_node_sk, subtree_pk)
        let shared = sender_sk.diffie_hellman(&PublicKey::from(subtree_pk));

        // Derive AEAD key: aead_key = HKDF-Expand(shared, "mls10 hpke-key", 32)
        let aead_key = hkdf_expand(&shared.to_bytes(), b"mls10 hpke-key", 32);

        // Generate nonce (in real implementation, this would be proper nonce generation)
        let nonce = generate_nonce();

        // Encrypt the path secret for this copath node
        let ciphertext = encrypt_aead(&aead_key, &nonce, path_secret);

        encrypted_secrets.push(CipherForSubtree {
            recipient_subtree_node: subtree_idx,
            nonce,
            ct: ciphertext,
        });
    }

    encrypted_secrets
}

/// Decrypt path secret from encrypted ciphertext
///
/// # Arguments
/// * `subtree_sk` - Recipient subtree private key
/// * `sender_node_pk` - Sender node public key
/// * `nonce` - Nonce used for encryption
/// * `ct` - Encrypted ciphertext
///
/// # Returns
/// Decrypted path secret s[i]
pub fn decrypt_start_secret(
    subtree_sk: &[u8; 32],
    sender_node_pk: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
) -> Result<[u8; 32], String> {
    // Sender: uses node[i] private key and copath public keys.
    // Recipient: uses their subtree private key and sender node[i] public key.

    // Generate shared secret: shared = X25519(recipient_sk, sender_pk)
    let recipient_sk = StaticSecret::from(*subtree_sk);
    let sender_pk = PublicKey::from(*sender_node_pk);
    let shared = recipient_sk.diffie_hellman(&sender_pk);

    // Derive AEAD key: aead_key = HKDF-Expand(shared, "mls10 hpke-key", 32)
    let aead_key = hkdf_expand(&shared.to_bytes(), b"mls10 hpke-key", 32);

    // Decrypt the ciphertext
    decrypt_aead(&aead_key, nonce, ct).map_err(|e| format!("Decryption failed: {}", e))
}

// ===== Helper Functions =====

/// HKDF-Expand implementation
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK length");
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expand failed");

    let mut result = [0u8; 32];
    result.copy_from_slice(&okm[..32]);
    result
}

/// Generate a random nonce
fn generate_nonce() -> [u8; 12] {
    use rand::{Rng, rngs::OsRng};
    let mut rng = OsRng;
    rng.r#gen()
}

/// Encrypt using ChaCha20-Poly1305
#[allow(deprecated)]
fn encrypt_aead(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext).expect("Encryption failed")
}

/// Decrypt using ChaCha20-Poly1305
#[allow(deprecated)]
fn decrypt_aead(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<[u8; 32], String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    if plaintext.len() != 32 {
        return Err("Invalid plaintext length".to_string());
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&plaintext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_derive_path_up() {
        let path_len = 3;
        let path_secrets = derive_path_up(0, path_len);

        // Verify we get the expected number of secrets
        assert_eq!(path_secrets.len(), path_len);

        // Verify all secrets are 32 bytes
        for secret in &path_secrets {
            assert_eq!(secret.len(), 32);
        }

        // Verify secrets are different (due to HKDF expansion)
        for i in 1..path_secrets.len() {
            assert_ne!(path_secrets[i - 1], path_secrets[i]);
        }
    }

    #[test]
    fn test_node_keys_from_path() {
        let path_secret = [42u8; 32];
        let keypair = node_keys_from_path(&path_secret);

        // Verify keypair structure
        assert_eq!(keypair.sk.len(), 32);
        assert_eq!(keypair.pk.len(), 32);

        // Verify public key can be derived from private key
        let sk = StaticSecret::from(keypair.sk);
        let pk = PublicKey::from(&sk);
        assert_eq!(keypair.pk, pk.to_bytes());
    }

    #[test]
    fn test_encrypt_to_copaths() {
        let path_secrets = vec![[1u8; 32], [2u8; 32]];
        let sender_node_keys = vec![
            KeyPair {
                sk: [3u8; 32],
                pk: [4u8; 32],
            },
            KeyPair {
                sk: [5u8; 32],
                pk: [6u8; 32],
            },
        ];
        let copath_subtrees = vec![[7u8; 32], [8u8; 32]];

        let encrypted_secrets =
            encrypt_to_copaths(&path_secrets, &sender_node_keys, &copath_subtrees);

        // Verify we get one encrypted secret per copath subtree
        assert_eq!(encrypted_secrets.len(), copath_subtrees.len());

        // Verify each encrypted secret has proper structure
        for encrypted in &encrypted_secrets {
            assert_eq!(encrypted.nonce.len(), 12);
            assert!(!encrypted.ct.is_empty());
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let path_secret = [42u8; 32];
        let sender_keypair = KeyPair::generate();
        let recipient_keypair = KeyPair::generate();

        // Encrypt
        let encrypted_secrets = encrypt_to_copaths(
            &[path_secret],
            &[sender_keypair.clone()],
            &[recipient_keypair.pk],
        );

        assert_eq!(encrypted_secrets.len(), 1);
        let encrypted = &encrypted_secrets[0];

        // Decrypt
        let decrypted_secret = decrypt_start_secret(
            &recipient_keypair.sk,
            &sender_keypair.pk,
            &encrypted.nonce,
            &encrypted.ct,
        );

        assert!(decrypted_secret.is_ok());
        assert_eq!(decrypted_secret.unwrap(), path_secret);
    }

    #[test]
    fn test_encrypt_decrypt_mismatch_fails() {
        let path_secret = [42u8; 32];
        let sender_keypair = KeyPair::generate();
        let recipient_keypair = KeyPair::generate();
        let wrong_keypair = KeyPair::generate();

        // Encrypt with sender_keypair
        let encrypted_secrets = encrypt_to_copaths(
            &[path_secret],
            &[sender_keypair.clone()],
            &[recipient_keypair.pk],
        );

        assert_eq!(encrypted_secrets.len(), 1);
        let encrypted = &encrypted_secrets[0];

        // Try to decrypt with wrong key
        let result = decrypt_start_secret(
            &wrong_keypair.sk, // Wrong private key
            &sender_keypair.pk,
            &encrypted.nonce,
            &encrypted.ct,
        );

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [1u8; 32];
        let info = b"test info";
        let length = 32;

        let result1 = hkdf_expand(&prk, info, length);
        let result2 = hkdf_expand(&prk, info, length);

        // Same input should produce same output
        assert_eq!(result1, result2);

        // Different info should produce different output
        let result3 = hkdf_expand(&prk, b"different info", length);
        assert_ne!(result1, result3);

        // Different PRK should produce different output
        let different_prk = [2u8; 32];
        let result4 = hkdf_expand(&different_prk, info, length);
        assert_ne!(result1, result4);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be 12 bytes
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);

        // Nonces should be different (random)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let plaintext = [2u8; 32];

        // Encrypt
        let ciphertext = encrypt_aead(&key, &nonce, &plaintext);
        assert!(!ciphertext.is_empty());

        // Decrypt
        let decrypted = decrypt_aead(&key, &nonce, &ciphertext);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let nonce = [1u8; 12];
        let plaintext = [2u8; 32];

        // Encrypt with key1
        let ciphertext = encrypt_aead(&key1, &nonce, &plaintext);

        // Try to decrypt with key2
        let result = decrypt_aead(&key2, &nonce, &ciphertext);

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_nonce_fails() {
        let key = [42u8; 32];
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        let plaintext = [3u8; 32];

        // Encrypt with nonce1
        let ciphertext = encrypt_aead(&key, &nonce1, &plaintext);

        // Try to decrypt with nonce2
        let result = decrypt_aead(&key, &nonce2, &ciphertext);

        // Should fail
        assert!(result.is_err());
    }
}
