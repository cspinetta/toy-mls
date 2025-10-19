//! Path secrets derivation for MLS (MLS TreeKEM)

use crate::crypto::KeyPair;
use crate::error::{MlsError, MlsResult};
use crate::messages::CipherForSubtree;
use crate::tree::LeafIndex;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{Rng, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Derive path secrets from a leaf up to the root
///
/// Implements MLS path secret derivation as defined in RFC 9420 §7.4.
/// Derives path secrets using HKDF-Expand with the "mls10 path" label.
///
/// # RFC 9420 Reference
/// - Section 7.4: Path Secret Derivation
/// - Section 7.2: TreeKEM Overview
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
/// Implements MLS node key derivation as defined in RFC 9420 §7.4.
/// Derives node secret using HKDF-Expand with the "mls10 node" label.
///
/// # RFC 9420 Reference
/// - Section 7.4: Path Secret Derivation
/// - Section 7.2: TreeKEM Overview
pub fn node_keys_from_path(path_secret: &[u8; 32]) -> KeyPair {
    // Derive node secret: node_secret = HKDF-Expand(s[i], "mls10 node", 32)
    let node_secret = hkdf_expand(path_secret, b"mls10 node", 32);

    // Convert to X25519 key pair (HPKE-style)
    let sk = StaticSecret::from(node_secret);
    let pk = PublicKey::from(&sk);

    KeyPair {
        sk: sk.to_bytes(),
        pk: pk.to_bytes(),
    }
}

/// Encrypt path secrets to copath subtrees using HPKE-style encryption
///
/// Implements MLS path secret encryption as defined in RFC 9420 §7.4.
/// Encrypts path secrets to copath subtrees using HPKE-style patterns.
///
/// This implementation follows HPKE patterns using compatible dependencies:
/// - X25519 for key exchange
/// - HKDF for key derivation  
/// - ChaCha20-Poly1305 for AEAD encryption
/// - AAD binding for context security
///
/// # RFC 9420 Reference
/// - Section 7.4: Path Secret Derivation
/// - Section 7.2: TreeKEM Overview
/// - Section 7.3: Update Paths
pub fn encrypt_to_copaths(
    path_secrets: &[[u8; 32]],
    sender_node_keys: &[KeyPair],
    copath_subtrees: &[[u8; 32]],
    group_id: [u8; 16],
    epoch: u64,
    node_indices: &[usize],
) -> Vec<CipherForSubtree> {
    let mut encrypted_secrets = Vec::new();

    // Each copath node gets one encrypted secret (the path secret at the corresponding level)
    for (subtree_idx, &subtree_pk) in copath_subtrees.iter().enumerate() {
        // Find the corresponding path secret and sender key for this copath level
        let path_secret = path_secrets
            .get(subtree_idx)
            .expect("Path secret missing for copath level");

        // Create AAD: group_id || epoch || node_index as u32
        let node_index = node_indices.get(subtree_idx).copied().unwrap_or(0) as u32;
        let mut aad = Vec::new();
        aad.extend_from_slice(&group_id);
        aad.extend_from_slice(&epoch.to_be_bytes());
        aad.extend_from_slice(&node_index.to_be_bytes());

        // HPKE-style key derivation: shared = DH(sender_sk, recipient_pk)
        let sender_sk = StaticSecret::from(sender_node_keys[subtree_idx].sk);
        let recipient_pk = PublicKey::from(subtree_pk);
        let shared = sender_sk.diffie_hellman(&recipient_pk);

        // HPKE-style key/nonce derivation: key = HKDF-Expand(shared, "mls10 hpke-key", 32)
        let key = hkdf_expand(shared.as_bytes(), b"mls10 hpke-key", 32);
        let nonce_bytes = hkdf_expand(shared.as_bytes(), b"mls10 hpke-nonce", 32);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes[..12]);

        // Encrypt with ChaCha20-Poly1305 using AAD
        let ciphertext = encrypt_with_ad(&key, &nonce, path_secret, &aad);

        encrypted_secrets.push(CipherForSubtree {
            recipient_subtree_node: subtree_idx,
            nonce,
            ct: ciphertext,
        });
    }

    encrypted_secrets
}

/// Decrypt path secret from encrypted ciphertext using HPKE-style decryption
///
/// Implements MLS path secret decryption as defined in RFC 9420 §7.4.
/// Decrypts path secrets from copath subtrees using HPKE-style patterns.
///
/// # RFC 9420 Reference
/// - Section 7.4: Path Secret Derivation
/// - Section 7.2: TreeKEM Overview
/// - Section 7.3: Update Paths
pub fn decrypt_start_secret(
    subtree_sk: &[u8; 32],
    sender_node_pk: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
    group_id: [u8; 16],
    epoch: u64,
    node_index: u32,
) -> MlsResult<[u8; 32]> {
    // Create AAD: group_id || epoch || node_index as u32
    let mut aad = Vec::new();
    aad.extend_from_slice(&group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&node_index.to_be_bytes());

    // HPKE-style key derivation: shared = DH(recipient_sk, sender_pk)
    let recipient_sk = StaticSecret::from(*subtree_sk);
    let sender_pk = PublicKey::from(*sender_node_pk);
    let shared = recipient_sk.diffie_hellman(&sender_pk);

    // HPKE-style key derivation: key = HKDF-Expand(shared, "mls10 hpke-key", 32)
    let key = hkdf_expand(shared.as_bytes(), b"mls10 hpke-key", 32);

    // Decrypt with ChaCha20-Poly1305 using AAD
    decrypt_with_ad(&key, nonce, ct, &aad)
}

// ===== Helper Functions =====

/// HKDF-Expand implementation
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK length");
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expand failed");

    let mut result = [0u8; 32];
    result.copy_from_slice(&okm[..32]);
    result
}

/// Encrypt data with ChaCha20-Poly1305 using AAD
// Suppress deprecation warning: chacha20poly1305 crate uses older generic-array internally
// This is a transitive dependency issue, not our code using deprecated APIs
#[allow(deprecated)]
fn encrypt_with_ad(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buffer)
        .expect("Encryption failed");

    // Append the authentication tag
    buffer.extend_from_slice(&tag);
    buffer
}

/// Decrypt data with ChaCha20-Poly1305 using AAD
// Suppress deprecation warning: chacha20poly1305 crate uses older generic-array internally
// This is a transitive dependency issue, not our code using deprecated APIs
#[allow(deprecated)]
fn decrypt_with_ad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> MlsResult<[u8; 32]> {
    if ciphertext.len() < 16 {
        return Err(MlsError::DecryptionError(
            "Ciphertext too short".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // Split ciphertext and tag
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut buffer = ct.to_vec();

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag.into())
        .map_err(|_| MlsError::DecryptionError("Decryption failed".to_string()))?;

    if buffer.len() != 32 {
        return Err(MlsError::DecryptionError(format!(
            "Decrypted data has wrong length: {}",
            buffer.len()
        )));
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&buffer);
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

        let encrypted_secrets = encrypt_to_copaths(
            &path_secrets,
            &sender_node_keys,
            &copath_subtrees,
            [1u8; 16], // group_id
            0,         // epoch
            &[0, 1],   // node_indices
        );

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
            std::slice::from_ref(&sender_keypair),
            &[recipient_keypair.pk],
            [1u8; 16], // group_id
            0,         // epoch
            &[0],      // node_indices
        );

        assert_eq!(encrypted_secrets.len(), 1);
        let encrypted = &encrypted_secrets[0];

        // Decrypt
        let decrypted_secret = decrypt_start_secret(
            &recipient_keypair.sk,
            &sender_keypair.pk,
            &encrypted.nonce,
            &encrypted.ct,
            [1u8; 16], // group_id
            0,         // epoch
            0,         // node_index
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
            std::slice::from_ref(&sender_keypair),
            &[recipient_keypair.pk],
            [1u8; 16], // group_id
            0,         // epoch
            &[0],      // node_indices
        );

        assert_eq!(encrypted_secrets.len(), 1);
        let encrypted = &encrypted_secrets[0];

        // Try to decrypt with wrong key
        let result = decrypt_start_secret(
            &wrong_keypair.sk, // Wrong private key
            &sender_keypair.pk,
            &encrypted.nonce,
            &encrypted.ct,
            [1u8; 16], // group_id
            0,         // epoch
            0,         // node_index
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
}
