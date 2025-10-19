//! MLS secrets management

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{Rng, rngs::OsRng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 key pair for HPKE-style operations
///
/// The private key (sk) is automatically zeroized when dropped to prevent
/// it from lingering in memory.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub sk: [u8; 32],
    pub pk: [u8; 32],
}

impl KeyPair {
    /// Generate a new random X25519 key pair for HPKE-style operations
    pub fn generate() -> Self {
        let rng = OsRng;
        let sk = StaticSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);

        Self {
            sk: sk.to_bytes(),
            pk: pk.to_bytes(),
        }
    }
}

/// Ed25519 signature key pair for authentication
///
/// The signing key (sk) is automatically zeroized when dropped.
/// Note: SigningKey from ed25519_dalek already implements ZeroizeOnDrop.
#[derive(Clone, Debug)]
pub struct SigKeyPair {
    pub sk: SigningKey,
    pub pk: VerifyingKey,
}

impl SigKeyPair {
    /// Generate a new random Ed25519 signature key pair
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Self {
            sk: signing_key,
            pk: verifying_key,
        }
    }
}

/// MLS epoch secrets
///
/// These secrets are automatically zeroized when dropped to prevent them
/// from lingering in memory.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Secrets {
    pub epoch: [u8; 32],
    pub handshake_key: [u8; 32],
    pub app_key: [u8; 32],
    pub conf_key: [u8; 32],
}

impl Secrets {
    /// Generate new epoch secrets
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            epoch: rng.r#gen(),
            handshake_key: rng.r#gen(),
            app_key: rng.r#gen(),
            conf_key: rng.r#gen(),
        }
    }
}

impl Default for Secrets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();

        // Verify keypair has valid structure
        assert_eq!(keypair.sk.len(), 32);
        assert_eq!(keypair.pk.len(), 32);

        // Verify public key can be derived from private key
        let sk = StaticSecret::from(keypair.sk);
        let pk = PublicKey::from(&sk);
        assert_eq!(keypair.pk, pk.to_bytes());
    }

    #[test]
    fn test_sigkeypair_generation() {
        let sig_keypair = SigKeyPair::generate();

        // Verify sig keypair has valid structure
        assert_eq!(sig_keypair.sk.to_bytes().len(), 32);
        assert_eq!(sig_keypair.pk.to_bytes().len(), 32);

        // Verify public key can be derived from private key
        let pk_from_sk = VerifyingKey::from(&sig_keypair.sk);
        assert_eq!(sig_keypair.pk.to_bytes(), pk_from_sk.to_bytes());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = KeyPair::generate();

        // Test that we can reconstruct the keypair from bytes
        let sk = StaticSecret::from(keypair.sk);
        let pk = PublicKey::from(&sk);

        assert_eq!(keypair.sk, sk.to_bytes());
        assert_eq!(keypair.pk, pk.to_bytes());
    }

    #[test]
    fn test_sigkeypair_serialization() {
        let sig_keypair = SigKeyPair::generate();

        // Test that we can reconstruct the sig keypair from bytes
        let sk_bytes = sig_keypair.sk.to_bytes();
        let pk_bytes = sig_keypair.pk.to_bytes();

        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = VerifyingKey::from(&sk);

        assert_eq!(sk_bytes, sk.to_bytes());
        assert_eq!(pk_bytes, pk.to_bytes());
    }

    #[test]
    fn test_secrets_generation() {
        let secrets1 = Secrets::new();
        let secrets2 = Secrets::new();

        // Verify secrets have valid structure
        assert_eq!(secrets1.epoch.len(), 32);
        assert_eq!(secrets1.handshake_key.len(), 32);
        assert_eq!(secrets1.app_key.len(), 32);
        assert_eq!(secrets1.conf_key.len(), 32);

        // Verify secrets are different (random)
        assert_ne!(secrets1.epoch, secrets2.epoch);
        assert_ne!(secrets1.handshake_key, secrets2.handshake_key);
        assert_ne!(secrets1.app_key, secrets2.app_key);
        assert_ne!(secrets1.conf_key, secrets2.conf_key);
    }

    #[test]
    fn test_secrets_default() {
        let secrets1 = Secrets::default();
        let secrets2 = Secrets::new();

        // Both should generate random secrets
        assert_eq!(secrets1.epoch.len(), 32);
        assert_eq!(secrets1.handshake_key.len(), 32);
        assert_eq!(secrets1.app_key.len(), 32);
        assert_eq!(secrets1.conf_key.len(), 32);

        // They should be different (random)
        assert_ne!(secrets1.epoch, secrets2.epoch);
    }

    #[test]
    fn test_secrets_zeroization() {
        let secrets = Secrets::new();
        let epoch_secret = secrets.epoch;
        let handshake_key = secrets.handshake_key;
        let app_key = secrets.app_key;
        let conf_key = secrets.conf_key;

        // Verify secrets are not zero initially
        assert_ne!(epoch_secret, [0u8; 32]);
        assert_ne!(handshake_key, [0u8; 32]);
        assert_ne!(app_key, [0u8; 32]);
        assert_ne!(conf_key, [0u8; 32]);

        // The secrets will be zeroized when dropped (tested by the zeroize crate)
        // This test mainly verifies that the zeroize derive works without compilation errors
    }

    #[test]
    fn test_keypair_zeroization() {
        let keypair = KeyPair::generate();
        let sk = keypair.sk;
        let pk = keypair.pk;

        // Verify keys are not zero initially
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);

        // The private key will be zeroized when dropped (tested by the zeroize crate)
        // This test mainly verifies that the zeroize derive works without compilation errors
    }

    #[test]
    fn test_sigkeypair_zeroization() {
        let sig_keypair = SigKeyPair::generate();
        let sk_bytes = sig_keypair.sk.to_bytes();
        let pk_bytes = sig_keypair.pk.to_bytes();

        // Verify keys are not zero initially
        assert_ne!(sk_bytes, [0u8; 32]);
        assert_ne!(pk_bytes, [0u8; 32]);

        // The signing key will be zeroized when dropped (tested by the zeroize crate)
        // This test mainly verifies that the zeroize derive works without compilation errors
    }
}
