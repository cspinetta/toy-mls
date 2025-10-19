use crate::crypto::SigKeyPair;
use crate::tree::{LeafIndex, NodeIndex};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proposal {
    Add { key_package: KeyPackage },
    Remove { removed: LeafIndex },
    Update, // (we'll pack the actual UpdatePath only in the Commit)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub node_public: [u8; 32],                    // X25519 public of path node
    pub encrypted_secrets: Vec<CipherForSubtree>, // one per copath subtree
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherForSubtree {
    pub recipient_subtree_node: NodeIndex,
    pub nonce: [u8; 12],
    pub ct: Vec<u8>, // AEAD over path secret s[i]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub proposals: Vec<Proposal>, // or inline proposals to stay simple
    pub update_path: Option<Vec<UpdatePathNode>>,
    pub confirmation_tag: [u8; 32],
    pub signature: Vec<u8>, // Ed25519 signature over the commit
}

impl Commit {
    /// Compute signature over the commit
    pub fn compute_signature(&self, signing_key: &SigningKey) -> Vec<u8> {
        // Create a message to sign: proposals || update_path || confirmation_tag
        let mut message = Vec::new();

        // Serialize proposals (simplified - just count for now)
        message.extend_from_slice(&(self.proposals.len() as u32).to_be_bytes());

        // Serialize update_path (simplified - just presence and count)
        if let Some(ref update_path) = self.update_path {
            message.push(1); // Present
            message.extend_from_slice(&(update_path.len() as u32).to_be_bytes());
        } else {
            message.push(0); // Not present
        }

        // Add confirmation tag
        message.extend_from_slice(&self.confirmation_tag);

        // Sign the message
        let signature = signing_key.sign(&message);
        signature.to_bytes().to_vec()
    }

    /// Verify the signature of the commit
    pub fn verify_signature(&self, sender_sig_pk: &[u8; 32]) -> Result<(), String> {
        // Reconstruct the message that was signed
        let mut message = Vec::new();

        // Serialize proposals (simplified - just count for now)
        message.extend_from_slice(&(self.proposals.len() as u32).to_be_bytes());

        // Serialize update_path (simplified - just presence and count)
        if let Some(ref update_path) = self.update_path {
            message.push(1); // Present
            message.extend_from_slice(&(update_path.len() as u32).to_be_bytes());
        } else {
            message.push(0); // Not present
        }

        // Add confirmation tag
        message.extend_from_slice(&self.confirmation_tag);

        // Parse the signature
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;

        // Parse the verifying key
        let verifying_key =
            VerifyingKey::from_bytes(sender_sig_pk).map_err(|_| "Invalid verifying key")?;

        // Create signature object
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        // Verify the signature
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| "Signature verification failed")?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackage {
    pub cred_sig_pk: [u8; 32], // ed25519 public
    pub leaf_dh_pk: [u8; 32],  // X25519 leaf public
    pub signature: Vec<u8>,    // sig over the struct (self-authenticating)
}

impl KeyPackage {
    /// Create a new KeyPackage with a signature
    pub fn new(sig_keypair: &SigKeyPair, leaf_dh_pk: [u8; 32]) -> Self {
        let mut key_package = Self {
            cred_sig_pk: sig_keypair.pk.to_bytes(),
            leaf_dh_pk,
            signature: vec![], // Will be filled after signature computation
        };

        // Compute signature over the key package
        key_package.signature = key_package.compute_signature(&sig_keypair.sk);

        key_package
    }

    /// Compute signature over the key package
    fn compute_signature(&self, signing_key: &SigningKey) -> Vec<u8> {
        // Create a message to sign: cred_sig_pk || leaf_dh_pk
        let mut message = Vec::new();
        message.extend_from_slice(&self.cred_sig_pk);
        message.extend_from_slice(&self.leaf_dh_pk);

        // Sign the message
        let signature = signing_key.sign(&message);
        signature.to_bytes().to_vec()
    }

    /// Verify the signature of the key package
    pub fn verify_signature(&self) -> Result<(), String> {
        // Reconstruct the message that was signed
        let mut message = Vec::new();
        message.extend_from_slice(&self.cred_sig_pk);
        message.extend_from_slice(&self.leaf_dh_pk);

        // Parse the signature
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;

        // Parse the verifying key
        let verifying_key =
            VerifyingKey::from_bytes(&self.cred_sig_pk).map_err(|_| "Invalid verifying key")?;

        // Create signature object
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        // Verify the signature
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| "Signature verification failed")?;

        Ok(())
    }
}
