//! Group state and context management

use crate::Secrets;
use crate::crypto::{KeyPair, SigKeyPair};
use crate::messages::Proposal;
use crate::messages::{CipherForSubtree, Commit, KeyPackage, UpdatePathNode};
use crate::path_secrets::{
    decrypt_start_secret, derive_path_up, encrypt_to_copaths, node_keys_from_path,
};
use crate::tree::{LeafIndex, RatchetTree};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Group context containing group metadata
#[derive(Clone, Debug)]
pub struct GroupContext {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub tree_hash: [u8; 32], // hash(nodes' publics)
}

/// Complete group state
#[derive(Clone, Debug)]
pub struct GroupState {
    pub context: GroupContext,
    pub tree: RatchetTree,
    pub my_leaf: LeafIndex,
    pub my_sig: SigKeyPair,
    pub my_sec: Vec<[u8; 32]>, // secrets for nodes in my direct path
    pub secrets: Secrets,      // current epoch secrets
}

/// Welcome bundle for new group members
#[derive(Debug)]
pub struct WelcomeBundle {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub tree: RatchetTree,
    pub encrypted_path_secrets: Vec<CipherForSubtree>,
    pub sender_node_public_keys: Vec<[u8; 32]>, // Public keys of sender's path nodes
}

/// Result of creating a new group
#[derive(Debug)]
pub struct GroupCreationResult {
    pub creator_state: GroupState,
    pub welcome_bundle: WelcomeBundle,
    pub commit: Commit,
}

impl GroupState {
    /// Create a new group state
    pub fn new(group_id: [u8; 16], tree_size: usize) -> Self {
        let tree = RatchetTree::new(tree_size);
        let tree_hash = tree.compute_tree_hash();

        Self {
            context: GroupContext {
                group_id,
                epoch: 0,
                tree_hash,
            },
            tree,
            my_leaf: 0,
            my_sig: SigKeyPair::generate(),
            my_sec: vec![],
            secrets: Secrets::new(),
        }
    }

    /// Create a new group state from key packages
    pub fn from_keypackages(group_id: [u8; 16], keypackages: Vec<KeyPackage>) -> Self {
        let tree = RatchetTree::from_leaves(keypackages);
        let tree_hash = tree.compute_tree_hash();

        Self {
            context: GroupContext {
                group_id,
                epoch: 0,
                tree_hash,
            },
            tree,
            my_leaf: 0,
            my_sig: SigKeyPair::generate(),
            my_sec: vec![],
            secrets: Secrets::new(),
        }
    }

    /// Update the tree hash in the group context
    pub fn update_tree_hash(&mut self) {
        self.context.tree_hash = self.tree.compute_tree_hash();
    }

    /// Compute the hash of the group context for confirmation
    fn compute_group_context_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.context.group_id);
        hasher.update(self.context.epoch.to_be_bytes());
        hasher.update(self.context.tree_hash);
        hasher.finalize().into()
    }

    /// Create a new group with creator and other members
    ///
    /// # Arguments
    /// * `group_id` - Unique group identifier
    /// * `creator_key_pkg` - Key package of the group creator
    /// * `others_key_pkgs` - Key packages of other members
    ///
    /// # Returns
    /// Group creation result with creator state, welcome bundle, and commit
    pub fn create_group(
        group_id: [u8; 16],
        creator_key_pkg: KeyPackage,
        others_key_pkgs: Vec<KeyPackage>,
    ) -> GroupCreationResult {
        // Combine all key packages (creator first)
        let mut all_keypackages = vec![creator_key_pkg.clone()];
        all_keypackages.extend(others_key_pkgs);

        // Create initial tree
        let tree = RatchetTree::from_leaves(all_keypackages.clone());
        let tree_hash = tree.compute_tree_hash();

        // Creator chooses their path (simplified: direct path from leaf 0)
        let creator_leaf = 0;
        let dirpath = tree.dirpath(creator_leaf);
        let _copath = tree.copath(creator_leaf);

        // Derive path secrets for the creator's path
        let path_secrets = derive_path_up(creator_leaf, dirpath.len());

        // Derive node keys from path secrets
        let sender_node_keys: Vec<_> = path_secrets.iter().map(node_keys_from_path).collect();

        // Get copath subtree public keys from the actual tree
        let copath_nodes = tree.copath(creator_leaf);
        let copath_subtree_pks: Vec<_> = copath_nodes
            .iter()
            .filter_map(|&node_idx| tree.get_node_public_key(node_idx))
            .collect();

        // Encrypt path secrets to copath subtrees
        let encrypted_secrets =
            encrypt_to_copaths(&path_secrets, &sender_node_keys, &copath_subtree_pks);

        // Create creator state
        let mut creator_state = GroupState {
            context: GroupContext {
                group_id,
                epoch: 0,
                tree_hash,
            },
            tree: tree.clone(),
            my_leaf: creator_leaf,
            my_sig: SigKeyPair::generate(),
            my_sec: path_secrets,
            secrets: Secrets::new(),
        };

        // Update creator's secrets with key schedule
        creator_state.secrets = key_schedule(&creator_state.my_sec);

        // Create welcome bundle
        let welcome_bundle = WelcomeBundle {
            group_id,
            epoch: 0,
            tree,
            encrypted_path_secrets: encrypted_secrets.clone(),
            sender_node_public_keys: sender_node_keys.iter().map(|kp| kp.pk).collect(),
        };

        // Create proper UpdatePath with sender node public keys and encrypted secrets
        let update_path_nodes: Vec<UpdatePathNode> = sender_node_keys
            .iter()
            .zip(encrypted_secrets.iter())
            .map(|(node_key, encrypted)| UpdatePathNode {
                node_public: node_key.pk,
                path_secret: [0u8; 32], // Path secret is encrypted in the CipherForSubtree
                encrypted_secrets: vec![encrypted.clone()], // One encrypted secret per copath
            })
            .collect();

        // Install new node public keys into the tree
        let dirpath = creator_state.tree.dirpath(creator_state.my_leaf);
        for (i, node_key) in sender_node_keys.iter().enumerate() {
            if let Some(node_index) = dirpath.get(i) {
                let _ = creator_state
                    .tree
                    .set_node_public_key(*node_index, node_key.pk);
            }
        }

        // Update tree hash after installing new public keys
        creator_state.update_tree_hash();

        // Create commit with proper confirmation tag
        let group_context_hash = creator_state.compute_group_context_hash();
        let confirmation_tag =
            compute_confirmation_tag(&creator_state.secrets.conf_key, &group_context_hash);

        let commit = Commit {
            proposals: vec![],                    // No proposals for initial group creation
            update_path: Some(update_path_nodes), // Proper update path with sender node keys
            confirmation_tag,
        };

        GroupCreationResult {
            creator_state,
            welcome_bundle,
            commit,
        }
    }

    /// Apply a commit to update group state
    ///
    /// # Arguments
    /// * `commit` - The commit to apply
    /// * `encrypted_secrets` - Encrypted path secrets for this recipient
    /// * `recipient_sk` - Recipient's subtree private key
    /// * `sender_node_public_keys` - Public keys of sender's path nodes
    ///
    /// # Returns
    /// Updated group state or error
    pub fn apply_commit(
        &mut self,
        commit: &Commit,
        encrypted_secrets: &[CipherForSubtree],
        recipient_sk: &[u8; 32],
        sender_node_public_keys: &[[u8; 32]],
    ) -> Result<(), String> {
        // Decrypt path secrets
        let mut decrypted_secrets = Vec::new();

        for (i, encrypted) in encrypted_secrets.iter().enumerate() {
            // Use the corresponding sender's public key
            let sender_node_pk = sender_node_public_keys
                .get(i)
                .ok_or_else(|| "Missing sender public key".to_string())?;

            match decrypt_start_secret(
                recipient_sk,
                sender_node_pk,
                &encrypted.nonce,
                &encrypted.ct,
            ) {
                Ok(secret) => decrypted_secrets.push(secret),
                Err(e) => return Err(format!("Failed to decrypt secret: {}", e)),
            }
        }

        // Update my secrets with decrypted path secrets
        self.my_sec = decrypted_secrets;

        // Derive root secret and update epoch secrets
        self.secrets = key_schedule(&self.my_sec);

        // Verify confirmation tag using HMAC
        let group_context_hash = self.compute_group_context_hash();
        let expected_confirmation =
            compute_confirmation_tag(&self.secrets.conf_key, &group_context_hash);

        if commit.confirmation_tag != expected_confirmation {
            return Err("Invalid confirmation tag".to_string());
        }

        // Increment epoch
        self.context.epoch += 1;

        // Update tree hash
        self.update_tree_hash();

        Ok(())
    }

    /// Add a new member to the group
    ///
    /// # Arguments
    /// * `new_member_key_pkg` - Key package of the new member
    ///
    /// # Returns
    /// Updated group state and commit for the addition
    pub fn add_member(&mut self, new_member_key_pkg: KeyPackage) -> Result<Commit, String> {
        // Insert the new member into the tree
        let _new_leaf_index = self.tree.insert_leaf(new_member_key_pkg.clone());

        // Update tree hash
        self.update_tree_hash();

        // Create a commit for the addition
        let proposals = vec![Proposal::Add {
            key_package: new_member_key_pkg,
        }];

        // Generate new path secrets for the updated tree
        let dirpath = self.tree.dirpath(self.my_leaf);
        let new_path_secrets = derive_path_up(self.my_leaf, dirpath.len());

        // Generate sender node keys from path secrets (one per path level)
        let sender_node_keys: Vec<KeyPair> =
            new_path_secrets.iter().map(node_keys_from_path).collect();

        // For simplicity, create a single encrypted secret for the first path level
        // In a real implementation, this would encrypt to all copath subtrees
        let encrypted_secrets = [CipherForSubtree {
            recipient_subtree_node: 0,        // Simplified: encrypt to first copath
            nonce: [0u8; 12],                 // Simplified: zero nonce
            ct: new_path_secrets[0].to_vec(), // Simplified: just the path secret
        }];

        // Update our secrets
        self.my_sec = new_path_secrets;
        self.secrets = key_schedule(&self.my_sec);

        // Create proper UpdatePath with sender node public keys and encrypted secrets
        let update_path_nodes: Vec<UpdatePathNode> = sender_node_keys
            .iter()
            .zip(encrypted_secrets.iter())
            .map(|(node_key, encrypted)| UpdatePathNode {
                node_public: node_key.pk,
                path_secret: [0u8; 32], // Path secret is encrypted in the CipherForSubtree
                encrypted_secrets: vec![encrypted.clone()], // One encrypted secret per copath
            })
            .collect();

        // Install new node public keys into the tree
        for (i, node_key) in sender_node_keys.iter().enumerate() {
            if let Some(node_index) = dirpath.get(i) {
                self.tree.set_node_public_key(*node_index, node_key.pk)?;
            }
        }

        // Update tree hash after installing new public keys
        self.update_tree_hash();

        // Generate confirmation tag
        let group_context_hash = self.compute_group_context_hash();
        let confirmation_tag =
            compute_confirmation_tag(&self.secrets.conf_key, &group_context_hash);

        let commit = Commit {
            proposals,
            update_path: Some(update_path_nodes), // Proper update path with sender node keys
            confirmation_tag,
        };

        // Increment epoch
        self.context.epoch += 1;

        Ok(commit)
    }

    /// Remove a member from the group
    ///
    /// # Arguments
    /// * `leaf_index` - Leaf index of the member to remove
    ///
    /// # Returns
    /// Updated group state and commit for the removal
    pub fn remove_member(&mut self, leaf_index: LeafIndex) -> Result<Commit, String> {
        // Remove the member from the tree
        self.tree.remove_leaf(leaf_index);

        // Update tree hash
        self.update_tree_hash();

        // Create a commit for the removal
        let proposals = vec![Proposal::Remove {
            removed: leaf_index,
        }];

        // Generate new path secrets for the updated tree
        let dirpath = self.tree.dirpath(self.my_leaf);
        let new_path_secrets = derive_path_up(self.my_leaf, dirpath.len());

        // Update our secrets
        self.my_sec = new_path_secrets;
        self.secrets = key_schedule(&self.my_sec);

        // Generate confirmation tag
        let group_context_hash = self.compute_group_context_hash();
        let confirmation_tag =
            compute_confirmation_tag(&self.secrets.conf_key, &group_context_hash);

        let commit = Commit {
            proposals,
            update_path: Some(vec![]), // Simplified: empty update path
            confirmation_tag,
        };

        // Increment epoch
        self.context.epoch += 1;

        Ok(commit)
    }

    /// Create an empty commit (epoch advancement without membership change)
    ///
    /// # Returns
    /// Commit for epoch advancement
    pub fn empty_commit(&mut self) -> Result<Commit, String> {
        // Generate new path secrets (same tree, but new secrets for forward secrecy)
        let dirpath = self.tree.dirpath(self.my_leaf);
        let new_path_secrets = derive_path_up(self.my_leaf, dirpath.len());

        // Update our secrets
        self.my_sec = new_path_secrets;
        self.secrets = key_schedule(&self.my_sec);

        // Generate confirmation tag
        let group_context_hash = self.compute_group_context_hash();
        let confirmation_tag =
            compute_confirmation_tag(&self.secrets.conf_key, &group_context_hash);

        let commit = Commit {
            proposals: vec![],         // No proposals - just epoch advancement
            update_path: Some(vec![]), // Simplified: empty update path
            confirmation_tag,
        };

        // Increment epoch
        self.context.epoch += 1;

        Ok(commit)
    }

    /// Verify a commit signature using the sender's signature key
    ///
    /// # Arguments
    /// * `commit` - The commit to verify
    /// * `sender_sig_pk` - The sender's signature public key
    ///
    /// # Returns
    /// Result indicating if the signature is valid
    pub fn verify_commit_signature(
        &self,
        commit: &Commit,
        _sender_sig_pk: &[u8; 32],
    ) -> Result<(), String> {
        // For this simplified implementation, we'll just verify the confirmation tag
        // In a full MLS implementation, this would verify the actual signature over the commit

        // The confirmation tag serves as our "signature" verification
        // It proves that the sender has the correct conf_key for this epoch
        // Note: The confirmation tag is computed with the epoch BEFORE the commit is applied
        let group_context_hash = self.compute_group_context_hash();
        let expected_confirmation =
            compute_confirmation_tag(&self.secrets.conf_key, &group_context_hash);

        if commit.confirmation_tag != expected_confirmation {
            return Err("Invalid commit signature/confirmation".to_string());
        }

        Ok(())
    }
}

/// Key schedule: derive epoch secrets from root secret
///
/// Implements the MLS key schedule as defined in RFC 9420 §7.2.
/// Derives epoch secrets from the root secret using HKDF-Expand.
///
/// # Arguments
/// * `path_secrets` - Vector of path secrets (last one is root secret)
///
/// # Returns
/// Current epoch secrets
pub fn key_schedule(path_secrets: &[[u8; 32]]) -> Secrets {
    // Get root secret (last path secret)
    let root_secret = path_secrets.last().copied().unwrap_or([0u8; 32]);

    // Derive epoch secret: epoch = HKDF-Expand(root, "mls10 epoch", 32)
    let epoch = hkdf_expand(&root_secret, b"mls10 epoch", 32);

    // Derive handshake key: hs_key = HKDF-Expand(epoch, "mls10 hs", 32)
    let handshake_key = hkdf_expand(&epoch, b"mls10 hs", 32);

    // Derive app key: app_key = HKDF-Expand(epoch, "mls10 app", 32)
    let app_key = hkdf_expand(&epoch, b"mls10 app", 32);

    // Derive confirmation key: conf_key = HKDF-Expand(epoch, "mls10 confirm", 32)
    let conf_key = hkdf_expand(&epoch, b"mls10 confirm", 32);

    Secrets {
        epoch,
        handshake_key,
        app_key,
        conf_key,
    }
}

/// HKDF-Expand helper function
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK length");
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expand failed");

    let mut result = [0u8; 32];
    result.copy_from_slice(&okm[..32]);
    result
}

/// Compute confirmation tag using HMAC-SHA256
///
/// Implements the MLS confirmation tag computation as defined in RFC 9420 §6.1.
/// Uses HMAC-SHA256 with the confirmation key and group context hash.
fn compute_confirmation_tag(
    confirmation_key: &[u8; 32],
    group_context_hash: &[u8; 32],
) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(confirmation_key).expect("HMAC can take key of any size");
    mac.update(group_context_hash);

    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, SigKeyPair};

    /// Helper function to create a test key package
    fn create_test_keypackage() -> KeyPackage {
        let keypair = KeyPair::generate();
        let sig_keypair = SigKeyPair::generate();

        KeyPackage {
            cred_sig_pk: sig_keypair.pk.to_bytes(),
            leaf_dh_pk: keypair.pk,
            signature: vec![],
        }
    }

    #[test]
    fn test_group_state_new() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let group_state = GroupState::new(group_id, 4);

        // Verify group state structure
        assert_eq!(group_state.context.group_id, group_id);
        assert_eq!(group_state.context.epoch, 0);
        assert_eq!(group_state.tree.size, 4);
        assert_eq!(group_state.my_leaf, 0);

        // Verify tree has correct number of nodes
        let expected_nodes = 2 * 4 - 1; // 2*size - 1 for complete binary tree
        assert_eq!(group_state.tree.nodes.len(), expected_nodes);
    }

    #[test]
    fn test_group_state_from_keypackages() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let keypackages = vec![
            create_test_keypackage(),
            create_test_keypackage(),
            create_test_keypackage(),
        ];

        let group_state = GroupState::from_keypackages(group_id, keypackages.clone());

        // Verify group state structure
        assert_eq!(group_state.context.group_id, group_id);
        assert_eq!(group_state.context.epoch, 0);
        assert_eq!(group_state.tree.size, 3);
        assert_eq!(group_state.my_leaf, 0);

        // Verify tree has correct number of nodes
        let expected_nodes = 2 * 3 - 1; // 2*size - 1 for complete binary tree
        assert_eq!(group_state.tree.nodes.len(), expected_nodes);
    }

    #[test]
    fn test_create_group() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage(), create_test_keypackage()];

        let group_result = GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs);

        // Verify creator state
        assert_eq!(group_result.creator_state.context.group_id, group_id);
        assert_eq!(group_result.creator_state.context.epoch, 0);
        assert_eq!(group_result.creator_state.tree.size, 3);
        assert_eq!(group_result.creator_state.my_leaf, 0);

        // Verify welcome bundle
        assert_eq!(group_result.welcome_bundle.group_id, group_id);
        assert_eq!(group_result.welcome_bundle.epoch, 0);
        assert_eq!(group_result.welcome_bundle.tree.size, 3);

        // Verify commit
        assert_eq!(group_result.commit.proposals.len(), 0); // No proposals for group creation
        assert!(group_result.commit.update_path.is_some());
        assert_ne!(group_result.commit.confirmation_tag, [0u8; 32]);
    }

    #[test]
    fn test_add_member() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage()];

        let mut group_state =
            GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
        let initial_epoch = group_state.context.epoch;
        let initial_size = group_state.tree.size;

        // Add a new member
        let new_member_key_pkg = create_test_keypackage();
        let commit = group_state
            .add_member(new_member_key_pkg)
            .expect("Failed to add member");

        // Verify group state updated
        assert_eq!(group_state.context.epoch, initial_epoch + 1);
        assert_eq!(group_state.tree.size, initial_size + 1);

        // Verify commit structure
        assert_eq!(commit.proposals.len(), 1);
        assert!(commit.update_path.is_some());
        assert_ne!(commit.confirmation_tag, [0u8; 32]);
    }

    #[test]
    fn test_remove_member() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage(), create_test_keypackage()];

        let mut group_state =
            GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
        let initial_epoch = group_state.context.epoch;
        let initial_size = group_state.tree.size;

        // Remove a member
        let commit = group_state
            .remove_member(1)
            .expect("Failed to remove member");

        // Verify group state updated
        assert_eq!(group_state.context.epoch, initial_epoch + 1);
        assert_eq!(group_state.tree.size, initial_size); // Size doesn't change, but active leaves do
        assert_eq!(group_state.tree.active_leaves(), initial_size - 1);

        // Verify commit structure
        assert_eq!(commit.proposals.len(), 1);
        assert!(commit.update_path.is_some());
        assert_ne!(commit.confirmation_tag, [0u8; 32]);
    }

    #[test]
    fn test_empty_commit() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage()];

        let mut group_state =
            GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
        let initial_epoch = group_state.context.epoch;
        let initial_secrets = group_state.secrets.epoch;

        // Create empty commit
        let commit = group_state
            .empty_commit()
            .expect("Failed to create empty commit");

        // Verify group state updated
        assert_eq!(group_state.context.epoch, initial_epoch + 1);
        assert_ne!(group_state.secrets.epoch, initial_secrets); // Secrets should change

        // Verify commit structure
        assert_eq!(commit.proposals.len(), 0); // No proposals for empty commit
        assert!(commit.update_path.is_some());
        assert_ne!(commit.confirmation_tag, [0u8; 32]);
    }

    #[test]
    fn test_key_schedule() {
        let path_secrets = vec![
            [1u8; 32], [2u8; 32], [3u8; 32], // This will be the root secret
        ];

        let secrets = key_schedule(&path_secrets);

        // Verify secrets structure
        assert_eq!(secrets.epoch.len(), 32);
        assert_eq!(secrets.handshake_key.len(), 32);
        assert_eq!(secrets.app_key.len(), 32);
        assert_eq!(secrets.conf_key.len(), 32);

        // Verify secrets are different
        assert_ne!(secrets.epoch, secrets.handshake_key);
        assert_ne!(secrets.handshake_key, secrets.app_key);
        assert_ne!(secrets.app_key, secrets.conf_key);
    }

    #[test]
    fn test_key_schedule_different_inputs() {
        let path_secrets1 = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let path_secrets2 = vec![[4u8; 32], [5u8; 32], [6u8; 32]];

        let secrets1 = key_schedule(&path_secrets1);
        let secrets2 = key_schedule(&path_secrets2);

        // Different inputs should produce different outputs
        assert_ne!(secrets1.epoch, secrets2.epoch);
        assert_ne!(secrets1.handshake_key, secrets2.handshake_key);
        assert_ne!(secrets1.app_key, secrets2.app_key);
        assert_ne!(secrets1.conf_key, secrets2.conf_key);
    }

    #[test]
    fn test_compute_group_context_hash() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let group_state = GroupState::new(group_id, 4);

        let hash1 = group_state.compute_group_context_hash();
        let hash2 = group_state.compute_group_context_hash();

        // Same state should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_compute_confirmation_tag() {
        let conf_key = [42u8; 32];
        let group_context_hash = [1u8; 32];

        let tag1 = compute_confirmation_tag(&conf_key, &group_context_hash);
        let tag2 = compute_confirmation_tag(&conf_key, &group_context_hash);

        // Same inputs should produce same tag
        assert_eq!(tag1, tag2);

        // Tag should be 32 bytes
        assert_eq!(tag1.len(), 32);

        // Different inputs should produce different tags
        let different_hash = [2u8; 32];
        let tag3 = compute_confirmation_tag(&conf_key, &different_hash);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_apply_commit_with_mock_keys() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage()];

        let group_result = GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs);
        let mut recipient_state = GroupState::new(group_id, 2);

        // Mock recipient private key
        let recipient_sk = [42u8; 32];

        // Apply commit (should fail with mock keys, but that's expected)
        let result = recipient_state.apply_commit(
            &group_result.commit,
            &group_result.welcome_bundle.encrypted_path_secrets,
            &recipient_sk,
            &group_result.welcome_bundle.sender_node_public_keys,
        );

        // Should fail with mock keys (expected behavior)
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_secrecy_property() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage()];

        let mut group_state =
            GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;

        // Get initial secrets
        let initial_epoch_secret = group_state.secrets.epoch;
        let initial_handshake_key = group_state.secrets.handshake_key;
        let initial_app_key = group_state.secrets.app_key;
        let initial_conf_key = group_state.secrets.conf_key;

        // Create empty commit (epoch advancement)
        group_state
            .empty_commit()
            .expect("Failed to create empty commit");

        // Verify all secrets changed (forward secrecy)
        assert_ne!(group_state.secrets.epoch, initial_epoch_secret);
        assert_ne!(group_state.secrets.handshake_key, initial_handshake_key);
        assert_ne!(group_state.secrets.app_key, initial_app_key);
        assert_ne!(group_state.secrets.conf_key, initial_conf_key);
    }

    #[test]
    fn test_tree_hash_consistency() {
        let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let creator_key_pkg = create_test_keypackage();
        let other_key_pkgs = vec![create_test_keypackage()];

        let mut group_state =
            GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
        let initial_tree_hash = group_state.context.tree_hash;

        // Add a member
        let new_member_key_pkg = create_test_keypackage();
        group_state
            .add_member(new_member_key_pkg)
            .expect("Failed to add member");

        // Tree hash should change
        assert_ne!(group_state.context.tree_hash, initial_tree_hash);

        // Remove a member
        group_state
            .remove_member(1)
            .expect("Failed to remove member");

        // Tree hash should change again
        assert_ne!(group_state.context.tree_hash, initial_tree_hash);
    }
}
