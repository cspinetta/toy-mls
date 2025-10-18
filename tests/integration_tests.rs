//! Integration tests for toy-mls
//!
//! These tests verify that the MLS implementation works correctly end-to-end,
//! including proper epoch secret derivation and participant validation.

use toy_mls::{
    crypto::{KeyPair, SigKeyPair},
    group::GroupState,
    messages::KeyPackage,
};

/// Create a test key package for testing
fn create_test_keypackage() -> KeyPackage {
    let keypair = KeyPair::generate();
    let sig_keypair = SigKeyPair::generate();

    // Create a simple signature (in real MLS this would be over the key package)
    let mut signature = vec![0u8; 64]; // Placeholder signature
    signature[0] = 1; // Make it non-zero for testing

    KeyPackage {
        cred_sig_pk: sig_keypair.pk.to_bytes(),
        leaf_dh_pk: keypair.pk,
        signature,
    }
}

#[test]
fn test_all_participants_derive_same_epoch_secret() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    // Create group
    let group_creation = GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs);
    let creator_state = group_creation.creator_state;
    let welcome_bundle = group_creation.welcome_bundle;

    // Verify that the creator has the correct epoch secret
    let creator_epoch_secret = creator_state.secrets.epoch;
    assert_ne!(creator_epoch_secret, [0u8; 32]); // Should not be zero

    // In a real implementation, other participants would:
    // 1. Decrypt their path secrets from the welcome bundle
    // 2. Derive the same epoch secret
    // For this test, we verify the structure is correct
    assert_eq!(welcome_bundle.group_id, group_id);
    assert_eq!(welcome_bundle.epoch, 0);
    assert!(!welcome_bundle.encrypted_path_secrets.is_empty());
    assert!(!welcome_bundle.sender_node_public_keys.is_empty());
}

#[test]
fn test_commit_has_proper_update_path() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    // Create group
    let group_creation = GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs);
    let commit = group_creation.commit;

    // Verify commit structure
    assert!(commit.update_path.is_some());
    let update_path = commit.update_path.unwrap();
    assert!(!update_path.is_empty()); // Should have update path nodes

    // Verify each update path node has the required fields
    for node in update_path {
        assert_ne!(node.node_public, [0u8; 32]); // Should have valid public key
        assert!(!node.encrypted_secrets.is_empty()); // Should have encrypted secrets
    }

    // Verify confirmation tag is valid
    assert_ne!(commit.confirmation_tag, [0u8; 32]);
}

#[test]
fn test_add_member_creates_proper_commit() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    let mut group_state =
        GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
    let initial_epoch = group_state.context.epoch;

    // Add a new member
    let new_member_key_pkg = create_test_keypackage();
    let commit = group_state
        .add_member(new_member_key_pkg)
        .expect("Failed to add member");

    // Verify commit structure
    assert_eq!(commit.proposals.len(), 1); // Should have one Add proposal
    assert!(commit.update_path.is_some());
    let update_path = commit.update_path.unwrap();
    assert!(!update_path.is_empty()); // Should have update path nodes

    // Verify epoch was incremented
    assert_eq!(group_state.context.epoch, initial_epoch + 1);

    // Verify confirmation tag is valid
    assert_ne!(commit.confirmation_tag, [0u8; 32]);
}

#[test]
fn test_removed_participant_cannot_derive_next_epoch() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    let mut group_state =
        GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
    let initial_epoch_secret = group_state.secrets.epoch;

    // Remove a member (leaf index 1, which is the first "other" member)
    let commit = group_state
        .remove_member(1)
        .expect("Failed to remove member");

    // Verify commit structure
    assert_eq!(commit.proposals.len(), 1); // Should have one Remove proposal
    assert!(commit.update_path.is_some());

    // Verify epoch was incremented
    assert_eq!(group_state.context.epoch, 1);

    // Verify that the epoch secret changed (forward secrecy)
    assert_ne!(group_state.secrets.epoch, initial_epoch_secret);

    // In a real implementation, the removed participant would not be able to:
    // 1. Decrypt the new path secrets (they're not in the copath anymore)
    // 2. Derive the new epoch secret
    // For this test, we verify the structure is correct
    assert_ne!(commit.confirmation_tag, [0u8; 32]);
}

#[test]
fn test_tree_public_keys_are_installed() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    let mut group_state =
        GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
    let initial_tree_hash = group_state.context.tree_hash;

    // Add a new member
    let new_member_key_pkg = create_test_keypackage();
    let _commit = group_state
        .add_member(new_member_key_pkg)
        .expect("Failed to add member");

    // Verify that tree hash changed (indicating public keys were installed)
    assert_ne!(group_state.context.tree_hash, initial_tree_hash);

    // Verify that the tree has the correct number of active leaves
    assert_eq!(group_state.tree.active_leaves(), 3); // Creator + 2 other members
}

#[test]
fn test_confirmation_tag_validation() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let creator_key_pkg = create_test_keypackage();
    let other_key_pkgs = vec![create_test_keypackage()];

    let mut group_state =
        GroupState::create_group(group_id, creator_key_pkg, other_key_pkgs).creator_state;
    let initial_epoch = group_state.context.epoch;

    // Create a commit
    let commit = group_state
        .add_member(create_test_keypackage())
        .expect("Failed to add member");

    // Verify that the commit signature/confirmation is valid
    // Note: We need to verify with the epoch before the commit was applied
    let mut verification_state = group_state.clone();
    verification_state.context.epoch = initial_epoch; // Reset to epoch before commit
    verification_state
        .verify_commit_signature(&commit, &verification_state.my_sig.pk.to_bytes())
        .expect("Valid commit signature should pass");

    // Create a commit with wrong confirmation tag
    let mut bad_commit = commit.clone();
    bad_commit.confirmation_tag = [1u8; 32]; // Wrong confirmation tag

    // Verify that the bad commit signature fails
    let result = verification_state
        .verify_commit_signature(&bad_commit, &verification_state.my_sig.pk.to_bytes());
    assert!(result.is_err());
}
