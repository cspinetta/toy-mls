//! Wire format tests for toy-mls
//!
//! These tests verify that all MLS message types can be serialized
//! and deserialized using CBOR, providing a realistic wire format.

// serde_cbor is used in the test functions
use toy_mls::{
    crypto::{KeyPair, SigKeyPair},
    group::GroupState,
    messages::{CipherForSubtree, Commit, KeyPackage, Proposal, UpdatePathNode},
    tree::RatchetTree,
};

/// Create a test key package for testing
fn create_test_keypackage() -> KeyPackage {
    let sig_keypair = SigKeyPair::generate();
    let dh_keypair = KeyPair::generate();
    KeyPackage::new(&sig_keypair, dh_keypair.pk)
}

#[test]
fn test_keypackage_serialization_roundtrip() {
    let sig_keypair = SigKeyPair::generate();
    let dh_keypair = KeyPair::generate();
    let key_package = KeyPackage::new(&sig_keypair, dh_keypair.pk);

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&key_package).expect("Failed to serialize KeyPackage");

    // Deserialize from CBOR
    let deserialized_key_package: KeyPackage =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize KeyPackage");

    // Verify they're identical
    assert_eq!(
        key_package.cred_sig_pk,
        deserialized_key_package.cred_sig_pk
    );
    assert_eq!(key_package.leaf_dh_pk, deserialized_key_package.leaf_dh_pk);
    assert_eq!(key_package.signature, deserialized_key_package.signature);
}

#[test]
fn test_proposal_serialization_roundtrip() {
    let key_package = create_test_keypackage();
    let proposal = Proposal::Add {
        key_package: key_package.clone(),
    };

    let cbor_data = serde_cbor::to_vec(&proposal).expect("Failed to serialize Proposal");
    let deserialized_proposal: Proposal =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize Proposal");

    match (&proposal, &deserialized_proposal) {
        (Proposal::Add { key_package: kp1 }, Proposal::Add { key_package: kp2 }) => {
            assert_eq!(kp1.cred_sig_pk, kp2.cred_sig_pk);
            assert_eq!(kp1.leaf_dh_pk, kp2.leaf_dh_pk);
            assert_eq!(kp1.signature, kp2.signature);
        }
        _ => panic!("Proposal deserialization failed"),
    }
}

#[test]
fn test_update_path_node_serialization_roundtrip() {
    let update_path_node = UpdatePathNode {
        node_public: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
        encrypted_secrets: vec![CipherForSubtree {
            subtree_root_node_index: 1,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            ct: vec![1, 2, 3, 4, 5],
        }],
    };

    let cbor_data =
        serde_cbor::to_vec(&update_path_node).expect("Failed to serialize UpdatePathNode");
    let deserialized_update_path_node: UpdatePathNode =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize UpdatePathNode");

    assert_eq!(
        update_path_node.node_public,
        deserialized_update_path_node.node_public
    );
    assert_eq!(
        update_path_node.encrypted_secrets.len(),
        deserialized_update_path_node.encrypted_secrets.len()
    );
}

#[test]
fn test_commit_serialization_roundtrip() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let commit = &group_result.commit;

    let cbor_data = serde_cbor::to_vec(commit).expect("Failed to serialize Commit");
    let deserialized_commit: Commit =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize Commit");

    assert_eq!(commit.proposals.len(), deserialized_commit.proposals.len());
    assert_eq!(
        commit.update_path.is_some(),
        deserialized_commit.update_path.is_some()
    );
    assert_eq!(
        commit.confirmation_tag,
        deserialized_commit.confirmation_tag
    );
    assert_eq!(commit.signature, deserialized_commit.signature);
}

#[test]
fn test_ratchet_tree_serialization_roundtrip() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let tree = &group_result.creator_state.tree;

    let cbor_data = serde_cbor::to_vec(tree).expect("Failed to serialize RatchetTree");
    let deserialized_tree: RatchetTree =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize RatchetTree");

    assert_eq!(tree.size, deserialized_tree.size);
    assert_eq!(tree.nodes.len(), deserialized_tree.nodes.len());
}

#[test]
fn test_welcome_bundle_serialization_roundtrip() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let welcome_bundle = &group_result.welcome_bundle;

    let cbor_data = serde_cbor::to_vec(welcome_bundle).expect("Failed to serialize WelcomeBundle");
    let deserialized_welcome_bundle: toy_mls::group::WelcomeBundle =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize WelcomeBundle");

    assert_eq!(
        welcome_bundle.group_id,
        deserialized_welcome_bundle.group_id
    );
    assert_eq!(welcome_bundle.epoch, deserialized_welcome_bundle.epoch);
    assert_eq!(
        welcome_bundle.tree.size,
        deserialized_welcome_bundle.tree.size
    );
    assert_eq!(
        welcome_bundle.encrypted_path_secrets.len(),
        deserialized_welcome_bundle.encrypted_path_secrets.len()
    );
    assert_eq!(
        welcome_bundle.sender_node_public_keys.len(),
        deserialized_welcome_bundle.sender_node_public_keys.len()
    );
}

#[test]
fn test_group_context_serialization_roundtrip() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let group_context = &group_result.creator_state.context;

    let cbor_data = serde_cbor::to_vec(group_context).expect("Failed to serialize GroupContext");
    let deserialized_group_context: toy_mls::group::GroupContext =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize GroupContext");

    assert_eq!(group_context.group_id, deserialized_group_context.group_id);
    assert_eq!(group_context.epoch, deserialized_group_context.epoch);
    assert_eq!(
        group_context.tree_hash,
        deserialized_group_context.tree_hash
    );
}
