//! Signature and error handling tests for toy-mls
//!
//! These tests verify that signatures work correctly and that proper error types are used.

use toy_mls::{
    crypto::{KeyPair, SigKeyPair},
    error::{MlsError, MlsResult},
    group::GroupState,
    messages::KeyPackage,
};

#[test]
fn test_keypackage_signature_verification() {
    let sig_keypair = SigKeyPair::generate();
    let dh_keypair = KeyPair::generate();
    let key_package = KeyPackage::new(&sig_keypair, dh_keypair.pk);

    // Verify the signature
    key_package
        .verify_signature()
        .expect("KeyPackage signature should be valid");
}

#[test]
fn test_tampered_keypackage_signature_fails() {
    let sig_keypair = SigKeyPair::generate();
    let dh_keypair = KeyPair::generate();
    let key_package = KeyPackage::new(&sig_keypair, dh_keypair.pk);

    // Tamper with the key package
    let mut tampered_key_package = key_package.clone();
    tampered_key_package.leaf_dh_pk[0] ^= 0xFF; // Flip some bits

    // Verify that tampered signature fails
    let result = tampered_key_package.verify_signature();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Signature verification failed")
    );
}

#[test]
fn test_commit_signature_verification() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let commit = &group_result.commit;

    // Verify the commit signature (use the creator's actual signature public key from the group state)
    let creator_actual_sig_pk = group_result.creator_state.my_sig.pk.to_bytes();
    commit
        .verify_signature(&creator_actual_sig_pk)
        .expect("Commit signature should be valid");
}

#[test]
fn test_tampered_commit_signature_fails() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let commit = &group_result.commit;

    // Tamper with the commit
    let mut tampered_commit = commit.clone();
    tampered_commit.confirmation_tag[0] ^= 0xFF; // Flip some bits

    // Verify that tampered signature fails
    let creator_actual_sig_pk = group_result.creator_state.my_sig.pk.to_bytes();
    let result = tampered_commit.verify_signature(&creator_actual_sig_pk);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Signature verification failed")
    );
}

#[test]
fn test_wrong_signer_commit_signature_fails() {
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let creator_sig_keypair = SigKeyPair::generate();
    let creator_dh_keypair = KeyPair::generate();
    let creator_key_pkg = KeyPackage::new(&creator_sig_keypair, creator_dh_keypair.pk);

    let other_sig_keypair = SigKeyPair::generate();
    let other_dh_keypair = KeyPair::generate();
    let other_key_pkg = KeyPackage::new(&other_sig_keypair, other_dh_keypair.pk);

    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![other_key_pkg]);
    let commit = &group_result.commit;

    // Use wrong signer's public key
    let wrong_sig_keypair = SigKeyPair::generate();
    let wrong_cred_pk = wrong_sig_keypair.pk.to_bytes();

    // Verify that wrong signer fails
    let result = commit.verify_signature(&wrong_cred_pk);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Signature verification failed")
    );
}

#[test]
fn test_error_types_are_available() {
    // Test that all error types are available
    let errors = vec![
        MlsError::CryptoError("Invalid key size".to_string()),
        MlsError::TreeError("Invalid tree structure".to_string()),
        MlsError::GroupError("Group not found".to_string()),
        MlsError::InvalidMessage("Invalid message format".to_string()),
        MlsError::SignatureError("Signature verification failed".to_string()),
        MlsError::DecryptionError("Decryption failed".to_string()),
        MlsError::InvalidKey("Invalid key format".to_string()),
        MlsError::InvalidLeafIndex("Leaf index out of range".to_string()),
        MlsError::InvalidNodeIndex("Node index out of range".to_string()),
        MlsError::ConfirmationError("Confirmation tag mismatch".to_string()),
        MlsError::Other("Generic error".to_string()),
    ];

    // Verify that all errors can be created and displayed
    for error in errors {
        let error_string = format!("{}", error);
        assert!(!error_string.is_empty());
    }
}

#[test]
fn test_error_conversion() {
    // Test conversion from String
    let error_from_string: MlsError = "Test error".into();
    assert!(matches!(error_from_string, MlsError::Other(_)));

    // Test conversion from &str
    let error_from_str: MlsError = "Another error".into();
    assert!(matches!(error_from_str, MlsError::Other(_)));
}

#[test]
fn test_mls_result_type_alias() {
    fn test_function() -> MlsResult<i32> {
        Ok(42)
    }

    let result = test_function();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);

    fn test_error_function() -> MlsResult<i32> {
        Err(MlsError::InvalidLeafIndex(
            "Leaf 999 does not exist".to_string(),
        ))
    }

    let error_result = test_error_function();
    assert!(error_result.is_err());
    assert!(matches!(
        error_result.unwrap_err(),
        MlsError::InvalidLeafIndex(_)
    ));
}
