//! Toy MLS - A simplified, educational implementation of the MLS (Messaging Layer Security) protocol
//!
//! This library provides a clear, well-documented implementation of MLS concepts for learning
//! and experimentation, including ratchet trees, key management, and group state handling.

pub mod crypto;
pub mod error;
pub mod group;
pub mod messages;
pub mod path_secrets;
pub mod tree;

// Re-export main types for convenience
pub use crypto::{KeyPair, Secrets, SigKeyPair};
pub use error::{MlsError, MlsResult};
pub use group::{GroupContext, GroupCreationResult, GroupState, WelcomeBundle, key_schedule};
pub use messages::KeyPackage;
pub use path_secrets::{
    decrypt_start_secret, derive_path_up, encrypt_to_copaths, node_keys_from_path,
};
pub use tree::{LeafIndex, Node, NodeIndex, RatchetTree};
