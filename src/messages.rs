use crate::tree::{LeafIndex, NodeIndex};

#[derive(Clone, Debug)]
pub enum Proposal {
    Add { key_package: KeyPackage },
    Remove { removed: LeafIndex },
    Update, // (we'll pack the actual UpdatePath only in the Commit)
}

#[derive(Clone, Debug)]
pub struct UpdatePathNode {
    pub node_public: [u8; 32],                    // X25519 public of path node
    pub path_secret: [u8; 32],                    // Path secret s[i] to be encrypted
    pub encrypted_secrets: Vec<CipherForSubtree>, // one per copath subtree
}

#[derive(Clone, Debug)]
pub struct CipherForSubtree {
    pub recipient_subtree_node: NodeIndex,
    pub nonce: [u8; 12],
    pub ct: Vec<u8>, // AEAD over path secret s[i]
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub proposals: Vec<Proposal>, // or inline proposals to stay simple
    pub update_path: Option<Vec<UpdatePathNode>>,
    pub confirmation_tag: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct KeyPackage {
    pub cred_sig_pk: [u8; 32], // ed25519 public
    pub leaf_dh_pk: [u8; 32],  // X25519 leaf public
    pub signature: Vec<u8>,    // sig over the struct (self-authenticating)
}
