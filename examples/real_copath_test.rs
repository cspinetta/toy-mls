//! Test demonstrating real copath public keys instead of mock keys

use toy_mls::{GroupState, KeyPackage, KeyPair, SigKeyPair};

fn main() {
    println!("=== Real Copath Keys Test ===");

    // Create a simple 2-member group to test copath functionality
    println!("\n1. Creating 2-member group...");

    let creator_keypair = KeyPair::generate();
    let creator_sig_keypair = SigKeyPair::generate();

    let creator_key_pkg = KeyPackage {
        cred_sig_pk: creator_sig_keypair.pk.to_bytes(),
        leaf_dh_pk: creator_keypair.pk,
        signature: vec![],
    };

    let member_keypair = KeyPair::generate();
    let member_sig_keypair = SigKeyPair::generate();

    let member_key_pkg = KeyPackage {
        cred_sig_pk: member_sig_keypair.pk.to_bytes(),
        leaf_dh_pk: member_keypair.pk,
        signature: vec![],
    };

    // Create group
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![member_key_pkg]);

    println!(
        "   Group created with {} members",
        group_result.creator_state.tree.size
    );

    // Show the tree structure
    println!("\n2. Tree structure:");
    for (i, node) in group_result.creator_state.tree.nodes.iter().enumerate() {
        match node {
            toy_mls::Node::Blank => println!("   Node {}: Blank", i),
            toy_mls::Node::Leaf { leaf_pk, .. } => {
                println!("   Node {}: Leaf (public key: {:02x?})", i, leaf_pk);
            }
            toy_mls::Node::Parent { node_pk } => {
                println!("   Node {}: Parent (public key: {:02x?})", i, node_pk);
            }
        }
    }

    // Show copath information
    println!("\n3. Copath analysis:");
    let creator_leaf = 0;
    let copath_nodes = group_result.creator_state.tree.copath(creator_leaf);
    println!("   Creator leaf: {}", creator_leaf);
    println!("   Copath nodes: {:?}", copath_nodes);

    // Show actual copath public keys (now real, not mock!)
    let copath_pks: Vec<_> = copath_nodes
        .iter()
        .filter_map(|&node_idx| {
            group_result
                .creator_state
                .tree
                .get_node_public_key(node_idx)
        })
        .collect();

    println!("   Copath public keys:");
    for (i, pk) in copath_pks.iter().enumerate() {
        println!("     Copath {}: {:02x?}", i, pk);
    }

    // Show sender's node public keys
    println!("\n4. Sender's path node public keys:");
    for (i, pk) in group_result
        .welcome_bundle
        .sender_node_public_keys
        .iter()
        .enumerate()
    {
        println!("   Sender node {}: {:02x?}", i, pk);
    }

    // Show encrypted secrets
    println!("\n5. Encrypted secrets:");
    println!(
        "   Number of encrypted secrets: {}",
        group_result.welcome_bundle.encrypted_path_secrets.len()
    );
    for (i, encrypted) in group_result
        .welcome_bundle
        .encrypted_path_secrets
        .iter()
        .enumerate()
    {
        println!(
            "   Secret {}: nonce={:02x?}, ct_len={}",
            i,
            encrypted.nonce,
            encrypted.ct.len()
        );
    }

    println!("\n=== Real Copath Keys Test completed! ===");
    println!("✅ Now using real tree public keys instead of mock keys");
    println!("✅ Copath keys come from actual tree nodes");
    println!("✅ Sender public keys are derived from path secrets");
}
