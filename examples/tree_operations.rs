//! Tree operations example demonstrating the complete binary tree functionality

use toy_mls::crypto::{KeyPair, SigKeyPair};
use toy_mls::{GroupState, KeyPackage, RatchetTree};

fn main() {
    println!("=== MLS Tree Operations Demo ===");

    // Create key packages for demonstration
    println!("\n1. Creating key packages...");
    let mut keypackages = Vec::new();
    for i in 0..4 {
        let keypair = KeyPair::generate();
        let sig_keypair = SigKeyPair::generate();

        let keypackage = KeyPackage {
            cred_sig_pk: sig_keypair.pk.to_bytes(),
            leaf_dh_pk: keypair.pk,
            signature: vec![], // Empty signature for demo
        };
        keypackages.push(keypackage);
        println!("   Created key package {} with leaf public key", i);
    }

    // Create tree from key packages
    println!("\n2. Creating ratchet tree from key packages...");
    let tree = RatchetTree::from_leaves(keypackages.clone());
    println!("   Tree size: {} leaves", tree.size);
    println!("   Total nodes: {}", tree.nodes.len());

    // Demonstrate tree navigation functions
    println!("\n3. Tree navigation functions:");

    // Test parent/child relationships
    println!("   parent(0) = {:?}", tree.parent(0));
    println!("   left(0) = {:?}", tree.left(0));
    println!("   right(0) = {:?}", tree.right(0));
    println!("   is_leaf(0) = {}", tree.is_leaf(0));
    println!("   is_leaf(3) = {}", tree.is_leaf(3));

    // Test direct path and copath
    println!("\n4. Direct path and copath for leaf 0:");
    let leaf_index = 0;
    let dirpath = tree.dirpath(leaf_index);
    let copath = tree.copath(leaf_index);

    println!("   dirpath(0) = {:?}", dirpath);
    println!("   copath(0) = {:?}", copath);

    println!("\n5. Direct path and copath for leaf 2:");
    let leaf_index = 2;
    let dirpath = tree.dirpath(leaf_index);
    let copath = tree.copath(leaf_index);

    println!("   dirpath(2) = {:?}", dirpath);
    println!("   copath(2) = {:?}", copath);

    // Compute tree hash
    println!("\n6. Tree hash computation:");
    let tree_hash = tree.compute_tree_hash();
    println!("   Tree hash: {:02x?}", tree_hash);

    // Create group state from key packages
    println!("\n7. Creating group state from key packages...");
    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let group_state = GroupState::from_keypackages(group_id, keypackages);

    println!("   Group created with {} members", group_state.tree.size);
    println!("   Group tree hash: {:02x?}", group_state.context.tree_hash);
    println!("   Current epoch: {}", group_state.context.epoch);

    // Demonstrate tree structure visualization
    println!("\n8. Tree structure:");
    for (i, node) in group_state.tree.nodes.iter().enumerate() {
        let node_type = match node {
            toy_mls::Node::Blank => "Blank",
            toy_mls::Node::Leaf { .. } => "Leaf",
            toy_mls::Node::Parent { .. } => "Parent",
        };

        let is_leaf = group_state.tree.is_leaf(i);
        let leaf_info = if is_leaf {
            format!(" (leaf {})", i - (group_state.tree.size - 1))
        } else {
            String::new()
        };

        println!("   Node {}: {} {}", i, node_type, leaf_info);

        if let Some(parent) = group_state.tree.parent(i) {
            println!("     parent: {}", parent);
        }
        if let Some(left) = group_state.tree.left(i) {
            println!("     left child: {}", left);
        }
        if let Some(right) = group_state.tree.right(i) {
            println!("     right child: {}", right);
        }
    }

    println!("\n=== Demo completed successfully! ===");
}
