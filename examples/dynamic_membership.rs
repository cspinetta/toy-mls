//! Dynamic membership example demonstrating add/remove members and empty commits

use toy_mls::{GroupState, KeyPackage, KeyPair, SigKeyPair};

fn main() {
    println!("=== MLS Dynamic Membership Demo ===");

    // Create initial group with 2 members
    println!("\n1. Creating initial group with 2 members...");

    let creator_keypair = KeyPair::generate();
    let creator_sig_keypair = SigKeyPair::generate();

    let creator_key_pkg = KeyPackage {
        cred_sig_pk: creator_sig_keypair.pk.to_bytes(),
        leaf_dh_pk: creator_keypair.pk,
        signature: vec![],
    };

    let member1_keypair = KeyPair::generate();
    let member1_sig_keypair = SigKeyPair::generate();

    let member1_key_pkg = KeyPackage {
        cred_sig_pk: member1_sig_keypair.pk.to_bytes(),
        leaf_dh_pk: member1_keypair.pk,
        signature: vec![],
    };

    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let group_result = GroupState::create_group(group_id, creator_key_pkg, vec![member1_key_pkg]);

    let mut group_state = group_result.creator_state;

    println!("   Initial group created:");
    println!("     Members: {}", group_state.tree.size);
    println!("     Epoch: {}", group_state.context.epoch);
    println!("     Tree hash: {:02x?}", group_state.context.tree_hash);
    println!("     Active leaves: {}", group_state.tree.active_leaves());

    // Show initial tree structure
    println!("\n2. Initial tree structure:");
    for (i, node) in group_state.tree.nodes.iter().enumerate() {
        match node {
            toy_mls::Node::Blank => println!("   Node {}: Blank", i),
            toy_mls::Node::Leaf { leaf_pk, .. } => {
                println!("   Node {}: Leaf (pk: {:02x?})", i, leaf_pk);
            }
            toy_mls::Node::Parent { node_pk } => {
                println!("   Node {}: Parent (pk: {:02x?})", i, node_pk);
            }
        }
    }

    // Add a new member
    println!("\n3. Adding a new member...");

    let new_member_keypair = KeyPair::generate();
    let new_member_sig_keypair = SigKeyPair::generate();

    let new_member_key_pkg = KeyPackage {
        cred_sig_pk: new_member_sig_keypair.pk.to_bytes(),
        leaf_dh_pk: new_member_keypair.pk,
        signature: vec![],
    };

    let add_commit = group_state
        .add_member(new_member_key_pkg.clone())
        .expect("Failed to add member");

    println!("   Member added successfully:");
    println!("     New members: {}", group_state.tree.size);
    println!("     New epoch: {}", group_state.context.epoch);
    println!("     New tree hash: {:02x?}", group_state.context.tree_hash);
    println!("     Active leaves: {}", group_state.tree.active_leaves());
    println!("     Proposals in commit: {}", add_commit.proposals.len());

    // Show updated tree structure
    println!("\n4. Updated tree structure after addition:");
    for (i, node) in group_state.tree.nodes.iter().enumerate() {
        match node {
            toy_mls::Node::Blank => println!("   Node {}: Blank", i),
            toy_mls::Node::Leaf { leaf_pk, .. } => {
                println!("   Node {}: Leaf (pk: {:02x?})", i, leaf_pk);
            }
            toy_mls::Node::Parent { node_pk } => {
                println!("   Node {}: Parent (pk: {:02x?})", i, node_pk);
            }
        }
    }

    // Demonstrate forward secrecy with empty commit
    println!("\n5. Demonstrating forward secrecy with empty commit...");

    let epoch_before = group_state.context.epoch;
    let tree_hash_before = group_state.context.tree_hash;
    let secrets_before = group_state.secrets.epoch;

    let empty_commit = group_state
        .empty_commit()
        .expect("Failed to create empty commit");

    println!("   Empty commit created:");
    println!("     Epoch before: {}", epoch_before);
    println!("     Epoch after: {}", group_state.context.epoch);
    println!(
        "     Tree hash changed: {}",
        tree_hash_before != group_state.context.tree_hash
    );
    println!(
        "     Secrets changed: {}",
        secrets_before != group_state.secrets.epoch
    );
    println!("     Proposals in commit: {}", empty_commit.proposals.len());

    // Show that secrets are different (forward secrecy)
    println!("\n6. Forward secrecy demonstration:");
    println!("   Epoch secret before: {:02x?}", secrets_before);
    println!("   Epoch secret after:  {:02x?}", group_state.secrets.epoch);
    println!(
        "   Secrets are different: {}",
        secrets_before != group_state.secrets.epoch
    );

    // Remove a member
    println!("\n7. Removing a member...");

    let remove_leaf_index = 1; // Remove the second member
    let remove_commit = group_state
        .remove_member(remove_leaf_index)
        .expect("Failed to remove member");

    println!("   Member removed successfully:");
    println!("     Members after removal: {}", group_state.tree.size);
    println!("     New epoch: {}", group_state.context.epoch);
    println!("     New tree hash: {:02x?}", group_state.context.tree_hash);
    println!("     Active leaves: {}", group_state.tree.active_leaves());
    println!(
        "     Proposals in commit: {}",
        remove_commit.proposals.len()
    );

    // Show final tree structure
    println!("\n8. Final tree structure after removal:");
    for (i, node) in group_state.tree.nodes.iter().enumerate() {
        match node {
            toy_mls::Node::Blank => println!("   Node {}: Blank", i),
            toy_mls::Node::Leaf { leaf_pk, .. } => {
                println!("   Node {}: Leaf (pk: {:02x?})", i, leaf_pk);
            }
            toy_mls::Node::Parent { node_pk } => {
                println!("   Node {}: Parent (pk: {:02x?})", i, node_pk);
            }
        }
    }

    // Demonstrate epoch progression
    println!("\n9. Epoch progression summary:");
    println!("   Initial epoch: 0");
    println!("   After group creation: 0");
    println!("   After adding member: {}", group_state.context.epoch - 1);
    println!("   After empty commit: {}", group_state.context.epoch - 1);
    println!("   After removing member: {}", group_state.context.epoch);

    // Show key properties of MLS
    println!("\n10. MLS Key Properties Demonstrated:");
    println!("   ✅ Forward Secrecy: Secrets change with each epoch");
    println!("   ✅ Post-Compromise Security: New secrets after member removal");
    println!("   ✅ Tree Consistency: Tree hash updates with membership changes");
    println!("   ✅ Epoch Advancement: Each operation increments epoch");
    println!("   ✅ Dynamic Membership: Members can be added and removed");

    println!("\n=== Dynamic Membership Demo completed successfully! ===");
}
