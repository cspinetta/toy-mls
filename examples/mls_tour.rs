//! MLS Tour Example - Complete Walkthrough with N=3 Group
//!
//! This example demonstrates every step of MLS group operations with detailed
//! explanations and visual output. Perfect for understanding how MLS works
//! in practice.

use toy_mls::GroupState;
use toy_mls::crypto::{KeyPair, SigKeyPair};
use toy_mls::messages::KeyPackage;

fn main() {
    println!("=== MLS Tour: Complete Walkthrough (N=3) ===\n");

    // Step 1: Create key packages for 3 members
    println!("🔑 Step 1: Creating Key Packages");
    println!("Generating cryptographic keys for 3 members...\n");

    let alice_keypair = KeyPair::generate();
    let alice_sig_keypair = SigKeyPair::generate();
    let alice_keypackage = KeyPackage::new(&alice_sig_keypair, alice_keypair.pk);

    let bob_keypair = KeyPair::generate();
    let bob_sig_keypair = SigKeyPair::generate();
    let bob_keypackage = KeyPackage::new(&bob_sig_keypair, bob_keypair.pk);

    let charlie_keypair = KeyPair::generate();
    let charlie_sig_keypair = SigKeyPair::generate();
    let charlie_keypackage = KeyPackage::new(&charlie_sig_keypair, charlie_keypair.pk);

    println!("✅ Alice's key package created");
    println!("✅ Bob's key package created");
    println!("✅ Charlie's key package created\n");

    // Step 2: Create initial group (Alice as creator)
    println!("🏗️  Step 2: Creating Initial Group");
    println!("Alice creates a group and invites Bob and Charlie...\n");

    let group_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let others = vec![bob_keypackage.clone(), charlie_keypackage.clone()];

    let creation_result = GroupState::create_group(group_id, alice_keypackage, others);
    let mut alice_state = creation_result.creator_state;
    let _initial_commit = creation_result.commit;

    println!("✅ Group created with ID: {:02x?}", group_id);
    println!(
        "✅ Initial tree hash: {:02x?}",
        alice_state.context.tree_hash
    );
    println!("✅ Initial epoch: {}", alice_state.context.epoch);
    println!("✅ Alice is leaf {}", alice_state.my_leaf);
    println!("✅ Bob is leaf 1");
    println!("✅ Charlie is leaf 2\n");

    // Step 3: Show tree structure
    println!("🌳 Step 3: Tree Structure");
    println!("Visualizing the actual in-memory tree:\n");
    alice_state.tree.print_ascii();

    // Step 4: Show direct paths and copaths
    println!("🛤️  Step 4: Direct Paths and Copaths");
    println!("Understanding how secrets flow in the tree:\n");

    let tree = &alice_state.tree;

    // Alice's paths
    let alice_dirpath = tree.dirpath(0);
    let alice_copath = tree.copath(0);
    println!("Alice (leaf 0):");
    println!("  Direct path: {:?} (path to root)", alice_dirpath);
    println!("  Copath: {:?} (siblings of direct path)", alice_copath);
    println!();

    // Bob's paths
    let bob_dirpath = tree.dirpath(1);
    let bob_copath = tree.copath(1);
    println!("Bob (leaf 1):");
    println!("  Direct path: {:?} (path to root)", bob_dirpath);
    println!("  Copath: {:?} (siblings of direct path)", bob_copath);
    println!();

    // Charlie's paths
    let charlie_dirpath = tree.dirpath(2);
    let charlie_copath = tree.copath(2);
    println!("Charlie (leaf 2):");
    println!("  Direct path: {:?} (path to root)", charlie_dirpath);
    println!("  Copath: {:?} (siblings of direct path)", charlie_copath);
    println!();

    // Step 5: Demonstrate secret derivation
    println!("🔐 Step 5: Secret Derivation");
    println!("How epoch secrets are derived from the tree:\n");

    let current_epoch = alice_state.context.epoch;
    println!("Current epoch: {}", current_epoch);
    println!("Epoch secret: {:02x?}", alice_state.secrets.epoch);
    println!("Handshake key: {:02x?}", alice_state.secrets.handshake_key);
    println!("Application key: {:02x?}", alice_state.secrets.app_key);
    println!("Confirmation key: {:02x?}", alice_state.secrets.conf_key);
    println!();

    // Step 6: Add a new member (David)
    println!("👤 Step 6: Adding New Member (David)");
    println!("Alice adds David to the group...\n");

    let david_keypair = KeyPair::generate();
    let david_sig_keypair = SigKeyPair::generate();
    let david_keypackage = KeyPackage::new(&david_sig_keypair, david_keypair.pk);

    let add_commit = alice_state.add_member(david_keypackage).unwrap();

    println!("✅ David added to the group");
    println!("✅ New tree hash: {:02x?}", alice_state.context.tree_hash);
    println!("✅ New epoch: {}", alice_state.context.epoch);
    println!("✅ David is now leaf 3");
    println!();

    // Show updated tree structure
    println!("Updated tree structure after adding David:");
    alice_state.tree.print_ascii();

    // Step 7: Demonstrate empty commit
    println!("🔄 Step 7: Empty Commit");
    println!("Alice performs an empty commit (no topology change)...\n");

    let empty_commit = alice_state.empty_commit().unwrap();

    println!("✅ Empty commit created");
    println!("✅ New epoch: {}", alice_state.context.epoch);
    println!("✅ Tree structure unchanged");
    println!("✅ New secrets derived (forward secrecy)");
    println!();

    // Step 8: Show security properties
    println!("🛡️  Step 8: Security Properties");
    println!("Demonstrating MLS security guarantees:\n");

    let old_epoch = current_epoch;
    let new_epoch = alice_state.context.epoch;

    println!("Forward Secrecy:");
    println!("  Old epoch: {}", old_epoch);
    println!("  New epoch: {}", new_epoch);
    println!("  Old secrets are now useless for new messages");
    println!();

    println!("Convergence:");
    println!("  All members derive identical epoch secrets");
    println!("  Tree hash ensures everyone has same view");
    println!();

    println!("Post-Compromise Security:");
    println!("  Compromised members can recover through updates");
    println!("  New secrets cannot be derived from old ones");
    println!();

    // Step 9: Show commit structure
    println!("📋 Step 9: Commit Structure");
    println!("Examining the structure of MLS commits:\n");

    println!("Add Member Commit:");
    println!("  Proposals: {:?}", add_commit.proposals);
    println!(
        "  Update path length: {}",
        add_commit.update_path.as_ref().map_or(0, |v| v.len())
    );
    println!("  Confirmation tag: {:02x?}", add_commit.confirmation_tag);
    println!("  Signature: {:02x?}", add_commit.signature);
    println!();

    println!("Empty Commit:");
    println!("  Proposals: {:?}", empty_commit.proposals);
    println!(
        "  Update path length: {}",
        empty_commit.update_path.as_ref().map_or(0, |v| v.len())
    );
    println!("  Confirmation tag: {:02x?}", empty_commit.confirmation_tag);
    println!("  Signature: {:02x?}", empty_commit.signature);
    println!();

    // Step 10: Demonstrate wire format
    println!("📡 Step 10: Wire Format");
    println!("How MLS messages are serialized for transmission:\n");

    let commit_bytes = serde_cbor::to_vec(&add_commit).unwrap();
    println!("Commit serialized to {} bytes", commit_bytes.len());

    let _deserialized_commit: toy_mls::messages::Commit =
        serde_cbor::from_slice(&commit_bytes).unwrap();
    println!("Commit deserialized successfully");
    println!("Round-trip integrity: ✅");
    println!();

    // Step 11: Show final state
    println!("🏁 Step 11: Final Group State");
    println!("Summary of the final group state:\n");

    println!("Group ID: {:02x?}", alice_state.context.group_id);
    println!("Current epoch: {}", alice_state.context.epoch);
    println!("Tree hash: {:02x?}", alice_state.context.tree_hash);
    println!("Number of members: 4 (Alice, Bob, Charlie, David)");
    println!("Alice's leaf index: {}", alice_state.my_leaf);
    println!("Path secrets stored: {}", alice_state.my_sec.len());
    println!();

    println!("🎉 MLS Tour Complete!");
    println!("You've seen how MLS provides:");
    println!("  ✅ Secure group messaging");
    println!("  ✅ Efficient key management");
    println!("  ✅ Forward secrecy");
    println!("  ✅ Post-compromise security");
    println!("  ✅ Scalable group operations");
    println!();

    println!("For more details, see:");
    println!("  📖 RFC 9420: The Messaging Layer Security (MLS) Protocol");
    println!("  📁 docs/direct-path-copath.md: Tree structure explanation");
    println!("  🧪 Run other examples: cargo run --example <name>");
}
