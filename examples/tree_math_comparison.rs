//! Tree Math Comparison Example
//!
//! This example demonstrates the difference between the default heap-style tree indexing
//! and the RFC 9420 compliant left-balanced tree indexing.
//!
//! Run with default indexing:
//!   cargo run --example tree_math_comparison
//!
//! Run with RFC 9420 indexing:
//!   cargo run --example tree_math_comparison --features rfc_treemath

// use toy_mls::tree::{LeafIndex, NodeIndex}; // Not directly used in this example

fn main() {
    println!("=== Tree Math Comparison ===\n");

    // Demonstrate with a 4-leaf tree
    let num_leaves = 4;
    let tree_size = 2 * num_leaves - 1; // 7 nodes total

    println!(
        "Tree with {} leaves ({} total nodes):",
        num_leaves, tree_size
    );
    println!("Tree structure:");
    println!("     6");
    println!("    / \\");
    println!("   2   5");
    println!("  / \\ / \\");
    println!(" 0  1 3  4");
    println!();

    #[cfg(not(feature = "rfc_treemath"))]
    {
        println!("Using DEFAULT heap-style indexing:");
        println!("- Root at index 0");
        println!("- Left child of i: 2*i+1");
        println!("- Right child of i: 2*i+2");
        println!("- Parent of i: (i-1)/2");
        println!();

        // Demonstrate heap-style navigation
        for leaf_idx in 0..num_leaves {
            let node_idx = tree_size - 1 + leaf_idx; // Heap-style leaf positioning
            println!("Leaf {} at node index {}", leaf_idx, node_idx);

            // Show direct path
            let mut path = Vec::new();
            let mut current = node_idx;
            while current > 0 {
                current = (current - 1) / 2; // Parent
                path.push(current);
            }
            println!("  Direct path: {:?}", path);

            // Show copath (simplified)
            let mut copath = Vec::new();
            let mut current = node_idx;
            while current > 0 {
                let parent = (current - 1) / 2;
                let sibling = if current % 2 == 1 {
                    current + 1
                } else {
                    current - 1
                };
                if sibling < tree_size {
                    copath.push(sibling);
                }
                current = parent;
            }
            println!("  Copath: {:?}", copath);
            println!();
        }
    }

    #[cfg(feature = "rfc_treemath")]
    {
        println!("Using RFC 9420 left-balanced indexing:");
        println!("- Leaves at even indices (0, 2, 4, 6, ...)");
        println!("- Internal nodes at odd indices (1, 3, 5, 7, ...)");
        println!("- Left-balanced structure (as left-heavy as possible)");
        println!();

        use toy_mls::tree::rfc_treemath::*;

        // Demonstrate RFC navigation
        for leaf_idx in 0..num_leaves {
            let node_idx = 2 * leaf_idx; // RFC-style: leaves at even indices
            println!("Leaf {} at node index {}", leaf_idx, node_idx);

            // Show direct path using RFC functions
            let path = direct_path(leaf_idx, num_leaves);
            println!("  Direct path: {:?}", path);

            // Show copath using RFC functions
            let copath = copath(leaf_idx, num_leaves);
            println!("  Copath: {:?}", copath);
            println!();
        }

        println!("RFC Tree Math Functions:");
        println!("- leaf_count({}) = {}", tree_size, leaf_count(tree_size));
        println!("- node_count({}) = {}", num_leaves, node_count(num_leaves));
        println!("- root({}) = {}", num_leaves, root(num_leaves));
        println!();

        println!("Node types:");
        for i in 0..tree_size {
            let node_type = if is_leaf(i) { "Leaf" } else { "Internal" };
            let level = level(i);
            println!("  Node {}: {} (level {})", i, node_type, level);
        }
    }

    println!("=== Key Differences ===");
    println!("1. **Leaf positioning**:");
    println!("   - Default: Leaves at end of array (indices 3,4,5,6 for 4 leaves)");
    println!("   - RFC: Leaves at even indices (0,2,4,6)");
    println!();
    println!("2. **Tree structure**:");
    println!("   - Default: Standard heap structure");
    println!("   - RFC: Left-balanced (optimized for MLS operations)");
    println!();
    println!("3. **Educational value**:");
    println!("   - Default: Easier to understand and visualize");
    println!("   - RFC: Matches the actual MLS specification");
    println!();
    println!("To switch between modes, use:");
    println!("  cargo run --example tree_math_comparison                    # Default");
    println!("  cargo run --example tree_math_comparison --features rfc_treemath  # RFC 9420");
}
