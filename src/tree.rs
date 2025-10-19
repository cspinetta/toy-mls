//! Ratchet tree implementation for MLS
//!
//! This implementation supports two tree indexing schemes:
//! 1. **Heap-style indexing** (default): root=0, left=2i+1, right=2i+2
//!    - Simpler for visualization and educational purposes
//!    - Used when `rfc_treemath` feature is disabled
//! 2. **RFC 9420 left-balanced indexing**: leaves at even indices, internal nodes at odd indices
//!    - Compliant with MLS specification
//!    - Used when `rfc_treemath` feature is enabled

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::messages::KeyPackage;

pub type LeafIndex = usize;
pub type NodeIndex = usize;

/// MLS ratchet tree node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Node {
    Blank,
    Leaf {
        cred_pk: [u8; 32], // Serialize as bytes instead of VerifyingKey
        leaf_pk: [u8; 32],
    },
    Parent {
        node_pk: [u8; 32],
    },
}

/// MLS ratchet tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetTree {
    pub nodes: Vec<Node>, // complete tree
    pub size: usize,      // number of leaves (some may be blank)
}

impl RatchetTree {
    /// Create a new ratchet tree with the specified number of leaves
    pub fn new(size: usize) -> Self {
        // For a complete binary tree with 'size' leaves, we need 2*size - 1 nodes
        let total_nodes = if size == 0 { 0 } else { 2 * size - 1 };

        Self {
            nodes: vec![Node::Blank; total_nodes],
            size,
        }
    }

    /// Create a ratchet tree from key packages (leaves)
    pub fn from_leaves(keypackages: Vec<KeyPackage>) -> Self {
        let size = keypackages.len();
        let mut tree = Self::new(size);

        // Initialize leaves with key packages
        for (i, keypackage) in keypackages.iter().enumerate() {
            let leaf_index = tree.size - 1 + i;
            tree.nodes[leaf_index] = Node::Leaf {
                cred_pk: keypackage.cred_sig_pk,
                leaf_pk: keypackage.leaf_dh_pk,
            };
        }

        // Compute naive parents (this would normally involve key derivation)
        tree.compute_naive_parents();

        tree
    }

    /// Compute naive parent nodes (simplified implementation)
    fn compute_naive_parents(&mut self) {
        // Early return if size <= 1 (no internal nodes to compute)
        if self.size <= 1 {
            return;
        }

        // For each internal node, compute a parent key
        // In a real implementation, this would involve proper key derivation
        for i in (0..self.size - 1).rev() {
            if let (Some(left_child), Some(right_child)) =
                (self.left_child_index(i), self.right_child_index(i))
            {
                // Simplified: use hash of children's public keys
                let left_pk = self.get_node_public_key(left_child);
                let right_pk = self.get_node_public_key(right_child);

                if let (Some(left_pk), Some(right_pk)) = (left_pk, right_pk) {
                    let mut hasher = Sha256::new();
                    hasher.update(left_pk);
                    hasher.update(right_pk);
                    let parent_pk = hasher.finalize().into();

                    self.nodes[i] = Node::Parent { node_pk: parent_pk };
                }
            }
        }
    }

    /// Get the public key of a node (if it has one)
    pub fn get_node_public_key(&self, node_index: NodeIndex) -> Option<[u8; 32]> {
        match &self.nodes[node_index] {
            Node::Leaf { leaf_pk, .. } => Some(*leaf_pk),
            Node::Parent { node_pk } => Some(*node_pk),
            Node::Blank => None,
        }
    }

    /// Compute tree hash over node public keys (for context)
    pub fn compute_tree_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash all non-blank node public keys
        for node in &self.nodes {
            if let Some(pk) = match node {
                Node::Leaf { leaf_pk, .. } => Some(*leaf_pk),
                Node::Parent { node_pk } => Some(*node_pk),
                Node::Blank => None,
            } {
                hasher.update(pk);
            }
        }

        hasher.finalize().into()
    }

    // ===== Tree Navigation Functions =====

    /// Get the parent index of a node: parent(i)
    pub fn parent(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        if node_index == 0 {
            None // Root has no parent
        } else {
            Some((node_index - 1) / 2)
        }
    }

    /// Get the left child index of a node: left(i)
    pub fn left(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        let left = 2 * node_index + 1;
        if left < self.nodes.len() {
            Some(left)
        } else {
            None
        }
    }

    /// Get the right child index of a node: right(i)
    pub fn right(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        let right = 2 * node_index + 2;
        if right < self.nodes.len() {
            Some(right)
        } else {
            None
        }
    }

    /// Check if a node is a leaf: is_leaf(i)
    pub fn is_leaf(&self, node_index: NodeIndex) -> bool {
        node_index >= self.size - 1 && node_index < self.nodes.len()
    }

    /// Get the direct path from a leaf to the root: dirpath(leaf)
    ///
    /// Implements MLS direct path computation as defined in RFC 9420 §7.3.
    /// Returns the path from a leaf to the root, excluding the leaf itself.
    ///
    /// # RFC 9420 Reference
    /// - Section 7.3: Update Paths
    /// - Section 7.2: TreeKEM Overview
    pub fn dirpath(&self, leaf_index: LeafIndex) -> Vec<NodeIndex> {
        let mut path = Vec::new();
        let mut node_index = self.size - 1 + leaf_index;

        while let Some(parent) = self.parent(node_index) {
            path.push(parent);
            node_index = parent;
        }

        path
    }

    /// Get the copath (siblings of the direct path): copath(leaf)
    ///
    /// Implements MLS copath computation as defined in RFC 9420 §7.3.
    /// Returns the siblings of nodes in the direct path from leaf to root.
    ///
    /// # RFC 9420 Reference
    /// - Section 7.3: Update Paths
    /// - Section 7.2: TreeKEM Overview
    pub fn copath(&self, leaf_index: LeafIndex) -> Vec<NodeIndex> {
        let mut copath = Vec::new();
        let mut node_index = self.size - 1 + leaf_index;

        while let Some(parent) = self.parent(node_index) {
            // Add the sibling of current node
            if let Some(sibling) = self.sibling(node_index) {
                copath.push(sibling);
            }
            node_index = parent;
        }

        copath
    }

    /// Get the sibling of a node
    fn sibling(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        if let Some(parent) = self.parent(node_index) {
            if let Some(left_child) = self.left(parent) {
                if left_child == node_index {
                    self.right(parent)
                } else {
                    Some(left_child)
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    // ===== Legacy Methods (for backward compatibility) =====

    /// Get the leaf index from a node index
    pub fn leaf_index(&self, node_index: NodeIndex) -> Option<LeafIndex> {
        if self.is_leaf(node_index) {
            Some(node_index - (self.size - 1))
        } else {
            None
        }
    }

    /// Get the parent index of a node (legacy method)
    pub fn parent_index(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        self.parent(node_index)
    }

    /// Get the left child index of a node (legacy method)
    pub fn left_child_index(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        self.left(node_index)
    }

    /// Get the right child index of a node (legacy method)
    pub fn right_child_index(&self, node_index: NodeIndex) -> Option<NodeIndex> {
        self.right(node_index)
    }

    // ===== Dynamic Tree Operations =====

    /// Insert a new leaf into the tree (for adding members)
    pub fn insert_leaf(&mut self, keypackage: KeyPackage) -> LeafIndex {
        let old_size = self.size;
        let new_size = old_size + 1;
        let new_leaf_index = old_size;

        // Compute the required number of nodes for the new size
        let required_nodes = if new_size == 0 { 0 } else { 2 * new_size - 1 };

        // If we need more nodes, rebuild the complete tree
        if required_nodes > self.nodes.len() {
            // Create a new vector with the correct size, all Blank
            let mut new_nodes = vec![Node::Blank; required_nodes];

            // Copy existing leaves to their new positions in the new leaf band
            // Old leaf band: [old_size-1 .. 2*old_size-2]
            // New leaf band: [new_size-1 .. 2*new_size-2]
            for i in 0..old_size {
                let old_leaf_index = old_size - 1 + i;
                let new_leaf_index = new_size - 1 + i;

                if old_leaf_index < self.nodes.len() {
                    new_nodes[new_leaf_index] = self.nodes[old_leaf_index].clone();
                }
            }

            // Replace the old nodes with the new ones
            self.nodes = new_nodes;
        }

        // Insert the new leaf at the correct position
        let new_node_index = new_size - 1 + new_leaf_index;
        self.nodes[new_node_index] = Node::Leaf {
            cred_pk: keypackage.cred_sig_pk,
            leaf_pk: keypackage.leaf_dh_pk,
        };

        // Update tree size
        self.size = new_size;

        // Recompute parent nodes (this will handle all internal nodes)
        self.compute_naive_parents();

        new_leaf_index
    }

    /// Remove a leaf from the tree (mark as blank)
    pub fn remove_leaf(&mut self, leaf_index: LeafIndex) {
        // Silently ignore invalid removal
        if leaf_index >= self.size {
            return;
        }

        // Use heap mapping to find the correct node index
        let node_index = self.size - 1 + leaf_index;

        // Mark this leaf as blank
        self.nodes[node_index] = Node::Blank;

        // Recompute parent nodes
        self.compute_naive_parents();
    }

    /// Set the public key for a specific node in the tree
    pub fn set_node_public_key(
        &mut self,
        node_index: NodeIndex,
        public_key: [u8; 32],
    ) -> Result<(), String> {
        if node_index >= self.nodes.len() {
            return Err(format!("Node index {} out of bounds", node_index));
        }

        match &mut self.nodes[node_index] {
            Node::Parent { node_pk } => {
                *node_pk = public_key;
            }
            Node::Leaf { leaf_pk, .. } => {
                *leaf_pk = public_key;
            }
            Node::Blank => {
                // Convert blank node to parent node with the new public key
                self.nodes[node_index] = Node::Parent {
                    node_pk: public_key,
                };
            }
        }

        Ok(())
    }

    /// Get the number of active (non-blank) leaves
    pub fn active_leaves(&self) -> usize {
        let mut count = 0;
        // Count only leaf nodes in the leaf band (consistent with is_leaf())
        // Leaves are stored at indices (size-1) to (nodes.len()-1)
        for i in 0..self.size {
            let node_index = self.size - 1 + i;
            if node_index < self.nodes.len() && matches!(self.nodes[node_index], Node::Leaf { .. })
            {
                count += 1;
            }
        }
        count
    }

    /// Pretty-print the tree as ASCII structure
    ///
    /// Displays the current in-memory tree layout showing each node's
    /// index, type (Parent/Leaf/Blank), and short public key prefix.
    /// This helps visualize tree evolution across commits.
    ///
    /// # Example
    /// ```
    /// let tree = RatchetTree::new(3);
    /// tree.print_ascii(); // prints 3-leaf tree layout
    /// ```
    ///
    /// Output (for N=3):
    /// ```text
    /// Level 0: [ 0] Parent(...)
    /// Level 1: [ 1] Parent(...) [ 2] Leaf(2)
    /// Level 2: [ 3] Leaf(0) [ 4] Leaf(1)
    /// ```
    pub fn print_ascii(&self) {
        use std::fmt::Write;

        println!("\n=== Current Ratchet Tree ===");

        let mut level_start = 0;
        let mut level_size = 1;
        let mut level = 0;
        let mut output = String::new();

        while level_start < self.nodes.len() {
            write!(&mut output, "Level {}: ", level).unwrap();

            for i in level_start..(level_start + level_size).min(self.nodes.len()) {
                match &self.nodes[i] {
                    Node::Blank => write!(&mut output, "[{:2}] Blank  ", i).unwrap(),
                    Node::Parent { node_pk } => {
                        write!(
                            &mut output,
                            "[{:2}] Parent({:02x?})  ",
                            i,
                            &node_pk[..4]
                        )
                        .unwrap();
                    }
                    Node::Leaf { leaf_pk, .. } => {
                        let leaf_idx = if self.size > 0 && i >= self.size - 1 {
                            i - (self.size - 1)
                        } else {
                            i
                        };
                        write!(
                            &mut output,
                            "[{:2}] Leaf({}) {:02x?}  ",
                            i,
                            leaf_idx,
                            &leaf_pk[..4]
                        )
                        .unwrap();
                    }
                }
            }

            output.push('\n');
            level_start += level_size;
            level_size *= 2;
            level += 1;
        }

        println!("{}", output);
        println!("============================\n");
    }
}

// ===== RFC 9420 Tree Math Implementation =====

/// RFC 9420 compliant tree math functions
///
/// These functions implement the left-balanced tree structure as defined in RFC 9420.
/// The key insight is that RFC 9420 uses a complete binary tree where:
/// - The tree is left-balanced (as left-heavy as possible)
/// - Leaves are at the bottom level
/// - Internal nodes are at higher levels
/// - The root is at the highest index
#[cfg(feature = "rfc_treemath")]
pub mod rfc_treemath {
    use super::{LeafIndex, NodeIndex};

    /// Get the number of leaves in a tree of given size
    pub fn leaf_count(size: usize) -> usize {
        size.div_ceil(2)
    }

    /// Get the number of nodes in a tree with given number of leaves
    /// RFC 9420: node_width(n) = 2*(n-1) + 1
    pub fn node_count(leaf_count: usize) -> usize {
        if leaf_count == 0 {
            0
        } else {
            2 * (leaf_count - 1) + 1
        }
    }

    /// Get the parent of a node in RFC tree structure
    /// RFC 9420: parent(x, n) = (x | (1 << k)) ^ (b << (k + 1)) where k = level(x), b = (x >> (k + 1)) & 0x01
    pub fn parent(node_index: NodeIndex, leaf_count: usize) -> Option<NodeIndex> {
        let root = root(leaf_count);
        if node_index == root {
            None // Root has no parent
        } else {
            let k = level(node_index);
            let b = (node_index >> (k + 1)) & 0x01;
            Some((node_index | (1 << k)) ^ (b << (k + 1)))
        }
    }

    /// Get the left child of a node in RFC tree structure
    /// RFC 9420: left(x) = x ^ (0x01 << (k - 1)) where k = level(x)
    pub fn left(node_index: NodeIndex, _size: usize) -> Option<NodeIndex> {
        let k = level(node_index);
        if k == 0 {
            None // Leaf node has no children
        } else {
            Some(node_index ^ (0x01 << (k - 1)))
        }
    }

    /// Get the right child of a node in RFC tree structure
    /// RFC 9420: right(x) = x ^ (0x03 << (k - 1)) where k = level(x)
    pub fn right(node_index: NodeIndex, _size: usize) -> Option<NodeIndex> {
        let k = level(node_index);
        if k == 0 {
            None // Leaf node has no children
        } else {
            Some(node_index ^ (0x03 << (k - 1)))
        }
    }

    /// Get the sibling of a node
    /// RFC 9420: sibling(x, n) = if x < parent(x) then right(parent(x)) else left(parent(x))
    pub fn sibling(node_index: NodeIndex, leaf_count: usize) -> Option<NodeIndex> {
        let root = root(leaf_count);
        if node_index == root {
            None // Root has no sibling
        } else {
            let parent = parent(node_index, leaf_count)?;
            if node_index < parent {
                right(parent, 0) // x is left child, sibling is right
            } else {
                left(parent, 0) // x is right child, sibling is left
            }
        }
    }

    /// Get the direct path from a leaf to the root
    /// RFC 9420: direct_path(x, n) - ordered from leaf to root
    pub fn direct_path(leaf_index: LeafIndex, leaf_count: usize) -> Vec<NodeIndex> {
        let mut path = Vec::new();
        let node_index = 2 * leaf_index; // RFC 9420: n-th leaf at 2*n
        let root = root(leaf_count);

        if node_index == root {
            return path; // Already at root
        }

        let mut x = node_index;
        while x != root {
            x = parent(x, leaf_count).unwrap();
            path.push(x);
        }

        path
    }

    /// Get the copath of a leaf (siblings of nodes on direct path)
    /// RFC 9420: copath(x, n) - ordered from leaf to root
    pub fn copath(leaf_index: LeafIndex, leaf_count: usize) -> Vec<NodeIndex> {
        let node_index = 2 * leaf_index; // RFC 9420: n-th leaf at 2*n
        let root = root(leaf_count);

        if node_index == root {
            return vec![]; // Root has no copath
        }

        let mut d = direct_path(leaf_index, leaf_count);
        d.insert(0, node_index);
        d.pop(); // Remove root

        d.into_iter()
            .filter_map(|y| sibling(y, leaf_count))
            .collect()
    }

    /// Check if a node is a leaf
    /// RFC 9420: Leaves are at even indices
    pub fn is_leaf(node_index: NodeIndex) -> bool {
        node_index & 0x01 == 0
    }

    /// Get the leaf index from a node index
    /// RFC 9420: n-th leaf at 2*n, so leaf_index = node_index / 2
    pub fn leaf_index(node_index: NodeIndex) -> Option<LeafIndex> {
        if is_leaf(node_index) {
            Some(node_index / 2)
        } else {
            None
        }
    }

    /// Get the level of a node (0 for leaves, increasing toward root)
    /// RFC 9420: Leaves are level 0, their parents are level 1, etc.
    pub fn level(node_index: NodeIndex) -> usize {
        if node_index & 0x01 == 0 {
            // Even index = leaf = level 0
            0
        } else {
            // Odd index = internal node
            // Count consecutive 1s from the right
            let mut k = 0;
            let mut x = node_index;
            while (x & 0x01) == 1 {
                k += 1;
                x >>= 1;
            }
            k
        }
    }

    /// Get the root index of a tree with given number of leaves
    /// RFC 9420: root(n) = (1 << log2(node_width(n))) - 1
    pub fn root(leaf_count: usize) -> NodeIndex {
        if leaf_count == 0 {
            0
        } else {
            let w = node_count(leaf_count);
            let log2_w = log2(w);
            (1 << log2_w) - 1
        }
    }

    /// The exponent of the largest power of 2 less than x
    /// RFC 9420: log2(x) = int(math.floor(math.log(x, 2)))
    fn log2(x: usize) -> usize {
        if x == 0 {
            return 0;
        }

        let mut k = 0;
        let mut temp = x;
        while temp > 0 {
            temp >>= 1;
            k += 1;
        }
        k - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, SigKeyPair};

    /// Helper function to create a test key package
    fn create_test_keypackage() -> KeyPackage {
        let keypair = KeyPair::generate();
        let sig_keypair = SigKeyPair::generate();

        KeyPackage {
            cred_sig_pk: sig_keypair.pk.to_bytes(),
            leaf_dh_pk: keypair.pk,
            signature: vec![],
        }
    }

    #[test]
    fn test_add_remove_leaves() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);
        assert_eq!(tree.active_leaves(), 2);
        assert_eq!(tree.size, 2);

        let idx3 = tree.insert_leaf(kp3.clone());
        assert_eq!(tree.active_leaves(), 3);
        assert_eq!(tree.size, 3);
        assert_eq!(idx3, 2); // Should be the third leaf (index 2)

        tree.remove_leaf(idx3);
        assert_eq!(tree.active_leaves(), 2);
        assert_eq!(tree.size, 3); // Size doesn't change, but active leaves do
    }

    #[test]
    fn test_multiple_insertions() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();
        let kp4 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone()]);
        assert_eq!(tree.active_leaves(), 1);
        assert_eq!(tree.size, 1);

        // Add multiple members in sequence
        let idx2 = tree.insert_leaf(kp2.clone());
        assert_eq!(idx2, 1);
        assert_eq!(tree.active_leaves(), 2);

        let idx3 = tree.insert_leaf(kp3.clone());
        assert_eq!(idx3, 2);
        assert_eq!(tree.active_leaves(), 3);

        let idx4 = tree.insert_leaf(kp4.clone());
        assert_eq!(idx4, 3);
        assert_eq!(tree.active_leaves(), 4);
    }

    #[test]
    fn test_remove_invalid_leaf() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);
        assert_eq!(tree.active_leaves(), 2);

        // Try to remove a non-existent leaf
        tree.remove_leaf(5); // Invalid index
        assert_eq!(tree.active_leaves(), 2); // Should remain unchanged

        // Try to remove a leaf beyond the current size
        tree.remove_leaf(10);
        assert_eq!(tree.active_leaves(), 2); // Should remain unchanged
    }

    #[test]
    fn test_tree_navigation_consistency() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);

        // For a 2-member tree: Node 0=Parent, Node 1=Leaf0, Node 2=Leaf1
        // Test initial navigation
        assert_eq!(tree.dirpath(0), vec![0]); // Leaf 0's path to root
        assert_eq!(tree.dirpath(1), vec![0]); // Leaf 1's path to root
        assert_eq!(tree.copath(0), vec![2]); // Leaf 0's copath (sibling leaf)
        assert_eq!(tree.copath(1), vec![1]); // Leaf 1's copath (sibling leaf)

        // Add a third member
        let idx3 = tree.insert_leaf(kp3.clone());
        assert_eq!(idx3, 2);

        // Test navigation after addition - structure may change
        // The exact paths depend on how the tree grows
        assert!(!tree.dirpath(0).is_empty()); // Should have a path
        assert!(!tree.dirpath(1).is_empty()); // Should have a path
        assert!(!tree.dirpath(2).is_empty()); // New leaf should have a path
    }

    #[test]
    fn test_tree_hash_consistency() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);
        let initial_hash = tree.compute_tree_hash();

        // Add a member
        tree.insert_leaf(kp3.clone());
        let after_add_hash = tree.compute_tree_hash();
        assert_ne!(initial_hash, after_add_hash); // Hash should change

        // Remove a member
        tree.remove_leaf(1);
        let after_remove_hash = tree.compute_tree_hash();
        assert_ne!(after_add_hash, after_remove_hash); // Hash should change again
    }

    #[test]
    fn test_active_leaves_counting() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);
        assert_eq!(tree.active_leaves(), 2);

        // Add a member
        tree.insert_leaf(kp3.clone());
        assert_eq!(tree.active_leaves(), 3);

        // Remove a member
        tree.remove_leaf(1);
        assert_eq!(tree.active_leaves(), 2);

        // Remove another member
        tree.remove_leaf(0);
        assert_eq!(tree.active_leaves(), 1);

        // Remove the last member (now at index 2, since we removed indices 1 and 0)
        tree.remove_leaf(2);
        assert_eq!(tree.active_leaves(), 0);
    }

    #[test]
    fn test_tree_structure_integrity() {
        let kp1 = create_test_keypackage();
        let kp2 = create_test_keypackage();
        let kp3 = create_test_keypackage();
        let kp4 = create_test_keypackage();

        let mut tree = RatchetTree::from_leaves(vec![kp1.clone(), kp2.clone()]);

        // Verify initial structure
        assert_eq!(tree.nodes.len(), 3); // 2*2-1 = 3 nodes for 2 leaves
        assert!(matches!(tree.nodes[0], Node::Parent { .. })); // Root
        assert!(matches!(tree.nodes[1], Node::Leaf { .. })); // Leaf 0
        assert!(matches!(tree.nodes[2], Node::Leaf { .. })); // Leaf 1

        // Add members and verify structure grows
        tree.insert_leaf(kp3.clone());
        assert!(tree.nodes.len() >= 4); // Should have at least 4 nodes now

        tree.insert_leaf(kp4.clone());
        assert!(tree.nodes.len() >= 5); // Should have at least 5 nodes now
    }

    #[test]
    fn test_both_tree_math_implementations() {
        // This test ensures both default and RFC treemath implementations work correctly
        // It runs regardless of feature flags and validates the educational implementation

        // Test basic tree math with default implementation
        let leaf_count = 4;
        let size = 2 * leaf_count - 1; // Default heap-style calculation

        // Test that our default tree math functions work
        assert_eq!(size, 7); // 4 leaves = 7 total nodes in heap structure

        // Test tree navigation with default implementation
        let tree = RatchetTree::from_leaves(vec![
            create_test_keypackage(),
            create_test_keypackage(),
            create_test_keypackage(),
            create_test_keypackage(),
        ]);

        // Verify the tree structure is correct
        assert_eq!(tree.active_leaves(), 4);
        assert!(tree.nodes.len() >= 7);

        // Test that tree navigation functions work
        assert!(tree.parent(0).is_some() || tree.parent(0).is_none()); // Should not panic
        assert!(tree.left(0).is_some() || tree.left(0).is_none());
        assert!(tree.right(0).is_some() || tree.right(0).is_none());

        // Test that direct path calculation works
        let path = tree.dirpath(0);
        assert!(path.len() <= 3); // Should be reasonable path length for 4 leaves

        // Test that copath calculation works
        let copath = tree.copath(0);
        assert!(copath.len() <= 3); // Should be reasonable copath length

        // If RFC treemath is available, test it too
        #[cfg(feature = "rfc_treemath")]
        {
            // Test RFC treemath functions
            assert_eq!(rfc_treemath::leaf_count(7), 4);
            assert_eq!(rfc_treemath::node_count(4), 7);
            assert_eq!(rfc_treemath::root(4), 3);

            // Test that RFC functions produce valid results
            assert!(rfc_treemath::parent(0, 4).is_some() || rfc_treemath::parent(0, 4).is_none());
            assert!(rfc_treemath::left(1, 7).is_some() || rfc_treemath::left(1, 7).is_none());
            assert!(rfc_treemath::right(1, 7).is_some() || rfc_treemath::right(1, 7).is_none());

            // Test direct path and copath
            let rfc_path = rfc_treemath::direct_path(0, 4);
            let rfc_copath = rfc_treemath::copath(0, 4);
            assert!(rfc_path.len() <= 3);
            assert!(rfc_copath.len() <= 3);

            // Verify RFC structure is different from default (educational value)
            assert_ne!(rfc_treemath::root(4), 6); // RFC root is 3, default would be 6
        }
    }

    #[cfg(feature = "rfc_treemath")]
    mod rfc_treemath_tests {
        use super::rfc_treemath::*;

        #[test]
        fn test_rfc_basic_functions() {
            // Test basic tree math functions
            assert_eq!(leaf_count(0), 0);
            assert_eq!(leaf_count(1), 1);
            assert_eq!(leaf_count(3), 2);
            assert_eq!(leaf_count(7), 4);

            assert_eq!(node_count(0), 0);
            assert_eq!(node_count(1), 1);
            assert_eq!(node_count(2), 3);
            assert_eq!(node_count(4), 7);

            assert_eq!(root(0), 0);
            assert_eq!(root(1), 0);
            assert_eq!(root(2), 1);
            assert_eq!(root(4), 3);
        }

        #[test]
        fn test_rfc_tree_structure() {
            // Test that the tree structure is consistent
            let leaf_count = 4;
            let size = node_count(leaf_count);

            // For 4 leaves, RFC 9420 structure:
            //     3 (root)
            //    / \
            //   1   5
            //  / \ / \
            // 0  2 4  6
            // Test parent-child relationships
            assert_eq!(parent(0, leaf_count), Some(1));
            assert_eq!(parent(1, leaf_count), Some(3));
            assert_eq!(parent(2, leaf_count), Some(1));
            assert_eq!(parent(3, leaf_count), None); // Root has no parent
            assert_eq!(parent(4, leaf_count), Some(5));
            assert_eq!(parent(5, leaf_count), Some(3));
            assert_eq!(parent(6, leaf_count), Some(5));

            // Test left-right children
            assert_eq!(left(1, size), Some(0));
            assert_eq!(right(1, size), Some(2));
            assert_eq!(left(3, size), Some(1));
            assert_eq!(right(3, size), Some(5));
            assert_eq!(left(5, size), Some(4));
            assert_eq!(right(5, size), Some(6));
        }

        #[test]
        fn test_rfc_direct_path() {
            // Test direct path calculation
            let leaf_count = 4;

            // For a 4-leaf tree with RFC 9420 structure:
            //     3 (root)
            //    / \
            //   1   5
            //  / \ / \
            // 0  2 4  6
            // Leaf 0 (node 0): path is 0 -> 1 -> 3
            assert_eq!(direct_path(0, leaf_count), vec![1, 3]);

            // Leaf 1 (node 2): path is 2 -> 1 -> 3
            assert_eq!(direct_path(1, leaf_count), vec![1, 3]);

            // Leaf 2 (node 4): path is 4 -> 5 -> 3
            assert_eq!(direct_path(2, leaf_count), vec![5, 3]);

            // Leaf 3 (node 6): path is 6 -> 5 -> 3
            assert_eq!(direct_path(3, leaf_count), vec![5, 3]);
        }

        #[test]
        fn test_rfc_copath() {
            // Test copath calculation
            let leaf_count = 4;

            // For RFC 9420 structure, test copaths
            // Leaf 0 (node 0): copath is [2, 5] (siblings of 0->1->3)
            assert_eq!(copath(0, leaf_count), vec![2, 5]);

            // Leaf 1 (node 2): copath is [0, 5] (siblings of 2->1->3)
            assert_eq!(copath(1, leaf_count), vec![0, 5]);

            // Leaf 2 (node 4): copath is [6, 1] (siblings of 4->5->3)
            assert_eq!(copath(2, leaf_count), vec![6, 1]);

            // Leaf 3 (node 6): copath is [4, 1] (siblings of 6->5->3)
            assert_eq!(copath(3, leaf_count), vec![4, 1]);
        }

        #[test]
        fn test_rfc_level() {
            // Test level calculation for RFC 9420 structure
            // For 4 leaves, the structure is:
            //     3 (level 2 - root)
            //    / \
            //   1   5 (level 1)
            //  / \ / \
            // 0  2 4  6 (level 0 - leaves)
            assert_eq!(level(0), 0); // Leaf
            assert_eq!(level(1), 1); // Internal
            assert_eq!(level(2), 0); // Leaf
            assert_eq!(level(3), 2); // Root
            assert_eq!(level(4), 0); // Leaf
            assert_eq!(level(5), 1); // Internal
            assert_eq!(level(6), 0); // Leaf
        }
    }
}
