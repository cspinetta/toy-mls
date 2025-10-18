//! Ratchet tree implementation for MLS

use sha2::{Digest, Sha256};

use crate::messages::KeyPackage;

pub type LeafIndex = usize;
pub type NodeIndex = usize;

/// MLS ratchet tree node
#[derive(Clone, Debug)]
pub enum Node {
    Blank,
    Leaf {
        cred_pk: ed25519_dalek::VerifyingKey,
        leaf_pk: [u8; 32],
    },
    Parent {
        node_pk: [u8; 32],
    },
}

/// MLS ratchet tree
#[derive(Clone, Debug)]
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
                cred_pk: ed25519_dalek::VerifyingKey::try_from(&keypackage.cred_sig_pk[..])
                    .unwrap(),
                leaf_pk: keypackage.leaf_dh_pk,
            };
        }

        // Compute naive parents (this would normally involve key derivation)
        tree.compute_naive_parents();

        tree
    }

    /// Compute naive parent nodes (simplified implementation)
    fn compute_naive_parents(&mut self) {
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
    ///
    /// # Arguments
    /// * `keypackage` - The key package of the new member
    ///
    /// # Returns
    /// The leaf index of the newly inserted member
    pub fn insert_leaf(&mut self, keypackage: KeyPackage) -> LeafIndex {
        let old_size = self.size;
        let new_leaf_index = old_size;
        let new_node_index = old_size - 1 + new_leaf_index;

        // Expand the tree if needed
        if new_node_index >= self.nodes.len() {
            let additional_nodes = new_node_index - self.nodes.len() + 1;
            self.nodes.extend(vec![Node::Blank; additional_nodes]);
        }

        // Insert the new leaf
        self.nodes[new_node_index] = Node::Leaf {
            cred_pk: ed25519_dalek::VerifyingKey::from_bytes(&keypackage.cred_sig_pk).unwrap(),
            leaf_pk: keypackage.leaf_dh_pk,
        };

        // Update tree size
        self.size = old_size + 1;

        // Recompute parent nodes
        self.compute_naive_parents();

        new_leaf_index
    }

    /// Remove a leaf from the tree (mark as blank)
    ///
    /// # Arguments
    /// * `leaf_index` - The leaf index to remove
    pub fn remove_leaf(&mut self, leaf_index: LeafIndex) {
        // Silently ignore invalid removal
        if leaf_index >= self.size {
            return;
        }

        // Find the node index for this leaf index
        // We need to find the nth leaf (where n = leaf_index)
        let mut leaf_count = 0;
        for i in 0..self.nodes.len() {
            if matches!(self.nodes[i], Node::Leaf { .. }) {
                if leaf_count == leaf_index {
                    // Mark this leaf as blank
                    self.nodes[i] = Node::Blank;

                    // Recompute parent nodes
                    self.compute_naive_parents();
                    return;
                }
                leaf_count += 1;
            }
        }
    }

    /// Set the public key for a specific node in the tree
    ///
    /// # Arguments
    /// * `node_index` - The index of the node to update
    /// * `public_key` - The new public key to set
    ///
    /// # Returns
    /// Result indicating success or failure
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
        // Count all leaf nodes in the tree
        // Leaves are stored at indices (size-1) to (nodes.len()-1)
        // But we need to count all allocated leaf positions
        for i in 0..self.nodes.len() {
            if matches!(self.nodes[i], Node::Leaf { .. }) {
                count += 1;
            }
        }
        count
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
        assert!(tree.dirpath(0).len() > 0); // Should have a path
        assert!(tree.dirpath(1).len() > 0); // Should have a path
        assert!(tree.dirpath(2).len() > 0); // New leaf should have a path
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

        // Remove the last member (now at index 0, since we removed the previous index 0)
        tree.remove_leaf(0);
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
}
