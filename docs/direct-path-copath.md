# Direct Path vs Copath in MLS TreeKEM

This diagram illustrates the key concepts of **direct path** and **copath** in MLS TreeKEM, showing how secrets flow during group operations.

## Tree Structure (N=4 members)

```
        Root (0)
       /        \
   Parent (1)   Parent (2)
   /      \     /      \
Leaf(3) Leaf(4) Leaf(5) Leaf(6)
  A       B       C       D
```

## Direct Path vs Copath

### For Member A (Leaf 3):

**Direct Path**: `[3, 1, 0]` - Path from A to root
- Node 3 (A's leaf)
- Node 1 (A's parent)  
- Node 0 (root)

**Copath**: `[4, 2]` - Siblings of direct path nodes
- Node 4 (sibling of Node 1)
- Node 2 (sibling of Node 0)

### For Member C (Leaf 5):

**Direct Path**: `[5, 2, 0]` - Path from C to root
- Node 5 (C's leaf)
- Node 2 (C's parent)
- Node 0 (root)

**Copath**: `[6, 1]` - Siblings of direct path nodes
- Node 6 (sibling of Node 2)
- Node 1 (sibling of Node 0)

## Secret Flow During Updates

When **Member A** performs an update:

1. **A generates new path secrets** for nodes in its direct path: `[3, 1, 0]`
2. **A encrypts secrets** to copath subtrees: `[4, 2]`
   - Secret for level 1 → encrypted to Node 4 (B's subtree)
   - Secret for level 0 → encrypted to Node 2 (C&D's subtree)
3. **Other members decrypt** from their copath level:
   - B decrypts from level 1 (Node 4)
   - C and D decrypt from level 0 (Node 2)

## Key Properties

- **Direct Path**: Contains nodes that will receive new secrets
- **Copath**: Contains nodes that will encrypt secrets to other subtrees
- **Efficiency**: Each member only needs to decrypt one secret (from their copath level)
- **Security**: Forward secrecy - old secrets become useless after update

## RFC 9420 References

- Section 7.2: TreeKEM Overview
- Section 7.3: Update Paths  
- Section 7.4: Path Secret Derivation
- Section 12.4: Processing a Commit

## Visual Representation

```
Update by A (Leaf 3):

Direct Path: 3 → 1 → 0
             │   │   │
             ▼   ▼   ▼
           [new] [new] [new]  ← New secrets generated
             │   │   │
             ▼   ▼   ▼
Copath:     4   2   (none)
             │   │
             ▼   ▼
           [enc] [enc]  ← Secrets encrypted to these subtrees
             │   │
             ▼   ▼
            B   C,D  ← Recipients decrypt from these levels
```

This design ensures that:
- Only one decryption per member (efficient)
- All members converge to same epoch secrets (convergence)
- Old secrets become useless (forward secrecy)
- Compromised members can recover (post-compromise security)
