# Toy MLS

A simplified, educational implementation of the Messaging Layer Security (MLS) protocol to experiment with core cryptographic and group key exchange concepts.

## What is MLS?

[Messaging Layer Security (MLS)](https://messaginglayersecurity.rocks/) is an emerging IETF standard that enables secure group messaging at scale - think WhatsApp groups, Slack channels, or video conference rooms where messages are encrypted end-to-end.

Unlike traditional encryption that requires managing separate keys for each conversation partner, MLS uses a clever "ratchet tree" structure that allows groups to efficiently establish shared secrets, authenticate each other, and evolve keys automatically when members join or leave.

MLS provides advanced security features including:
- **Post-compromise secrecy**: Recovering security even if a device is compromised
- **Forward secrecy**: Past messages remain secure
- **Authentication**: All group members are verified

## Purpose of this Repository

`toy-mls` is a **learning-oriented prototype** that explores the fundamental ideas behind MLS, including:

* The **ratchet tree** structure used for group key derivation (TreeKEM)
* **Path secrets**, **copath encryption**, and **epoch key schedules**
* Simplified examples of **group creation**, **updates**, and **commits**
* **Proper UpdatePath handling** with sender node public keys
* **Confirmation tag validation** using HMAC-SHA256
* **Tree public key installation** after commits

This implementation focuses on **clarity and pedagogy**, not production security.
It's meant for engineers and students who want to **understand MLS by building it**.

## What's Intentionally Simplified

This educational implementation makes several intentional simplifications to focus on core MLS concepts:

### Tree Indexing
- **Default**: Uses heap-style indexing (root=0, left=2i+1, right=2i+2) for easier visualization
- **RFC 9420**: Available via `rfc_treemath` feature for specification compliance
- Both implementations are tested and functional

### Cryptographic Patterns
- **HPKE-style**: Uses simplified HPKE-like key derivation patterns instead of full HPKE
- **Key derivation**: Uses HKDF-Expand with MLS-specific labels for educational clarity
- **Path secrets**: Uses symmetric HKDF expansion instead of per-node HPKE encryption chains
- **Signatures**: Uses Ed25519 for simplicity, though MLS supports multiple schemes

### Confirmation Mechanism
- **Primary check**: Uses confirmation tags as the primary validation mechanism in this toy implementation
- **Simplified**: In production MLS, confirmation tags are one of several validation steps
- **Educational**: Focuses on the core concept of shared secret validation

### Error Handling
- **Simplified**: Uses basic error types instead of the full MLS error taxonomy
- **Educational**: Focuses on core error conditions rather than edge cases

These simplifications make the code more readable and educational while maintaining the essential MLS security properties and concepts.

## Prerequisites

You’ll need:

* 🦀 **Rust 1.80+** (Edition 2024 recommended)
* Cargo for building and running examples
* Basic familiarity with cryptography (Ed25519, X25519, HKDF)

Install Rust if needed:

```bash
curl https://sh.rustup.rs -sSf | sh
```

## How to Use

Clone the repository and explore the examples:

```bash
git clone https://github.com/cspinetta/toy-mls.git
cd toy-mls

# Run examples
cargo run --example mls_tour               # Complete MLS walkthrough with N=3 group
cargo run --example tree_operations        # Complete binary tree functionality and navigation
cargo run --example dynamic_membership     # Add/remove members and empty commits
cargo run --example real_copath_test       # Real copath public keys (not mock keys)
cargo run --example tree_math_comparison   # Compare educational vs RFC tree math
```

Each example demonstrates a specific aspect of MLS:

- **`mls_tour`**: Complete walkthrough of MLS operations with detailed explanations and visual output
- **`tree_operations`**: Shows how the ratchet tree structure works, including node navigation, direct paths, and copaths
- **`dynamic_membership`**: Demonstrates group lifecycle operations like adding/removing members and empty commits
- **`real_copath_test`**: Tests actual copath encryption/decryption with real public keys instead of mock data
- **`tree_math_comparison`**: Compares the educational heap-style tree math with the RFC 9420 compliant implementation

## Documentation

The project includes comprehensive documentation to help learners understand MLS concepts:

- **`docs/direct-path-copath.md`**: Visual explanation of direct paths vs copaths in MLS TreeKEM
- **Inline RFC references**: All key functions include references to relevant RFC 9420 sections
- **Educational comments**: Code is extensively commented to explain MLS concepts

## Testing

The project includes comprehensive testing to ensure both the educational implementation and RFC 9420 compliant implementation for tree indexing work correctly.

### Running Tests

```bash
# Run all tests (both implementations)
make test-all

# Run tests with default features (educational tree math)
make test-default

# Run tests with RFC treemath feature enabled
make test-rfc

# Run all checks (format, clippy, tests)
make check
```

### Test Coverage

The test suite includes:

- **36 unit tests** - Core functionality and edge cases
- **6 integration tests** - End-to-end MLS operations
- **4 security property tests** - Convergence, forward secrecy, post-compromise security
- **8 signature and error tests** - Ed25519 signatures and error handling
- **7 wire format tests** - CBOR serialization/deserialization
- **5 RFC treemath tests** - RFC 9420 compliant tree math (when feature enabled)

### Tree Math Implementations

The project supports two tree math implementations:

1. **Default (Educational)**: Heap-style tree structure that's easy to understand and visualize
2. **RFC 9420**: Exact specification-compliant implementation with left-balanced trees

Both implementations are tested to ensure they work correctly:

```bash
# Compare both implementations
cargo run --example tree_math_comparison                    # Default
cargo run --example tree_math_comparison --features rfc_treemath  # RFC 9420
```

### Continuous Integration

The project includes GitHub Actions CI that:
- Tests both tree math implementations
- Runs clippy and formatting checks
- Performs security audits
- Builds documentation

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to the open community around [messaginglayersecurity.rocks](https://messaginglayersecurity.rocks/), the **IETF MLS Working Group**, and open-source contributors building educational cryptographic software.

## Let’s Talk

I enjoy discussing **cybersecurity**, **cryptography**, and the design of secure systems.

If you’re interested in these topics or want to exchange ideas, feel free to **reach out or open a discussion** in this repository.
