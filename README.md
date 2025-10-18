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
It’s meant for engineers and students who want to **understand MLS by building it**.

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

# Run basic examples
cargo run --example basic_usage
cargo run --example group_operations
cargo run --example path_secrets
```

Each example demonstrates a specific aspect of MLS, such as ratchet trees, path secret derivation, or group commit processing.

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to the open community around [messaginglayersecurity.rocks](https://messaginglayersecurity.rocks/), the **IETF MLS Working Group**, and open-source contributors building educational cryptographic software.

## Let’s Talk

I enjoy discussing **cybersecurity**, **cryptography**, and the design of secure systems.

If you’re interested in these topics or want to exchange ideas, feel free to **reach out or open a discussion** in this repository.
