# AI Agent Guidelines for toy-mls

This document provides guidelines for AI agents contributing to the toy-mls project, an educational implementation of the MLS (Messaging Layer Security) protocol.

## Project Overview

toy-mls is a simplified, educational implementation of MLS designed for learning and experimentation. It focuses on clarity and educational value over production robustness.

## Code Style & Documentation

### Documentation Philosophy
- **Avoid verbosity**: Keep documentation concise and focused
- **Educational focus**: Add short, meaningful documentation when it helps understanding
- **No redundant details**: Avoid `# Arguments` and `# Returns` sections - the function signature is self-explanatory
- **Focus on "why" not "what"**: Explain the purpose and context, not just the implementation

### Rust Code Style
- Follow standard Rust formatting with `cargo fmt`
- **Code must pass `cargo clippy` cleanly** - no warnings or suggestions
- Use `snake_case` for functions and variables
- Use `PascalCase` for types and traits
- Prefer explicit error handling with `Result<T, E>`
- Use meaningful variable names that reflect MLS terminology
- Group related functionality in modules

### Import Organization
- **Always place imports at the top of modules** - never inside functions
- Group imports logically: std, external crates, internal modules
- Use `use` statements consistently across the codebase

## Architecture Guidelines

### Module Structure
- Keep cryptographic operations in `crypto.rs`
- Tree operations in `tree.rs`
- Path secret derivation in `path_secrets.rs`
- Group state management in `group.rs`
- Message types in `messages.rs`
- Error types in `error.rs`

### Security Considerations
- Always zeroize secrets when they're dropped using the `zeroize` crate
- Use proper error types (`MlsError`) instead of generic strings
- Validate inputs and handle edge cases gracefully
- Document security properties and assumptions

### Testing Philosophy
- Write comprehensive tests for all public APIs
- Include both unit tests and integration tests
- Test security properties explicitly (convergence, forward secrecy, post-compromise security)
- Use meaningful test names that describe the scenario
- Prefer integration tests over unit tests for complex MLS operations

## MLS-Specific Guidelines

### Terminology
- Use correct MLS terminology: "leaf", "node", "path", "copath", "epoch", "commit", "proposal"
- Be consistent with RFC 9420 terminology
- Explain MLS concepts when introducing new functionality

### Implementation Approach
- Prioritize educational clarity over performance optimization
- Use simplified but correct implementations
- Document deviations from the full MLS specification
- Focus on core MLS concepts: ratchet trees, key derivation, group operations

### Error Handling
- Use the project's `MlsError` enum for all errors
- Provide meaningful error messages that help with debugging
- Handle edge cases gracefully (invalid indices, missing keys, etc.)

## Code Quality

### Quality Checks
- **All code must pass `cargo clippy` cleanly** - no warnings or suggestions
- Run `cargo clippy -- -D warnings` to treat warnings as errors
- Fix all clippy suggestions before submitting code
- Use `cargo fmt` to ensure consistent formatting
- Run `cargo test` to ensure all tests pass

### Dependencies
- Minimize external dependencies
- Use well-established, audited cryptographic libraries
- Document why specific dependencies are chosen
- Keep dependencies up to date

### Performance
- Don't optimize prematurely - this is an educational project
- Focus on correctness and clarity over speed
- Use appropriate data structures for the use case

### Maintainability
- Write self-documenting code with clear variable names
- Keep functions focused and single-purpose
- Avoid deep nesting and complex control flow
- Use consistent patterns across the codebase

## Testing Guidelines

### Test Organization
- Unit tests in `#[cfg(test)]` modules within source files
- Integration tests in `tests/` directory
- Security property tests in dedicated test files
- Wire format tests for serialization/deserialization

### Test Coverage
- Test all public APIs
- Test error conditions and edge cases
- Test security properties explicitly
- Test round-trip operations (serialization, encryption/decryption)

### Test Data
- Use deterministic test data where possible
- Create helper functions for generating test data
- Avoid hardcoded values in tests
- Use meaningful test data that reflects real MLS scenarios

## Documentation Standards

### Code Comments
- Explain complex algorithms and MLS-specific logic
- Document security assumptions and properties
- Use inline comments for non-obvious code
- Avoid obvious comments that just repeat the code

### Function Documentation
- Start with a brief description of what the function does
- Explain the MLS context when relevant
- Reference RFC sections when implementing spec-defined behavior
- Keep documentation concise and focused

### Example Code
- Provide working examples for complex operations
- Show typical usage patterns
- Demonstrate security properties through examples
- Keep examples simple and educational

## Common Patterns

### Error Handling
```rust
// Good: Use project error types
fn some_operation() -> MlsResult<()> {
    if condition {
        return Err(MlsError::InvalidInput("explanation".to_string()));
    }
    Ok(())
}

// Avoid: Generic string errors
fn bad_operation() -> Result<(), String> {
    Err("something went wrong".to_string())
}
```

### Secret Management
```rust
// Good: Use zeroize for secrets
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretData {
    pub secret: [u8; 32],
}

// Good: Clear secrets when done
let mut secret = [0u8; 32];
// ... use secret ...
secret.zeroize();
```

### Documentation Style
```rust
// Good: Concise, educational
/// Derive path secrets from a leaf up to the root
///
/// Implements the MLS path secret derivation as defined in RFC 9420 §7.4.
/// Derives path secrets using HKDF-Expand with the "mls10 path" label.
pub fn derive_path_up(leaf_idx: LeafIndex, path_len: usize) -> Vec<[u8; 32]> {
    // ...
}

// Avoid: Verbose, redundant
/// Derive path secrets from a leaf up to the root
///
/// # Arguments
/// * `leaf_idx` - The leaf index to start from
/// * `path_len` - Length of the path (number of secrets to derive)
///
/// # Returns
/// Vector of path secrets s[i] from leaf to root
pub fn derive_path_up(leaf_idx: LeafIndex, path_len: usize) -> Vec<[u8; 32]> {
    // ...
}
```

## Contributing Guidelines

### Before Making Changes
- Understand the MLS protocol concepts being implemented
- Review existing code patterns and follow them
- Consider the educational value of the implementation
- Ensure changes maintain the project's focus on clarity

### Code Review Checklist
- [ ] Code follows project style guidelines
- [ ] **Code passes `cargo clippy` cleanly** (no warnings)
- [ ] Code is properly formatted with `cargo fmt`
- [ ] Documentation is concise and educational
- [ ] Tests cover new functionality
- [ ] Security properties are maintained
- [ ] Error handling is appropriate
- [ ] Imports are properly organized
- [ ] No unused code or dependencies

### Commit Messages
- Use clear, descriptive commit messages
- Reference relevant MLS concepts or RFC sections
- Explain the educational value of changes
- Keep messages concise but informative

## Resources

- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://tools.ietf.org/html/rfc9420)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

Remember: This is an educational project. Prioritize clarity, correctness, and learning value over performance optimization or production robustness.
