# Makefile for toy-mls project

.PHONY: help test test-all test-default test-rfc fmt clippy clean build doc

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test: test-all ## Run all tests (default and RFC treemath)

test-all: test-default test-rfc ## Run tests for both implementations

test-default: ## Run tests with default features (educational tree math)
	cargo test --verbose

test-rfc: ## Run tests with RFC treemath feature enabled
	cargo test --features rfc_treemath --verbose

fmt: ## Check code formatting
	cargo fmt --all -- --check

fmt-fix: ## Fix code formatting
	cargo fmt --all

clippy: ## Run clippy linter
	cargo clippy --all-targets --all-features -- -D warnings

build: ## Build the project
	cargo build

build-release: ## Build the project in release mode
	cargo build --release

clean: ## Clean build artifacts
	cargo clean

doc: ## Generate documentation
	cargo doc --no-deps --open

doc-rfc: ## Generate documentation with RFC treemath feature
	cargo doc --no-deps --features rfc_treemath --open

examples: ## Run all examples
	cargo run --example tree_operations
	cargo run --example dynamic_membership
	cargo run --example real_copath_test
	cargo run --example tree_math_comparison
	cargo run --example tree_math_comparison --features rfc_treemath
	cargo run --example hpke_style_encryption

check: fmt clippy test-all ## Run all checks (format, clippy, tests)

ci: check ## Run CI checks locally
