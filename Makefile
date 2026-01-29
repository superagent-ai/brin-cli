.PHONY: setup fmt lint test check all

# Set up git hooks
setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured!"

# Format code
fmt:
	cargo fmt --all

# Run clippy
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Run tests
test:
	cargo test --workspace

# Run all checks (same as CI)
check: fmt lint test

# Build release
build:
	cargo build --workspace --release

# Run all checks before commit
all: check build
