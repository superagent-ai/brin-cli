.PHONY: setup fmt lint test check all dev dev-api dev-worker

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

# Start local development (databases + API + worker)
dev:
	docker-compose up -d db redis
	@echo "Starting API and worker..."
	@trap 'kill 0' INT; cargo run --bin sus-api & cargo run --bin sus-worker & wait

# Start only the API
dev-api:
	docker-compose up -d db redis
	cargo run --bin sus-api

# Start only the worker
dev-worker:
	docker-compose up -d db redis
	cargo run --bin sus-worker
