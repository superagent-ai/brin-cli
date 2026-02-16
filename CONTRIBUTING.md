# Contributing to brin

Thanks for your interest in contributing to brin! We welcome contributions of all kinds.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## Getting Started

Before contributing, please:

1. Read the [README](README.md) to understand the project
2. Check [existing issues](https://github.com/superagent-ai/brin/issues) to avoid duplicates
3. For major changes, open an issue first to discuss

## Development Setup

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- [Docker](https://docker.com) (for PostgreSQL and Redis)
- [jq](https://jqlang.github.io/jq/) (for git hooks)

### Setup

```bash
# Clone the repo
git clone https://github.com/superagent-ai/brin
cd brin

# Set up git hooks
make setup

# Start databases
docker-compose up -d db redis

# Run the API
make dev-api

# Or run everything (API + worker)
make dev
```

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_name
```

### Useful Commands

```bash
make fmt      # Format code
make lint     # Run clippy
make test     # Run tests
make check    # Run all checks (fmt + lint + test)
```

## How to Contribute

### Reporting Bugs

Use the [bug report template](https://github.com/superagent-ai/brin/issues/new?template=bug.yml) and include:

- Steps to reproduce
- Expected vs actual behavior
- Rust version (`rustc --version`)
- OS and architecture

### Suggesting Features

Use the [feature request template](https://github.com/superagent-ai/brin/issues/new?template=feature.yml) and describe:

- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

### Security Issues

**Do not open public issues for security vulnerabilities.** Email security@superagent.sh instead.

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Run checks (`make check`)
5. Commit with a descriptive message
6. Push and open a pull request

## Code Style

We follow standard Rust conventions:

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- Use meaningful variable and function names
- Add doc comments for public APIs
- Keep functions small and focused
- Write tests for new functionality

### Project Structure

```
crates/
├── api/        # HTTP API server
├── cli/        # Command-line interface
├── common/     # Shared types and database
├── cve/        # CVE enrichment worker
├── watcher/    # npm registry watcher
└── worker/     # Package scanner
```

## Commit Messages

Use conventional commits:

```
type: short description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code change that doesn't fix a bug or add a feature
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat: add pypi support
fix: handle scoped package names correctly
docs: update API reference
refactor: extract trust score calculation
```

## Pull Request Process

1. **Title**: Use conventional commit format
2. **Description**: Explain what and why
3. **Tests**: Add tests for new functionality
4. **Checks**: Ensure CI passes (fmt, clippy, tests)
5. **Review**: Address feedback promptly

PRs are squash-merged to keep history clean.

## Community

- [Discord](https://discord.gg/spZ7MnqFT4) — chat with the team
- [Twitter/X](https://x.com/superagent_ai) — follow for updates
- [GitHub Issues](https://github.com/superagent-ai/brin/issues) — bugs and features

---

Thank you for contributing!
