# NPM Publishing Guide

This document explains how to publish the `sus` package to npm.

## Prerequisites

1. **npm account**: You need an npm account with publishing rights for the `sus` package
2. **npm authentication**: Run `npm login` to authenticate
3. **Release binaries**: Ensure GitHub releases exist for the version you're publishing

## Publishing Process

### 1. Verify Package Contents

Before publishing, check what will be included in the package:

```bash
npm pack --dry-run
```

This should show:
- `bin/sus.js` - CLI wrapper script
- `scripts/postinstall.js` - Installation script
- `index.js` - Main entry point
- `package.json` - Package metadata
- `README.md` - Documentation
- `LICENSE` - License file

### 2. Test Locally

You can test the package locally before publishing:

```bash
# Create a tarball
npm pack

# Install it globally from the tarball
npm install -g ./sus-0.1.8.tgz

# Test the installation
sus --version
```

### 3. Publish to npm

#### For a new version:

1. Update the version in `package.json` and `Cargo.toml` (workspace.package.version)
2. Ensure GitHub releases are created with binaries for:
   - `sus-linux-x86_64.tar.gz`
   - `sus-linux-aarch64.tar.gz`
   - `sus-darwin-x86_64.tar.gz`
   - `sus-darwin-aarch64.tar.gz`
3. Publish to npm:

```bash
npm publish
```

### 4. Verify Publication

After publishing, verify the package:

```bash
# Check on npm
npm view sus

# Test installation
npm install -g sus
sus --version
```

## Version Management

The package version should match the Rust crate version defined in `/workspace/Cargo.toml`:

```toml
[workspace.package]
version = "0.1.8"
```

When bumping versions:
1. Update `Cargo.toml` (workspace.package.version)
2. Update `package.json` (version)
3. Create and push a git tag: `git tag v0.1.8 && git push origin v0.1.8`
4. Create GitHub release with binaries
5. Publish to npm

## Binary Distribution

The postinstall script downloads pre-built binaries from GitHub releases. The binary naming convention is:

```
sus-{os}-{arch}.tar.gz
```

Where:
- `os`: `linux` or `darwin`
- `arch`: `x86_64` or `aarch64`

The postinstall script will:
1. Detect the user's platform and architecture
2. Download the appropriate binary from GitHub releases
3. Extract it to `node_modules/sus/bin/`
4. Make it executable

## Troubleshooting

### "Binary not found" error

If users get a "binary not found" error, it means:
1. The GitHub release doesn't exist for that version
2. The binary for their platform wasn't included in the release
3. The download failed during installation

Users can check the postinstall output for more details.

### Platform not supported

Currently supported platforms:
- Linux (x64, arm64)
- macOS (x64, arm64)

Windows is not currently supported. Windows users should use WSL or install from source.

## CI/CD Integration

Consider adding npm publishing to the GitHub Actions release workflow:

```yaml
- name: Publish to npm
  if: startsWith(github.ref, 'refs/tags/v')
  run: |
    echo "//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}" > ~/.npmrc
    npm publish --access public
  env:
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

This will automatically publish to npm when a new version tag is pushed.
