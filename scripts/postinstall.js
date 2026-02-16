#!/usr/bin/env node

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const zlib = require('zlib');
const tar = require('tar');

const REPO = 'superagent-ai/brin';
const BINARY_NAME = 'brin';

// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function detectPlatform() {
  const platform = process.platform;
  const arch = process.arch;

  let os;
  switch (platform) {
    case 'darwin':
      os = 'darwin';
      break;
    case 'linux':
      os = 'linux';
      break;
    case 'win32':
      log('Windows is not currently supported. Please use WSL or install from source.', colors.red);
      process.exit(1);
    default:
      log(`Unsupported platform: ${platform}`, colors.red);
      process.exit(1);
  }

  let architecture;
  switch (arch) {
    case 'x64':
      architecture = 'x86_64';
      break;
    case 'arm64':
      architecture = 'aarch64';
      break;
    default:
      log(`Unsupported architecture: ${arch}`, colors.red);
      process.exit(1);
  }

  return { os, architecture };
}

function getLatestVersion() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${REPO}/releases/latest`,
      headers: {
        'User-Agent': 'brin-npm-installer',
      },
    };

    https.get(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const release = JSON.parse(data);
          resolve(release.tag_name);
        } catch (error) {
          reject(new Error('Failed to parse release data'));
        }
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);

    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Follow redirect
        return downloadFile(response.headers.location, destPath)
          .then(resolve)
          .catch(reject);
      }

      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
        return;
      }

      response.pipe(file);

      file.on('finish', () => {
        file.close();
        resolve();
      });
    }).on('error', (error) => {
      fs.unlink(destPath, () => {}); // Clean up on error
      reject(error);
    });
  });
}

async function extractTarGz(tarPath, destDir) {
  return tar.extract({
    file: tarPath,
    cwd: destDir,
  });
}

async function install() {
  try {
    log('📦 Installing brin...', colors.green);

    const { os, architecture } = detectPlatform();
    log(`   Detected: ${os}-${architecture}`);

    // Get version from package.json
    const packageJson = require('../package.json');
    const version = `v${packageJson.version}`;
    log(`   Version: ${version}`);

    // Construct download URL
    const downloadUrl = `https://github.com/${REPO}/releases/download/${version}/brin-${os}-${architecture}.tar.gz`;
    
    // Create bin directory
    const binDir = path.join(__dirname, '..', 'bin');
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }

    // Download binary
    const tarPath = path.join(binDir, 'brin.tar.gz');
    log(`   Downloading from ${downloadUrl}...`);
    
    try {
      await downloadFile(downloadUrl, tarPath);
    } catch (error) {
      log(`   Failed to download release binary: ${error.message}`, colors.yellow);
      log(`   This might be because the release hasn't been published yet.`, colors.yellow);
      log(`   You can install from source using: cargo install --path crates/cli`, colors.yellow);
      process.exit(0); // Exit gracefully
    }

    // Extract binary
    log('   Extracting...');
    await extractTarGz(tarPath, binDir);

    // Make binary executable
    const binaryPath = path.join(binDir, BINARY_NAME);
    fs.chmodSync(binaryPath, 0o755);

    // Clean up tar file
    fs.unlinkSync(tarPath);

    log('✅ brin installed successfully!', colors.green);
    log('   Run "brin --help" to get started.');
  } catch (error) {
    log(`❌ Installation failed: ${error.message}`, colors.red);
    process.exit(1);
  }
}

install();
