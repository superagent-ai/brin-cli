#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Path to the actual sus binary
const binaryPath = path.join(__dirname, 'sus');

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('Error: sus binary not found. Please reinstall the package.');
  console.error('Run: npm install @superagent/sus');
  process.exit(1);
}

// Forward all arguments to the binary
const args = process.argv.slice(2);
const child = spawn(binaryPath, args, {
  stdio: 'inherit',
  env: process.env,
});

child.on('exit', (code) => {
  process.exit(code || 0);
});

child.on('error', (error) => {
  console.error(`Error executing sus: ${error.message}`);
  process.exit(1);
});
