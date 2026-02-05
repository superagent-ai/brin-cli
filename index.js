// This package provides the sus CLI binary
// Use it via the command line: sus <command>
// For documentation, visit: https://sus-pm.com

module.exports = {
  version: require('./package.json').version,
  binaryPath: require('path').join(__dirname, 'bin', 'sus'),
};
