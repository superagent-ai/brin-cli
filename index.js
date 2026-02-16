// This package provides the brin CLI binary
// Use it via the command line: brin <command>
// For documentation, visit: https://brin.sh

module.exports = {
  version: require('./package.json').version,
  binaryPath: require('path').join(__dirname, 'bin', 'brin'),
};
