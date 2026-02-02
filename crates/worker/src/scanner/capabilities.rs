//! Capability extraction using static analysis

use super::npm::ExtractedPackage;
use super::pypi::ExtractedPypiPackage;
use anyhow::Result;
use common::{
    EnvironmentCapabilities, FilesystemCapabilities, NativeCapabilities, NetworkCapabilities,
    PackageCapabilities, PathPermission, ProcessCapabilities,
};

/// Known native npm modules
const KNOWN_NATIVE_MODULES: &[&str] = &[
    "node-gyp",
    "node-pre-gyp",
    "prebuild",
    "node-addon-api",
    "napi-rs",
    "nan",
    "ffi-napi",
    "ref-napi",
];

/// Known Python native extension packages
const KNOWN_PYTHON_NATIVE_PACKAGES: &[&str] = &[
    "cython",
    "cffi",
    "pybind11",
    "numpy",
    "scipy",
    "pandas",
    "pillow",
    "lxml",
    "cryptography",
    "psycopg2",
    "mysqlclient",
    "grpcio",
];

/// Capability extractor using regex-based static analysis
pub struct CapabilityExtractor;

impl CapabilityExtractor {
    /// Create a new capability extractor
    pub fn new() -> Self {
        Self
    }

    /// Extract capabilities from a package
    pub fn extract(&self, extracted: &ExtractedPackage) -> Result<PackageCapabilities> {
        let mut caps = PackageCapabilities::default();

        // Check for native modules
        caps.native.has_native = extracted.has_binding_gyp || extracted.has_napi;

        // Check dependencies for known native modules
        if let Some(deps) = extracted
            .package_json
            .get("dependencies")
            .and_then(|d| d.as_object())
        {
            for dep in deps.keys() {
                if KNOWN_NATIVE_MODULES.contains(&dep.as_str()) {
                    caps.native.has_native = true;
                    caps.native.native_modules.push(dep.clone());
                }
            }
        }

        // Analyze source files
        for file in &extracted.source_files {
            self.analyze_source(&file.content, &mut caps);
        }

        // Deduplicate
        caps.network.domains.sort();
        caps.network.domains.dedup();
        caps.network.protocols.sort();
        caps.network.protocols.dedup();
        caps.process.commands.sort();
        caps.process.commands.dedup();
        caps.environment.accessed_vars.sort();
        caps.environment.accessed_vars.dedup();

        Ok(caps)
    }

    /// Extract capabilities from a Python package
    pub fn extract_python(&self, extracted: &ExtractedPypiPackage) -> Result<PackageCapabilities> {
        let mut caps = PackageCapabilities::default();

        // Check for native extensions
        caps.native.has_native = extracted.has_c_extension || extracted.has_cython;
        if extracted.has_c_extension {
            caps.native.native_modules.push("C extension".to_string());
        }
        if extracted.has_cython {
            caps.native.native_modules.push("Cython".to_string());
        }

        // Analyze Python source files
        for file in &extracted.source_files {
            self.analyze_python_source(&file.content, &mut caps);
        }

        // Deduplicate
        caps.network.domains.sort();
        caps.network.domains.dedup();
        caps.network.protocols.sort();
        caps.network.protocols.dedup();
        caps.process.commands.sort();
        caps.process.commands.dedup();
        caps.environment.accessed_vars.sort();
        caps.environment.accessed_vars.dedup();
        caps.native.native_modules.sort();
        caps.native.native_modules.dedup();

        Ok(caps)
    }

    /// Analyze Python source code for capabilities
    fn analyze_python_source(&self, source: &str, caps: &mut PackageCapabilities) {
        // Network detection
        self.detect_python_network(source, &mut caps.network);

        // Filesystem detection
        self.detect_python_filesystem(source, &mut caps.filesystem);

        // Process detection
        self.detect_python_process(source, &mut caps.process);

        // Environment detection
        self.detect_python_environment(source, &mut caps.environment);

        // Native module detection
        self.detect_python_native(source, &mut caps.native);
    }

    /// Detect network capabilities in Python code
    fn detect_python_network(&self, source: &str, caps: &mut NetworkCapabilities) {
        // Common Python network patterns
        let network_patterns = [
            // requests library
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "requests.request",
            // urllib
            "urllib.request",
            "urllib.urlopen",
            "urlopen(",
            // httpx
            "httpx.get",
            "httpx.post",
            "httpx.AsyncClient",
            "httpx.Client",
            // aiohttp
            "aiohttp.ClientSession",
            "aiohttp.request",
            // socket
            "socket.socket",
            "socket.create_connection",
            // httplib/http.client
            "http.client",
            "HTTPConnection",
            "HTTPSConnection",
        ];

        for pattern in network_patterns {
            if source.contains(pattern) {
                caps.makes_requests = true;
                break;
            }
        }

        // Also check for import statements
        let import_patterns = [
            "import requests",
            "from requests",
            "import urllib",
            "from urllib",
            "import httpx",
            "from httpx",
            "import aiohttp",
            "from aiohttp",
            "import socket",
            "from socket",
        ];

        for pattern in import_patterns {
            if source.contains(pattern) {
                caps.makes_requests = true;
                break;
            }
        }

        // Extract domains from URLs
        self.extract_domains(source, caps);

        // Detect protocols
        if source.contains("http://") {
            caps.protocols.push("http".to_string());
        }
        if source.contains("https://") {
            caps.protocols.push("https".to_string());
        }
        if source.contains("ws://") || source.contains("wss://") {
            caps.protocols.push("websocket".to_string());
        }
        if source.contains("socket.SOCK_STREAM") {
            caps.protocols.push("tcp".to_string());
        }
        if source.contains("socket.SOCK_DGRAM") {
            caps.protocols.push("udp".to_string());
        }
    }

    /// Detect filesystem capabilities in Python code
    fn detect_python_filesystem(&self, source: &str, caps: &mut FilesystemCapabilities) {
        // Read patterns
        let read_patterns = [
            "open(",
            ".read(",
            ".readline(",
            ".readlines(",
            "Path.read_text",
            "Path.read_bytes",
            "os.listdir",
            "os.scandir",
            "pathlib.Path",
            "glob.glob",
            "glob.iglob",
            "shutil.copy",
            "json.load(",
            "yaml.safe_load",
            "configparser",
        ];

        for pattern in read_patterns {
            if source.contains(pattern) {
                caps.reads = true;
                break;
            }
        }

        // Write patterns
        let write_patterns = [
            ".write(",
            ".writelines(",
            "Path.write_text",
            "Path.write_bytes",
            "os.mkdir",
            "os.makedirs",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "shutil.rmtree",
            "shutil.move",
            "shutil.copy",
            "json.dump(",
            "yaml.dump",
        ];

        for pattern in write_patterns {
            if source.contains(pattern) {
                caps.writes = true;
                break;
            }
        }

        // Check for write mode in open()
        if source.contains("open(") {
            let write_modes = [
                "'w'", "\"w\"", "'a'", "\"a\"", "'wb'", "\"wb\"", "'ab'", "\"ab\"",
            ];
            for mode in write_modes {
                if source.contains(mode) {
                    caps.writes = true;
                    break;
                }
            }
        }

        // Extract paths
        self.extract_python_paths(source, caps);
    }

    /// Extract file paths from Python source
    fn extract_python_paths(&self, source: &str, caps: &mut FilesystemCapabilities) {
        let path_indicators = [
            "/tmp/",
            "/var/",
            "/etc/",
            "/home/",
            "/usr/",
            "~/.config",
            "~/.local",
            ".env",
            "__pycache__",
            "site-packages",
            "requirements.txt",
            "setup.py",
            "pyproject.toml",
        ];

        for indicator in path_indicators {
            if source.contains(indicator) {
                let mode = match (caps.reads, caps.writes) {
                    (true, true) => "rw",
                    (true, false) => "r",
                    (false, true) => "w",
                    _ => "r",
                };

                caps.paths.push(PathPermission {
                    path: indicator.to_string(),
                    mode: mode.to_string(),
                });
            }
        }
    }

    /// Detect process spawning capabilities in Python code
    fn detect_python_process(&self, source: &str, caps: &mut ProcessCapabilities) {
        let spawn_patterns = [
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
            "os.system(",
            "os.popen(",
            "os.exec",
            "os.spawn",
            "os.fork(",
            "multiprocessing.Process",
            "concurrent.futures.ProcessPoolExecutor",
        ];

        for pattern in spawn_patterns {
            if source.contains(pattern) {
                caps.spawns_children = true;
                break;
            }
        }

        // Also check imports
        let import_patterns = [
            "import subprocess",
            "from subprocess",
            "import multiprocessing",
            "from multiprocessing",
        ];

        for pattern in import_patterns {
            if source.contains(pattern) {
                caps.spawns_children = true;
                break;
            }
        }

        // Extract command names
        self.extract_python_commands(source, caps);
    }

    /// Extract command names from Python subprocess calls
    fn extract_python_commands(&self, source: &str, caps: &mut ProcessCapabilities) {
        let common_commands = [
            "python", "pip", "git", "curl", "wget", "sh", "bash", "rm", "chmod", "chown", "sudo",
            "apt", "yum", "npm", "node", "docker", "kubectl",
        ];

        for cmd in common_commands {
            // Look for command in various subprocess patterns
            let patterns = [
                format!("subprocess.run(['{}", cmd),
                format!("subprocess.run([\"{}", cmd),
                format!("subprocess.call(['{}", cmd),
                format!("subprocess.call([\"{}", cmd),
                format!("Popen(['{}", cmd),
                format!("Popen([\"{}", cmd),
                format!("os.system('{}", cmd),
                format!("os.system(\"{}", cmd),
            ];

            for pattern in patterns {
                if source.contains(&pattern) {
                    caps.commands.push(cmd.to_string());
                    break;
                }
            }
        }
    }

    /// Detect environment variable access in Python code
    fn detect_python_environment(&self, source: &str, caps: &mut EnvironmentCapabilities) {
        // os.environ access
        let env_patterns = [
            "os.environ[",
            "os.environ.get(",
            "os.getenv(",
            "environ.get(",
            "environ[",
        ];

        for pattern in env_patterns {
            let mut search_from = 0;
            while let Some(start) = source[search_from..].find(pattern) {
                let abs_start = search_from + start + pattern.len();
                if abs_start >= source.len() {
                    break;
                }

                // Find the variable name
                let remaining = &source[abs_start..];
                let end_chars = [')', ']', ',', ' '];

                // Skip quote character
                let var_start = if remaining.starts_with('"') || remaining.starts_with('\'') {
                    1
                } else {
                    0
                };

                if var_start >= remaining.len() {
                    break;
                }

                let remaining = &remaining[var_start..];
                let var_end = remaining
                    .find(|c: char| c == '"' || c == '\'' || end_chars.contains(&c))
                    .unwrap_or(remaining.len());

                let var_name = &remaining[..var_end];

                if !var_name.is_empty() && var_name.len() < 50 {
                    caps.accessed_vars.push(var_name.to_string());
                }

                search_from = abs_start + var_end + 1;
            }
        }
    }

    /// Detect native module usage in Python code
    fn detect_python_native(&self, source: &str, caps: &mut NativeCapabilities) {
        // Check for imports of known native packages
        for pkg in KNOWN_PYTHON_NATIVE_PACKAGES {
            let patterns = [format!("import {}", pkg), format!("from {} import", pkg)];

            for pattern in patterns {
                if source.contains(&pattern) {
                    caps.has_native = true;
                    caps.native_modules.push(pkg.to_string());
                    break;
                }
            }
        }

        // Check for ctypes usage
        if source.contains("import ctypes") || source.contains("from ctypes") {
            caps.has_native = true;
            caps.native_modules.push("ctypes".to_string());
        }

        // Check for CFFI
        if source.contains("from cffi import") || source.contains("import cffi") {
            caps.has_native = true;
            caps.native_modules.push("cffi".to_string());
        }
    }

    /// Analyze source code for capabilities
    fn analyze_source(&self, source: &str, caps: &mut PackageCapabilities) {
        // Network detection
        self.detect_network(source, &mut caps.network);

        // Filesystem detection
        self.detect_filesystem(source, &mut caps.filesystem);

        // Process detection
        self.detect_process(source, &mut caps.process);

        // Environment detection
        self.detect_environment(source, &mut caps.environment);
    }

    /// Detect network capabilities
    fn detect_network(&self, source: &str, caps: &mut NetworkCapabilities) {
        // Common network APIs
        let network_patterns = [
            "fetch(",
            "axios",
            "request(",
            "http.request",
            "https.request",
            "http.get",
            "https.get",
            "net.connect",
            "net.createConnection",
            "dgram.createSocket",
            "WebSocket",
            "XMLHttpRequest",
        ];

        for pattern in network_patterns {
            if source.contains(pattern) {
                caps.makes_requests = true;
                break;
            }
        }

        // Extract domains from URLs
        self.extract_domains(source, caps);

        // Detect protocols
        if source.contains("http://") {
            caps.protocols.push("http".to_string());
        }
        if source.contains("https://") {
            caps.protocols.push("https".to_string());
        }
        if source.contains("ws://") || source.contains("wss://") {
            caps.protocols.push("websocket".to_string());
        }
        if source.contains("net.connect") || source.contains("net.createConnection") {
            caps.protocols.push("tcp".to_string());
        }
        if source.contains("dgram") {
            caps.protocols.push("udp".to_string());
        }
    }

    /// Extract domain names from source
    fn extract_domains(&self, source: &str, caps: &mut NetworkCapabilities) {
        // Simple URL extraction
        let url_prefixes = ["http://", "https://", "ws://", "wss://"];

        for prefix in url_prefixes {
            let mut search_from = 0;
            while let Some(start) = source[search_from..].find(prefix) {
                let abs_start = search_from + start + prefix.len();
                if abs_start >= source.len() {
                    break;
                }

                // Find end of domain
                let domain_end = source[abs_start..]
                    .find(|c: char| {
                        c == '/'
                            || c == ':'
                            || c == '"'
                            || c == '\''
                            || c == '`'
                            || c.is_whitespace()
                    })
                    .unwrap_or(source.len() - abs_start);

                let domain = &source[abs_start..abs_start + domain_end];

                // Validate it looks like a domain
                if domain.contains('.') && !domain.starts_with('.') && domain.len() < 100 {
                    // Skip template literals and variables
                    if !domain.contains("${") && !domain.contains("{{") {
                        caps.domains.push(domain.to_string());
                    }
                }

                search_from = abs_start + domain_end;
            }
        }
    }

    /// Detect filesystem capabilities
    fn detect_filesystem(&self, source: &str, caps: &mut FilesystemCapabilities) {
        // Read patterns
        let read_patterns = [
            "fs.readFile",
            "fs.readFileSync",
            "fs.readdir",
            "fs.readdirSync",
            "fs.createReadStream",
            "fsPromises.readFile",
            "fsPromises.readdir",
            "fs.promises.readFile",
        ];

        for pattern in read_patterns {
            if source.contains(pattern) {
                caps.reads = true;
                break;
            }
        }

        // Write patterns
        let write_patterns = [
            "fs.writeFile",
            "fs.writeFileSync",
            "fs.appendFile",
            "fs.appendFileSync",
            "fs.createWriteStream",
            "fs.mkdir",
            "fs.mkdirSync",
            "fs.unlink",
            "fs.unlinkSync",
            "fs.rm",
            "fs.rmSync",
            "fsPromises.writeFile",
            "fsPromises.mkdir",
            "fs.promises.writeFile",
        ];

        for pattern in write_patterns {
            if source.contains(pattern) {
                caps.writes = true;
                break;
            }
        }

        // Extract paths (basic heuristic)
        self.extract_paths(source, caps);
    }

    /// Extract file paths from source
    fn extract_paths(&self, source: &str, caps: &mut FilesystemCapabilities) {
        // Look for common path patterns
        let path_indicators = [
            "/tmp/",
            "/var/",
            "/etc/",
            "/home/",
            "/usr/",
            "~/.config",
            "~/.local",
            ".env",
            "node_modules",
            "package.json",
        ];

        for indicator in path_indicators {
            if source.contains(indicator) {
                let mode = match (caps.reads, caps.writes) {
                    (true, true) => "rw",
                    (true, false) => "r",
                    (false, true) => "w",
                    _ => "r",
                };

                caps.paths.push(PathPermission {
                    path: indicator.to_string(),
                    mode: mode.to_string(),
                });
            }
        }
    }

    /// Detect process spawning capabilities
    fn detect_process(&self, source: &str, caps: &mut ProcessCapabilities) {
        let spawn_patterns = [
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
            "child_process.spawnSync",
            "child_process.fork",
            "execSync(",
            "exec(",
            "spawn(",
            "spawnSync(",
            "fork(",
            "execa(",
            "shelljs",
        ];

        for pattern in spawn_patterns {
            if source.contains(pattern) {
                caps.spawns_children = true;
                break;
            }
        }

        // Try to extract command names
        self.extract_commands(source, caps);
    }

    /// Extract command names from exec/spawn calls
    fn extract_commands(&self, source: &str, caps: &mut ProcessCapabilities) {
        // Common commands that might be executed
        let common_commands = [
            "npm", "node", "git", "curl", "wget", "sh", "bash", "python", "pip", "rm", "chmod",
            "chown", "sudo",
        ];

        for cmd in common_commands {
            // Look for command in quotes after exec/spawn
            let patterns = [
                format!("exec('{}", cmd),
                format!("exec(\"{}", cmd),
                format!("spawn('{}", cmd),
                format!("spawn(\"{}", cmd),
                format!("execSync('{}", cmd),
                format!("execSync(\"{}", cmd),
            ];

            for pattern in patterns {
                if source.contains(&pattern) {
                    caps.commands.push(cmd.to_string());
                    break;
                }
            }
        }
    }

    /// Detect environment variable access
    fn detect_environment(&self, source: &str, caps: &mut EnvironmentCapabilities) {
        // Look for process.env access
        let env_pattern = "process.env.";
        let mut search_from = 0;

        while let Some(start) = source[search_from..].find(env_pattern) {
            let abs_start = search_from + start + env_pattern.len();
            if abs_start >= source.len() {
                break;
            }

            // Find end of variable name
            let var_end = source[abs_start..]
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(source.len() - abs_start);

            let var_name = &source[abs_start..abs_start + var_end];

            if !var_name.is_empty() && var_name.len() < 50 {
                caps.accessed_vars.push(var_name.to_string());
            }

            search_from = abs_start + var_end;
        }

        // Also check for bracket notation: process.env["VAR"] or process.env['VAR']
        for quote in ['"', '\''] {
            let _pattern = format!("process.env[{}]", quote);
            let mut search_from = 0;

            while let Some(start) = source[search_from..].find(&format!("process.env[{}", quote)) {
                let abs_start = search_from + start + format!("process.env[{}", quote).len();
                if abs_start >= source.len() {
                    break;
                }

                if let Some(end) = source[abs_start..].find(quote) {
                    let var_name = &source[abs_start..abs_start + end];
                    if !var_name.is_empty() && var_name.len() < 50 {
                        caps.accessed_vars.push(var_name.to_string());
                    }
                }

                search_from = abs_start + 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_detection() {
        let extractor = CapabilityExtractor::new();
        let mut caps = NetworkCapabilities::default();

        extractor.detect_network("fetch('https://api.example.com/data')", &mut caps);

        assert!(caps.makes_requests);
        assert!(caps.domains.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn test_env_detection() {
        let extractor = CapabilityExtractor::new();
        let mut caps = EnvironmentCapabilities::default();

        extractor.detect_environment(
            r#"const key = process.env.API_KEY; const secret = process.env["SECRET"];"#,
            &mut caps,
        );

        assert!(caps.accessed_vars.contains(&"API_KEY".to_string()));
        assert!(caps.accessed_vars.contains(&"SECRET".to_string()));
    }
}
