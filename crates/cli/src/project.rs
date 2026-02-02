//! Project type detection for multi-registry support

use common::Registry;
use std::path::Path;

/// Detected project type with associated package manager
#[derive(Debug, Clone, PartialEq)]
pub enum ProjectType {
    Npm(NpmPackageManager),
    Pypi(PypiPackageManager),
}

impl ProjectType {
    /// Get the registry for this project type
    pub fn registry(&self) -> Registry {
        match self {
            ProjectType::Npm(_) => Registry::Npm,
            ProjectType::Pypi(_) => Registry::Pypi,
        }
    }
}

/// npm ecosystem package managers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NpmPackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

impl NpmPackageManager {
    /// Get the command name for this package manager
    pub fn command(&self) -> &'static str {
        match self {
            NpmPackageManager::Npm => "npm",
            NpmPackageManager::Yarn => "yarn",
            NpmPackageManager::Pnpm => "pnpm",
            NpmPackageManager::Bun => "bun",
        }
    }

    /// Get the install subcommand for this package manager
    pub fn install_cmd(&self) -> &'static str {
        "add"
    }
}

/// Python ecosystem package managers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PypiPackageManager {
    Pip,
    Poetry,
    Pipenv,
    Uv,
}

impl PypiPackageManager {
    /// Get the command name for this package manager
    pub fn command(&self) -> &'static str {
        match self {
            PypiPackageManager::Pip => "pip",
            PypiPackageManager::Poetry => "poetry",
            PypiPackageManager::Pipenv => "pipenv",
            PypiPackageManager::Uv => "uv",
        }
    }

    /// Get the install subcommand for this package manager
    pub fn install_cmd(&self) -> &'static str {
        match self {
            PypiPackageManager::Pip => "install",
            PypiPackageManager::Poetry => "add",
            PypiPackageManager::Pipenv => "install",
            PypiPackageManager::Uv => "add",
        }
    }
}

/// Detect the project type based on files in the current directory
///
/// Detection priority:
/// 1. Python lockfiles (most specific): poetry.lock, Pipfile.lock, uv.lock
/// 2. Python project files: pyproject.toml, requirements.txt, Pipfile, setup.py
/// 3. npm lockfiles: pnpm-lock.yaml, yarn.lock, bun.lockb
/// 4. npm project files: package.json
pub fn detect_project_type() -> Option<ProjectType> {
    // Check Python lockfiles first (most specific)
    if Path::new("poetry.lock").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Poetry));
    }
    if Path::new("Pipfile.lock").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Pipenv));
    }
    if Path::new("uv.lock").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Uv));
    }

    // Check Python project files
    if Path::new("pyproject.toml").exists() {
        // Check if it's a poetry project
        if let Ok(content) = std::fs::read_to_string("pyproject.toml") {
            if content.contains("[tool.poetry]") {
                return Some(ProjectType::Pypi(PypiPackageManager::Poetry));
            }
            if content.contains("[tool.uv]") {
                return Some(ProjectType::Pypi(PypiPackageManager::Uv));
            }
        }
        // Default to pip for pyproject.toml
        return Some(ProjectType::Pypi(PypiPackageManager::Pip));
    }
    if Path::new("requirements.txt").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Pip));
    }
    if Path::new("Pipfile").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Pipenv));
    }
    if Path::new("setup.py").exists() {
        return Some(ProjectType::Pypi(PypiPackageManager::Pip));
    }

    // Check npm lockfiles
    if Path::new("pnpm-lock.yaml").exists() {
        return Some(ProjectType::Npm(NpmPackageManager::Pnpm));
    }
    if Path::new("yarn.lock").exists() {
        return Some(ProjectType::Npm(NpmPackageManager::Yarn));
    }
    if Path::new("bun.lockb").exists() {
        return Some(ProjectType::Npm(NpmPackageManager::Bun));
    }

    // Check npm project file
    if Path::new("package.json").exists() {
        return Some(ProjectType::Npm(NpmPackageManager::Npm));
    }

    None
}

/// Parse a package specification into name and optional version
///
/// Handles both npm-style (@) and PyPI-style (==, >=, etc.) version specifiers
pub fn parse_package_spec(spec: &str, project_type: &ProjectType) -> (String, Option<String>) {
    match project_type {
        ProjectType::Npm(_) => parse_npm_package_spec(spec),
        ProjectType::Pypi(_) => parse_pypi_package_spec(spec),
    }
}

/// Parse npm package specification (e.g., "lodash@4.17.0", "@types/node@18.0.0")
fn parse_npm_package_spec(spec: &str) -> (String, Option<String>) {
    // Handle scoped packages like @types/node@1.0.0
    if let Some(rest) = spec.strip_prefix('@') {
        // Find the second @ for version
        if let Some(idx) = rest.find('@') {
            let idx = idx + 1; // Adjust for the @ prefix
            return (spec[..idx].to_string(), Some(spec[idx + 1..].to_string()));
        }
        return (spec.to_string(), None);
    }

    // Regular package like lodash@4.17.0
    if let Some(idx) = spec.find('@') {
        return (spec[..idx].to_string(), Some(spec[idx + 1..].to_string()));
    }

    (spec.to_string(), None)
}

/// Parse PyPI package specification (e.g., "requests==2.31.0", "flask>=2.0")
fn parse_pypi_package_spec(spec: &str) -> (String, Option<String>) {
    // Check for version specifiers in order of specificity
    let version_ops = ["===", "==", "!=", "~=", ">=", "<=", ">", "<"];

    for op in version_ops {
        if let Some(idx) = spec.find(op) {
            let name = spec[..idx].to_string();
            let version = spec[idx + op.len()..].to_string();
            return (name, Some(version));
        }
    }

    // Check for bracket extras like requests[security]
    if let Some(idx) = spec.find('[') {
        let name = spec[..idx].to_string();
        return (name, None);
    }

    (spec.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm_package_spec() {
        let npm = ProjectType::Npm(NpmPackageManager::Npm);

        assert_eq!(
            parse_package_spec("lodash", &npm),
            ("lodash".to_string(), None)
        );
        assert_eq!(
            parse_package_spec("lodash@4.17.0", &npm),
            ("lodash".to_string(), Some("4.17.0".to_string()))
        );
        assert_eq!(
            parse_package_spec("@types/node", &npm),
            ("@types/node".to_string(), None)
        );
        assert_eq!(
            parse_package_spec("@types/node@18.0.0", &npm),
            ("@types/node".to_string(), Some("18.0.0".to_string()))
        );
    }

    #[test]
    fn test_parse_pypi_package_spec() {
        let pypi = ProjectType::Pypi(PypiPackageManager::Pip);

        assert_eq!(
            parse_package_spec("requests", &pypi),
            ("requests".to_string(), None)
        );
        assert_eq!(
            parse_package_spec("requests==2.31.0", &pypi),
            ("requests".to_string(), Some("2.31.0".to_string()))
        );
        assert_eq!(
            parse_package_spec("flask>=2.0", &pypi),
            ("flask".to_string(), Some("2.0".to_string()))
        );
        assert_eq!(
            parse_package_spec("django~=4.2", &pypi),
            ("django".to_string(), Some("4.2".to_string()))
        );
        assert_eq!(
            parse_package_spec("requests[security]", &pypi),
            ("requests".to_string(), None)
        );
    }

    #[test]
    fn test_project_type_registry() {
        assert_eq!(
            ProjectType::Npm(NpmPackageManager::Npm).registry(),
            Registry::Npm
        );
        assert_eq!(
            ProjectType::Pypi(PypiPackageManager::Pip).registry(),
            Registry::Pypi
        );
    }

    #[test]
    fn test_package_manager_commands() {
        assert_eq!(NpmPackageManager::Npm.command(), "npm");
        assert_eq!(NpmPackageManager::Yarn.command(), "yarn");
        assert_eq!(NpmPackageManager::Pnpm.command(), "pnpm");
        assert_eq!(NpmPackageManager::Bun.command(), "bun");

        assert_eq!(PypiPackageManager::Pip.command(), "pip");
        assert_eq!(PypiPackageManager::Poetry.command(), "poetry");
        assert_eq!(PypiPackageManager::Pipenv.command(), "pipenv");
        assert_eq!(PypiPackageManager::Uv.command(), "uv");
    }

    #[test]
    fn test_install_commands() {
        assert_eq!(NpmPackageManager::Npm.install_cmd(), "add");
        assert_eq!(PypiPackageManager::Pip.install_cmd(), "install");
        assert_eq!(PypiPackageManager::Poetry.install_cmd(), "add");
        assert_eq!(PypiPackageManager::Uv.install_cmd(), "add");
    }
}
