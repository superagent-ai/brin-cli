//! Upgrade command - update sus to the latest version

use anyhow::{anyhow, Result};
use colored::Colorize;
use flate2::read::GzDecoder;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tar::Archive;

const GITHUB_REPO: &str = "superagent-ai/sus";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
}

/// Run the upgrade command
pub async fn run(force: bool) -> Result<()> {
    println!();
    println!("🔄 Checking for updates...");
    println!();

    let current = CURRENT_VERSION;
    let latest = get_latest_version().await?;

    // Strip 'v' prefix for comparison
    let latest_clean = latest.strip_prefix('v').unwrap_or(&latest);
    let current_clean = current.strip_prefix('v').unwrap_or(current);

    println!(
        "   Current version: {}",
        format!("v{}", current_clean).cyan()
    );
    println!(
        "   Latest version:  {}",
        format!("v{}", latest_clean).cyan()
    );
    println!();

    // Compare versions using semver
    let is_newer = is_version_newer(latest_clean, current_clean);

    if !is_newer && !force {
        if current_clean == latest_clean {
            println!("   {} Already on the latest version.", "✓".green());
        } else {
            println!(
                "   {} Local version is newer than latest release.",
                "✓".green()
            );
        }
        println!();
        return Ok(());
    }

    if !is_newer && force {
        println!(
            "   {} Forcing reinstall (will replace with v{})...",
            "⚡".yellow(),
            latest_clean
        );
        println!();
    }

    // Detect platform
    let (os, arch) = detect_platform()?;
    let tarball_name = format!("sus-{}-{}.tar.gz", os, arch);

    println!("   Downloading {}...", tarball_name.cyan());

    // Download and install
    download_and_install(&latest, &os, &arch).await?;

    println!("   {} Upgraded to v{}", "✓".green(), latest_clean);
    println!();
    println!(
        "   {} Restart your terminal or run '{}' to verify.",
        "note:".yellow(),
        "sus --version".cyan()
    );
    println!();

    Ok(())
}

/// Fetch the latest release version from GitHub
async fn get_latest_version() -> Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", "sus-cli")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to fetch latest version: HTTP {}",
            response.status()
        ));
    }

    let release: GitHubRelease = response.json().await?;
    Ok(release.tag_name)
}

/// Detect the current platform (OS and architecture)
fn detect_platform() -> Result<(String, String)> {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return Err(anyhow!("Unsupported OS"));
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return Err(anyhow!("Unsupported architecture"));
    };

    Ok((os.to_string(), arch.to_string()))
}

/// Download the release tarball and install it
async fn download_and_install(version: &str, os: &str, arch: &str) -> Result<()> {
    let tarball_name = format!("sus-{}-{}.tar.gz", os, arch);
    let download_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, version, tarball_name
    );

    // Download to temp file
    let client = reqwest::Client::new();
    let response = client
        .get(&download_url)
        .header("User-Agent", "sus-cli")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to download release: HTTP {} - Check if {} exists for {}-{}",
            response.status(),
            version,
            os,
            arch
        ));
    }

    let bytes = response.bytes().await?;

    // Create temp directory
    let temp_dir = std::env::temp_dir().join("sus-upgrade");
    fs::create_dir_all(&temp_dir)?;

    let tarball_path = temp_dir.join(&tarball_name);
    let mut file = File::create(&tarball_path)?;
    file.write_all(&bytes)?;
    drop(file);

    // Extract tarball
    let tar_gz = File::open(&tarball_path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(&temp_dir)?;

    // Find the extracted binary
    let extracted_binary = temp_dir.join("sus");
    if !extracted_binary.exists() {
        return Err(anyhow!("Binary not found in archive"));
    }

    // Get current executable path
    let current_exe = std::env::current_exe()?;

    // Replace the binary
    replace_binary(&extracted_binary, &current_exe)?;

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);

    Ok(())
}

/// Compare two version strings (semver-like)
/// Returns true if `new_version` is newer than `current_version`
fn is_version_newer(new_version: &str, current_version: &str) -> bool {
    let parse_version =
        |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse::<u32>().ok()).collect() };

    let new_parts = parse_version(new_version);
    let current_parts = parse_version(current_version);

    for i in 0..3 {
        let new_val = new_parts.get(i).copied().unwrap_or(0);
        let cur_val = current_parts.get(i).copied().unwrap_or(0);

        if new_val > cur_val {
            return true;
        }
        if new_val < cur_val {
            return false;
        }
    }

    false // versions are equal
}

/// Replace the current binary with the new one
fn replace_binary(new_binary: &PathBuf, current_exe: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // On Unix, we can copy over the running binary
        // The old binary stays in memory until the process exits
        fs::copy(new_binary, current_exe)?;

        // Ensure executable permissions
        let mut perms = fs::metadata(current_exe)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(current_exe, perms)?;
    }

    #[cfg(windows)]
    {
        // On Windows, rename the old binary and copy new one
        let backup_path = current_exe.with_extension("old");
        let _ = fs::remove_file(&backup_path); // Remove any existing backup
        fs::rename(current_exe, &backup_path)?;
        fs::copy(new_binary, current_exe)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform() {
        let result = detect_platform();
        assert!(result.is_ok());

        let (os, arch) = result.unwrap();

        #[cfg(target_os = "macos")]
        assert_eq!(os, "darwin");

        #[cfg(target_os = "linux")]
        assert_eq!(os, "linux");

        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "x86_64");

        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "aarch64");
    }

    #[test]
    fn test_current_version() {
        // Verify version is a valid semver-like string
        assert!(CURRENT_VERSION.contains('.'));
    }

    #[test]
    fn test_is_version_newer() {
        // Newer versions
        assert!(is_version_newer("0.1.6", "0.1.5"));
        assert!(is_version_newer("0.2.0", "0.1.9"));
        assert!(is_version_newer("1.0.0", "0.9.9"));

        // Same version
        assert!(!is_version_newer("0.1.5", "0.1.5"));

        // Older versions
        assert!(!is_version_newer("0.1.4", "0.1.5"));
        assert!(!is_version_newer("0.1.0", "0.2.0"));
    }
}
