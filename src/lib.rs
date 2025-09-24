use color_eyre::eyre::Result;
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, path::Path};

#[derive(Debug, Serialize, Deserialize)]
pub struct FsCapability {
    pub read: Option<Vec<String>>,  // Glob patter for read
    pub write: Option<Vec<String>>, // Stub for now
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Capability {
    Fs(FsCapability),
    // TODO: add Net, Cpu, etc
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub fs: Option<FsCapability>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub plugin: String,
    pub version: String,
    pub capabilities: Capabilities,
    pub issued_by: String,
    // TODO: add signature
}

pub struct HostState {
    pub manifest: CapabilityManifest,
}

impl HostState {
    #[inline]
    #[must_use]
    pub const fn new(manifest: CapabilityManifest) -> Self {
        Self { manifest }
    }

    /// Simulate "plugin execution": check if path is allowed via FS read cap.
    /// Returns `true` if allowed, `false` if denied.
    #[must_use]
    pub fn execute_plugin<P: AsRef<Path>>(&self, path: P) -> bool {
        let Some(fs_cap) = &self.manifest.capabilities.fs else {
            return false;
        };

        let Some(read_patterns) = &fs_cap.read else {
            return false;
        };

        let path_str = path.as_ref().to_string_lossy();

        read_patterns.iter().any(|pattern| {
            Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        })
    }
}

/// Loads a capability manifest from a JSON file.
///
/// # Errors
///
/// - bubbles up `std::fs::read_to_string` and `serde_json::from_str` errors;
pub fn load_manifest(path: &str) -> Result<CapabilityManifest> {
    let json_str = read_to_string(path)?;
    let manifest = serde_json::from_str(&json_str)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_some;

    #[test]
    fn manifest_loader() {
        let manifest = load_manifest("examples/manifest.json").expect("Load failed");
        assert_eq!(manifest.plugin, "formatter-v1");
        assert_eq!(manifest.version, "0.1");
        assert_eq!(manifest.issued_by, "dev-team");

        let caps = manifest.capabilities;
        let fs_cap = assert_some!(caps.fs);
        let read_patterns = assert_some!(fs_cap.read);
        assert_eq!(read_patterns, vec!["./workspace/*"]);
        let write_patterns = assert_some!(fs_cap.write);
        assert!(write_patterns.is_empty());
    }

    #[test]
    fn host_enforcement() {
        let manifest = load_manifest("examples/manifest.json").expect("Load failed");
        let host = HostState::new(manifest);

        // Allowed: matches ./workspace/*
        assert!(host.execute_plugin("./workspace/config.toml"));
        // Disallowed: outside pattern
        assert!(!host.execute_plugin("/etc/passwd"))
    }
}
