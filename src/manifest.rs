use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, path::Path};
use thiserror::Error;

/// Prime for seq hashing to derive per-event RNG state
pub const PRIME_MULTIPLIER: u64 = 314_159;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapability {
    pub read: Option<Vec<String>>,  // Glob patter for read
    pub write: Option<Vec<String>>, // Stub for now
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Capability {
    Fs(FsCapability),
    // TODO: add Net, Cpu, etc
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub fs: Option<FsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub plugin: String,
    pub version: String,
    pub capabilities: Capabilities,
    pub issued_by: String,
    // TODO: add signature
}

/// Errors from manifest loading/validation.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("IO error reading manifest: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON deserialization failed: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("Invalid plugin name: must be non-empty")]
    InvalidPlugin,

    #[error("Invalid version: must be non-empty")]
    InvalidVersion,

    #[error("Invalid issuer: must be non-empty")]
    InvalidIssuer,

    #[error("Invalid glob pattern at index {idx}: {pattern} - {err}")]
    InvalidGlob {
        idx: usize,
        pattern: String,
        err: String,
    },
}

impl CapabilityManifest {
    /// Validates the manifest: non-empty fields and compilable glob patterns.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] if invalid.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.plugin.is_empty() {
            return Err(ManifestError::InvalidPlugin);
        }
        if self.version.is_empty() {
            return Err(ManifestError::InvalidVersion);
        }
        if self.issued_by.is_empty() {
            return Err(ManifestError::InvalidIssuer);
        }
        if let Some(fs_cap) = &self.capabilities.fs
            && let Some(read_patterns) = &fs_cap.read
        {
            for (idx, pattern) in read_patterns.iter().enumerate() {
                Pattern::new(pattern).map_err(|err| ManifestError::InvalidGlob {
                    idx,
                    pattern: pattern.clone(),
                    err: err.to_string(),
                })?;
            }
        }
        Ok(())
    }

    /// Loads a capability manifest from a JSON file and validates it.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] (IO, JSON, or validation failures).
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ManifestError> {
        let json_str = read_to_string(path)?;
        let manifest = serde_json::from_str::<Self>(&json_str)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

/// A think wrapper around `CapabilityManifest::load()`
///
/// # Errors
///
/// [`ManifestError`] (IO, JSON, or validation failures).
pub fn load_manifest<P: AsRef<Path>>(path: P) -> Result<CapabilityManifest, ManifestError> {
    CapabilityManifest::load(path)
}
