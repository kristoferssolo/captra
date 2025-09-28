use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

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
