use std::fs::read_to_string;

use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FsCapability {
    pub read: Vec<String>,  // Glob patter for read
    pub write: Vec<String>, // Stub for now
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Capability {
    Fs(FsCapability),
    // TODO: add Net, Cpu
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
        assert_eq!(fs_cap.read, vec!["./workspace/*"]);
        assert!(fs_cap.write.is_empty());
    }
}
