use color_eyre::eyre::Result;
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, read_to_string},
    path::Path,
};
use tracing::{Level, info};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub seq: u64,
    pub event_type: String,
    pub input: String,
    pub outcome: bool,
}

#[derive(Debug)]
pub struct HostState {
    pub manifest: CapabilityManifest,
    pub trace: Vec<TraceEvent>,
}

impl HostState {
    #[inline]
    #[must_use]
    pub const fn new(manifest: CapabilityManifest) -> Self {
        Self {
            manifest,
            trace: Vec::new(),
        }
    }

    /// Simulate "plugin execution": check if path is allowed via FS read cap.
    /// Returns `true` if allowed, `false` if denied.
    #[must_use]
    pub fn execute_plugin<P: AsRef<Path>>(&mut self, path: P) -> bool {
        let seq = u64::try_from(self.trace.len()).map_or_else(|_| 1, |len| len + 1);

        let Some(fs_cap) = &self.manifest.capabilities.fs else {
            return false;
        };

        let Some(read_patterns) = &fs_cap.read else {
            return false;
        };

        let path_str = path.as_ref().to_string_lossy();

        let is_allowed = read_patterns.iter().any(|pattern| {
            Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        });

        info!(
            seq = seq,
            event_type = "cap.call",
            input = %path_str,
            outcome = is_allowed,
            plugin = %self.manifest.plugin
        );

        self.trace.push(TraceEvent {
            seq,
            event_type: "cap.call".into(),
            input: path_str.into(),
            outcome: is_allowed,
        });

        is_allowed
    }

    #[inline]
    #[must_use]
    pub fn finalize_trace(&self) -> String {
        serde_json::to_string_pretty(&self.trace).unwrap_or_else(|_| "[]".into())
    }

    /// Save the current trace to a file as pretty JSON.
    /// # Errors
    /// If file write fails (e.g., I/O error) or JSON serialization fails.
    pub fn save_trace<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json_str = serde_json::to_string_pretty(&self.trace)?;
        fs::write(path, json_str)?;
        Ok(())
    }

    /// Load a trace from a JSON file to Vec<TraceEvent>.
    ///
    /// # Errors
    ///
    /// If file read fails (e.g., I/O error) or JSON parsing fails.
    pub fn load_trace<P: AsRef<Path>>(path: P) -> Result<Vec<TraceEvent>> {
        let json_str = fs::read_to_string(path)?;
        let trace = serde_json::from_str(&json_str)?;
        Ok(trace)
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

pub fn init_tracing() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_ok, assert_some};
    use tempfile::tempdir;

    #[test]
    fn tracing_init() {
        init_tracing();
    }

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
    fn host_enforcement_with_trace() {
        init_tracing();

        let manifest = load_manifest("examples/manifest.json").expect("Load failed");
        let mut host = HostState::new(manifest);

        // allowed - expect a tracing event
        let out1 = host.execute_plugin("./workspace/config.toml");
        assert!(out1);
        // denied - event + entry
        let out2 = host.execute_plugin("/etc/passwd");
        assert!(!out2);

        assert_eq!(host.trace.len(), 2);

        let trace1 = assert_some!(host.trace.first());
        assert_eq!(trace1.seq, 1);
        assert_eq!(trace1.event_type, "cap.call");
        assert_eq!(trace1.input, "./workspace/config.toml");
        assert!(trace1.outcome);

        let trace2 = assert_some!(host.trace.get(1));
        assert_eq!(trace2.seq, 2);
        assert_eq!(trace2.input, "/etc/passwd");
        assert!(!trace2.outcome);

        let tmp_dir = tempdir().expect("Temp dir failed");
        let tmp_path = tmp_dir.as_ref().join("trace.json");

        assert_ok!(host.save_trace(&tmp_path));

        let loaded_trace = assert_ok!(HostState::load_trace(tmp_path));
        assert_eq!(loaded_trace.len(), 2);

        let loaded_trace1 = assert_some!(loaded_trace.first());
        assert_eq!(trace1, loaded_trace1);

        let loaded_trace2 = assert_some!(loaded_trace.get(1));
        assert_eq!(trace2, loaded_trace2);
    }
}
