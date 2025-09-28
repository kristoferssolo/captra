use color_eyre::eyre::Result;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey};
use glob::Pattern;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, read_to_string},
    path::Path,
};
use tracing::{Level, info};

/// Prime for seq hashing to derive per-event RNG state
const PRIME_MULTIPLIER: u64 = 314_159;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub seq: u64,
    pub event_type: String,
    pub input: String,
    pub outcome: bool,
    pub ts_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTrace {
    pub run_id: String,
    pub manifest_hash: String,
    pub trace_json: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct HostState {
    pub manifest: CapabilityManifest,
    pub trace: Vec<TraceEvent>,
    pub seed: u64,
    pub keypair: SigningKey,
    pub pubkey: [u8; PUBLIC_KEY_LENGTH],
}

impl HostState {
    #[inline]
    #[must_use]
    pub fn new(manifest: CapabilityManifest, seed: u64, keypair: SigningKey) -> Self {
        let pubkey = keypair.verifying_key().to_bytes();
        Self {
            manifest,
            trace: Vec::new(),
            seed,
            keypair,
            pubkey,
        }
    }

    /// Simulate "plugin execution": check if path is allowed via FS read cap.
    /// Returns `true` if allowed, `false` if denied.
    #[must_use]
    pub fn execute_plugin<P: AsRef<Path>>(&mut self, path: P) -> bool {
        let Some(fs_cap) = &self.manifest.capabilities.fs else {
            return false;
        };

        let Some(read_patterns) = &fs_cap.read else {
            return false;
        };

        let seq = u64::try_from(self.trace.len()).map_or(1, |len| len + 1);
        let path_str = path.as_ref().to_string_lossy();

        let mut rng = StdRng::seed_from_u64(self.seed.wrapping_mul(PRIME_MULTIPLIER + seq));
        let ts_seed = rng.r#gen();

        let is_allowed = read_patterns.iter().any(|pattern| {
            Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        });

        info!(
            seq = seq,
            ts_seed = ts_seed,
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
            ts_seed,
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
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    #[test]
    fn tracing_init() {
        init_tracing();
    }

    #[test]
    fn manifest_loader() {
        let manifest = assert_ok!(load_manifest("examples/manifest.json"), "Load failed");
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

        let manifest = assert_ok!(load_manifest("examples/manifest.json"), "Load failed");
        let fixed_seed = 12345;
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        let mut host = HostState::new(manifest, fixed_seed, keypair);

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
        assert_eq!(trace1.ts_seed, 8_166_419_713_379_829_776);
        assert_ne!(trace1.ts_seed, 0);

        let trace2 = assert_some!(host.trace.get(1));
        assert_eq!(trace2.seq, 2);
        assert_eq!(trace2.input, "/etc/passwd");
        assert!(!trace2.outcome);
        assert_eq!(trace2.ts_seed, 10_553_447_931_939_622_718);
        assert_ne!(trace1.ts_seed, trace2.ts_seed);

        let tmp_dir = tempdir().expect("Temp dir failed");
        let tmp_path = tmp_dir.as_ref().join("trace.json");

        assert_ok!(host.save_trace(&tmp_path), "Save failed");

        let loaded_trace = assert_ok!(HostState::load_trace(tmp_path), "Load failed");
        assert_eq!(loaded_trace.len(), 2);

        let loaded_trace1 = assert_some!(loaded_trace.first());
        assert_eq!(trace1, loaded_trace1);

        let loaded_trace2 = assert_some!(loaded_trace.get(1));
        assert_eq!(trace2, loaded_trace2);
    }

    #[test]
    fn trace_reproducibility() {
        init_tracing();

        let manifest = assert_ok!(load_manifest("examples/manifest.json"), "Load failed");

        let fixed_seed = 12345;
        let mut csprng1 = OsRng;
        let keypair1 = SigningKey::generate(&mut csprng1);

        let mut host1 = HostState::new(manifest.clone(), fixed_seed, keypair1);
        assert!(!host1.execute_plugin("./allowed.txt"));
        let trace1 = host1.finalize_trace();

        let mut csprng2 = OsRng;
        let keypair2 = SigningKey::generate(&mut csprng2);
        let mut host2 = HostState::new(manifest, fixed_seed, keypair2);
        assert!(!host2.execute_plugin("./allowed.txt"));
        let trace2 = host2.finalize_trace();

        let parsed1 = assert_ok!(serde_json::from_str::<Vec<TraceEvent>>(&trace1));
        let parsed2 = assert_ok!(serde_json::from_str::<Vec<TraceEvent>>(&trace2));
        assert_eq!(parsed1, parsed2);
        assert_eq!(parsed1[0].ts_seed, parsed2[0].ts_seed);
    }
}
