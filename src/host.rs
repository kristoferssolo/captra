use color_eyre::Result;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey};
use glob::Pattern;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::path::Path;
use tracing::Level;

use crate::{
    manifest::{CapabilityManifest, PRIME_MULTIPLIER},
    trace::{TraceEvent, finalize_trace, log_trace_event, save_trace},
};

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

        log_trace_event(
            seq,
            "cap.call",
            &path_str,
            is_allowed,
            ts_seed,
            &self.manifest.plugin,
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

    /// Serialize trace to pretty JSON string
    #[inline]
    #[must_use]
    pub fn get_trace_json(&self) -> String {
        finalize_trace(&self.trace)
    }

    /// Save the current trace to a file as pretty JSON.
    ///
    /// # Errors
    ///
    /// If file write fails (e.g., I/O error) or JSON serialization fails.
    pub fn save_current_trace<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        save_trace(&self.trace, path)
    }
}

pub fn init_tracing() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
}
