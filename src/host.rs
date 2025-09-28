use crate::{
    manifest::{CapabilityManifest, PRIME_MULTIPLIER},
    trace::{
        CapEventSubtype, EventType, SignedTrace, TraceError, TraceEvent, finalize_trace,
        log_trace_event, save_trace,
    },
};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey, ed25519::signature::SignerMut};
use glob::Pattern;
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use tracing::Level;

#[derive(Debug)]
pub struct HostState {
    manifest: CapabilityManifest,
    trace: Vec<TraceEvent>,
    seed: u64,
    keypair: SigningKey,
    pubkey: [u8; PUBLIC_KEY_LENGTH],
    run_id: String,
    manifest_hash: String,
}

/// Errors from capability enforcement.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapError {
    #[error("No FS capability declared")]
    NoFsCapability,

    #[error("No read patterns defined")]
    NoReadPatterns,

    #[error("Path does not match any glob pattern")]
    GlobMismatch,

    #[error("Invalid path provided (empty or invalid UTF-8)")]
    InvalidPath,
}

impl HostState {
    #[inline]
    #[must_use]
    /// # Panics
    ///
    /// Should not panic
    pub fn new(manifest: CapabilityManifest, seed: u64, keypair: SigningKey) -> Self {
        let pubkey = keypair.verifying_key().to_bytes();
        let run_id = format!("captra-run-{seed}");
        let manifest_json = serde_json::to_string(&manifest).expect("Manifest serializes"); // Safe: validated earlier
        let mut hashser = Sha256::default();
        hashser.update(manifest_json.as_bytes());
        let manifest_hash = format!("{:x}", hashser.finalize());

        Self {
            manifest,
            trace: Vec::new(),
            seed,
            keypair,
            pubkey,
            run_id,
            manifest_hash,
        }
    }

    /// Get `pubkey`
    #[must_use]
    pub const fn pubkey(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.pubkey
    }

    /// Get `run_id`
    #[inline]
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Get `trace`
    #[inline]
    #[must_use]
    pub fn trace(&self) -> &[TraceEvent] {
        &self.trace
    }

    /// Simulate "plugin execution": check if path is allowed via FS read cap.
    /// Logs to trace on success/error (outcome=false for errors).
    ///
    /// # Errors
    ///
    /// [`CapError`] if enforcement fails (e.g., no caps or mismatch).
    pub fn execute_plugin<P: AsRef<Path>>(&mut self, path: P) -> Result<bool, CapError> {
        let path_str = path.as_ref().to_string_lossy();
        if path_str.is_empty() {
            return Err(CapError::InvalidPath);
        }

        if self.manifest.capabilities.fs.is_none() {
            self.log_cap_error(CapEventSubtype::NoFsCapability, "missing fs cap", &path_str);
            return Err(CapError::NoFsCapability);
        }

        let read_patterns_ops = self
            .manifest
            .capabilities
            .fs
            .as_ref()
            .and_then(|fs| fs.read.clone());

        let read_patterns = match read_patterns_ops {
            Some(v) if !v.is_empty() => v,
            _ => {
                self.log_cap_error(
                    CapEventSubtype::NoReadPatterns,
                    "empty read patterns",
                    &path_str,
                );
                return Err(CapError::NoReadPatterns);
            }
        };

        let seq = u64::try_from(self.trace.len()).map_or(1, |len| len + 1);

        let mut rng = StdRng::seed_from_u64(self.seed.wrapping_mul(PRIME_MULTIPLIER + seq));
        let ts_seed = rng.r#gen();

        let is_allowed = read_patterns.iter().any(|pattern| {
            Pattern::new(pattern).map_or_else(
                |_| {
                    self.log_cap_error(CapEventSubtype::InvalidGlob, pattern, &path_str);
                    false
                },
                |p| p.matches(&path_str),
            )
        });

        if !is_allowed {
            self.log_cap_error(
                CapEventSubtype::GlobMismatch,
                "no matching pattern",
                &path_str,
            );
            return Err(CapError::GlobMismatch);
        }

        log_trace_event(
            seq,
            EventType::CapCall,
            &path_str,
            true,
            ts_seed,
            &self.manifest.plugin,
        );

        self.trace.push(TraceEvent {
            run_id: self.run_id.clone(),
            seq,
            event_type: EventType::CapCall,
            input: path_str.into(),
            outcome: is_allowed,
            ts_seed,
        });

        Ok(true)
    }

    /// Signs the current trace JSON with the host keypair.
    /// Computes SHA256 hash of trace for integrity.
    ///
    /// # Errors
    ///
    /// [`TraceError`] (serialization).
    pub fn sign_current_trace(&mut self) -> Result<SignedTrace, TraceError> {
        let trace_json = finalize_trace(&self.trace);
        let mut hasher = Sha256::default();
        hasher.update(trace_json.as_bytes());
        let trace_hash = format!("{:x}", hasher.finalize());

        let signature = self.keypair.sign(trace_hash.as_bytes()).to_bytes().to_vec();

        Ok(SignedTrace::new(
            self.run_id.clone(),
            self.manifest_hash.clone(),
            trace_json,
            signature,
        ))
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
    pub fn save_current_trace<P: AsRef<Path>>(&self, path: P) -> Result<(), TraceError> {
        save_trace(&self.trace, path)
    }

    fn log_cap_error(&mut self, event_subtype: CapEventSubtype, reason: &str, path_str: &str) {
        let seq = u64::try_from(self.trace.len()).map_or(1, |len| len + 1);
        let mut rng = StdRng::seed_from_u64(self.seed.wrapping_mul(PRIME_MULTIPLIER + seq));
        let ts_seed = rng.r#gen();

        let event_type = EventType::from(event_subtype);

        log_trace_event(
            seq,
            event_type,
            path_str,
            false,
            ts_seed,
            &self.manifest.plugin,
        );

        self.trace.push(TraceEvent {
            run_id: self.run_id.clone(),
            seq,
            event_type,
            input: format!("{event_subtype}: {reason}"),
            outcome: false,
            ts_seed,
        });
    }
}

pub fn init_tracing() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
}
