use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, fs, path::Path, str::FromStr};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub run_id: String,
    pub seq: u64,
    pub event_type: EventType,
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

/// Errors from trace serialization/IO.
#[derive(Debug, Error)]
pub enum TraceError {
    #[error("JSON serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Base64 encoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    CapCall,
    CapError,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapEventSubtype {
    InvalidPath,
    NoFsCapability,
    NoReadPatterns,
    GlobMismatch,
    InvalidGlob,
    // TODO: NetConnect, NetDeny, CpuQuotaExceeded
}

impl SignedTrace {
    #[inline]
    #[must_use]
    pub fn new(
        run_id: String,
        manifest_hash: String,
        trace_json: String,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            run_id,
            manifest_hash,
            trace_json,
            signature: general_purpose::STANDARD.encode(signature),
        }
    }
}

/// Save the current trace to a file as pretty JSON.
///
/// # Errors
///
/// [`TraceError`] (JSON or IO).
pub fn save_trace<P: AsRef<Path>>(trace: &[TraceEvent], path: P) -> Result<(), TraceError> {
    let json_str = serde_json::to_string_pretty(trace)?;
    fs::write(path, json_str)?;
    Ok(())
}

/// Load a trace from a JSON file to [`Vec<TraceEvent>`].
///
/// # Errors
///
/// [`TraceError`] (JSON or IO).
pub fn load_trace<P: AsRef<Path>>(path: P) -> Result<Vec<TraceEvent>, TraceError> {
    let json_str = fs::read_to_string(path)?;
    let trace = serde_json::from_str(&json_str)?;
    Ok(trace)
}

/// Serialize trace to pretty JSON string (fallback to "[]").
#[inline]
#[must_use]
pub fn finalize_trace(trace: &[TraceEvent]) -> String {
    serde_json::to_string_pretty(trace).unwrap_or_else(|_| "[]".into())
}

/// Log a trace event
pub fn log_trace_event(
    seq: u64,
    event_type: EventType,
    input: &str,
    outcome: bool,
    ts_seed: u64,
    plugin: &str,
) {
    info!(
        seq = seq,
        ts_seed = ts_seed,
        event_type = %event_type,
        input = %input,
        outcome = outcome,
        plugin = plugin,
    );
}

impl FromStr for EventType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cap.call" => Ok(Self::CapCall),
            "cap.error" => Ok(Self::CapError),
            _ => Err("Unknown event type"),
        }
    }
}

impl Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CapCall => "cap.call",
            Self::CapError => "cap.error",
        };
        f.write_str(s)
    }
}

impl FromStr for CapEventSubtype {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invalid_path" => Ok(Self::InvalidPath),
            "no_fs_capability" => Ok(Self::NoFsCapability),
            "no_read_patterns" => Ok(Self::NoReadPatterns),
            "glob_mismatch" => Ok(Self::GlobMismatch),
            "invalid_glob" => Ok(Self::InvalidGlob),
            _ => Err("Unknown cap event subtype"),
        }
    }
}

impl Display for CapEventSubtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidPath => "invalid_path",
            Self::NoFsCapability => "no_fs_capability",
            Self::NoReadPatterns => "no_read_patterns",
            Self::GlobMismatch => "glob_mismatch",
            Self::InvalidGlob => "invalid_glob",
        };
        f.write_str(s)
    }
}

impl From<CapEventSubtype> for EventType {
    fn from(subtype: CapEventSubtype) -> Self {
        match subtype {
            CapEventSubtype::GlobMismatch => Self::CapCall,
            _ => Self::CapError,
        }
    }
}
