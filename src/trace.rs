use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use tracing::info;

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

/// Save the current trace to a file as pretty JSON.
///
/// # Errors
///
/// If file write fails (e.g., I/O error) or JSON serialization fails.
pub fn save_trace<P: AsRef<Path>>(trace: &[TraceEvent], path: P) -> Result<()> {
    let json_str = serde_json::to_string_pretty(trace)?;
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

/// Serialize trace to pretty JSON string (fallback to "[]").
#[inline]
#[must_use]
pub fn finalize_trace(trace: &[TraceEvent]) -> String {
    serde_json::to_string_pretty(trace).unwrap_or_else(|_| "[]".into())
}

/// Log a trace event
pub fn log_trace_event(
    seq: u64,
    event_type: &str,
    input: &str,
    outcome: bool,
    ts_seed: u64,
    plugin: &str,
) {
    info!(
        seq = seq,
        ts_seed = ts_seed,
        event_type = event_type,
        input = %input,
        outcome = outcome,
        plugin = plugin,
    );
}
