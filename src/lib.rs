pub mod host;
pub mod manifest;
pub mod trace;

#[cfg(test)]
mod tests {
    use crate::{
        host::{HostState, init_tracing},
        manifest::load_manifest,
        trace::{TraceEvent, load_trace},
    };
    use claims::{assert_ok, assert_some};
    use ed25519_dalek::SigningKey;
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

        assert_ok!(host.save_current_trace(&tmp_path), "Save failed");

        let loaded_trace = assert_ok!(load_trace(tmp_path), "Load failed");
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
        let trace1 = host1.get_trace_json();

        let mut csprng2 = OsRng;
        let keypair2 = SigningKey::generate(&mut csprng2);
        let mut host2 = HostState::new(manifest, fixed_seed, keypair2);
        assert!(!host2.execute_plugin("./allowed.txt"));
        let trace2 = host2.get_trace_json();

        let parsed1 = assert_ok!(serde_json::from_str::<Vec<TraceEvent>>(&trace1));
        let parsed2 = assert_ok!(serde_json::from_str::<Vec<TraceEvent>>(&trace2));
        assert_eq!(parsed1, parsed2);
        assert_eq!(parsed1[0].ts_seed, parsed2[0].ts_seed);
    }
}
