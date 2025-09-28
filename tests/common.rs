use captra::{CapabilityManifest, HostState, add_wasm_linker_funcs, load_manifest};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use wasmtime::{Engine, Linker, Store};

/// Load the example manifest bundled with the repo.
pub fn load_example_manifest() -> CapabilityManifest {
    load_manifest("examples/manifest.json").expect("examples/manifest.json must exists")
}

/// Build a HostState with a fixed seed and a fresh SigningKey (OsRng).
pub fn make_host_with_seed(seed: u64) -> HostState {
    let manifest = load_example_manifest();
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    HostState::new(manifest, seed, keypair)
}

/// Create a wasmtime engine + linker with your host functions registered,
/// and a Store that owns the given HostState.
pub fn wasm_store_with_hosts(host: HostState) -> (Engine, Linker<HostState>, Store<HostState>) {
    let engine = Engine::default();
    let mut linker = Linker::new(&engine);
    add_wasm_linker_funcs(&mut linker).expect("linker registration");
    let store = Store::new(&engine, host);
    (engine, linker, store)
}
