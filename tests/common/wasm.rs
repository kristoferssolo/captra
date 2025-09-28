use captra::{HostState, add_wasm_linker_funcs};
use wasmtime::{Engine, Linker, Store};

/// Create a wasmtime engine + linker with your host functions registered,
/// and a [`Store`] that owns the given [`HostState`].
/// # Panics
#[must_use]
pub fn wasm_store_with_hosts(host: HostState) -> (Engine, Linker<HostState>, Store<HostState>) {
    let engine = Engine::default();
    let mut linker = Linker::new(&engine);
    add_wasm_linker_funcs(&mut linker).expect("linker registration");
    let store = Store::new(&engine, host);
    (engine, linker, store)
}
