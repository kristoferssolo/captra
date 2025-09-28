mod common;

use captra::{HostState, HostStatus, add_wasm_linker_funcs, load_manifest};
use claims::{assert_ok, assert_some};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use wasmtime::{Engine, Linker, Module, Store};

#[test]
fn wasm_integration_allowed() {
    let manifest = assert_ok!(load_manifest("examples/manifest.json"), "Load failed");
    let fixed_seed = 12345;
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let host = HostState::new(manifest, fixed_seed, keypair);

    let engine = Engine::default();
    let mut linker = Linker::new(&engine);

    assert_ok!(add_wasm_linker_funcs(&mut linker));

    let path = "./workspace/test.txt";
    let path_len = path.as_bytes().len();
    let wat = format!(
        r#"
        (module
          (import "host" "read_file" (func $host_read_file (param i32 i32) (result i32)))
          (import "host" "status_allowed" (func $host_status_allowed (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{path}")
          (func (export "run") (result i32)
                i32.const 0
                i32.const {path_len}
                call $host_read_file
                call $host_status_allowed
                i32.eq    ;; returns 1 if allowed, 0 if denied, -1 if error
                )
          )
    "#
    );

    let module = assert_ok!(Module::new(&engine, wat));
    let mut store = Store::new(&engine, host);

    let instance = assert_ok!(linker.instantiate(&mut store, &module));
    let run = assert_ok!(instance.get_typed_func::<(), i32>(&mut store, "run"));

    let ret = assert_ok!(run.call(&mut store, ()));
    assert_eq!(ret, HostStatus::Denied as i32);

    let host_state = store.data();
    assert_eq!(host_state.trace().len(), 1);
    dbg!(&host_state);
    let ev = assert_some!(host_state.trace().first());
    assert_eq!(ev.input, "./workspace/test.txt");
    assert!(ev.outcome);
}
