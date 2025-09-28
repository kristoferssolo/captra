mod common;

use crate::common::{host::make_host_with_seed, wasm::wasm_store_with_hosts};
use captra::HostStatus;
use claims::{assert_ok, assert_some};
use wasmtime::Module;

#[test]
fn wasm_integration_allowed() {
    let host = make_host_with_seed(12345);
    let (engine, linker, mut store) = wasm_store_with_hosts(host);

    let path = "./workspace/test.txt";
    let wat = format!(
        r#"
        (module
          (import "host" "read_file" (func $host_read_file (param i32 i32) (result i32)))
          (import "host" "status_allowed" (func $host_status_allowed (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{path}")
          (func (export "run") (result i32)
                i32.const 0
                i32.const {len}
                call $host_read_file
                call $host_status_allowed
                i32.eq    ;; returns 1 if allowed, 0 if denied, -1 if error
                )
          )
    "#,
        len = path.len()
    );

    let module = assert_ok!(Module::new(&engine, &wat));
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
