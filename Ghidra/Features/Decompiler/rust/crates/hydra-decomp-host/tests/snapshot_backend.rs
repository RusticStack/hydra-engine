//! The snapshot backend's C ABI without the engine: a store the decompiler cannot register from
//! fails cleanly (no process exit at "end of input", no crash), the pool size is honoured, a store
//! accepts answers, and closing a store while workers hold Architectures for it is safe.
//! The end-to-end identity proof (host vs process replies) is the engine gate
//! (`_logs/rust-integration/gate/gate_p6.py`), since the answers come from the Java exporter.

use std::ffi::c_char;
use std::ptr::null_mut;

use hydra_decomp_host::snapshot::*;

fn store(pspec: &str) -> *mut std::ffi::c_void {
    let p = pspec.as_bytes();
    // SAFETY: every buffer is valid for its length.
    unsafe {
        hydra_dhost_store_new(
            p.as_ptr() as *const c_char,
            p.len(),
            c"<compiler_spec/>".as_ptr(),
            16,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        )
    }
}

fn decompile(h: *mut std::ffi::c_void) -> (i32, Vec<u8>, Vec<Vec<u8>>) {
    let addr = [0x20u8, 0x21];
    let (mut out, mut outlen, mut m, mut ml, mut a) =
        (null_mut(), 0usize, null_mut(), 0usize, 0u64);
    // SAFETY: live handle, valid buffers and out-pointers.
    let rc = unsafe {
        hydra_dhost_decompile(
            h,
            addr.as_ptr() as *const c_char,
            addr.len(),
            &mut out,
            &mut outlen,
            &mut m,
            &mut ml,
            &mut a,
        )
    };
    // SAFETY: buffers returned by the library, read once and freed once.
    let (o, mv) = unsafe {
        let o = if out.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(out as *const u8, outlen).to_vec()
        };
        let mv = if m.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(m as *const u8, ml).to_vec()
        };
        hydra_dhost_free(out);
        hydra_dhost_free(m);
        (o, mv)
    };
    (rc, o, split_misses(&mv))
}

#[test]
fn unusable_store_fails_cleanly_on_every_worker() {
    assert_eq!(hydra_dhost_abi_version(), ABI_VERSION);
    let n = hydra_dhost_start(3);
    assert_eq!(n, 3, "the first start decides the pool size");
    assert_eq!(hydra_dhost_start(7), 3, "later starts return it");
    assert_eq!(pool_threads(), 3);

    let h = store("this is not a processor spec");
    assert!(!h.is_null());
    // SAFETY: live handle; empty scope; valid buffers.
    let rc = unsafe {
        hydra_dhost_store_put(h, std::ptr::null(), 0, c"q".as_ptr(), 1, c"r".as_ptr(), 1)
    };
    assert_eq!(rc, 0);
    let (mut count, mut bytes) = (0u64, 0u64);
    // SAFETY: live handle, writable outputs.
    unsafe { hydra_dhost_store_stats(h, &mut count, &mut bytes) };
    assert_eq!((count, bytes), (1, 2));

    // More jobs than workers: every worker tries to register, none may exit or crash the process.
    let results: Vec<_> = std::thread::scope(|s| {
        let hs = h as usize;
        let js: Vec<_> = (0..8)
            .map(|_| s.spawn(move || decompile(hs as *mut std::ffi::c_void)))
            .collect();
        js.into_iter().map(|j| j.join().unwrap()).collect()
    });
    for (rc, out, misses) in results {
        assert!(rc == FAILED || rc == MISSES, "rc {rc}");
        if rc == FAILED {
            assert!(!out.is_empty(), "a failure carries its message");
        } else {
            assert!(!misses.is_empty());
        }
    }
    // SAFETY: closed once, no job running.
    unsafe { hydra_dhost_store_close(h) };
    hydra_dhost_release_workers();
}
