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

#[test]
fn async_submit_posts_every_run_once_with_its_ticket() {
    let n = hydra_dhost_start(3);
    assert_eq!(n, 3);
    assert_eq!(hydra_dhost_queue_capacity(), 24, "8 runs per worker");
    let addr = [0x20u8, 0x21];
    // SAFETY: a null store is refused before anything is queued.
    let rc = unsafe { hydra_dhost_submit(null_mut(), addr.as_ptr() as *const c_char, 2, 1) };
    assert_eq!(rc, FAILED);

    let h = store("not a processor spec either");
    assert!(!h.is_null());
    let mut want = std::collections::BTreeSet::new();
    for t in 100..112u64 {
        // SAFETY: live store, kept open until every completion is taken; addr copied.
        let rc = unsafe { hydra_dhost_submit(h, addr.as_ptr() as *const c_char, 2, t) };
        assert_eq!(rc, OK, "12 runs fit the bound of 24");
        want.insert(t);
    }
    let mut got = std::collections::BTreeSet::new();
    let mut buf = vec![
        Completion {
            ticket: 0,
            out: null_mut(),
            outlen: 0,
            misses: null_mut(),
            misseslen: 0,
            answered: 0,
            rc: -9,
        };
        5
    ];
    let t0 = std::time::Instant::now();
    while got.len() < want.len() {
        assert!(t0.elapsed().as_secs() < 120, "completions did not arrive");
        // SAFETY: buf holds 5 entries.
        let k = unsafe { hydra_dhost_completions(buf.as_mut_ptr(), buf.len(), 1000) };
        assert!((0..=5).contains(&k));
        for c in &buf[..k as usize] {
            assert!(got.insert(c.ticket), "ticket {} posted twice", c.ticket);
            assert!(c.rc == FAILED || c.rc == MISSES, "rc {}", c.rc);
            if c.rc == FAILED {
                assert!(
                    !c.out.is_null() && c.outlen > 0,
                    "a failure carries its message"
                );
            }
            // SAFETY: buffers handed over by the completion, freed once.
            unsafe {
                hydra_dhost_free(c.out);
                hydra_dhost_free(c.misses);
            }
        }
    }
    assert_eq!(got, want);
    // SAFETY: buf holds 5 entries; nothing is in flight, so this times out empty.
    let k = unsafe { hydra_dhost_completions(buf.as_mut_ptr(), buf.len(), 20) };
    assert_eq!(k, 0);
    assert_eq!(
        std::mem::size_of::<Completion>(),
        48,
        "the layout the JVM binds"
    );
    // SAFETY: closed once, every completion taken.
    unsafe { hydra_dhost_store_close(h) };
}
