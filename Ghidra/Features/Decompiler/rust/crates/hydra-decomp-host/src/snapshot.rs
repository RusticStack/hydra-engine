//! The snapshot decompile backend (DESIGN.md step 6): the C ABI the engine calls through FFM.
//!
//! A *store* holds what the Java `DecompileCallback` answers for one program generation (the
//! registerProgram spec strings, the encoded options, the byte snapshot file and the answer table,
//! filled by the Java side once per generation). A decompile runs on this library's worker pool:
//! the worker finds or builds its own `SnapshotArchitecture` for the store (an `ArchitectureGhidra`
//! whose client is the store, `cpp/snapshot_arch.cc`), decompiles, flushes, and hands back the
//! command response exactly as `decompile.exe` writes it to its pipe. No call goes back to Java;
//! a query the store does not hold is reported as a miss and the result is discarded.
//!
//! Every exported function is a plain downcall. Buffers returned to the caller are freed with
//! [`hydra_dhost_free`].

use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

/// Version of this C ABI; the Java binding refuses a library with another value.
pub const ABI_VERSION: c_int = 2;

/// The command response is complete.
pub const OK: c_int = 0;
/// At least one query was not in the store; the misses are returned with the answers the run was
/// fed for them, and the command response when the run went to its end.
pub const MISSES: c_int = 1;
/// Registration or the host failed (the message is returned).
pub const FAILED: c_int = 2;
/// A hardware exception was caught in the decompiler; the worker dropped its Architectures.
pub const CRASHED: c_int = 3;
/// The library is not started ([`hydra_dhost_start`] not called or failed).
pub const NOT_STARTED: c_int = -1;

mod ffi {
    use std::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn hydra_snapshot_start() -> c_int;
        pub fn hydra_snapshot_store_new(
            pspec: *const c_char,
            pspeclen: usize,
            cspec: *const c_char,
            cspeclen: usize,
            tspec: *const c_char,
            tspeclen: usize,
            core: *const c_char,
            corelen: usize,
            opt: *const c_char,
            optlen: usize,
            snap: *const c_char,
            snaplen: usize,
        ) -> *mut c_void;
        pub fn hydra_snapshot_store_put(
            h: *mut c_void,
            scope: *const c_char,
            scopelen: usize,
            query: *const c_char,
            querylen: usize,
            resp: *const c_char,
            resplen: usize,
        ) -> c_int;
        pub fn hydra_snapshot_store_stats(h: *mut c_void, count: *mut u64, bytes: *mut u64);
        pub fn hydra_snapshot_store_close(h: *mut c_void);
        pub fn hydra_snapshot_decompile(
            h: *mut c_void,
            addr: *const c_char,
            addrlen: usize,
            out: *mut *mut c_char,
            outlen: *mut usize,
            misses: *mut *mut c_char,
            misseslen: *mut usize,
            answered: *mut u64,
        ) -> c_int;
        pub fn hydra_snapshot_free(p: *mut c_char);
        pub fn hydra_snapshot_release_thread();
    }
}

static POOL: OnceLock<Result<rayon::ThreadPool, String>> = OnceLock::new();

/// Threads of the worker pool, or 0 before a successful start.
pub fn pool_threads() -> usize {
    match POOL.get() {
        Some(Ok(p)) => p.current_num_threads(),
        _ => 0,
    }
}

/// The ABI version of this library.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_abi_version() -> c_int {
    ABI_VERSION
}

/// Starts the decompiler library and the worker pool (`threads` workers, 0 = the CPUs the OS
/// grants). The first call decides the pool size; later calls return it. Returns the number of
/// workers, or a negative value when the library could not start.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_start(threads: c_int) -> c_int {
    let r = POOL.get_or_init(|| {
        // SAFETY: no arguments; the C++ start is serialised internally and idempotent.
        if unsafe { ffi::hydra_snapshot_start() } != 0 {
            return Err("the decompiler library did not start".into());
        }
        let n = if threads > 0 {
            threads as usize
        } else {
            crate::granted_cpus()
        };
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name(|i| format!("decomp-snapshot-{i}"))
            // Deep recursion in the C++ passes; give workers more than the default 2 MB.
            .stack_size(16 << 20)
            .build()
            .map_err(|e| e.to_string())
    });
    match r {
        Ok(p) => p.current_num_threads() as c_int,
        Err(_) => -2,
    }
}

/// Creates the store of one generation. Each `(ptr, len)` pair is a byte string (UTF-8 for the
/// specs and the snapshot path, packed for the options); `len` 0 means empty. Returns null on
/// failure. The handle stays valid until [`hydra_dhost_store_close`].
///
/// # Safety
/// Every pointer must be valid for reads of its length (any pointer when the length is 0).
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn hydra_dhost_store_new(
    pspec: *const c_char,
    pspeclen: usize,
    cspec: *const c_char,
    cspeclen: usize,
    tspec: *const c_char,
    tspeclen: usize,
    core: *const c_char,
    corelen: usize,
    opt: *const c_char,
    optlen: usize,
    snap: *const c_char,
    snaplen: usize,
) -> *mut c_void {
    // SAFETY: the caller guarantees the buffers; the C++ side copies them.
    unsafe {
        ffi::hydra_snapshot_store_new(
            nz(pspec, pspeclen),
            pspeclen,
            nz(cspec, cspeclen),
            cspeclen,
            nz(tspec, tspeclen),
            tspeclen,
            nz(core, corelen),
            corelen,
            nz(opt, optlen),
            optlen,
            nz(snap, snaplen),
            snaplen,
        )
    }
}

/// A pointer the C++ side may read `len` bytes from (a dangling one when `len` is 0).
fn nz(p: *const c_char, len: usize) -> *const c_char {
    if len == 0 || p.is_null() {
        c"".as_ptr()
    } else {
        p
    }
}

/// Adds one answer: `query` is the packed query payload, `resp` the complete response;
/// `scope` (the packed entry address of a function) is empty for an answer every function shares.
/// Returns 0, or 1 on failure.
///
/// # Safety
/// `h` must be a live store handle; every buffer must be valid for reads of its length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_store_put(
    h: *mut c_void,
    scope: *const c_char,
    scopelen: usize,
    query: *const c_char,
    querylen: usize,
    resp: *const c_char,
    resplen: usize,
) -> c_int {
    if h.is_null() {
        return 1;
    }
    // SAFETY: the caller guarantees the handle and the buffers; the C++ side copies them.
    unsafe {
        ffi::hydra_snapshot_store_put(
            h,
            nz(scope, scopelen),
            scopelen,
            nz(query, querylen),
            querylen,
            nz(resp, resplen),
            resplen,
        )
    }
}

/// Number of answers and their bytes.
///
/// # Safety
/// `h` must be a live store handle; `count` and `bytes` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_store_stats(h: *mut c_void, count: *mut u64, bytes: *mut u64) {
    // SAFETY: guaranteed by the caller.
    unsafe { ffi::hydra_snapshot_store_stats(h, count, bytes) }
}

/// Releases the caller's handle. Workers drop their Architectures for the store at their next
/// job; the store itself is freed with the last of them.
///
/// # Safety
/// `h` must be a live store handle, closed once, with no decompile using it still running.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_store_close(h: *mut c_void) {
    if !h.is_null() {
        // SAFETY: guaranteed by the caller.
        unsafe { ffi::hydra_snapshot_store_close(h) }
    }
}

/// Raw pointers moved into a pool job (the caller blocks until the job is done).
struct Job {
    h: *mut c_void,
    addr: *const c_char,
    addrlen: usize,
    out: *mut *mut c_char,
    outlen: *mut usize,
    misses: *mut *mut c_char,
    misseslen: *mut usize,
    answered: *mut u64,
}

// SAFETY: the pointers are only used by the one worker running the job while the caller waits.
unsafe impl Send for Job {}

impl Job {
    /// # Safety
    /// The pointers must be valid as [`hydra_dhost_decompile`] requires.
    unsafe fn run(&self) -> c_int {
        // SAFETY: forwarded from the caller's guarantees.
        unsafe {
            ffi::hydra_snapshot_decompile(
                self.h,
                self.addr,
                self.addrlen,
                self.out,
                self.outlen,
                self.misses,
                self.misseslen,
                self.answered,
            )
        }
    }
}

/// Decompiles the function whose packed entry address is `addr` (the `decompileAt` parameter)
/// on a worker of the pool; the calling thread blocks until it is done. Returns [`OK`] with the
/// command response in `*out`, [`MISSES`] with the missed queries in `*misses` (records of a u32
/// little-endian length and the bytes: each query payload, then the answer fed for it, empty when
/// an exception ended the run) and the command response of the run in `*out` when it went to its
/// end, [`FAILED`] or [`CRASHED`] with a message in `*out`, or
/// [`NOT_STARTED`]. `*answered` receives the number of queries the store answered.
///
/// # Safety
/// `h` must be a live store handle; `addr` valid for `addrlen` bytes; every out-pointer writable.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn hydra_dhost_decompile(
    h: *mut c_void,
    addr: *const c_char,
    addrlen: usize,
    out: *mut *mut c_char,
    outlen: *mut usize,
    misses: *mut *mut c_char,
    misseslen: *mut usize,
    answered: *mut u64,
) -> c_int {
    // SAFETY: the out-pointers are writable (caller guarantee).
    unsafe {
        *out = std::ptr::null_mut();
        *outlen = 0;
        *misses = std::ptr::null_mut();
        *misseslen = 0;
        *answered = 0;
    }
    let Some(Ok(pool)) = POOL.get() else {
        return NOT_STARTED;
    };
    if h.is_null() {
        return FAILED;
    }
    let job = Job {
        h,
        addr: nz(addr, addrlen),
        addrlen,
        out,
        outlen,
        misses,
        misseslen,
        answered,
    };
    // SAFETY: the job's pointers stay valid while install() blocks this thread.
    pool.install(move || unsafe { job.run() })
}

/// Frees a buffer returned by [`hydra_dhost_decompile`].
///
/// # Safety
/// `p` must come from this library and be freed once (null is ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_free(p: *mut c_char) {
    if !p.is_null() {
        // SAFETY: allocated by the C++ side with malloc.
        unsafe { ffi::hydra_snapshot_free(p) }
    }
}

/// Drops the Architectures every pool worker holds (for tests and shutdown).
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_release_workers() {
    if let Some(Ok(pool)) = POOL.get() {
        // SAFETY: no arguments; acts on the calling worker's thread_local cache only.
        pool.broadcast(|_| unsafe { ffi::hydra_snapshot_release_thread() });
    }
}

/// Splits the `misses` buffer of [`hydra_dhost_decompile`] into its records: for each miss the
/// query payload, then the answer the run was fed for it (empty when an exception ended the run).
pub fn split_misses(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let n = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + n > buf.len() {
            break;
        }
        v.push(buf[i..i + n].to_vec());
        i += n;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_misses() {
        let mut b = Vec::new();
        for p in [&b"ab"[..], &b""[..], &b"xyz"[..]] {
            b.extend_from_slice(&(p.len() as u32).to_le_bytes());
            b.extend_from_slice(p);
        }
        assert_eq!(
            split_misses(&b),
            vec![b"ab".to_vec(), Vec::new(), b"xyz".to_vec()]
        );
        assert!(split_misses(&[1, 0]).is_empty());
    }

    #[test]
    fn decompile_refuses_before_start() {
        // No unit test starts the pool (the integration test does, in its own process).
        if POOL.get().is_some() {
            return;
        }
        let (mut out, mut outlen, mut m, mut ml, mut a) = (
            std::ptr::null_mut(),
            0usize,
            std::ptr::null_mut(),
            0usize,
            0u64,
        );
        // SAFETY: valid out-pointers; the null handle is refused.
        let rc = unsafe {
            hydra_dhost_decompile(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                &mut out,
                &mut outlen,
                &mut m,
                &mut ml,
                &mut a,
            )
        };
        assert_eq!(rc, NOT_STARTED);
    }
}
