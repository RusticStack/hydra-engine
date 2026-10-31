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
pub const ABI_VERSION: c_int = 3;

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
        pub fn hydra_snapshot_store_put_bulk(
            h: *mut c_void,
            blob: *const c_char,
            len: usize,
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

static POOL: OnceLock<Result<std::sync::Arc<crate::workers::Pool>, String>> = OnceLock::new();

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
        // Deep recursion in the C++ passes; give workers more than the default 2 MB. Jobs go
        // to workers by store affinity (workers.rs), so Architectures follow real concurrency.
        crate::workers::Pool::new(n, 16 << 20)
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

/// Adds the answers of one packed block: for each answer a record of a little-endian u32 length
/// and the bytes, three times (scope, query, response). One call per function instead of one per
/// answer: the Java exporter builds the block in one buffer. Returns 0, or 1 on failure.
///
/// # Safety
/// `h` must be a live store handle; `blob` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_store_put_bulk(
    h: *mut c_void,
    blob: *const c_char,
    len: usize,
) -> c_int {
    if h.is_null() {
        return 1;
    }
    // SAFETY: the caller guarantees the handle and the buffer; the C++ side copies the records.
    unsafe { ffi::hydra_snapshot_store_put_bulk(h, nz(blob, len), len) }
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
        if let Some(Ok(pool)) = POOL.get() {
            pool.forget(h as usize);
        }
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
    // SAFETY: the job's pointers stay valid while install_for() blocks this thread.
    pool.install_for(h as usize, move || unsafe { job.run() })
        .unwrap_or(FAILED)
}

// ---- asynchronous submission (ABI 3) --------------------------------------------------------
//
// `hydra_dhost_submit` queues a decompile on the pool and returns at once; the finished run is
// posted to one completion queue that a single caller thread drains with
// `hydra_dhost_completions` (a blocking downcall with a timeout). No caller thread waits per
// request, and nothing calls back into the JVM (plain downcalls only). The number of runs queued
// or running is bounded: a submit over the bound is refused with [`BUSY`].

/// [`hydra_dhost_submit`]: the bounded queue is full (nothing was queued).
pub const BUSY: c_int = 4;

/// One finished run, as [`hydra_dhost_completions`] writes it (48 bytes, C layout). The fields are
/// those of [`hydra_dhost_decompile`]; `out` and `misses` are freed with [`hydra_dhost_free`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Completion {
    /// The caller's ticket from [`hydra_dhost_submit`].
    pub ticket: u64,
    /// The command response or message (may be null).
    pub out: *mut c_char,
    /// Bytes at `out`.
    pub outlen: u64,
    /// The missed queries and the answers fed for them (may be null).
    pub misses: *mut c_char,
    /// Bytes at `misses`.
    pub misseslen: u64,
    /// Queries the store answered.
    pub answered: u32,
    /// The status, as [`hydra_dhost_decompile`] returns it.
    pub rc: c_int,
}

// SAFETY: the buffers are owned by the completion until the caller takes them.
unsafe impl Send for Completion {}

struct Completions {
    done: std::sync::Mutex<std::collections::VecDeque<Completion>>,
    ready: std::sync::Condvar,
    /// Runs queued or running (submitted, not yet posted).
    inflight: std::sync::atomic::AtomicUsize,
}

static COMPLETIONS: Completions = Completions {
    done: std::sync::Mutex::new(std::collections::VecDeque::new()),
    ready: std::sync::Condvar::new(),
    inflight: std::sync::atomic::AtomicUsize::new(0),
};

/// Runs that may be queued or running at once: 8 per worker (0 before a successful start).
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_queue_capacity() -> c_int {
    (pool_threads() * 8) as c_int
}

fn post(c: Completion) {
    let mut q = COMPLETIONS
        .done
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    q.push_back(c);
    COMPLETIONS
        .inflight
        .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    drop(q);
    COMPLETIONS.ready.notify_one();
}

/// Store handle moved into a pool job.
struct StoreRef(*mut c_void);
// SAFETY: the store is thread-safe for decompiles; the caller keeps it open until the
// completion of every run submitted on it has been taken.
unsafe impl Send for StoreRef {}

/// Queues a decompile of the function whose packed entry address is `addr` on store `h` and
/// returns at once: 0 when queued (its [`Completion`], carrying `ticket`, is posted when the run
/// ends), [`BUSY`] when [`hydra_dhost_queue_capacity`] runs are already queued or running,
/// [`FAILED`] for a null store, [`NOT_STARTED`]. `addr` is copied.
///
/// # Safety
/// `h` must be a live store handle that stays open until this run's completion has been taken;
/// `addr` valid for `addrlen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_submit(
    h: *mut c_void,
    addr: *const c_char,
    addrlen: usize,
    ticket: u64,
) -> c_int {
    use std::sync::atomic::Ordering;
    let Some(Ok(pool)) = POOL.get() else {
        return NOT_STARTED;
    };
    if h.is_null() {
        return FAILED;
    }
    let cap = pool.current_num_threads() * 8;
    if COMPLETIONS
        .inflight
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < cap).then_some(n + 1)
        })
        .is_err()
    {
        return BUSY;
    }
    let a: Vec<u8> = if addrlen == 0 || addr.is_null() {
        Vec::new()
    } else {
        // SAFETY: valid for addrlen bytes (caller guarantee); copied before returning.
        unsafe { std::slice::from_raw_parts(addr.cast::<u8>(), addrlen) }.to_vec()
    };
    let store = StoreRef(h);
    pool.spawn_for(h as usize, move || {
        let store = store;
        let mut c = Completion {
            ticket,
            out: std::ptr::null_mut(),
            outlen: 0,
            misses: std::ptr::null_mut(),
            misseslen: 0,
            answered: 0,
            rc: FAILED,
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (mut out, mut outlen, mut miss, mut misslen, mut answered) = (
                std::ptr::null_mut(),
                0usize,
                std::ptr::null_mut(),
                0usize,
                0u64,
            );
            let p = if a.is_empty() {
                c"".as_ptr()
            } else {
                a.as_ptr().cast()
            };
            // SAFETY: the store is open (caller guarantee), the out-pointers are locals.
            let rc = unsafe {
                ffi::hydra_snapshot_decompile(
                    store.0,
                    p,
                    a.len(),
                    &mut out,
                    &mut outlen,
                    &mut miss,
                    &mut misslen,
                    &mut answered,
                )
            };
            (rc, out, outlen, miss, misslen, answered)
        }));
        if let Ok((rc, out, outlen, miss, misslen, answered)) = r {
            c.rc = rc;
            c.out = out;
            c.outlen = outlen as u64;
            c.misses = miss;
            c.misseslen = misslen as u64;
            c.answered = answered.min(u32::MAX as u64) as u32;
        }
        post(c);
    });
    OK
}

/// Takes up to `max` finished runs into `buf`, waiting up to `timeout_ms` milliseconds (negative:
/// no limit) for the first. Returns how many were written (0 on timeout).
///
/// # Safety
/// `buf` must be writable for `max` [`Completion`]s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_completions(
    buf: *mut Completion,
    max: usize,
    timeout_ms: i64,
) -> c_int {
    if buf.is_null() || max == 0 {
        return 0;
    }
    let mut q = COMPLETIONS
        .done
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if q.is_empty() {
        if timeout_ms < 0 {
            while q.is_empty() {
                q = COMPLETIONS
                    .ready
                    .wait(q)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        } else {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
            while q.is_empty() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return 0;
                }
                q = COMPLETIONS
                    .ready
                    .wait_timeout(q, deadline - now)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
        }
    }
    let n = q.len().min(max).min(c_int::MAX as usize);
    for i in 0..n {
        let c = q.pop_front().expect("n <= len");
        // SAFETY: buf is writable for max >= n entries (caller guarantee).
        unsafe { buf.add(i).write(c) };
    }
    n as c_int
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
        pool.broadcast(|| unsafe { ffi::hydra_snapshot_release_thread() });
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
