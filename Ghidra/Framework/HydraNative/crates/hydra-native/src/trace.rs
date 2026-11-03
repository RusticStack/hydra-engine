//! The C ABI of the semantic trace: one call per `trace_*` command, request bytes in and reply
//! bytes out, both JSON (see `include/hydra_native.h`). The work is in the `hydra-trace` crate's
//! `Service`; this file is the pointer handling only.

use hydra_trace::route::{Built, Ctx, Lane, Outcome, Router, Symbols};
use hydra_trace::service::Service;
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The call succeeded and the reply is in `out`.
pub const TRACE_OK: i32 = 0;
/// A required pointer was null.
pub const TRACE_ERR_NULL: i32 = -1;
/// The root or the command is not UTF-8.
pub const TRACE_ERR_UTF8: i32 = -3;
/// `hydra_trace_init` with a root different from the one in use.
pub const TRACE_ERR_STATE: i32 = -4;
/// `out_cap` is too small; `*out_len` is the size needed.
pub const TRACE_ERR_BUFFER: i32 = -5;
/// A Rust panic was caught inside the call; nothing was written to `out`.
pub const TRACE_ERR_PANIC: i32 = -6;

static SERVICE: OnceLock<(PathBuf, Service)> = OnceLock::new();
static ROUTER: OnceLock<Router> = OnceLock::new();

fn router() -> &'static Router {
    ROUTER.get_or_init(Router::new)
}

thread_local! {
    /// The last reply of this thread, kept when it did not fit the caller's buffer.
    static KEPT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// # Safety
/// `p` must be valid for `len` bytes when `len > 0`.
unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        // SAFETY: guaranteed by the caller.
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

fn default_root() -> PathBuf {
    std::env::var_os("HYDRA_TRACE_ROOT").map_or_else(|| PathBuf::from("traces"), PathBuf::from)
}

/// Sizes the trace's worker threads from this process's CPU grants, once.
fn size_workers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let info = crate::HydraCpuInfo::detect(None);
        hydra_trace::workers::configure(
            info.compute_threads as usize,
            info.background_threads as usize,
        );
    });
}

fn service() -> &'static Service {
    size_workers();
    &SERVICE
        .get_or_init(|| {
            let root = default_root();
            let svc = Service::new(root.clone());
            (root, svc)
        })
        .1
}

/// Sets the directory sessions live in (optional, before the first request).
///
/// # Safety
/// `root` must be valid for `root_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_init(root: *const u8, root_len: usize) -> i32 {
    crate::guard(TRACE_ERR_PANIC, || {
        if root.is_null() {
            return TRACE_ERR_NULL;
        }
        // SAFETY: guaranteed by the caller.
        let Ok(text) = std::str::from_utf8(unsafe { bytes(root, root_len) }) else {
            return TRACE_ERR_UTF8;
        };
        let path = PathBuf::from(text);
        size_workers();
        let set = SERVICE.get_or_init(|| (path.clone(), Service::new(path.clone())));
        if set.0 == path {
            TRACE_OK
        } else {
            TRACE_ERR_STATE
        }
    })
}

/// Runs one trace command.
///
/// # Safety
/// `cmd` valid for `cmd_len` bytes; `req` valid for `req_len` bytes (may be null when 0);
/// `out` valid for `out_cap` bytes (may be null when 0); `out_len` valid for one `usize` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_request(
    cmd: *const u8,
    cmd_len: usize,
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    crate::guard(TRACE_ERR_PANIC, || {
        if cmd.is_null() || out_len.is_null() || (req.is_null() && req_len > 0) {
            return TRACE_ERR_NULL;
        }
        // SAFETY: guaranteed by the caller.
        let (cmd, req) = unsafe { (bytes(cmd, cmd_len), bytes(req, req_len)) };
        let Ok(cmd) = std::str::from_utf8(cmd) else {
            return TRACE_ERR_UTF8;
        };
        let reply = service().handle(cmd, req);
        // SAFETY: out_len is valid for a write; out is valid for out_cap bytes (the caller's promise).
        unsafe { deliver(reply, out, out_cap, out_len) }
    })
}

/// Writes `reply` to `out` or keeps it on this thread when it does not fit.
///
/// # Safety
/// `out` valid for `out_cap` bytes (may be null when 0); `out_len` valid for one `usize` write.
unsafe fn deliver(reply: Vec<u8>, out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {
    // SAFETY: out_len is valid for a write.
    unsafe { *out_len = reply.len() };
    if reply.len() > out_cap || (out.is_null() && !reply.is_empty()) {
        KEPT.with(|k| *k.borrow_mut() = Some(reply));
        return TRACE_ERR_BUFFER;
    }
    if !reply.is_empty() {
        // SAFETY: out is valid for out_cap >= reply.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(reply.as_ptr(), out, reply.len()) };
    }
    KEPT.with(|k| *k.borrow_mut() = None);
    TRACE_OK
}

/// Copies the reply kept by a `TRACE_ERR_BUFFER` call on this thread.
///
/// # Safety
/// `out` valid for `out_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_reply_copy(out: *mut u8, out_cap: usize) -> i64 {
    crate::guard(-1, || {
        KEPT.with(|k| {
            let mut kept = k.borrow_mut();
            match kept.as_ref() {
                Some(r) if r.len() <= out_cap && !out.is_null() => {
                    // SAFETY: out is valid for out_cap >= r.len() bytes.
                    unsafe { std::ptr::copy_nonoverlapping(r.as_ptr(), out, r.len()) };
                    let n = r.len() as i64;
                    *kept = None;
                    n
                }
                _ => -1,
            }
        })
    })
}

fn install_cancel(flag: *const i32) {
    if flag.is_null() {
        hydra_trace::cancel::set(None);
        return;
    }
    let addr = flag as usize;
    hydra_trace::cancel::set(Some(Box::new(move || {
        // SAFETY: the caller keeps the flag valid until it is removed (see the callers).
        unsafe { std::ptr::read_volatile(addr as *const i32) != 0 }
    })));
}

fn install_progress(cell: *mut i64) {
    if cell.is_null() {
        hydra_trace::cancel::set_progress(None);
        return;
    }
    let addr = cell as usize;
    hydra_trace::cancel::set_progress(Some(Box::new(move |done, total| {
        let p = addr as *mut i64;
        // SAFETY: the caller keeps the cell valid until it is removed (see the callers).
        unsafe {
            std::ptr::write_volatile(p.add(1), total as i64);
            std::ptr::write_volatile(p, done as i64);
        }
    })));
}

/// Installs the cancel flag of the next requests on this thread: a native `int32` the caller sets
/// non-zero to cancel; `hydra_trace_request` stops `trace_export` and `trace_resymbolize` at the
/// next check and answers `cancelled`. `NULL` removes it. The flag must stay valid until removed.
///
/// # Safety
/// `flag` is null or valid for reads of one `i32` until it is removed on this thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_set_cancel(flag: *const i32) {
    crate::guard((), || {
        install_cancel(flag);
    })
}

/// Installs a progress cell for the next requests on this thread: two native `int64` the long
/// commands write `(done, total)` into (total 0 when unknown); the caller reads them from another
/// thread. `NULL` removes it. The cell must stay valid until removed.
///
/// # Safety
/// `cell` is null or valid for writes of two `i64` until it is removed on this thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_set_progress(cell: *mut i64) {
    crate::guard((), || {
        install_progress(cell);
    })
}

// ---- the router: validation, lanes, the writer lease, request shaping and reply wrapping ------

/// The kind of a `hydra_trace_route` outcome: the reply is the client's result.
pub const ROUTE_REPLY: i32 = 0;
/// A refusal; the bytes are `{"code","message"[,"details"]}`.
pub const ROUTE_ERROR: i32 = 1;
/// The request needs disk room the caller's headroom did not show; the bytes are
/// `{"estimate":n,"what":".."}`.
pub const ROUTE_DISK: i32 = 2;
/// The symbol callback failed; the caller holds the reason.
pub const ROUTE_CALLBACK: i32 = 3;
/// `hydra_trace_route` flag: the connection speaks protocol 3.
pub const ROUTE_V3: u32 = 1;
/// `hydra_trace_route` flag: only validate the request (a preflight), run nothing.
pub const ROUTE_CHECK_ONLY: u32 = 2;

type SymbolsBuild = unsafe extern "C" fn(*const u8, usize, i64) -> i64;
type SymbolsCopy = unsafe extern "C" fn(*mut u8, usize);

static SYMBOLS: OnceLock<(SymbolsBuild, SymbolsCopy)> = OnceLock::new();

/// Registers the function-table callbacks (once): `build(session, session_len, revision)` builds
/// the table of the request's program on the calling thread and returns the size of its payload
/// (`{"symbols":{..},"summary":{..}}`), or a negative number when it failed; `copy(out, n)` then
/// copies the payload.
///
/// # Safety
/// Both functions must stay valid for the life of the process and be callable from any thread
/// that calls `hydra_trace_route`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_set_symbols(build: SymbolsBuild, copy: SymbolsCopy) {
    crate::guard((), || {
        let _ = SYMBOLS.set((build, copy));
    })
}

struct CSymbols;

impl Symbols for CSymbols {
    fn build(&self, session: &str, revision: u64) -> Option<Built> {
        let (build, copy) = SYMBOLS.get()?;
        // SAFETY: session is a live string; the callback was registered as valid.
        let n = unsafe { build(session.as_ptr(), session.len(), revision as i64) };
        if n < 0 {
            return None;
        }
        let mut buf = vec![0u8; n as usize];
        // SAFETY: buf is valid for n bytes.
        unsafe { copy(buf.as_mut_ptr(), buf.len()) };
        Built::from_payload(&buf)
    }
}

/// Sets `trace.quickMB` and `trace.quotaMB` (before the first route).
#[unsafe(no_mangle)]
pub extern "C" fn hydra_trace_configure(quick_mb: u64, quota_mb: u64) {
    crate::guard((), || {
        router().configure(quick_mb, quota_mb);
    })
}

/// The lane of a command: 0 quick, 1 long, 2 depends on the request (given none; `trace_diff` and
/// `trace_relations`), -1 a bad argument.
///
/// # Safety
/// `cmd` valid for `cmd_len` bytes; `req` valid for `req_len` bytes (may be null when 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_lane(
    cmd: *const u8,
    cmd_len: usize,
    req: *const u8,
    req_len: usize,
) -> i32 {
    crate::guard(-1, || {
        if cmd.is_null() || (req.is_null() && req_len > 0) {
            return -1;
        }
        // SAFETY: guaranteed by the caller.
        let (cmd, req) = unsafe { (bytes(cmd, cmd_len), bytes(req, req_len)) };
        let Ok(cmd) = std::str::from_utf8(cmd) else {
            return -1;
        };
        let request = if req_len == 0 { None } else { Some(req) };
        // the lane of a diff reads the store's indexes: the root in use, or the default one, without
        // starting the service
        let root = SERVICE
            .get()
            .map_or_else(default_root, |(root, _)| root.clone());
        match router().lane(&root, cmd, request) {
            Lane::Quick => 0,
            Lane::Long => 1,
            Lane::Dynamic => 2,
        }
    })
}

/// A connection is ending: a writer lease it holds counts as orphaned from now.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_trace_client_leaving(client: u64) {
    crate::guard((), || {
        router().client_leaving(client);
    })
}

/// A connection ended: every writer lease it held is orphaned.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_trace_client_gone(client: u64) {
    crate::guard((), || {
        router().client_gone(client);
    })
}

/// How many sessions have a writer lease record in memory.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_trace_lease_count() -> i64 {
    crate::guard(0, || router().lease_count() as i64)
}

/// Removes the cancel flag and the progress cell of this thread when a route ends.
struct Armed;

impl Drop for Armed {
    fn drop(&mut self) {
        install_cancel(std::ptr::null());
        install_progress(std::ptr::null_mut());
    }
}

/// Runs one trace command for a connection: validation, the writer lease, request shaping, the
/// engine call and reply wrapping, with the cancel flag and progress cell installed for the call.
/// Returns the same codes as `hydra_trace_request`; `*kind` says what the bytes are
/// (`ROUTE_REPLY`, `ROUTE_ERROR`, `ROUTE_DISK`, `ROUTE_CALLBACK`).
///
/// # Safety
/// `label` valid for `label_len` bytes (may be null when 0), `cmd` for `cmd_len`, `req` for
/// `req_len`; `cancel` null or valid for reads of one `i32` and `progress` null or valid for
/// writes of two `i64` for the duration of the call; `out` valid for `out_cap` bytes (may be null
/// when 0); `out_len` and `kind` valid for one write each.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn hydra_trace_route(
    client: u64,
    label: *const u8,
    label_len: usize,
    flags: u32,
    headroom: i64,
    cmd: *const u8,
    cmd_len: usize,
    req: *const u8,
    req_len: usize,
    cancel: *const i32,
    progress: *mut i64,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    kind: *mut i32,
) -> i32 {
    crate::guard(TRACE_ERR_PANIC, || {
        if cmd.is_null()
            || out_len.is_null()
            || kind.is_null()
            || (req.is_null() && req_len > 0)
            || (label.is_null() && label_len > 0)
        {
            return TRACE_ERR_NULL;
        }
        // SAFETY: guaranteed by the caller.
        let (cmd, req, label) = unsafe {
            (
                bytes(cmd, cmd_len),
                bytes(req, req_len),
                bytes(label, label_len),
            )
        };
        let (Ok(cmd), Ok(label)) = (std::str::from_utf8(cmd), std::str::from_utf8(label)) else {
            return TRACE_ERR_UTF8;
        };
        let _armed = Armed;
        install_cancel(cancel);
        install_progress(progress);
        let (k, reply) = if flags & ROUTE_CHECK_ONLY != 0 {
            match router().check(cmd, req) {
                Some(e) => (ROUTE_ERROR, e.json()),
                None => (ROUTE_REPLY, Vec::new()),
            }
        } else {
            let ctx = Ctx {
                client,
                label,
                v3: flags & ROUTE_V3 != 0,
                headroom,
            };
            match router().route(service(), &ctx, cmd, req, &CSymbols) {
                Outcome::Reply(b) => (ROUTE_REPLY, b),
                Outcome::Error(e) => (ROUTE_ERROR, e.json()),
                Outcome::Disk { estimate, what } => {
                    (ROUTE_DISK, hydra_trace::route::disk_json(estimate, &what))
                }
                Outcome::Callback => (ROUTE_CALLBACK, Vec::new()),
            }
        };
        // SAFETY: kind is valid for a write.
        unsafe { *kind = k };
        // SAFETY: out_len is valid for a write; out is valid for out_cap bytes.
        unsafe { deliver(reply, out, out_cap, out_len) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(cmd: &str, req: &str, cap: usize) -> (i32, Vec<u8>, usize) {
        let mut out = vec![0u8; cap];
        let mut len = 0usize;
        // SAFETY: all pointers come from live Rust values of the stated sizes.
        let rc = unsafe {
            hydra_trace_request(
                cmd.as_ptr(),
                cmd.len(),
                req.as_ptr(),
                req.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };
        out.truncate(if rc == TRACE_OK { len } else { 0 });
        (rc, out, len)
    }

    fn route(
        client: u64,
        flags: u32,
        headroom: i64,
        cmd: &str,
        req: &str,
        cap: usize,
    ) -> (i32, i32, Vec<u8>) {
        let mut out = vec![0u8; cap];
        let mut len = 0usize;
        let mut kind = -1i32;
        let label = b"agent-x";
        // SAFETY: all pointers come from live Rust values of the stated sizes; no cancel flag, no
        // progress cell.
        let rc = unsafe {
            hydra_trace_route(
                client,
                label.as_ptr(),
                label.len(),
                flags,
                headroom,
                cmd.as_ptr(),
                cmd.len(),
                req.as_ptr(),
                req.len(),
                std::ptr::null(),
                std::ptr::null_mut(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                &mut kind,
            )
        };
        if rc == TRACE_OK {
            out.truncate(len);
        } else if rc == TRACE_ERR_BUFFER {
            out = vec![0u8; len];
            // SAFETY: out is valid for len bytes.
            let n = unsafe { hydra_trace_reply_copy(out.as_mut_ptr(), out.len()) };
            assert_eq!(n as usize, len);
        }
        (rc, kind, out)
    }

    #[test]
    fn every_command_round_trips_through_the_c_abi() {
        let dir = std::env::temp_dir().join(format!("hydra-native-trace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.to_str().unwrap();
        // SAFETY: root is a live string.
        let first = unsafe { hydra_trace_init(root.as_ptr(), root.len()) };
        assert_eq!(first, TRACE_OK);
        // SAFETY: a live 5 byte string, a different root.
        let other = unsafe { hydra_trace_init(b"other".as_ptr(), 5) };
        assert_eq!(other, TRACE_ERR_STATE);
        // SAFETY: a null root is refused before it is read.
        let null = unsafe { hydra_trace_init(std::ptr::null(), 0) };
        assert_eq!(null, TRACE_ERR_NULL);

        let ok = |cmd: &str, req: &str| -> serde_json::Value {
            let (rc, out, _) = call(cmd, req, 1 << 20);
            assert_eq!(rc, TRACE_OK, "{cmd}");
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(v["ok"], true, "{cmd}: {v}");
            v
        };
        ok("trace_open", r#"{"session":"abi"}"#);
        let ev = r#"{"kind":"core.marker","source_id":"p","source_seq":0,"producer_gen":1,"clock_domain":"c","t_mono_ns":1,"confidence":"exact","payload":{"corr":"x"}}"#;
        assert_eq!(
            ok(
                "trace_append",
                &format!(r#"{{"session":"abi","events":[{ev}]}}"#)
            )["accepted"],
            1
        );
        ok("trace_mark", r#"{"session":"abi","label":"m"}"#);
        let q = ok("trace_query", r#"{"session":"abi"}"#);
        let id = q["rows"][0]["event_id"].as_str().unwrap().to_string();
        ok(
            "trace_explain",
            &format!(r#"{{"session":"abi","event_id":"{id}"}}"#),
        );
        ok(
            "trace_check",
            r#"{"session":"abi","assertions":[{"type":"cardinality","name":"c","kind":"core.marker","min":1,"max":5}]}"#,
        );
        ok("trace_info", r#"{"session":"abi"}"#);
        ok("trace_list", "");
        ok("trace_diff", r#"{"a":"abi","b":"abi"}"#);
        let out = dir.join("exp");
        ok(
            "trace_export",
            &format!(
                r#"{{"session":"abi","out":{}}}"#,
                serde_json::to_string(out.to_str().unwrap()).unwrap()
            ),
        );
        ok(
            "trace_resymbolize",
            r#"{"session":"abi","symbols":{"modules":{}},"symbol_revision":"r"}"#,
        );
        ok("trace_relations", r#"{"session":"abi"}"#);
        ok(
            "trace_reprocess",
            r#"{"session":"abi","codecs":{"a":{"name":"m","fields":[]}},"contexts":[{"from_seq":0,"layout":"a"}]}"#,
        );
        ok("trace_close", r#"{"session":"abi"}"#);

        // The router: validation, the lease, lanes, disk questions and wrapped replies.
        let (rc, kind, bytes) = route(
            7,
            ROUTE_V3,
            i64::MAX,
            "trace_open",
            r#"{"session":"rt","create":true}"#,
            1 << 16,
        );
        assert_eq!((rc, kind), (TRACE_OK, ROUTE_REPLY));
        let opened: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(opened["lease"]["holder"], "agent-x");
        assert!(opened.get("ok").is_none());
        let cap = opened["lease"]["cap"].as_str().unwrap().to_string();
        let mark = format!(r#"{{"session":"rt","cap":"{cap}","label":"m"}}"#);
        let (_, kind, _) = route(7, ROUTE_V3, i64::MAX, "trace_mark", &mark, 1 << 16);
        assert_eq!(kind, ROUTE_REPLY);
        let (_, kind, bytes) = route(8, ROUTE_V3, i64::MAX, "trace_mark", &mark, 1 << 16);
        assert_eq!(kind, ROUTE_ERROR);
        let e: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(e["code"], "not_owner");
        // a preflight validates without running
        let (_, kind, bytes) = route(
            0,
            ROUTE_V3 | ROUTE_CHECK_ONLY,
            i64::MAX,
            "trace_mark",
            r#"{"session":"rt"}"#,
            4096,
        );
        assert_eq!(kind, ROUTE_ERROR);
        assert!(String::from_utf8_lossy(&bytes).contains("missing field: cap"));
        let (_, kind, bytes) = route(
            0,
            ROUTE_V3 | ROUTE_CHECK_ONLY,
            i64::MAX,
            "trace_info",
            r#"{"session":"rt"}"#,
            4096,
        );
        assert_eq!((kind, bytes.len()), (ROUTE_REPLY, 0));
        // not enough room is a question for the caller
        let (_, kind, bytes) = route(7, ROUTE_V3, 1, "trace_mark", &mark, 4096);
        assert_eq!(kind, ROUTE_DISK);
        assert!(String::from_utf8_lossy(&bytes).contains("\"estimate\""));
        // a reply bigger than the buffer is kept for the retry
        let (rc, kind, bytes) = route(7, ROUTE_V3, i64::MAX, "trace_list", "{}", 4);
        assert_eq!((rc, kind), (TRACE_ERR_BUFFER, ROUTE_REPLY));
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_ok());
        // protocol 2 connections get no trace commands
        let (_, kind, bytes) = route(7, 0, i64::MAX, "trace_list", "{}", 4096);
        assert_eq!(kind, ROUTE_ERROR);
        assert!(String::from_utf8_lossy(&bytes).contains("unknown_command"));
        // lanes
        // SAFETY: live strings.
        let lane = |c: &str, r: &str| unsafe {
            hydra_trace_lane(c.as_ptr(), c.len(), r.as_ptr(), r.len())
        };
        assert_eq!(lane("trace_query", ""), 0);
        assert_eq!(lane("trace_export", ""), 1);
        assert_eq!(lane("trace_diff", ""), 2);
        assert_eq!(
            lane("trace_diff", r#"{"a":"x","b":"y","background":true}"#),
            1
        );
        // the lease follows the connection
        assert_eq!(hydra_trace_lease_count(), 1);
        hydra_trace_client_gone(7);
        let (_, _, bytes) = route(
            8,
            ROUTE_V3,
            i64::MAX,
            "trace_info",
            r#"{"session":"rt"}"#,
            1 << 16,
        );
        assert!(String::from_utf8_lossy(&bytes).contains("\"state\":\"orphan\""));

        // Errors are replies, not crashes.
        let (rc, out, _) = call("trace_nope", "{}", 4096);
        assert_eq!(rc, TRACE_OK);
        assert!(String::from_utf8_lossy(&out).contains("unknown_command"));
        let (rc, out, _) = call("trace_info", "{broken", 4096);
        assert_eq!(rc, TRACE_OK);
        assert!(String::from_utf8_lossy(&out).contains("bad_request"));

        // A small buffer reports the size needed and keeps the reply for the retry.
        let (rc, _, needed) = call("trace_list", "{}", 4);
        assert_eq!(rc, TRACE_ERR_BUFFER);
        assert!(needed > 4);
        let mut big = vec![0u8; needed];
        // SAFETY: big is valid for needed bytes.
        let n = unsafe { hydra_trace_reply_copy(big.as_mut_ptr(), big.len()) };
        assert_eq!(n as usize, needed);
        assert!(serde_json::from_slice::<serde_json::Value>(&big).is_ok());
        // SAFETY: big is still valid; nothing is kept any more.
        let again = unsafe { hydra_trace_reply_copy(big.as_mut_ptr(), big.len()) };
        assert_eq!(again, -1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_set_cancel_flag_stops_an_export() {
        let dir = std::env::temp_dir().join(format!("hydra-native-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let svc = hydra_trace::service::Service::new(&dir);
        let r = svc.handle("trace_open", br#"{"session":"c"}"#);
        assert!(String::from_utf8_lossy(&r).contains("\"ok\":true"));
        let flag = Box::new(1i32);
        // SAFETY: the flag outlives the request and is removed below.
        unsafe { hydra_trace_set_cancel(&*flag) };
        let out = dir.join("exp");
        let req = format!(
            r#"{{"session":"c","out":{}}}"#,
            serde_json::to_string(out.to_str().unwrap()).unwrap()
        );
        let reply = String::from_utf8(svc.handle("trace_export", req.as_bytes())).unwrap();
        // SAFETY: removing the flag.
        unsafe { hydra_trace_set_cancel(std::ptr::null()) };
        assert!(reply.contains("cancelled"), "{reply}");
        assert!(!out.exists());
        let again = String::from_utf8(svc.handle("trace_export", req.as_bytes())).unwrap();
        assert!(again.contains("\"ok\":true"), "{again}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn null_pointers_are_refused() {
        let mut len = 0usize;
        // SAFETY: null command pointer is the case under test; no other pointer is read.
        let rc = unsafe {
            hydra_trace_request(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        assert_eq!(rc, TRACE_ERR_NULL);
    }
}
