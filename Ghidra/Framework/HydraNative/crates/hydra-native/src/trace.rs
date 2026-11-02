//! The C ABI of the semantic trace: one call per `trace_*` command, request bytes in and reply
//! bytes out, both JSON (see `include/hydra_native.h`). The work is in the `hydra-trace` crate's
//! `Service`; this file is the pointer handling only.

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

static SERVICE: OnceLock<(PathBuf, Service)> = OnceLock::new();

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
    if cmd.is_null() || out_len.is_null() || (req.is_null() && req_len > 0) {
        return TRACE_ERR_NULL;
    }
    // SAFETY: guaranteed by the caller.
    let (cmd, req) = unsafe { (bytes(cmd, cmd_len), bytes(req, req_len)) };
    let Ok(cmd) = std::str::from_utf8(cmd) else {
        return TRACE_ERR_UTF8;
    };
    let reply = service().handle(cmd, req);
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
}

/// Installs the cancel flag of the next requests on this thread: a native `int32` the caller sets
/// non-zero to cancel; `hydra_trace_request` stops `trace_export` and `trace_resymbolize` at the
/// next check and answers `cancelled`. `NULL` removes it. The flag must stay valid until removed.
///
/// # Safety
/// `flag` is null or valid for reads of one `i32` until it is removed on this thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_set_cancel(flag: *const i32) {
    if flag.is_null() {
        hydra_trace::cancel::set(None);
        return;
    }
    let addr = flag as usize;
    hydra_trace::cancel::set(Some(Box::new(move || {
        // SAFETY: the caller keeps the flag valid until it is removed (see above).
        unsafe { std::ptr::read_volatile(addr as *const i32) != 0 }
    })));
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
        ok("trace_close", r#"{"session":"abi"}"#);

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
