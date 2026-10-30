//! C ABI over [`Snapshot`](crate::Snapshot). Every function is safe to call from any number of
//! threads at once on the same handle (reads take `&Snapshot`); only `hysnap_close` must not race
//! with other calls on that handle.

use std::ffi::{CStr, c_char};
use std::slice;

use crate::{ReadRequest, Snapshot};

/// Open and validate a snapshot. `path` is a NUL-terminated UTF-8 path. Returns null on any error.
///
/// # Safety
/// `path` must point to a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_open(path: *const c_char) -> *mut Snapshot {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
        return std::ptr::null_mut();
    };
    match Snapshot::open(path) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close a handle from `hysnap_open` (null is ignored).
///
/// # Safety
/// `handle` must come from `hysnap_open` and not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_close(handle: *mut Snapshot) {
    if !handle.is_null() {
        // SAFETY: guaranteed by the caller, see the function's "Safety" section.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// The generation (program modification number) of the snapshot.
///
/// # Safety
/// `handle` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_generation(handle: *const Snapshot) -> u64 {
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    unsafe { &*handle }.generation()
}

/// The index of the address space named by `name[0..len]` (UTF-8), or -1.
///
/// # Safety
/// `handle` must be live; `name` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_space_index(
    handle: *const Snapshot,
    name: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let snap = unsafe { &*handle };
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let Ok(name) = std::str::from_utf8(unsafe { slice::from_raw_parts(name, len) }) else {
        return -1;
    };
    snap.space_index(name).map_or(-1, |i| i as i32)
}

/// Copy `len` bytes at `offset` in `space` to `out`. Returns 1 if served, 0 if the snapshot does
/// not hold the whole range (the caller then reads through the program database).
///
/// # Safety
/// `handle` must be live; `out` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_read(
    handle: *const Snapshot,
    space: u32,
    offset: u64,
    len: usize,
    out: *mut u8,
) -> i32 {
    if len == 0 || out.is_null() {
        return 0;
    }
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let snap = unsafe { &*handle };
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let out = unsafe { slice::from_raw_parts_mut(out, len) };
    snap.read(space, offset, out) as i32
}

/// Serve `count` requests into `out[0..out_len]`, setting each request's `served`. Returns the
/// number served.
///
/// # Safety
/// `handle` must be live; `requests` must point to `count` requests; `out` to `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hysnap_read_bulk(
    handle: *const Snapshot,
    requests: *mut ReadRequest,
    count: usize,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if requests.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let snap = unsafe { &*handle };
    // SAFETY: guaranteed by the caller, see the function's "Safety" section.
    let requests = unsafe { slice::from_raw_parts_mut(requests, count) };
    let out: &mut [u8] = if out.is_null() {
        &mut []
    } else {
        // SAFETY: guaranteed by the caller, see the function's "Safety" section.
        unsafe { slice::from_raw_parts_mut(out, out_len) }
    };
    snap.read_bulk(requests, out)
}
