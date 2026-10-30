//! The read plane: immutable per-program-state tables that answer the daemon's most frequent
//! read commands with reply bytes rendered in Rust, without Java objects per row.
//!
//! The first table is the function listing (command `functions`, hotspot H1 of the Rust plan). Java
//! exports one program state once, in bulk (names and entries as UTF-8 arenas, sizes and flags as
//! arrays), and Rust keeps every row pre-rendered as the JSON object Gson writes for it
//! (`{"name":..,"address":..,"size":..,"thunk":..,"external":..}`, Gson's escaping with HTML
//! escaping off). A page is then a copy of a contiguous run of row bytes (no filter) or a scan of
//! the names with a substring finder (`contains`), wrapped in the reply's fixed frame. A table never
//! changes after it is built: any number of threads read it at once with no lock, and Java frees it
//! when the program state it describes is gone.
//!
//! Byte identity with the Java path is the contract. Names are UTF-8 as `String.getBytes(UTF_8)`
//! gives them; a `contains` match on UTF-8 bytes is the same as Java's `String.contains` on UTF-16
//! for valid text (UTF-8 is self-synchronising), and Java keeps names with unpaired surrogates (or
//! a `contains` argument with one) on its own path.

use std::ptr;
use std::slice;

/// The version of the read-plane C ABI (`hydra_rp_*`); separate from [`crate::ABI_VERSION`] so the
/// CPU part's callers are unaffected.
pub const RP_ABI_VERSION: u32 = 1;

/// Row flag: the function is a thunk.
pub const THUNK: u8 = 1;
/// Row flag: the function is external.
pub const EXTERNAL: u8 = 2;

/// One program state's function listing, rows in `getFunctions(true)` order.
pub struct FunctionTable {
    /// Every row's JSON object, back to back.
    rows: Vec<u8>,
    /// `rows[row_start[i]..row_start[i + 1]]` is row `i`; `n + 1` entries.
    row_start: Vec<usize>,
    /// Every name's UTF-8, back to back (the `contains` scan).
    names: Vec<u8>,
    /// `names[name_start[i]..name_start[i + 1]]` is the name of row `i`; `n + 1` entries.
    name_start: Vec<usize>,
}

/// Appends `s` as a JSON string the way Gson's `JsonWriter` writes it with HTML escaping off:
/// `"` and `\` escaped, `\t \b \n \r \f` by name, other controls below 0x20 as `\u00xx`, and
/// U+2028 / U+2029 as ` ` / ` `; everything else as is.
pub fn push_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let b = s.as_bytes();
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let rep: Option<&[u8]> = match c {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            b'\t' => Some(b"\\t"),
            0x08 => Some(b"\\b"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            0x0c => Some(b"\\f"),
            // U+2028 and U+2029 are E2 80 A8 / E2 80 A9
            0xE2 if i + 2 < b.len()
                && b[i + 1] == 0x80
                && (b[i + 2] == 0xA8 || b[i + 2] == 0xA9) =>
            {
                Some(if b[i + 2] == 0xA8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                })
            }
            _ => None,
        };
        if let Some(r) = rep {
            out.extend_from_slice(&b[last..i]);
            out.extend_from_slice(r);
            i += if c == 0xE2 { 3 } else { 1 };
            last = i;
        } else if c < 0x20 {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(&b[last..i]);
            out.extend_from_slice(b"\\u00");
            out.push(HEX[(c >> 4) as usize]);
            out.push(HEX[(c & 15) as usize]);
            i += 1;
            last = i;
        } else {
            i += 1;
        }
    }
    out.extend_from_slice(&b[last..]);
    out.push(b'"');
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    let mut buf = [0u8; 20];
    let mut n = v.unsigned_abs();
    let mut k = buf.len();
    loop {
        k -= 1;
        buf[k] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if v < 0 {
        out.push(b'-');
    }
    out.extend_from_slice(&buf[k..]);
}

impl FunctionTable {
    /// Builds the table from its rows; `None` when a name or entry is not UTF-8.
    pub fn new<'a>(
        names: impl ExactSizeIterator<Item = &'a [u8]>,
        entries: impl ExactSizeIterator<Item = &'a [u8]>,
        sizes: &[i64],
        flags: &[u8],
    ) -> Option<FunctionTable> {
        let n = names.len();
        if entries.len() != n || sizes.len() != n || flags.len() != n {
            return None;
        }
        let mut t = FunctionTable {
            rows: Vec::with_capacity(n * 96),
            row_start: Vec::with_capacity(n + 1),
            names: Vec::with_capacity(n * 24),
            name_start: Vec::with_capacity(n + 1),
        };
        t.row_start.push(0);
        t.name_start.push(0);
        for (i, (name, entry)) in names.zip(entries).enumerate() {
            let name = std::str::from_utf8(name).ok()?;
            let entry = std::str::from_utf8(entry).ok()?;
            t.names.extend_from_slice(name.as_bytes());
            t.name_start.push(t.names.len());
            let r = &mut t.rows;
            r.extend_from_slice(b"{\"name\":");
            push_json_string(r, name);
            r.extend_from_slice(b",\"address\":");
            push_json_string(r, entry);
            r.extend_from_slice(b",\"size\":");
            push_i64(r, sizes[i]);
            r.extend_from_slice(b",\"thunk\":");
            r.extend_from_slice(if flags[i] & THUNK != 0 {
                b"true"
            } else {
                b"false"
            });
            r.extend_from_slice(b",\"external\":");
            r.extend_from_slice(if flags[i] & EXTERNAL != 0 {
                b"true"
            } else {
                b"false"
            });
            r.push(b'}');
            t.row_start.push(r.len());
        }
        t.rows.shrink_to_fit();
        t.names.shrink_to_fit();
        Some(t)
    }

    pub fn len(&self) -> usize {
        self.row_start.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes held (the budget weight Java accounts for).
    pub fn weight(&self) -> usize {
        self.rows.capacity() + self.names.capacity() + 16 * self.row_start.capacity() + 64
    }

    fn row(&self, i: usize) -> &[u8] {
        &self.rows[self.row_start[i]..self.row_start[i + 1]]
    }

    fn name(&self, i: usize) -> &[u8] {
        &self.names[self.name_start[i]..self.name_start[i + 1]]
    }

    /// Writes the reply of `functions` (the `result` object) for these arguments into `out`
    /// (cleared first): `{"functions":[rows],"offset":o,"returned":r,"truncated":t}`, as Java's
    /// walk gives it. `contains`, when given, keeps the rows whose name contains it.
    pub fn page(&self, contains: Option<&[u8]>, offset: usize, limit: usize, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(b"{\"functions\":[");
        let n = self.len();
        let mut returned = 0usize;
        let truncated;
        match contains {
            None => {
                let start = offset.min(n);
                let end = start.saturating_add(limit).min(n);
                if end > start {
                    let a = self.row_start[start];
                    let b = self.row_start[end];
                    out.reserve(b - a + (end - start) + 64);
                    for i in start..end {
                        if i > start {
                            out.push(b',');
                        }
                        out.extend_from_slice(self.row(i));
                    }
                }
                returned = end - start;
                truncated = n - start > limit;
            }
            Some(needle) => {
                let finder = Finder::new(needle);
                let mut seen = 0usize;
                let mut cut = false;
                for i in 0..n {
                    if !finder.matches(self.name(i)) {
                        continue;
                    }
                    let k = seen;
                    seen += 1;
                    if k < offset {
                        continue;
                    }
                    if returned >= limit {
                        cut = true;
                        break;
                    }
                    if returned > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(self.row(i));
                    returned += 1;
                }
                truncated = cut;
            }
        }
        out.extend_from_slice(b"],\"offset\":");
        push_i64(out, offset as i64);
        out.extend_from_slice(b",\"returned\":");
        push_i64(out, returned as i64);
        out.extend_from_slice(b",\"truncated\":");
        out.extend_from_slice(if truncated { b"true" } else { b"false" });
        out.push(b'}');
    }
}

/// A substring test on bytes: first-byte scan (`memchr`-style, auto-vectorised by the compiler on
/// the slice search) and a compare of the rest; the empty needle matches everything, as
/// `String.contains("")` does.
struct Finder<'a> {
    needle: &'a [u8],
}

impl<'a> Finder<'a> {
    fn new(needle: &'a [u8]) -> Self {
        Finder { needle }
    }

    #[inline]
    fn matches(&self, hay: &[u8]) -> bool {
        let nd = self.needle;
        if nd.is_empty() {
            return true;
        }
        if nd.len() > hay.len() {
            return false;
        }
        let first = nd[0];
        let rest = &nd[1..];
        let last_start = hay.len() - nd.len();
        let mut from = 0;
        while from <= last_start {
            match hay[from..=last_start].iter().position(|&c| c == first) {
                None => return false,
                Some(p) => {
                    let at = from + p;
                    if &hay[at + 1..at + nd.len()] == rest {
                        return true;
                    }
                    from = at + 1;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------- C ABI

/// The read-plane ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_rp_abi_version() -> u32 {
    RP_ABI_VERSION
}

/// Builds a function table of `n` rows. `names`/`entries` are UTF-8 arenas and
/// `name_ends`/`entry_ends` the end offset of each row's bytes in them (`n` each); `sizes` and
/// `flags` have `n` entries. Returns the table, or null when an argument is null or not UTF-8.
/// Free it with [`hydra_rp_ft_free`].
///
/// # Safety
/// Every pointer must be valid for the lengths given; the arenas must hold at least the last end
/// offset bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_rp_ft_new(
    n: u32,
    names: *const u8,
    names_len: u64,
    name_ends: *const u32,
    entries: *const u8,
    entries_len: u64,
    entry_ends: *const u32,
    sizes: *const i64,
    flags: *const u8,
) -> *mut FunctionTable {
    let n = n as usize;
    if n > 0
        && (names.is_null()
            || name_ends.is_null()
            || entries.is_null()
            || entry_ends.is_null()
            || sizes.is_null()
            || flags.is_null())
    {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees each pointer is valid for its length (null only when n == 0
    // and the length is 0, where an empty slice is made instead).
    let (na, ne, ea, ee, sz, fl) = unsafe {
        (
            slice_or_empty(names, names_len as usize),
            slice_or_empty(name_ends, n),
            slice_or_empty(entries, entries_len as usize),
            slice_or_empty(entry_ends, n),
            slice_or_empty(sizes, n),
            slice_or_empty(flags, n),
        )
    };
    let Some(ni) = arena_iter(na, ne) else {
        return ptr::null_mut();
    };
    let Some(ei) = arena_iter(ea, ee) else {
        return ptr::null_mut();
    };
    match FunctionTable::new(ni, ei, sz, fl) {
        Some(t) => Box::into_raw(Box::new(t)),
        None => ptr::null_mut(),
    }
}

/// # Safety
/// `p` must be valid for `len` elements, or `len` is 0.
unsafe fn slice_or_empty<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 || p.is_null() {
        &[]
    } else {
        // SAFETY: guaranteed by the caller.
        unsafe { slice::from_raw_parts(p, len) }
    }
}

/// The slices of an arena cut at `ends`; `None` when an end runs backwards or past the arena.
fn arena_iter<'a>(
    arena: &'a [u8],
    ends: &'a [u32],
) -> Option<impl ExactSizeIterator<Item = &'a [u8]>> {
    let mut prev = 0u32;
    for &e in ends {
        if e < prev || e as usize > arena.len() {
            return None;
        }
        prev = e;
    }
    Some((0..ends.len()).map(move |i| {
        let a = if i == 0 { 0 } else { ends[i - 1] as usize };
        &arena[a..ends[i] as usize]
    }))
}

/// Rows in the table.
///
/// # Safety
/// `t` must come from [`hydra_rp_ft_new`] and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_rp_ft_len(t: *const FunctionTable) -> u64 {
    // SAFETY: guaranteed by the caller.
    unsafe { t.as_ref() }.map_or(0, |t| t.len() as u64)
}

/// Bytes held by the table.
///
/// # Safety
/// As [`hydra_rp_ft_len`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_rp_ft_weight(t: *const FunctionTable) -> u64 {
    // SAFETY: guaranteed by the caller.
    unsafe { t.as_ref() }.map_or(0, |t| t.weight() as u64)
}

/// The last render of this thread, and the request it answers when it did not fit the caller's
/// buffer (the retry then only copies).
struct PageBuf {
    buf: Vec<u8>,
    pending: Option<(usize, Vec<u8>, bool, u64, u64)>,
}

thread_local! {
    static PAGE: std::cell::RefCell<PageBuf> =
        const { std::cell::RefCell::new(PageBuf { buf: Vec::new(), pending: None }) };
}

/// Renders the `functions` result for (`contains`, `offset`, `limit`) and copies it into
/// `out[..out_cap]`. Returns the reply's length: when it is larger than `out_cap` nothing usable
/// was written and the caller calls again, on the same thread, with a buffer that large; that
/// second call for the same table and arguments only copies the render kept by the first.
/// `contains` is null for no filter. Returns -1 on a null table.
///
/// # Safety
/// `t` as [`hydra_rp_ft_len`]; `contains` valid for `contains_len` bytes when not null; `out`
/// valid for `out_cap` bytes when `out_cap > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_rp_ft_page(
    t: *const FunctionTable,
    contains: *const u8,
    contains_len: u64,
    offset: u64,
    limit: u64,
    out: *mut u8,
    out_cap: u64,
) -> i64 {
    // SAFETY: guaranteed by the caller.
    let Some(t) = (unsafe { t.as_ref() }) else {
        return -1;
    };
    let needle = if contains.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        Some(unsafe { slice_or_empty(contains, contains_len as usize) })
    };
    let key = (
        t as *const FunctionTable as usize,
        needle.map_or_else(Vec::new, <[u8]>::to_vec),
        needle.is_some(),
        offset,
        limit,
    );
    PAGE.with(|cell| {
        let mut pb = cell.borrow_mut();
        let pb = &mut *pb;
        if pb.pending.take().as_ref() != Some(&key) {
            t.page(needle, offset as usize, limit as usize, &mut pb.buf);
        }
        let len = pb.buf.len();
        if len as u64 <= out_cap && !out.is_null() {
            // SAFETY: out is valid for out_cap >= len bytes.
            unsafe { ptr::copy_nonoverlapping(pb.buf.as_ptr(), out, len) };
        } else {
            pb.pending = Some(key);
            return len as i64; // kept for the retry
        }
        if pb.buf.capacity() > (8 << 20) {
            // do not keep a huge one-off page alive on this thread
            pb.buf = Vec::new();
        }
        len as i64
    })
}

/// Frees a table.
///
/// # Safety
/// `t` must come from [`hydra_rp_ft_new`] and not be used afterwards (null is ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_rp_ft_free(t: *mut FunctionTable) {
    if !t.is_null() {
        // SAFETY: t came from Box::into_raw in hydra_rp_ft_new.
        drop(unsafe { Box::from_raw(t) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &[(&str, &str, i64, u8)]) -> FunctionTable {
        let names: Vec<&[u8]> = rows.iter().map(|r| r.0.as_bytes()).collect();
        let entries: Vec<&[u8]> = rows.iter().map(|r| r.1.as_bytes()).collect();
        let sizes: Vec<i64> = rows.iter().map(|r| r.2).collect();
        let flags: Vec<u8> = rows.iter().map(|r| r.3).collect();
        FunctionTable::new(names.into_iter(), entries.into_iter(), &sizes, &flags).unwrap()
    }

    fn page(t: &FunctionTable, c: Option<&str>, o: usize, l: usize) -> String {
        let mut v = Vec::new();
        t.page(c.map(str::as_bytes), o, l, &mut v);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn escapes_like_gson() {
        let mut v = Vec::new();
        push_json_string(
            &mut v,
            "a\"b\\c\td\u{8}e\nf\rg\u{c}h\u{1}i\u{1f}j\u{7f}k<>&='\u{2028}\u{2029}\u{e9}\u{1F600}",
        );
        assert_eq!(
            String::from_utf8(v).unwrap(),
            "\"a\\\"b\\\\c\\td\\be\\nf\\rg\\fh\\u0001i\\u001fj\u{7f}k<>&='\\u2028\\u2029\u{e9}\u{1F600}\""
        );
    }

    #[test]
    fn retry_copies_the_kept_render() {
        let t = table(&[("alpha", "00401000", 4, 0), ("beta", "00401010", 8, 1)]);
        let want = page(&t, Some("a"), 0, 10);
        let tp: *const FunctionTable = &t;
        let mut small = [0u8; 4];
        // SAFETY: t outlives the calls; buffers valid for their lengths.
        let len = unsafe { hydra_rp_ft_page(tp, b"a".as_ptr(), 1, 0, 10, small.as_mut_ptr(), 4) };
        assert_eq!(len as usize, want.len());
        assert!(
            PAGE.with(|c| c.borrow().pending.is_some()),
            "the render is kept"
        );
        let mut out = vec![0u8; len as usize];
        // SAFETY: as above.
        let l2 =
            unsafe { hydra_rp_ft_page(tp, b"a".as_ptr(), 1, 0, 10, out.as_mut_ptr(), len as u64) };
        assert_eq!(l2, len);
        assert_eq!(String::from_utf8(out).unwrap(), want);
        assert!(
            PAGE.with(|c| c.borrow().pending.is_none()),
            "the retry consumed it"
        );
        // another request after a miss renders afresh
        // SAFETY: as above.
        unsafe { hydra_rp_ft_page(tp, ptr::null(), 0, 0, 10, small.as_mut_ptr(), 4) };
        let mut o3 = vec![0u8; 4096];
        // SAFETY: as above.
        let l3 = unsafe { hydra_rp_ft_page(tp, b"a".as_ptr(), 1, 1, 10, o3.as_mut_ptr(), 4096) };
        assert_eq!(&o3[..l3 as usize], page(&t, Some("a"), 1, 10).as_bytes());
    }

    #[test]
    fn pages_like_the_walk() {
        let t = table(&[
            ("FUN_1", "00401000", 10, 0),
            ("thunk_x", "00401010", 1, THUNK),
            ("ext::f", "EXTERNAL:00000001", 1, EXTERNAL),
        ]);
        assert_eq!(
            page(&t, None, 0, 2),
            "{\"functions\":[{\"name\":\"FUN_1\",\"address\":\"00401000\",\"size\":10,\"thunk\":false,\"external\":false},\
             {\"name\":\"thunk_x\",\"address\":\"00401010\",\"size\":1,\"thunk\":true,\"external\":false}],\
             \"offset\":0,\"returned\":2,\"truncated\":true}"
        );
        assert_eq!(
            page(&t, None, 3, 5),
            "{\"functions\":[],\"offset\":3,\"returned\":0,\"truncated\":false}"
        );
        assert_eq!(
            page(&t, None, 9, 5),
            "{\"functions\":[],\"offset\":9,\"returned\":0,\"truncated\":false}"
        );
        assert!(page(&t, None, 2, 1).ends_with("\"offset\":2,\"returned\":1,\"truncated\":false}"));
        // contains: offset counts matches, truncated only when a further match exists
        assert!(page(&t, Some("x"), 0, 1).ends_with("\"returned\":1,\"truncated\":true}"));
        assert!(page(&t, Some("x"), 1, 1).contains("ext::f"));
        assert!(page(&t, Some("x"), 1, 1).ends_with("\"returned\":1,\"truncated\":false}"));
        assert!(page(&t, Some(""), 0, 10).ends_with("\"returned\":3,\"truncated\":false}"));
        assert!(page(&t, Some("zz"), 0, 10).starts_with("{\"functions\":[],"));
    }

    #[test]
    fn finder() {
        let f = Finder::new(b"aab");
        assert!(f.matches(b"xaaab"));
        assert!(!f.matches(b"aa"));
        assert!(!f.matches(b"abab"));
        assert!(Finder::new(b"b").matches(b"ab"));
    }

    #[test]
    fn c_abi_round_trip() {
        let names = b"ab\"c";
        let entries = b"0001EXTERNAL:2";
        // SAFETY: every pointer is to a live local of the length given.
        let t = unsafe {
            hydra_rp_ft_new(
                2,
                names.as_ptr(),
                4,
                [2u32, 4].as_ptr(),
                entries.as_ptr(),
                14,
                [4u32, 14].as_ptr(),
                [5i64, -1].as_ptr(),
                [0u8, 3].as_ptr(),
            )
        };
        assert!(!t.is_null());
        let mut out = [0u8; 16];
        // SAFETY: every pointer is to a live local of the length given.
        let need = unsafe { hydra_rp_ft_page(t, ptr::null(), 0, 0, 10, out.as_mut_ptr(), 16) };
        assert!(need > 16);
        let mut big = vec![0u8; need as usize];
        // SAFETY: every pointer is to a live local of the length given.
        let got =
            unsafe { hydra_rp_ft_page(t, ptr::null(), 0, 0, 10, big.as_mut_ptr(), need as u64) };
        assert_eq!(got, need);
        let s = String::from_utf8(big).unwrap();
        assert!(s.contains("{\"name\":\"\\\"c\",\"address\":\"EXTERNAL:2\",\"size\":-1,\"thunk\":true,\"external\":true}"));
        // bad arena ends
        // SAFETY: every pointer is to a live local of the length given.
        let bad = unsafe {
            hydra_rp_ft_new(
                1,
                names.as_ptr(),
                4,
                [9u32].as_ptr(),
                entries.as_ptr(),
                14,
                [4u32].as_ptr(),
                [5i64].as_ptr(),
                [0u8].as_ptr(),
            )
        };
        assert!(bad.is_null());
        // SAFETY: every pointer is to a live local of the length given.
        unsafe { hydra_rp_ft_free(t) };
    }
}
