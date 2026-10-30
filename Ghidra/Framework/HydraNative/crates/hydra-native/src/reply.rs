//! Daemon reply encoding off the JVM: JSON writers whose output is byte-identical to what the
//! HeadlessSession daemon's Gson (`disableHtmlEscaping().serializeNulls()`) writes for the same
//! values, so a large reply part is written straight into a native buffer from columnar data
//! instead of being built as a tree of Java objects and then serialized.
//!
//! Gson's string rules (`JsonWriter.string`, not HTML-safe): `"` and `\` are escaped with a
//! backslash; `\t`, `\b`, `\n`, `\r` and `\f` get their short forms; every other code unit below
//! U+0020 becomes `\u00xx` (lowercase hex); U+2028 and U+2029 become ` ` and ` `;
//! everything else (U+007F and all other non-ASCII) is written as is. The input here is UTF-8 that
//! Java produced with `String.getBytes(UTF_8)`, which is also what the daemon's
//! `OutputStreamWriter(UTF_8)` writes for the same string (an unpaired surrogate becomes `?` in
//! both), so escaping the UTF-8 bytes gives the bytes the daemon would send.

/// The output buffer was too small: nothing useful was written.
pub const ERR_SPACE: i64 = -1;
/// A null pointer, a negative count, or offsets that are not monotonic or out of range.
pub const ERR_ARGS: i64 = -2;
/// An index is outside `0..n`.
pub const ERR_INDEX: i64 = -3;

/// The escape of each ASCII byte: 0 = none, `b'u'` = `\u00xx`, else the short escape letter.
const ESC: [u8; 128] = {
    let mut t = [0u8; 128];
    let mut i = 0;
    while i < 0x20 {
        t[i] = b'u';
        i += 1;
    }
    t[b'"' as usize] = b'"';
    t[b'\\' as usize] = b'\\';
    t[b'\t' as usize] = b't';
    t[0x08] = b'b';
    t[b'\n' as usize] = b'n';
    t[b'\r' as usize] = b'r';
    t[0x0c] = b'f';
    t
};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A bounded writer over a caller's buffer; every write fails once it would overflow.
pub struct Sink<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

/// The buffer is full.
#[derive(Debug, PartialEq, Eq)]
pub struct Full;

impl<'a> Sink<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Sink { buf, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    #[inline]
    pub fn put(&mut self, b: &[u8]) -> Result<(), Full> {
        let end = self.pos.checked_add(b.len()).ok_or(Full)?;
        if end > self.buf.len() {
            return Err(Full);
        }
        self.buf[self.pos..end].copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    #[inline]
    fn byte(&mut self, b: u8) -> Result<(), Full> {
        if self.pos >= self.buf.len() {
            return Err(Full);
        }
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }

    /// `v` as Java's `Long.toString`.
    pub fn long(&mut self, v: i64) -> Result<(), Full> {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let neg = v < 0;
        let mut u = v.unsigned_abs();
        loop {
            i -= 1;
            tmp[i] = b'0' + (u % 10) as u8;
            u /= 10;
            if u == 0 {
                break;
            }
        }
        if neg {
            self.byte(b'-')?;
        }
        self.put(&tmp[i..])
    }

    pub fn boolean(&mut self, v: bool) -> Result<(), Full> {
        self.put(if v { b"true" } else { b"false" })
    }

    /// `s` (UTF-8) as a quoted JSON string, escaped as Gson does.
    pub fn string(&mut self, s: &[u8]) -> Result<(), Full> {
        self.byte(b'"')?;
        let mut run = 0; // start of the bytes not yet copied
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            if c < 0x80 {
                let e = ESC[c as usize];
                if e == 0 {
                    i += 1;
                    continue;
                }
                self.put(&s[run..i])?;
                if e == b'u' {
                    self.put(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(c >> 4) as usize],
                        HEX[(c & 15) as usize],
                    ])?;
                } else {
                    self.put(&[b'\\', e])?;
                }
                i += 1;
                run = i;
            } else if c == 0xE2
                && i + 2 < s.len()
                && s[i + 1] == 0x80
                && (s[i + 2] == 0xA8 || s[i + 2] == 0xA9)
            {
                self.put(&s[run..i])?;
                self.put(if s[i + 2] == 0xA8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                })?;
                i += 3;
                run = i;
            } else {
                i += 1;
            }
        }
        self.put(&s[run..])?;
        self.byte(b'"')
    }
}

/// The most bytes [`Sink::string`] writes for `n` input bytes (every byte as `\u00xx`, plus quotes).
pub const fn string_bound(n: usize) -> usize {
    n.saturating_mul(6).saturating_add(2)
}

/// One column of strings: `bytes[off[i]..off[i + 1]]` is string `i`.
pub struct Strings<'a> {
    pub bytes: &'a [u8],
    pub off: &'a [i32],
}

impl Strings<'_> {
    fn get(&self, i: usize) -> Option<&[u8]> {
        let a = usize::try_from(*self.off.get(i)?).ok()?;
        let b = usize::try_from(*self.off.get(i + 1)?).ok()?;
        self.bytes.get(a..b)
    }
}

/// The function listing columns (`FunctionIndex.Snapshot` in HeadlessSession).
pub struct FunctionRows<'a> {
    pub names: Strings<'a>,
    pub addresses: Strings<'a>,
    pub sizes: &'a [i64],
    /// bit 0: thunk, bit 1: external
    pub flags: &'a [u8],
}

/// What went wrong writing rows.
#[derive(Debug, PartialEq, Eq)]
pub enum RowsError {
    Full,
    Index,
}

impl From<Full> for RowsError {
    fn from(_: Full) -> Self {
        RowsError::Full
    }
}

impl FunctionRows<'_> {
    fn n(&self) -> usize {
        self.sizes.len()
    }

    /// Writes row `i` as the daemon's
    /// `{"name":…,"address":…,"size":…,"thunk":…,"external":…}`.
    pub fn row(&self, out: &mut Sink<'_>, i: usize) -> Result<(), RowsError> {
        if i >= self.n() {
            return Err(RowsError::Index);
        }
        let name = self.names.get(i).ok_or(RowsError::Index)?;
        let addr = self.addresses.get(i).ok_or(RowsError::Index)?;
        out.put(b"{\"name\":")?;
        out.string(name)?;
        out.put(b",\"address\":")?;
        out.string(addr)?;
        out.put(b",\"size\":")?;
        out.long(self.sizes[i])?;
        out.put(b",\"thunk\":")?;
        out.boolean(self.flags[i] & 1 != 0)?;
        out.put(b",\"external\":")?;
        out.boolean(self.flags[i] & 2 != 0)?;
        out.put(b"}")?;
        Ok(())
    }

    /// Writes the JSON array of the rows `rows` yields.
    pub fn array(
        &self,
        out: &mut Sink<'_>,
        rows: impl Iterator<Item = usize>,
    ) -> Result<(), RowsError> {
        out.put(b"[")?;
        let mut first = true;
        for i in rows {
            if !first {
                out.put(b",")?;
            }
            first = false;
            self.row(out, i)?;
        }
        out.put(b"]")?;
        Ok(())
    }
}

/// # Safety
/// `p` must be null or valid for reads of `n` values of `T`.
unsafe fn slice<'a, T>(p: *const T, n: i64) -> Option<&'a [T]> {
    let n = usize::try_from(n).ok()?;
    if n == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `p` is valid for `n` reads.
    Some(unsafe { std::slice::from_raw_parts(p, n) })
}

/// Writes the JSON array of function rows `idx[0..nidx]` (or `from..to` when `idx` is null) of a
/// listing of `n` functions into `out` (`cap` bytes) and returns the number of bytes written, or
/// [`ERR_SPACE`], [`ERR_ARGS`] or [`ERR_INDEX`].
///
/// The columns: `names`/`addrs` are UTF-8 arenas of `name_off[n]`/`addr_off[n]` bytes, with string
/// `i` at `off[i]..off[i + 1]` (`n + 1` offsets each); `sizes` and `flags` (bit 0 thunk, bit 1
/// external) have `n` values. Each row is the daemon's
/// `{"name":…,"address":…,"size":…,"thunk":…,"external":…}`, byte-identical to its Gson output.
///
/// # Safety
/// Every pointer must be valid for the reads (or, for `out`, the writes) its count describes, and
/// `out` must not overlap the inputs.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn hydra_reply_function_rows(
    names: *const u8,
    name_off: *const i32,
    addrs: *const u8,
    addr_off: *const i32,
    sizes: *const i64,
    flags: *const u8,
    n: i64,
    idx: *const i32,
    nidx: i64,
    from: i64,
    to: i64,
    out: *mut u8,
    cap: i64,
) -> i64 {
    // SAFETY: the caller's contract above, for each slice.
    let cols = unsafe {
        (|| {
            let name_off = slice(name_off, n.checked_add(1)?)?;
            let addr_off = slice(addr_off, n.checked_add(1)?)?;
            let names = slice(names, i64::from(*name_off.last()?))?;
            let addrs = slice(addrs, i64::from(*addr_off.last()?))?;
            Some(FunctionRows {
                names: Strings {
                    bytes: names,
                    off: name_off,
                },
                addresses: Strings {
                    bytes: addrs,
                    off: addr_off,
                },
                sizes: slice(sizes, n)?,
                flags: slice(flags, n)?,
            })
        })()
    };
    let Some(cols) = cols else { return ERR_ARGS };
    let Ok(cap) = usize::try_from(cap) else {
        return ERR_ARGS;
    };
    if out.is_null() || cap == 0 {
        return ERR_ARGS;
    }
    // SAFETY: the caller guarantees `out` is valid for `cap` writes and overlaps no input.
    let buf = unsafe { std::slice::from_raw_parts_mut(out, cap) };
    let mut sink = Sink::new(buf);
    let r = if idx.is_null() {
        if from < 0 || to < from || to > n {
            return ERR_ARGS;
        }
        cols.array(&mut sink, (from as usize)..(to as usize))
    } else {
        // SAFETY: the caller guarantees `idx` is valid for `nidx` reads.
        let Some(ix) = (unsafe { slice(idx, nidx) }) else {
            return ERR_ARGS;
        };
        if ix.iter().any(|&i| i < 0) {
            return ERR_INDEX;
        }
        cols.array(&mut sink, ix.iter().map(|&i| i as usize))
    };
    match r {
        Ok(()) => sink.len() as i64,
        Err(RowsError::Full) => ERR_SPACE,
        Err(RowsError::Index) => ERR_INDEX,
    }
}

/// Writes `src` (`len` bytes of UTF-8) as a quoted JSON string escaped as the daemon's Gson does
/// into `out` (`cap` bytes, at least `6 * len + 2` is always enough) and returns the bytes written,
/// or [`ERR_SPACE`] / [`ERR_ARGS`].
///
/// # Safety
/// `src` must be valid for `len` reads and `out` for `cap` writes; they must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_reply_json_string(
    src: *const u8,
    len: i64,
    out: *mut u8,
    cap: i64,
) -> i64 {
    // SAFETY: the caller's contract.
    let Some(s) = (unsafe { slice(src, len) }) else {
        return ERR_ARGS;
    };
    let Ok(cap) = usize::try_from(cap) else {
        return ERR_ARGS;
    };
    if out.is_null() || cap == 0 {
        return ERR_ARGS;
    }
    // SAFETY: the caller's contract.
    let buf = unsafe { std::slice::from_raw_parts_mut(out, cap) };
    let mut sink = Sink::new(buf);
    match sink.string(s) {
        Ok(()) => sink.len() as i64,
        Err(Full) => ERR_SPACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(s: &str) -> String {
        let mut buf = vec![0u8; string_bound(s.len())];
        let mut k = Sink::new(&mut buf);
        k.string(s.as_bytes()).unwrap();
        let n = k.len();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    /// Expected values are Gson 2.13.2's `toJson` with `disableHtmlEscaping()`.
    #[test]
    fn strings_escape_as_gson() {
        assert_eq!(esc(""), r#""""#);
        assert_eq!(esc("plain FUN_00401000"), r#""plain FUN_00401000""#);
        assert_eq!(esc("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(esc("\t\u{8}\n\r\u{c}"), r#""\t\b\n\r\f""#);
        assert_eq!(
            esc("\u{0}\u{1}\u{1f}\u{b}"),
            r#""\u0000\u0001\u001f\u000b""#
        );
        assert_eq!(esc("<>&='\u{7f}"), "\"<>&='\u{7f}\"");
        assert_eq!(
            esc("x\u{2028}y\u{2029}z\u{2027}"),
            "\"x\\u2028y\\u2029z\u{2027}\""
        );
        assert_eq!(esc("aé中😀"), "\"aé中😀\"");
    }

    #[test]
    fn longs_print_as_java() {
        for v in [0i64, 1, -1, 42, 1 << 40, i64::MAX, i64::MIN] {
            let mut buf = [0u8; 24];
            let mut k = Sink::new(&mut buf);
            k.long(v).unwrap();
            let n = k.len();
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), v.to_string());
        }
    }

    #[allow(clippy::type_complexity)]
    fn table() -> (Vec<u8>, Vec<i32>, Vec<u8>, Vec<i32>, Vec<i64>, Vec<u8>) {
        let names = ["main", "a\"q", "ns::f\u{2028}"];
        let addrs = ["00401000", "00401010", "EXTERNAL:00000001"];
        let mut nb = Vec::new();
        let mut no = vec![0];
        for s in names {
            nb.extend_from_slice(s.as_bytes());
            no.push(nb.len() as i32);
        }
        let mut ab = Vec::new();
        let mut ao = vec![0];
        for s in addrs {
            ab.extend_from_slice(s.as_bytes());
            ao.push(ab.len() as i32);
        }
        (nb, no, ab, ao, vec![16, 0, -3], vec![0, 1, 3])
    }

    fn call(idx: Option<&[i32]>, from: i64, to: i64, cap: usize) -> Result<String, i64> {
        let (nb, no, ab, ao, sz, fl) = table();
        let mut out = vec![0u8; cap];
        // SAFETY: every pointer and count comes from the vectors above.
        let r = unsafe {
            hydra_reply_function_rows(
                nb.as_ptr(),
                no.as_ptr(),
                ab.as_ptr(),
                ao.as_ptr(),
                sz.as_ptr(),
                fl.as_ptr(),
                3,
                idx.map_or(std::ptr::null(), |x| x.as_ptr()),
                idx.map_or(0, |x| x.len() as i64),
                from,
                to,
                out.as_mut_ptr(),
                cap as i64,
            )
        };
        if r < 0 {
            return Err(r);
        }
        Ok(String::from_utf8(out[..r as usize].to_vec()).unwrap())
    }

    #[test]
    fn rows_match_the_daemon_listing() {
        let row0 =
            r#"{"name":"main","address":"00401000","size":16,"thunk":false,"external":false}"#;
        let row1 = r#"{"name":"a\"q","address":"00401010","size":0,"thunk":true,"external":false}"#;
        let row2 = r#"{"name":"ns::f\u2028","address":"EXTERNAL:00000001","size":-3,"thunk":true,"external":true}"#;
        assert_eq!(
            call(None, 0, 3, 4096).unwrap(),
            format!("[{row0},{row1},{row2}]")
        );
        assert_eq!(call(None, 1, 2, 4096).unwrap(), format!("[{row1}]"));
        assert_eq!(call(None, 3, 3, 4096).unwrap(), "[]");
        assert_eq!(
            call(Some(&[2, 0]), 0, 0, 4096).unwrap(),
            format!("[{row2},{row0}]")
        );
        assert_eq!(call(Some(&[]), 0, 0, 4096).unwrap(), "[]");
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert_eq!(call(None, 0, 3, 40), Err(ERR_SPACE));
        assert_eq!(call(None, 2, 1, 4096), Err(ERR_ARGS));
        assert_eq!(call(None, 0, 4, 4096), Err(ERR_ARGS));
        assert_eq!(call(Some(&[3]), 0, 0, 4096), Err(ERR_INDEX));
        assert_eq!(call(Some(&[-1]), 0, 0, 4096), Err(ERR_INDEX));
    }

    #[test]
    fn json_string_entry_point() {
        let s = "x\"\u{1}";
        let mut out = vec![0u8; 32];
        // SAFETY: valid buffers.
        let n =
            unsafe { hydra_reply_json_string(s.as_ptr(), s.len() as i64, out.as_mut_ptr(), 32) };
        assert_eq!(
            std::str::from_utf8(&out[..n as usize]).unwrap(),
            r#""x\"\u0001""#
        );
        // SAFETY: valid buffers.
        let n = unsafe { hydra_reply_json_string(s.as_ptr(), s.len() as i64, out.as_mut_ptr(), 3) };
        assert_eq!(n, ERR_SPACE);
    }
}
