//! The extension-point class scan: which classes in the shipped jars are extension points.
//!
//! `ghidra.util.classfinder.ClassSearcher` scans the classpath once at start-up, opens every jar,
//! enumerates its entries and asks each class name whether it ends with one of the extension-point
//! suffixes (76 of them in a full install) before the classes are loaded. The suffix question is a
//! regular expression `.*(suffix1|suffix2|...)$` matched with `find()`; with 76 alternatives
//! Java's backtracking matcher costs 34.8 us per class name (measured on the install: 1143 ms for
//! 32 820 names), while a suffix test costs 0.7 us for the same 1709 matches. That, plus reading
//! the jars' central directories directly instead of building a `JarFile`, is this module.
//!
//! # Observable behaviour (the Java it replaces)
//!
//! [`scan_jars`] reproduces `ClassJar.processClassFiles` and `ClassSearcher.getExtensionPointSuffix`
//! for one jar each, in the order the jars are given:
//!
//! 1. Entries come in central-directory order, which is the order `JarFile.entries()` gives.
//! 2. An entry counts when its name (bytes as stored in the zip) ends with `.class`, exactly.
//! 3. The class name is the entry name cut at the *first* `.class` (`String.indexOf`), with every
//!    `/` replaced by `.`. So `a/B.class.class` is `a.B`, not `a.B.class`.
//! 4. A name containing `$` or ending with `Test` is not an extension point.
//! 5. The simple name is what follows the last `.`, when there is a `.` anywhere but at index 0;
//!    otherwise the whole name is the simple name.
//! 6. The suffix is the *shortest* suffix that the simple name ends with, because the Java regex
//!    backtracks `.*` from the longest and therefore tries the shortest remainder first. When no
//!    suffix matches, the class is not an extension point.
//! 7. Entries are UTF-8; a jar whose entry names are not UTF-8 fails the scan rather than being
//!    guessed at, and Java takes over.
//!
//! A jar that cannot be read as a zip (no end-of-central-directory, a truncated central directory,
//! ZIP64 that does not resolve) fails the whole scan: the caller falls back to Java rather than
//! silently dropping a jar's classes. An empty jar is not an error.
//!
//! # Deliberate differences
//!
//! * The Java scan checks `TaskMonitor.checkCancelled()` between entries; this one runs to the end
//!   (a full scan is under 100 ms) and the caller checks the monitor before and after. A cancelled
//!   scan still ends in `CancelledException`, just after the scan instead of during it.
//! * Suffix *patterns* are a superset of literals: when any suffix line is not a literal (it holds
//!   a regular-expression metacharacter) the caller keeps the Java path, because the equivalence in
//!   point 6 is only proven for literals. Every suffix in a Ghidra 12.3 install is a literal.

use std::path::Path;

/// The version of the class-scan C ABI (`hydra_cs_*`).
pub const CS_ABI_VERSION: u32 = 1;

/// Why a scan could not be answered from Rust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// A jar's entry names are not UTF-8, so the class names Java would build cannot be reproduced.
    NotUtf8,
    /// A jar's central directory could not be read.
    BadZip,
}

/// One extension-point class found in a jar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Index into the `paths` given to [`scan_jars`].
    pub jar: u32,
    /// The class name, package included (`ghidra.app.plugin.core.foo.FooPlugin`).
    pub name: String,
    /// The suffix that matched (`Plugin`).
    pub suffix: String,
}

/// Scans `paths` (jar files, in classpath order) for extension-point classes of `suffixes`.
///
/// Returns every match in jar order and, within a jar, in central-directory order. Duplicate names
/// across jars are kept: the caller de-duplicates in classpath order, as the Java scan does.
///
/// # Errors
///
/// [`ScanError::NotUtf8`] when an entry name is not UTF-8, [`ScanError::BadZip`] when a file is not
/// a zip whose central directory can be walked.
pub fn scan_jars(paths: &[&Path], suffixes: &[&str]) -> Result<Vec<Hit>, ScanError> {
    if paths.len() < 8 {
        return scan_range(paths, 0, suffixes);
    }
    // The scan is read-bound: one small read per jar for its tail and one for its directory, on a
    // cold cache. Overlapping them across a few threads is what makes it fast; the hits come back
    // in path order either way.
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .clamp(1, 8)
        .min(paths.len());
    if threads == 1 {
        return scan_range(paths, 0, suffixes);
    }
    let chunk = paths.len().div_ceil(threads);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .enumerate()
            .map(|(part, chunk_paths)| {
                scope.spawn(move || scan_range(chunk_paths, part * chunk, suffixes))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(Err(ScanError::BadZip)))
            .collect::<Vec<_>>()
    });
    let mut hits = Vec::new();
    for result in results {
        hits.extend(result?);
    }
    Ok(hits)
}

/// Scans `paths`, numbering their hits from `first`.
fn scan_range(paths: &[&Path], first: usize, suffixes: &[&str]) -> Result<Vec<Hit>, ScanError> {
    let mut hits = Vec::new();
    for (offset, path) in paths.iter().enumerate() {
        let jar = u32::try_from(first + offset).map_err(|_| ScanError::BadZip)?;
        for name in central_directory(path).ok_or(ScanError::BadZip)? {
            let Some(name) = std::str::from_utf8(&name).ok() else {
                return Err(ScanError::NotUtf8);
            };
            if let Some((name, suffix)) = extension_point(name, suffixes) {
                hits.push(Hit { jar, name, suffix });
            }
        }
    }
    Ok(hits)
}

/// The class name and suffix of one zip entry name, when it is an extension point.
///
/// `entry` is the name as stored in the zip (`a/b/FooPlugin.class`); `None` when the entry is not
/// a `.class` file or the class matches no suffix.
#[must_use]
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "a zip entry name is not a file path, and the Java scan compares `.class` exactly"
)]
pub fn extension_point(entry: &str, suffixes: &[&str]) -> Option<(String, String)> {
    // ClassJar first requires the entry name to end with ".class", then cuts at the first
    // occurrence, so `Foo.class.class` becomes `Foo`.
    if !entry.ends_with(".class") {
        return None;
    }
    let cut = entry.find(".class")?;
    let class: String = entry[..cut].replace('/', ".");
    if class.contains('$') || class.ends_with("Test") {
        return None;
    }
    let simple = match class.rfind('.') {
        Some(i) if i > 0 => &class[i + 1..],
        _ => class.as_str(),
    };
    let suffix = shortest_suffix(simple, suffixes)?;
    Some((class, suffix.to_owned()))
}

/// The shortest suffix `simple` ends with; the first one in `suffixes` order on a tie (a tie means
/// two equal strings, so the order does not matter in practice).
#[must_use]
pub fn shortest_suffix<'a>(simple: &str, suffixes: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<&str> = None;
    for &s in suffixes {
        if simple.ends_with(s) && best.is_none_or(|b| s.len() < b.len()) {
            best = Some(s);
        }
    }
    best
}

/// The file names of a zip's central directory, in order.
///
/// Reads the end-of-central-directory record from the file's tail and then the central directory
/// itself, never the entry data: a jar costs one small read plus its directory, not its size.
/// Returns `None` when the file is not a zip or its central directory cannot be walked (a bad
/// signature, an offset past the end of the file, a record that runs off the end).
fn central_directory(path: &Path) -> Option<Vec<Vec<u8>>> {
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const EOCD64_LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const EOCD64: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const CEN: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    // The record is at the end, after a comment of at most 65535 bytes.
    let tail_len = len.min(22 + 0xffff);
    let tail = read_at(&mut file, len - tail_len, tail_len)?;
    let eocd = find_last(&tail, &EOCD)?;
    let mut entries = u64::from(read_u16(&tail, eocd + 10)?);
    let mut cd_offset = u64::from(read_u32(&tail, eocd + 16)?);
    let mut cd_size = u64::from(read_u32(&tail, eocd + 12)?);
    if entries == u64::from(u16::MAX) || cd_offset == 0xffff_ffff {
        // ZIP64: the locator sits immediately before the end-of-central-directory record.
        let locator = eocd.checked_sub(20)?;
        if read_bytes(&tail, locator, 4)? != EOCD64_LOCATOR {
            return None;
        }
        let z64 = read_u64(&tail, locator + 8)?;
        let record = read_at(&mut file, z64, 56)?;
        if read_bytes(&record, 0, 4)? != EOCD64 {
            return None;
        }
        entries = read_u64(&record, 32)?;
        cd_size = read_u64(&record, 40)?;
        cd_offset = read_u64(&record, 48)?;
    }
    let directory = read_at(&mut file, cd_offset, cd_size)?;
    let mut at = 0usize;
    let mut names = Vec::with_capacity(usize::try_from(entries).unwrap_or(0));
    for _ in 0..entries {
        if read_bytes(&directory, at, 4)? != CEN {
            return None;
        }
        let name_len = usize::from(read_u16(&directory, at + 28)?);
        let extra_len = usize::from(read_u16(&directory, at + 30)?);
        let comment_len = usize::from(read_u16(&directory, at + 32)?);
        let name = read_bytes(&directory, at + 46, name_len)?;
        names.push(name.to_vec());
        at = at
            .checked_add(46)?
            .checked_add(name_len)?
            .checked_add(extra_len)?
            .checked_add(comment_len)?;
    }
    Some(names)
}

/// `len` bytes at `at` of the file; `None` when `at + len` runs past the end (or the read fails).
fn read_at(file: &mut std::fs::File, at: u64, len: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let end = at.checked_add(len)?;
    let size = file.metadata().ok()?.len();
    if end > size {
        return None;
    }
    file.seek(SeekFrom::Start(at)).ok()?;
    let mut buf = vec![0u8; usize::try_from(len).ok()?];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// The last offset of `needle` in `data` (the caller hands over only the file's tail).
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "a fixed four-byte signature reads as a slice at the call site"
)]
fn find_last(data: &[u8], needle: &[u8; 4]) -> Option<usize> {
    (0..data.len().saturating_sub(needle.len() - 1))
        .rev()
        .find(|&i| data.get(i..i + needle.len()) == Some(needle.as_slice()))
}

fn read_bytes(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    let end = at.checked_add(len)?;
    data.get(at..end)
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let b = read_bytes(data, at, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let b = read_bytes(data, at, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], at: usize) -> Option<u64> {
    let b = read_bytes(data, at, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------- C ABI

/// The class-scan ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_cs_abi_version() -> u32 {
    CS_ABI_VERSION
}

/// One scan's encoded hits, kept until [`hydra_cs_free`].
pub struct ClassScan {
    /// Records: `jar u32 | name_len u32 | suffix_len u32 | name | suffix`, little endian.
    bytes: Vec<u8>,
}

impl ClassScan {
    /// `None` when a name or suffix is longer than the ABI's `u32` length field.
    fn of(hits: &[Hit]) -> Option<Self> {
        let mut bytes = Vec::with_capacity(hits.len() * 48);
        for hit in hits {
            bytes.extend_from_slice(&hit.jar.to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(hit.name.len()).ok()?.to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(hit.suffix.len()).ok()?.to_le_bytes());
            bytes.extend_from_slice(hit.name.as_bytes());
            bytes.extend_from_slice(hit.suffix.as_bytes());
        }
        Some(Self { bytes })
    }
}

/// Scans `paths` (a NUL-separated UTF-8 list of jar paths, in classpath order) for extension-point
/// classes of `suffixes` (a NUL-separated UTF-8 list of literal suffixes). Returns the scan, or
/// null when an argument is not UTF-8, a jar cannot be read, or an entry name is not UTF-8; the
/// caller then keeps its own path. Free the result with [`hydra_cs_free`].
///
/// # Safety
/// `paths` must be valid for `paths_len` bytes and `suffixes` for `suffixes_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_cs_scan(
    paths: *const u8,
    paths_len: u64,
    suffixes: *const u8,
    suffixes_len: u64,
) -> *mut ClassScan {
    // SAFETY: guaranteed by the caller, pointer and length together.
    let path_bytes = unsafe { arena(paths, paths_len) };
    // SAFETY: as above.
    let suffix_bytes = unsafe { arena(suffixes, suffixes_len) };
    let Some(paths) = utf8_list(path_bytes) else {
        return std::ptr::null_mut();
    };
    let Some(suffixes) = utf8_list(suffix_bytes) else {
        return std::ptr::null_mut();
    };
    let paths: Vec<&Path> = paths.iter().map(Path::new).collect();
    match scan_jars(&paths, &suffixes)
        .ok()
        .and_then(|hits| ClassScan::of(&hits))
    {
        Some(scan) => Box::into_raw(Box::new(scan)),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// `p` must be valid for `len` bytes, or `len` must be 0.
unsafe fn arena<'a>(p: *const u8, len: u64) -> &'a [u8] {
    let Ok(len) = usize::try_from(len) else {
        return &[]; // a length the address space cannot hold: no caller buffer is that big
    };
    if len == 0 {
        &[]
    } else {
        let Some(ptr) = std::ptr::NonNull::new(p.cast_mut()) else {
            return &[];
        };
        // SAFETY: guaranteed by the caller.
        unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) }
    }
}

/// A NUL-separated UTF-8 list; `None` when a part is not UTF-8.
fn utf8_list(bytes: &[u8]) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    for part in bytes.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        out.push(std::str::from_utf8(part).ok()?);
    }
    Some(out)
}

/// Bytes of the scan's encoded hits.
///
/// # Safety
/// `s` must come from [`hydra_cs_scan`] and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_cs_len(s: *const ClassScan) -> u64 {
    // SAFETY: guaranteed by the caller.
    unsafe { s.as_ref() }.map_or(0, |s| s.bytes.len() as u64)
}

/// Copies the encoded hits into `out`, which must hold `len` bytes. Returns the bytes copied.
///
/// # Safety
/// As [`hydra_cs_len`]; `out` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_cs_copy(s: *const ClassScan, out: *mut u8, len: u64) -> u64 {
    // SAFETY: guaranteed by the caller.
    let Some(scan) = (unsafe { s.as_ref() }) else {
        return 0;
    };
    let len = usize::try_from(len).unwrap_or(0).min(scan.bytes.len());
    if len == 0 {
        return 0;
    }
    // SAFETY: guaranteed by the caller (valid for `len` bytes).
    unsafe { std::ptr::copy_nonoverlapping(scan.bytes.as_ptr(), out, len) };
    len as u64
}

/// Frees a scan.
///
/// # Safety
/// `s` must come from [`hydra_cs_scan`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_cs_free(s: *mut ClassScan) {
    if !s.is_null() {
        // SAFETY: guaranteed by the caller.
        drop(unsafe { Box::from_raw(s) });
    }
}

#[cfg(test)]
mod tests;
