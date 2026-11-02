//! Reading segments from disk: a memory-mapped reader for closed or whole segments, and (on
//! Windows) a tail that reads new bytes with overlapped I/O and blocks on a directory change
//! notification instead of polling. Both feed the same verifier as `raw::scan`: bytes from disk
//! are untrusted until their CRC and hash chain check out.

use crate::raw::{self, Damage, Scan};
use serde_json::{Map, Value};
use std::io;
use std::path::Path;

/// Scan the segment file at `path` through a memory map. An empty file is a clean empty
/// segment (it cannot be mapped).
pub fn scan_file(path: &Path, segment: &str) -> io::Result<Scan> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(raw::scan(b"", segment));
    }
    // SAFETY: the mapping is read-only and every byte read from it is validated (line CRC, record
    // numbering and hash chain) before it is used. Writers only append, so the mapped range stays
    // valid; a segment that is truncated underneath a reader is a damaged segment, which the
    // session owner prevents by being the only writer.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    Ok(raw::scan(&map, segment))
}

/// What one [`Tail::poll`] found.
#[derive(Debug, Default)]
pub struct Poll {
    /// New verified records, in order.
    pub records: Vec<Map<String, Value>>,
    /// Corruption or a chain break (a torn tail is not damage: the writer may be mid-append).
    pub damage: Option<Damage>,
    /// Bytes at the end that are not yet a complete line.
    pub pending_bytes: u64,
}

#[cfg(windows)]
pub use win::Tail;

#[cfg(windows)]
mod win {
    use super::Poll;
    use crate::raw::{self, Damage};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_HANDLE_EOF, ERROR_IO_PENDING, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
        OPEN_EXISTING, ReadFile,
    };
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

    const CHUNK: usize = 1 << 20;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Follows one growing segment. The file is read with overlapped I/O; [`Tail::wait`] sleeps
    /// until the directory reports a size or write-time change (or the timeout passes).
    pub struct Tail {
        file: HANDLE,
        event: HANDLE,
        notify: HANDLE,
        offset: u64,
        head: String,
        next_n: u64,
        #[allow(dead_code)]
        path: PathBuf,
    }

    // SAFETY: the handles are owned by the Tail and used from one thread at a time (`&mut self`
    // for reads); Windows kernel handles may be used from any thread.
    unsafe impl Send for Tail {}

    impl Tail {
        /// Open `path` (which must exist) as the segment `segment`.
        pub fn open(path: &Path, segment: &str) -> io::Result<Self> {
            let w = wide(path);
            // SAFETY: w is a NUL terminated wide string; the other arguments are plain values.
            let file = unsafe {
                CreateFileW(
                    w.as_ptr(),
                    FILE_GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            };
            if file == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a manual-reset, initially unsignalled, unnamed event.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                let err = io::Error::last_os_error();
                // SAFETY: file is a valid handle we own.
                unsafe { CloseHandle(file) };
                return Err(err);
            }
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            let wd = wide(dir);
            // SAFETY: wd is a NUL terminated wide string.
            let notify = unsafe {
                FindFirstChangeNotificationW(
                    wd.as_ptr(),
                    0,
                    FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                )
            };
            if notify == INVALID_HANDLE_VALUE {
                let err = io::Error::last_os_error();
                // SAFETY: both handles are valid and owned.
                unsafe {
                    CloseHandle(event);
                    CloseHandle(file);
                }
                return Err(err);
            }
            Ok(Self {
                file,
                event,
                notify,
                offset: 0,
                head: raw::genesis_hash(segment),
                next_n: 0,
                path: path.to_path_buf(),
            })
        }

        /// Records consumed so far.
        pub fn records_seen(&self) -> u64 {
            self.next_n
        }

        /// One overlapped read of up to `buf.len()` bytes at `at`; 0 at the end of the file.
        fn read_at(&mut self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
            // SAFETY: an all-zero OVERLAPPED is the documented initial state.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.Anonymous.Anonymous.Offset = at as u32;
            ov.Anonymous.Anonymous.OffsetHigh = (at >> 32) as u32;
            ov.hEvent = self.event;
            // SAFETY: buf is valid for buf.len() bytes and outlives the operation, which is
            // waited for below before returning; ov likewise.
            let ok = unsafe {
                ReadFile(
                    self.file,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    std::ptr::null_mut(),
                    &mut ov,
                )
            };
            if ok == 0 {
                // SAFETY: plain thread-local error query.
                let err = unsafe { GetLastError() };
                if err == ERROR_HANDLE_EOF {
                    return Ok(0);
                }
                if err != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
            }
            let mut n = 0u32;
            // SAFETY: ov is the structure the read was issued with; bWait = 1 blocks until it
            // completes, so buf is no longer in use afterwards.
            let done = unsafe { GetOverlappedResult(self.file, &ov, &mut n, 1) };
            if done == 0 {
                // SAFETY: plain thread-local error query.
                let err = unsafe { GetLastError() };
                if err == ERROR_HANDLE_EOF {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(n as usize)
        }

        /// Read everything appended since the last poll and verify it.
        pub fn poll(&mut self) -> io::Result<Poll> {
            let mut data: Vec<u8> = Vec::new();
            let mut chunk = vec![0u8; CHUNK];
            loop {
                let at = self.offset + data.len() as u64;
                let n = self.read_at(at, &mut chunk)?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
            }
            let scan = raw::scan_from(&data, 0, self.head.clone(), self.next_n);
            let mut out = Poll {
                records: scan.records,
                ..Poll::default()
            };
            self.offset += scan.valid_end as u64;
            self.head = scan.head;
            self.next_n += out.records.len() as u64;
            match scan.damage {
                None => {}
                Some(Damage::TornTail { bytes, .. }) => out.pending_bytes = bytes as u64,
                Some(other) => out.damage = Some(other),
            }
            Ok(out)
        }

        /// Block until the directory changes or `timeout_ms` passes. Returns true on a change.
        /// The caller polls afterwards either way; a change only means "look now".
        pub fn wait(&self, timeout_ms: u32) -> bool {
            // SAFETY: notify is a valid change-notification handle.
            let r = unsafe { WaitForSingleObject(self.notify, timeout_ms) };
            if r == WAIT_OBJECT_0 {
                // SAFETY: re-arm the same valid handle.
                unsafe { FindNextChangeNotification(self.notify) };
                true
            } else {
                false
            }
        }

        /// Like [`Tail::wait`] without a timeout.
        pub fn wait_forever(&self) -> bool {
            self.wait(INFINITE)
        }
    }

    impl Drop for Tail {
        fn drop(&mut self) {
            // SAFETY: all three handles are valid and owned by this Tail.
            unsafe {
                FindCloseChangeNotification(self.notify);
                CloseHandle(self.event);
                CloseHandle(self.file);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{self, Recipe};

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hydra-rawio-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn mapped_scan_equals_the_in_memory_scan() {
        let d = tmp("map");
        let seg = synth::generate(Recipe::Baseline, 1, 300).remove(0);
        let p = d.join("a.trace");
        std::fs::write(&p, &seg.bytes).unwrap();
        let mapped = scan_file(&p, &seg.id).unwrap();
        let direct = raw::scan(&seg.bytes, &seg.id);
        assert_eq!(mapped.records, direct.records);
        assert!(mapped.is_clean());
        // empty and torn files keep their distinct outcomes
        std::fs::write(d.join("e.trace"), b"").unwrap();
        assert!(scan_file(&d.join("e.trace"), "e").unwrap().is_clean());
        let torn = synth::generate(Recipe::Torn, 1, 50).remove(0);
        std::fs::write(d.join("t.trace"), &torn.bytes).unwrap();
        assert!(matches!(
            scan_file(&d.join("t.trace"), &torn.id).unwrap().damage,
            Some(Damage::TornTail { .. })
        ));
        assert!(scan_file(&d.join("missing.trace"), "m").is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(windows)]
    #[test]
    fn tail_follows_a_growing_segment_and_waits_for_a_complete_line() {
        use std::io::Write;
        let d = tmp("tail");
        let seg = synth::generate(Recipe::Baseline, 2, 200).remove(0);
        let total = raw::scan(&seg.bytes, &seg.id).records.len() as u64;
        let p = d.join("src_a.trace");
        std::fs::write(&p, b"").unwrap();
        let mut tail = Tail::open(&p, &seg.id).unwrap();
        assert_eq!(tail.poll().unwrap().records.len(), 0);
        let bytes = seg.bytes.clone();
        let path = p.clone();
        let writer = std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
            // Odd-sized slices split lines in the middle.
            for part in bytes.chunks(997) {
                f.write_all(part).unwrap();
                f.flush().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        let mut seen = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while seen < total && std::time::Instant::now() < deadline {
            tail.wait(200);
            let poll = tail.poll().unwrap();
            assert!(poll.damage.is_none());
            seen += poll.records.len() as u64;
        }
        writer.join().unwrap();
        assert_eq!(seen, total);
        assert_eq!(tail.records_seen(), total);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(windows)]
    #[test]
    fn tail_holds_back_a_partial_line_until_it_is_complete() {
        use std::io::Write;
        let d = tmp("partial");
        let seg = synth::generate(Recipe::Baseline, 2, 20).remove(0);
        let p = d.join("src_a.trace");
        let first_line_end = seg.bytes.iter().position(|&b| b == 10).unwrap() + 1;
        let cut = first_line_end + 30; // 30 bytes into the second line
        std::fs::write(&p, &seg.bytes[..cut]).unwrap();
        let mut tail = Tail::open(&p, &seg.id).unwrap();
        let poll = tail.poll().unwrap();
        assert_eq!(poll.records.len(), 1);
        assert_eq!(poll.pending_bytes, 30);
        assert!(poll.damage.is_none());
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&seg.bytes[cut..]).unwrap();
        f.flush().unwrap();
        // NTFS reports size changes of a file the writer still holds open lazily, so a wait may
        // time out: the poll that follows reads the appended bytes either way.
        let _ = tail.wait(300);
        let poll = tail.poll().unwrap();
        assert_eq!(poll.pending_bytes, 0);
        assert_eq!(
            tail.records_seen(),
            raw::scan(&seg.bytes, &seg.id).records.len() as u64
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(windows)]
    #[test]
    fn tail_reports_a_chain_break() {
        let d = tmp("break");
        let seg = synth::generate(Recipe::Baseline, 3, 20).remove(0);
        let p = d.join("x.trace");
        // Open the tail under the wrong segment id: the first record cannot chain.
        std::fs::write(&p, &seg.bytes).unwrap();
        let mut tail = Tail::open(&p, "other").unwrap();
        let poll = tail.poll().unwrap();
        assert!(poll.records.is_empty());
        assert!(matches!(poll.damage, Some(Damage::ChainBreak { .. })));
        let _ = std::fs::remove_dir_all(d);
    }
}
