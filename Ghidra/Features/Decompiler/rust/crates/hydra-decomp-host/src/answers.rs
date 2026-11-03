//! A bounded answer store: decompile answers (the C text of a function, with a small metadata
//! blob) kept in this library, off the Java heap, keyed by caller-chosen key bytes (program
//! revision, function, options).
//!
//! The Java side streams an answer in with `begin` / `append` / `commit` while it is produced, and
//! later serves any page of it with `read` instead of decompiling again. Two tiers bound the
//! memory: a RAM tier (`ram` bytes) and a disk tier (`disk` bytes, one unlinked-on-close temporary
//! file per entry). The least recently read entry leaves RAM first (moving to disk when the disk
//! tier has room, else it is dropped) and the least recently read disk entry is dropped when the
//! disk tier is full. An answer that does not fit even the disk tier is refused, never kept
//! partially: the caller then simply decompiles again, as it did before the store existed.
//!
//! Nothing here allocates in proportion to a request: an in-flight answer holds at most
//! `builder_ram` bytes in RAM before it moves to its file, and every byte is reserved against a
//! tier before it is stored.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_char, c_int};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Tier sizes and where the disk tier lives.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Bytes the RAM tier may hold (entries and in-flight answers).
    pub ram: u64,
    /// Bytes the disk tier may hold.
    pub disk: u64,
    /// The most bytes of one answer (RAM or disk).
    pub entry_max: u64,
    /// Directory of the disk tier's temporary files.
    pub dir: PathBuf,
}

/// A temporary file that is deleted when the last handle closes (also after a crash).
struct Spill {
    file: File,
    len: u64,
}

impl Spill {
    fn create(dir: &Path, id: u64) -> std::io::Result<File> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("ans-{}-{id}.bin", std::process::id()));
        let mut o = std::fs::OpenOptions::new();
        o.read(true).write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // GENERIC_READ | GENERIC_WRITE | DELETE (delete-on-close needs DELETE access), and
            // FILE_FLAG_DELETE_ON_CLOSE
            o.access_mode(0xC001_0000).custom_flags(0x0400_0000);
        }
        let f = o.open(&path)?;
        #[cfg(not(windows))]
        {
            // unlinked at once: the open handle keeps the data, the OS reclaims it on close/exit
            let _ = std::fs::remove_file(&path);
        }
        Ok(f)
    }

    /// Reads at `off` without moving a shared file position.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file.seek_read(buf, off)
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_at(buf, off)
        }
    }

    fn read_full(&self, mut off: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            let n = self.read_at(off, buf)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            off += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

enum Body {
    Ram(Vec<u8>),
    Disk(Arc<Spill>),
}

struct Entry {
    meta: Vec<u8>,
    body: Body,
    len: u64,
    tick: u64,
}

impl Entry {
    fn ram_bytes(&self) -> u64 {
        self.meta.len() as u64
            + match &self.body {
                Body::Ram(v) => v.len() as u64,
                Body::Disk(_) => 0,
            }
    }
    fn disk_bytes(&self) -> u64 {
        match &self.body {
            Body::Disk(s) => s.len,
            Body::Ram(_) => 0,
        }
    }
}

/// An answer being written (its bytes are already reserved against the tiers).
struct Builder {
    key: Vec<u8>,
    ram: Vec<u8>,
    file: Option<File>,
    len: u64,
    /// Bytes reserved in the RAM tier / the disk tier.
    ram_res: u64,
    disk_res: u64,
}

/// Counters of the store.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub ram_used: u64,
    pub disk_used: u64,
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evicted: u64,
    pub puts: u64,
    pub rejected: u64,
    pub ram_limit: u64,
    pub disk_limit: u64,
}

struct Inner {
    limits: Option<Limits>,
    entries: HashMap<Vec<u8>, Entry>,
    order: BTreeMap<u64, Vec<u8>>,
    builders: HashMap<u64, Arc<Mutex<Builder>>>,
    ram_used: u64,
    disk_used: u64,
    tick: u64,
    next_id: u64,
    hits: u64,
    misses: u64,
    evicted: u64,
    puts: u64,
    rejected: u64,
}

/// The store. One per process in the C ABI; tests make their own.
pub struct AnswerStore {
    inner: Mutex<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Default for AnswerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AnswerStore {
    /// An unconfigured store: every `begin` is refused until [`Self::configure`].
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                limits: None,
                entries: HashMap::new(),
                order: BTreeMap::new(),
                builders: HashMap::new(),
                ram_used: 0,
                disk_used: 0,
                tick: 0,
                next_id: 1,
                hits: 0,
                misses: 0,
                evicted: 0,
                puts: 0,
                rejected: 0,
            }),
        }
    }

    /// Sets (or changes) the limits; a smaller limit evicts at once.
    pub fn configure(&self, limits: Limits) {
        let mut g = lock(&self.inner);
        g.limits = Some(limits);
        g.shrink_to_fit_tiers(0, 0);
    }

    /// Starts an answer for `key`. `None` when the store is not configured.
    pub fn begin(&self, key: &[u8]) -> Option<u64> {
        let mut g = lock(&self.inner);
        g.limits.as_ref()?;
        let id = g.next_id;
        g.next_id += 1;
        g.builders.insert(
            id,
            Arc::new(Mutex::new(Builder {
                key: key.to_vec(),
                ram: Vec::new(),
                file: None,
                len: 0,
                ram_res: 0,
                disk_res: 0,
            })),
        );
        Some(id)
    }

    /// Adds bytes to an answer. `Err` (the answer is discarded) when it would pass `entry_max`
    /// or fit neither tier, or the file cannot be written.
    pub fn append(&self, id: u64, data: &[u8]) -> Result<(), AppendError> {
        let b = {
            let g = lock(&self.inner);
            g.builders.get(&id).cloned().ok_or(AppendError::Unknown)?
        };
        let mut bl = lock(&b);
        let r = self.append_locked(&mut bl, data);
        drop(bl);
        if r.is_err() {
            self.abort(id);
        }
        r
    }

    fn append_locked(&self, b: &mut Builder, data: &[u8]) -> Result<(), AppendError> {
        let n = data.len() as u64;
        let (dir, entry_max, builder_ram) = {
            let g = lock(&self.inner);
            let l = g.limits.as_ref().ok_or(AppendError::Refused)?;
            (l.dir.clone(), l.entry_max, l.ram / 4)
        };
        if b.len + n > entry_max {
            lock(&self.inner).rejected += 1;
            return Err(AppendError::TooBig);
        }
        if b.file.is_none() && b.ram_res + n <= builder_ram.max(1) {
            // stays in RAM if the tier has room
            let mut g = lock(&self.inner);
            if g.reserve_ram(n) {
                b.ram_res += n;
                drop(g);
                b.ram.extend_from_slice(data);
                b.len += n;
                return Ok(());
            }
        }
        // the disk: move what RAM holds there first
        let mut g = lock(&self.inner);
        let need = b.ram.len() as u64 + n;
        if !g.reserve_disk(need) {
            g.rejected += 1;
            return Err(AppendError::Refused);
        }
        b.disk_res += need;
        let ram_res = std::mem::take(&mut b.ram_res);
        g.ram_used = g.ram_used.saturating_sub(ram_res);
        let fid = g.next_id;
        g.next_id += 1;
        drop(g);
        if b.file.is_none() {
            b.file = Some(Spill::create(&dir, fid).map_err(|_| AppendError::Io)?);
        }
        let f = b.file.as_mut().ok_or(AppendError::Io)?;
        if !b.ram.is_empty() {
            f.write_all(&b.ram).map_err(|_| AppendError::Io)?;
            b.ram = Vec::new();
        }
        f.write_all(data).map_err(|_| AppendError::Io)?;
        b.len += n;
        Ok(())
    }

    /// Stores the answer under its key (replacing an older one) with `meta`.
    pub fn commit(&self, id: u64, meta: &[u8]) -> bool {
        let Some(b) = lock(&self.inner).builders.remove(&id) else {
            return false;
        };
        let mut b = lock(&b);
        let (ram, file) = (std::mem::take(&mut b.ram), b.file.take());
        let (key, len) = (std::mem::take(&mut b.key), b.len);
        let (ram_res, disk_res) = (b.ram_res, b.disk_res);
        drop(b);
        let mut g = lock(&self.inner);
        // swap the reservation of the builder for the entry's own accounting
        g.ram_used = g.ram_used.saturating_sub(ram_res);
        g.disk_used = g.disk_used.saturating_sub(disk_res);
        let body = match file {
            Some(f) => Body::Disk(Arc::new(Spill { file: f, len })),
            None => Body::Ram(ram),
        };
        if let Some(old) = g.entries.remove(&key) {
            g.order.remove(&old.tick);
            g.ram_used = g.ram_used.saturating_sub(old.ram_bytes());
            g.disk_used = g.disk_used.saturating_sub(old.disk_bytes());
        }
        g.tick += 1;
        let e = Entry {
            meta: meta.to_vec(),
            body,
            len,
            tick: g.tick,
        };
        g.ram_used += e.ram_bytes();
        g.disk_used += e.disk_bytes();
        g.order.insert(e.tick, key.clone());
        g.entries.insert(key, e);
        g.puts += 1;
        g.shrink_to_fit_tiers(0, 0);
        true
    }

    /// Discards an unfinished answer and releases what it reserved.
    pub fn abort(&self, id: u64) {
        let mut g = lock(&self.inner);
        if let Some(b) = g.builders.remove(&id) {
            let b = lock(&b);
            g.ram_used = g.ram_used.saturating_sub(b.ram_res);
            g.disk_used = g.disk_used.saturating_sub(b.disk_res);
        }
    }

    /// Reads up to `out.len()` bytes of the answer from byte `off`. Returns the answer's total
    /// length, the bytes copied and its metadata, or `None` on a miss (or a file error, which
    /// drops the entry).
    pub fn read(&self, key: &[u8], off: u64, out: &mut [u8]) -> Option<(u64, usize, Vec<u8>)> {
        enum Src {
            Ram,
            Disk(Arc<Spill>),
        }
        let (total, meta, src) = {
            let mut g = lock(&self.inner);
            let Some(e) = g.entries.get(key) else {
                g.misses += 1;
                return None;
            };
            let old = e.tick;
            let (total, meta) = (e.len, e.meta.clone());
            let mut ram_copy = None;
            let src = match &e.body {
                Body::Ram(v) => {
                    let s = (off.min(total)) as usize;
                    let n = out.len().min(v.len() - s);
                    ram_copy = Some(v[s..s + n].to_vec());
                    Src::Ram
                }
                Body::Disk(s) => Src::Disk(Arc::clone(s)),
            };
            g.tick += 1;
            let t = g.tick;
            if let Some(e) = g.entries.get_mut(key) {
                e.tick = t;
            }
            g.order.remove(&old);
            g.order.insert(t, key.to_vec());
            g.hits += 1;
            if let Some(c) = ram_copy {
                out[..c.len()].copy_from_slice(&c);
                return Some((total, c.len(), meta));
            }
            (total, meta, src)
        };
        let Src::Disk(s) = src else { return None };
        let start = off.min(total);
        let n = (out.len() as u64).min(total - start) as usize;
        if s.read_full(start, &mut out[..n]).is_err() {
            self.remove(key);
            return None;
        }
        Some((total, n, meta))
    }

    /// Drops one answer.
    pub fn remove(&self, key: &[u8]) {
        let mut g = lock(&self.inner);
        g.drop_key(key);
    }

    /// Drops every answer (not the in-flight ones).
    pub fn clear(&self) {
        let mut g = lock(&self.inner);
        let keys: Vec<Vec<u8>> = g.entries.keys().cloned().collect();
        for k in keys {
            g.drop_key(&k);
        }
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        let g = lock(&self.inner);
        Stats {
            ram_used: g.ram_used,
            disk_used: g.disk_used,
            entries: g.entries.len() as u64,
            hits: g.hits,
            misses: g.misses,
            evicted: g.evicted,
            puts: g.puts,
            rejected: g.rejected,
            ram_limit: g.limits.as_ref().map_or(0, |l| l.ram),
            disk_limit: g.limits.as_ref().map_or(0, |l| l.disk),
        }
    }
}

/// Why [`AnswerStore::append`] refused (the answer is discarded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendError {
    /// No such answer in progress.
    Unknown,
    /// The answer passes `entry_max`.
    TooBig,
    /// Neither tier has room.
    Refused,
    /// The temporary file could not be written.
    Io,
}

impl Inner {
    fn drop_key(&mut self, key: &[u8]) {
        if let Some(e) = self.entries.remove(key) {
            self.order.remove(&e.tick);
            self.ram_used = self.ram_used.saturating_sub(e.ram_bytes());
            self.disk_used = self.disk_used.saturating_sub(e.disk_bytes());
            self.evicted += 1;
        }
    }

    /// Reserves `n` RAM bytes, moving or dropping least recently read entries if needed.
    fn reserve_ram(&mut self, n: u64) -> bool {
        let Some(limit) = self.limits.as_ref().map(|l| l.ram) else {
            return false;
        };
        if n > limit {
            return false;
        }
        self.shrink_to_fit_tiers(n, 0);
        if self.ram_used + n > limit {
            return false;
        }
        self.ram_used += n;
        true
    }

    /// Reserves `n` disk bytes, dropping least recently read disk entries if needed.
    fn reserve_disk(&mut self, n: u64) -> bool {
        let Some(limit) = self.limits.as_ref().map(|l| l.disk) else {
            return false;
        };
        if n > limit {
            return false;
        }
        self.shrink_to_fit_tiers(0, n);
        if self.disk_used + n > limit {
            return false;
        }
        self.disk_used += n;
        true
    }

    /// Makes room for `ram_extra` / `disk_extra` more bytes: RAM entries move to the disk tier
    /// (oldest first), then disk entries are dropped (oldest first). In-flight answers are not
    /// touched, so this can end short of the target; the caller checks.
    fn shrink_to_fit_tiers(&mut self, ram_extra: u64, disk_extra: u64) {
        let Some(l) = self.limits.clone() else { return };
        // RAM -> disk, then drop
        let keys: Vec<Vec<u8>> = self.order.values().cloned().collect();
        for k in &keys {
            if self.ram_used + ram_extra <= l.ram {
                break;
            }
            let Some(e) = self.entries.get(k) else {
                continue;
            };
            if e.ram_bytes() == 0 {
                continue;
            }
            if let Body::Ram(_) = e.body {
                let len = e.len;
                if len <= l.disk
                    && self.disk_used + len <= l.disk.saturating_sub(disk_extra)
                    && let Some(sp) = self.spill_entry(k, &l.dir)
                {
                    let e = self.entries.get_mut(k).expect("present");
                    let freed = match std::mem::replace(&mut e.body, Body::Disk(Arc::new(sp))) {
                        Body::Ram(v) => v.len() as u64,
                        Body::Disk(_) => 0,
                    };
                    self.ram_used = self.ram_used.saturating_sub(freed);
                    self.disk_used += len;
                    continue;
                }
                self.drop_key(k);
            }
        }
        // disk limit
        for k in &keys {
            if self.disk_used + disk_extra <= l.disk {
                break;
            }
            if self.entries.get(k).is_some_and(|e| e.disk_bytes() > 0) {
                self.drop_key(k);
            }
        }
        // an entry's metadata is RAM too: if still over, drop the oldest whole entries
        for k in &keys {
            if self.ram_used + ram_extra <= l.ram {
                break;
            }
            self.drop_key(k);
        }
    }

    fn spill_entry(&mut self, key: &[u8], dir: &Path) -> Option<Spill> {
        let id = self.next_id;
        self.next_id += 1;
        let e = self.entries.get(key)?;
        let Body::Ram(v) = &e.body else { return None };
        let mut f = Spill::create(dir, id).ok()?;
        f.write_all(v).ok()?;
        Some(Spill {
            file: f,
            len: v.len() as u64,
        })
    }
}

static STORE: std::sync::LazyLock<AnswerStore> = std::sync::LazyLock::new(AnswerStore::new);

fn slice<'a>(p: *const c_char, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: the caller of every exported function guarantees `p` is valid for `n` bytes.
        unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) }
    }
}

/// Sets the tier limits (bytes) and the directory of the disk tier; may be called again to
/// change them. Returns 0, or 1 for a bad directory name.
///
/// # Safety
/// `dir` must be valid for `dirlen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_configure(
    ram: u64,
    disk: u64,
    entry_max: u64,
    dir: *const c_char,
    dirlen: usize,
) -> c_int {
    let Ok(d) = std::str::from_utf8(slice(dir, dirlen)) else {
        return 1;
    };
    STORE.configure(Limits {
        ram,
        disk,
        entry_max,
        dir: PathBuf::from(d),
    });
    0
}

/// Starts an answer; returns its ticket, or 0 when the store is not configured.
///
/// # Safety
/// `key` must be valid for `keylen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_begin(key: *const c_char, keylen: usize) -> u64 {
    STORE.begin(slice(key, keylen)).unwrap_or(0)
}

/// Appends bytes to an answer. Returns 0, or non-zero when the answer was discarded (too big,
/// no room, I/O error, unknown ticket): the caller stops writing it.
///
/// # Safety
/// `data` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_append(
    ticket: u64,
    data: *const c_char,
    len: usize,
) -> c_int {
    match STORE.append(ticket, slice(data, len)) {
        Ok(()) => 0,
        Err(AppendError::Unknown) => 1,
        Err(AppendError::TooBig) => 2,
        Err(AppendError::Refused) => 3,
        Err(AppendError::Io) => 4,
    }
}

/// Finishes an answer and stores it with its metadata. Returns 0, or 1 for an unknown ticket.
///
/// # Safety
/// `meta` must be valid for `metalen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_commit(
    ticket: u64,
    meta: *const c_char,
    metalen: usize,
) -> c_int {
    c_int::from(!STORE.commit(ticket, slice(meta, metalen)))
}

/// Discards an unfinished answer.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_answer_abort(ticket: u64) {
    STORE.abort(ticket);
}

/// Reads from a stored answer. Returns 0 on a hit (`*total` the answer's length, `*copied` the
/// bytes written to `out`, the metadata copied to `meta` when it fits `metacap`, its length in
/// `*metalen`), 1 on a miss.
///
/// # Safety
/// `key` valid for `keylen`; `out` writable for `outcap`; `meta` writable for `metacap`; the
/// three out-pointers writable.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn hydra_dhost_answer_read(
    key: *const c_char,
    keylen: usize,
    off: u64,
    out: *mut c_char,
    outcap: usize,
    total: *mut u64,
    copied: *mut u64,
    meta: *mut c_char,
    metacap: usize,
    metalen: *mut u64,
) -> c_int {
    let mut empty = [0u8; 0];
    let buf: &mut [u8] = if out.is_null() || outcap == 0 {
        &mut empty
    } else {
        // SAFETY: writable for `outcap` bytes (caller guarantee).
        unsafe { std::slice::from_raw_parts_mut(out.cast::<u8>(), outcap) }
    };
    match STORE.read(slice(key, keylen), off, buf) {
        Some((t, n, m)) => {
            // SAFETY: the out-pointers are writable (caller guarantee).
            unsafe {
                *total = t;
                *copied = n as u64;
                *metalen = m.len() as u64;
                if !meta.is_null() && m.len() <= metacap {
                    std::ptr::copy_nonoverlapping(m.as_ptr(), meta.cast::<u8>(), m.len());
                }
            }
            0
        }
        None => 1,
    }
}

/// Drops one stored answer.
///
/// # Safety
/// `key` must be valid for `keylen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_remove(key: *const c_char, keylen: usize) {
    STORE.remove(slice(key, keylen));
}

/// Writes ten counters to `out`: RAM used, disk used, entries, hits, misses, evicted, puts,
/// rejected, RAM limit, disk limit.
///
/// # Safety
/// `out` must be writable for ten `u64`s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_dhost_answer_stats(out: *mut u64) {
    let s = STORE.stats();
    let v = [
        s.ram_used,
        s.disk_used,
        s.entries,
        s.hits,
        s.misses,
        s.evicted,
        s.puts,
        s.rejected,
        s.ram_limit,
        s.disk_limit,
    ];
    // SAFETY: writable for ten u64s (caller guarantee).
    unsafe { std::ptr::copy_nonoverlapping(v.as_ptr(), out, v.len()) }
}

/// Drops every stored answer.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_dhost_answer_clear() {
    STORE.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hydra-answers-ut-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(s: &AnswerStore, key: &[u8], data: &[u8], meta: &[u8]) -> bool {
        let Some(id) = s.begin(key) else {
            return false;
        };
        for c in data.chunks(7) {
            if s.append(id, c).is_err() {
                return false;
            }
        }
        s.commit(id, meta)
    }

    fn get(s: &AnswerStore, key: &[u8], off: u64, cap: usize) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        let mut b = vec![0u8; cap];
        let (t, n, m) = s.read(key, off, &mut b)?;
        b.truncate(n);
        Some((t, b, m))
    }

    fn limits(ram: u64, disk: u64, tag: &str) -> Limits {
        Limits {
            ram,
            disk,
            entry_max: 1 << 20,
            dir: dir(tag),
        }
    }

    #[test]
    fn refuses_until_configured() {
        let s = AnswerStore::new();
        assert!(s.begin(b"k").is_none());
        assert!(get(&s, b"k", 0, 4).is_none());
    }

    #[test]
    fn ram_round_trip_and_pages() {
        let s = AnswerStore::new();
        s.configure(limits(1 << 16, 1 << 16, "rt"));
        let text: Vec<u8> = (0..1000u32)
            .flat_map(|i| (i as u16).to_le_bytes())
            .collect();
        assert!(put(&s, b"k", &text, b"meta"));
        let (t, page, m) = get(&s, b"k", 100, 50).unwrap();
        assert_eq!((t, m.as_slice()), (2000, &b"meta"[..]));
        assert_eq!(page, text[100..150]);
        let (_, tail, _) = get(&s, b"k", 1990, 50).unwrap();
        assert_eq!(tail, text[1990..]);
        let (_, none, _) = get(&s, b"k", 5000, 50).unwrap();
        assert!(none.is_empty());
        assert!(get(&s, b"other", 0, 4).is_none());
        let st = s.stats();
        assert_eq!((st.entries, st.hits, st.misses, st.puts), (1, 3, 1, 1));
    }

    #[test]
    fn big_answer_goes_to_disk_and_reads_back() {
        let s = AnswerStore::new();
        // RAM tier 4 KB: an answer of 20 KB can only be on disk
        s.configure(limits(4096, 1 << 20, "disk"));
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        assert!(put(&s, b"big", &data, b"m"));
        let st = s.stats();
        assert_eq!(st.disk_used, 20_000);
        assert!(st.ram_used <= 4096);
        let (t, page, _) = get(&s, b"big", 10_000, 300).unwrap();
        assert_eq!(t, 20_000);
        assert_eq!(page, data[10_000..10_300]);
    }

    #[test]
    fn lru_moves_ram_entries_to_disk_then_drops() {
        let s = AnswerStore::new();
        s.configure(limits(3000, 5000, "lru"));
        let blob = |n: u8| vec![n; 700];
        for n in 1..=4u8 {
            assert!(put(&s, &[n], &blob(n), b""));
        }
        // touch 1 so 2 is the oldest; a fifth entry pushes 2 to the disk tier
        assert!(get(&s, &[1], 0, 1).is_some());
        assert!(put(&s, &[5], &blob(5), b""));
        let st = s.stats();
        assert!(st.ram_used <= 3000, "{st:?}");
        assert!(st.disk_used == 700 && st.entries == 5, "{st:?}");
        assert_eq!(get(&s, &[2], 500, 4).unwrap().1, vec![2; 4]);
        // fill the disk tier: the oldest disk entries go, the store stays within both limits
        for n in 6..=16u8 {
            assert!(put(&s, &[n], &blob(n), b""));
        }
        let st = s.stats();
        assert!(st.ram_used <= 3000 && st.disk_used <= 5000, "{st:?}");
        assert!(st.evicted > 0);
        assert!(get(&s, &[16], 0, 1).is_some());
    }

    #[test]
    fn answer_over_every_limit_is_refused_whole() {
        let s = AnswerStore::new();
        let mut l = limits(1000, 2000, "big");
        l.entry_max = 1500;
        s.configure(l);
        assert!(!put(&s, b"x", &vec![1u8; 1600], b""), "entry_max");
        let mut l = limits(1000, 2000, "big2");
        l.entry_max = 10_000;
        s.configure(l);
        assert!(
            !put(&s, b"y", &vec![1u8; 2100], b""),
            "bigger than the disk tier"
        );
        let st = s.stats();
        assert_eq!((st.entries, st.ram_used, st.disk_used), (0, 0, 0), "{st:?}");
        assert_eq!(st.rejected, 2);
        // an unfinished answer releases its reservation
        let id = s.begin(b"z").unwrap();
        s.append(id, &[0u8; 200]).unwrap();
        assert!(s.stats().ram_used > 0);
        s.abort(id);
        assert_eq!(s.stats().ram_used, 0);
    }

    #[test]
    fn replacing_a_key_keeps_accounting_exact() {
        let s = AnswerStore::new();
        s.configure(limits(10_000, 10_000, "rep"));
        assert!(put(&s, b"k", &[1u8; 800], b"a"));
        assert!(put(&s, b"k", &[2u8; 300], b"bb"));
        let st = s.stats();
        assert_eq!((st.entries, st.ram_used), (1, 302));
        assert_eq!(get(&s, b"k", 0, 2).unwrap().1, vec![2, 2]);
        s.clear();
        assert_eq!(s.stats().ram_used, 0);
    }

    #[test]
    fn concurrent_writers_and_readers_stay_within_limits() {
        let s = Arc::new(AnswerStore::new());
        s.configure(limits(20_000, 60_000, "mt"));
        let hs: Vec<_> = (0..8u8)
            .map(|t| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    for i in 0..60u8 {
                        let key = [t, i % 10];
                        let data = vec![t ^ i; 1000 + usize::from(i) * 50];
                        put(&s, &key, &data, b"m");
                        if let Some((total, page, _)) = get(&s, &key, 0, 16) {
                            assert!(total >= 1000);
                            assert!(page.iter().all(|b| *b == page[0]));
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let st = s.stats();
        assert!(st.ram_used <= 20_000 && st.disk_used <= 60_000, "{st:?}");
    }
}
