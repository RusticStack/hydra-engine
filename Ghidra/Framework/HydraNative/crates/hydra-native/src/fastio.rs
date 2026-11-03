//! Native file I/O for the heavy paths of the daemon: the copy or link of a fork's files and the
//! flush of a staged tree, run on native threads (`hydra_io_*`, called from
//! `ghidra.app.util.headless.session.HydraIo`).
//!
//! Java keeps every decision that belongs to Ghidra's project semantics (which files a fork
//! shares by hard link, which it copies, which flushes the process has already done, the crash
//! safety order: intent, staged copy, flush, rename, intent clear). This module only moves the
//! bytes and forces them to the disk, side by side, for a list the caller hands over as one
//! blob. A job runs on its own threads and the caller polls it ([`hydra_io_wait`]), so the
//! request thread can keep checking its monitor while the device works, and the caller never
//! treats a job as done before [`hydra_io_wait`] says so: nothing is acknowledged before it is
//! durable.
//!
//! # Durability
//!
//! A flush op opens the file for write (read on Unix) and calls `FlushFileBuffers` / `fsync`
//! (`File::sync_all`) on it, which is what `FileChannel.force(true)` did. A flush job ends only
//! when every op has ended, whatever failed, so no flush still runs when the caller removes the
//! folder. The rules for read-only files are those of `ProjectFork.forceFile` / `forceLinked`:
//! an *owned* read-only file (a copy) is made writable for the flush and read-only again; a
//! *linked* file (shared by hard link with its source, whose attributes belong to every fork)
//! is never touched, and a read-only linked file is a sealed version that is already durable, so
//! it is skipped. On Windows the directory flush is a no-op, as in Java (a directory cannot be
//! opened for flushing without elevated rights; the order of names rests on NTFS's journal).
//!
//! # Copy
//!
//! A copy op is `CopyFileExW` with `COPY_FILE_FAIL_IF_EXISTS` on Windows (what `Files.copy` with
//! `COPY_ATTRIBUTES` does: attributes and times come along, and ReFS clones the blocks on Windows
//! 11 24H2 and later), a create-new copy with permissions and times elsewhere. A link op is a
//! hard link, falling back to the copy when the file system cannot link, exactly like
//! `UpgradeCache.tryLink`. Not found and already exists are reported as such.
//!
//! The blob (little endian) of both jobs starts with `count u32`. Flush record: `kind u8`
//! (0 owned file, 1 linked file, 2 directory), `path_len u32`, path (UTF-8). Copy record:
//! `mode u8` (0 copy, 1 link or copy, 2 create directory), `flags u8` (bit 0: flush the copy,
//! bit 1: a file that is gone is skipped), `size u64`, `src_len u32`, `dst_len u32`, `src`,
//! `dst`. Copy outcomes, one byte per record: 0 copied, 1 linked, 2 skipped (gone), 3 copied and
//! flushed, 4 directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// The version of the `hydra_io_*` C ABI; separate from [`crate::ABI_VERSION`].
pub const IO_ABI_VERSION: u32 = 1;

/// The job is still running ([`hydra_io_wait`]).
pub const JOB_RUNNING: i32 = 0;
/// The job ended and every op succeeded.
pub const JOB_OK: i32 = 1;
/// The job ended and an op failed or the job was cancelled ([`hydra_io_error`]).
pub const JOB_FAILED: i32 = 2;

/// Error kind: no error.
pub const KIND_NONE: i32 = 0;
/// Error kind: a file or folder is not there.
pub const KIND_NOT_FOUND: i32 = 1;
/// Error kind: the destination exists.
pub const KIND_EXISTS: i32 = 2;
/// Error kind: any other I/O error.
pub const KIND_IO: i32 = 3;
/// Error kind: the job was cancelled.
pub const KIND_CANCELLED: i32 = 4;

const FLUSH_OWNED: u8 = 0;
const FLUSH_LINKED: u8 = 1;
const FLUSH_DIR: u8 = 2;

const MODE_COPY: u8 = 0;
const MODE_LINK: u8 = 1;
const MODE_MKDIR: u8 = 2;
const FLAG_FLUSH: u8 = 1;
const FLAG_SKIP_GONE: u8 = 2;

/// Copy outcome: the file was copied.
pub const OUT_COPIED: u8 = 0;
/// Copy outcome: the file was hard-linked.
pub const OUT_LINKED: u8 = 1;
/// Copy outcome: the source was gone and the record is left out.
pub const OUT_SKIPPED: u8 = 2;
/// Copy outcome: the file was copied and flushed.
pub const OUT_COPIED_FLUSHED: u8 = 3;
/// Copy outcome: a folder was created.
pub const OUT_DIR: u8 = 4;

/// What went wrong, for the caller to turn back into its own exception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// One of the `KIND_*` constants.
    pub kind: i32,
    /// The path and the OS error, for the log.
    pub message: String,
}

impl Failure {
    fn of(path: &Path, e: &io::Error) -> Self {
        let kind = match e.kind() {
            ErrorKind::NotFound => KIND_NOT_FOUND,
            ErrorKind::AlreadyExists => KIND_EXISTS,
            _ => KIND_IO,
        };
        Failure {
            kind,
            message: format!("{}: {e}", path.display()),
        }
    }

    fn cancelled() -> Self {
        Failure {
            kind: KIND_CANCELLED,
            message: "cancelled".into(),
        }
    }
}

/// One op of a flush job.
#[derive(Debug)]
struct FlushOp {
    kind: u8,
    path: PathBuf,
}

/// One op of a copy job.
#[derive(Debug)]
struct CopyOp {
    mode: u8,
    flags: u8,
    size: u64,
    src: PathBuf,
    dst: PathBuf,
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Some(h)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }

    fn path(&mut self, n: usize) -> Option<PathBuf> {
        let s = self.take(n)?;
        Some(PathBuf::from(std::str::from_utf8(s).ok()?))
    }
}

fn parse_flush(blob: &[u8]) -> Option<Vec<FlushOp>> {
    let mut r = Reader { b: blob };
    let n = r.u32()? as usize;
    let mut ops = Vec::with_capacity(n.min(1 << 16));
    for _ in 0..n {
        let kind = r.u8()?;
        let len = r.u32()? as usize;
        let path = r.path(len)?;
        if kind > FLUSH_DIR {
            return None;
        }
        ops.push(FlushOp { kind, path });
    }
    r.b.is_empty().then_some(ops)
}

fn parse_copy(blob: &[u8]) -> Option<Vec<CopyOp>> {
    let mut r = Reader { b: blob };
    let n = r.u32()? as usize;
    let mut ops = Vec::with_capacity(n.min(1 << 16));
    for _ in 0..n {
        let mode = r.u8()?;
        let flags = r.u8()?;
        let size = r.u64()?;
        let sl = r.u32()? as usize;
        let dl = r.u32()? as usize;
        let src = r.path(sl)?;
        let dst = r.path(dl)?;
        if mode > MODE_MKDIR {
            return None;
        }
        ops.push(CopyOp {
            mode,
            flags,
            size,
            src,
            dst,
        });
    }
    r.b.is_empty().then_some(ops)
}

// ---------------------------------------------------------------- the file operations

/// Forces an *owned* file to the disk: a read-only file is made writable for the flush and
/// read-only again (`FlushFileBuffers` needs a handle with write access), as
/// `ProjectFork.forceFile` does.
pub fn flush_owned(path: &Path) -> io::Result<()> {
    if !cfg!(windows) {
        return File::open(path)?.sync_all();
    }
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();
    let ro = perms.readonly();
    if ro {
        #[allow(clippy::permissions_set_readonly_false)] // Windows: the DOS read-only bit only
        perms.set_readonly(false);
        fs::set_permissions(path, perms.clone())?;
    }
    let flushed = OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|f| f.sync_all());
    if ro {
        perms.set_readonly(true);
        let restored = fs::set_permissions(path, perms);
        flushed?;
        return restored;
    }
    flushed
}

/// Forces a file shared by hard link without touching its attributes, as
/// `ProjectFork.forceLinked` does: a read-only one is a sealed version and already durable.
pub fn flush_linked(path: &Path) -> io::Result<()> {
    if !cfg!(windows) {
        return File::open(path)?.sync_all();
    }
    if fs::metadata(path)?.permissions().readonly() {
        return Ok(());
    }
    OpenOptions::new().write(true).open(path)?.sync_all()
}

/// Forces the entries of a folder to the disk where the platform allows it; never fails.
pub fn sync_dir(path: &Path) {
    if cfg!(windows) {
        return;
    }
    if let Ok(f) = File::open(path) {
        let _ = f.sync_all();
    }
}

#[cfg(windows)]
fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{COPY_FILE_FAIL_IF_EXISTS, CopyFileExW};
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain([0]).collect() };
    let (s, d) = (wide(src), wide(dst));
    // SAFETY: both paths are NUL-terminated UTF-16 that live across the call; the optional
    // progress routine, its data and the cancel flag are null, which the API allows.
    let ok = unsafe {
        CopyFileExW(
            s.as_ptr(),
            d.as_ptr(),
            None,
            std::ptr::null(),
            std::ptr::null_mut(),
            COPY_FILE_FAIL_IF_EXISTS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut from = File::open(src)?;
    let meta = from.metadata()?;
    let mut to = OpenOptions::new().write(true).create_new(true).open(dst)?;
    io::copy(&mut from, &mut to)?;
    to.set_permissions(meta.permissions())?;
    let mut times = fs::FileTimes::new();
    if let Ok(t) = meta.modified() {
        times = times.set_modified(t);
    }
    if let Ok(t) = meta.accessed() {
        times = times.set_accessed(t);
    }
    to.set_times(times)
}

/// Runs one copy op; the outcome byte, or the failure.
fn run_copy(op: &CopyOp) -> Result<u8, Failure> {
    if op.mode == MODE_MKDIR {
        return fs::create_dir_all(&op.dst)
            .map(|()| OUT_DIR)
            .map_err(|e| Failure::of(&op.dst, &e));
    }
    debug_assert!(op.mode == MODE_COPY || op.mode == MODE_LINK);
    let gone = |e: &io::Error| -> Option<Result<u8, Failure>> {
        if e.kind() == ErrorKind::NotFound
            && op.flags & FLAG_SKIP_GONE != 0
            && fs::symlink_metadata(&op.src).is_err()
        {
            return Some(Ok(OUT_SKIPPED));
        }
        None
    };
    if op.mode == MODE_LINK {
        match fs::hard_link(&op.src, &op.dst) {
            Ok(()) => return Ok(OUT_LINKED),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::AlreadyExists) => {
                if let Some(r) = gone(&e) {
                    return r;
                }
                return Err(Failure::of(&op.dst, &e));
            }
            Err(_) => {} // the file system cannot link: copy
        }
    }
    if let Err(e) = copy_file(&op.src, &op.dst) {
        if let Some(r) = gone(&e) {
            return r;
        }
        return Err(Failure::of(&op.dst, &e));
    }
    if op.flags & FLAG_FLUSH != 0 {
        flush_owned(&op.dst).map_err(|e| Failure::of(&op.dst, &e))?;
        return Ok(OUT_COPIED_FLUSHED);
    }
    Ok(OUT_COPIED)
}

fn run_flush(op: &FlushOp) -> Result<(), Failure> {
    match op.kind {
        FLUSH_OWNED => flush_owned(&op.path),
        FLUSH_LINKED => flush_linked(&op.path),
        _ => {
            sync_dir(&op.path);
            Ok(())
        }
    }
    .map_err(|e| Failure::of(&op.path, &e))
}

// ---------------------------------------------------------------- jobs

struct Inner {
    /// `true` once the job has ended; guarded with `done_cv`.
    ended: Mutex<bool>,
    done_cv: Condvar,
    cancel: AtomicBool,
    bytes: AtomicU64,
    failure: Mutex<Option<Failure>>,
    outcomes: Vec<AtomicU8>,
}

impl Inner {
    fn new(n: usize) -> Arc<Self> {
        Arc::new(Inner {
            ended: Mutex::new(false),
            done_cv: Condvar::new(),
            cancel: AtomicBool::new(false),
            bytes: AtomicU64::new(0),
            failure: Mutex::new(None),
            outcomes: (0..n).map(|_| AtomicU8::new(OUT_COPIED)).collect(),
        })
    }

    fn fail(&self, f: Failure) {
        // a job that has ended stays as it ended (a late cancel changes nothing)
        let Ok(ended) = self.ended.lock() else {
            return;
        };
        if *ended {
            return;
        }
        if let Ok(mut slot) = self.failure.lock()
            && slot.is_none()
        {
            *slot = Some(f);
        }
        // the other workers stop at their next op: the job ends when they all have
        self.cancel.store(true, Ordering::Release);
    }

    fn failed(&self) -> bool {
        self.failure.lock().map(|f| f.is_some()).unwrap_or(true)
    }

    fn end(&self) {
        if let Ok(mut e) = self.ended.lock() {
            *e = true;
        }
        self.done_cv.notify_all();
    }

    fn state(&self) -> i32 {
        match self.ended.lock() {
            Ok(e) if !*e => JOB_RUNNING,
            _ if self.failed() => JOB_FAILED,
            _ => JOB_OK,
        }
    }
}

/// A running or finished job. Opaque to C; freed with [`hydra_io_free`].
pub struct IoJob {
    inner: Arc<Inner>,
}

type Task = Box<dyn FnOnce() + Send>;

/// The threads that run the jobs: made on demand, kept for the life of the process. A thread made
/// for one job and gone after it costs more than a small fork's whole copy in a JVM (every new
/// thread of the process is announced to every library it has loaded).
struct Pool {
    state: Mutex<PoolState>,
    wake: Condvar,
}

struct PoolState {
    tasks: std::collections::VecDeque<Task>,
    idle: usize,
    workers: usize,
}

/// The most threads the pool makes; a job asks for fewer (the caller's `threads`).
const MAX_WORKERS: usize = 64;

fn pool() -> &'static Pool {
    static POOL: std::sync::OnceLock<Pool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| Pool {
        state: Mutex::new(PoolState {
            tasks: std::collections::VecDeque::new(),
            idle: 0,
            workers: 0,
        }),
        wake: Condvar::new(),
    })
}

fn worker_loop() {
    let p = pool();
    let Ok(mut g) = p.state.lock() else {
        return;
    };
    loop {
        if let Some(task) = g.tasks.pop_front() {
            drop(g);
            task();
            match p.state.lock() {
                Ok(next) => g = next,
                Err(_) => return,
            }
            continue;
        }
        g.idle += 1;
        match p.wake.wait(g) {
            Ok(next) => g = next,
            Err(_) => return,
        }
        g.idle -= 1;
    }
}

/// Queues `tasks`, making threads when fewer are idle than there are tasks. False when there is
/// no thread to run them (none could be made): nothing was queued.
fn submit(tasks: Vec<Task>) -> bool {
    let p = pool();
    let Ok(mut g) = p.state.lock() else {
        return false;
    };
    let wanted = (g.tasks.len() + tasks.len()).saturating_sub(g.idle);
    let mut made = 0;
    while made < wanted && g.workers < MAX_WORKERS {
        if std::thread::Builder::new()
            .name("hydra-io".into())
            .spawn(worker_loop)
            .is_err()
        {
            break;
        }
        g.workers += 1;
        made += 1;
    }
    if g.workers == 0 {
        return false;
    }
    let n = tasks.len();
    g.tasks.extend(tasks);
    drop(g);
    for _ in 0..n {
        p.wake.notify_one();
    }
    true
}

/// What the drains of one job share.
struct Shared {
    inner: Arc<Inner>,
    n: usize,
    next: AtomicUsize,
    remaining: AtomicUsize,
    body: Box<dyn Fn(usize) + Send + Sync>,
    post: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Shared {
    /// Claims ops until none is left or the job is cancelled or failed; the last drain to end runs
    /// `post` (when nothing failed) and ends the job. A drain that starts after the others have
    /// taken every op does nothing, so a job never waits for a thread the pool has not got.
    fn drain(&self) {
        loop {
            if self.inner.cancel.load(Ordering::Acquire) {
                break;
            }
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            if i >= self.n {
                break;
            }
            (self.body)(i);
        }
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish();
        }
    }

    fn finish(&self) {
        let post = self.post.lock().ok().and_then(|mut p| p.take());
        if let Some(post) = post
            && !self.inner.failed()
        {
            post();
        }
        self.inner.end();
    }
}

/// Runs `body(i)` for `0..n` on up to `threads` pool threads, then `post`, and ends the job; the
/// job is ended before this returns when there is nothing to do. False when the pool has no
/// thread (the caller falls back to Java).
fn launch(
    inner: &Arc<Inner>,
    n: usize,
    threads: usize,
    body: impl Fn(usize) + Send + Sync + 'static,
    post: impl FnOnce() + Send + 'static,
) -> bool {
    let drains = threads.clamp(1, n.max(1));
    let shared = Arc::new(Shared {
        inner: Arc::clone(inner),
        n,
        next: AtomicUsize::new(0),
        remaining: AtomicUsize::new(drains),
        body: Box::new(body),
        post: Mutex::new(Some(Box::new(post))),
    });
    let tasks: Vec<Task> = (0..drains)
        .map(|_| {
            let s = Arc::clone(&shared);
            Box::new(move || s.drain()) as Task
        })
        .collect();
    submit(tasks)
}

fn job_of(inner: Arc<Inner>, launched: bool) -> *mut IoJob {
    if !launched {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(IoJob { inner }))
}

/// Starts the flush of `ops` (files first, side by side, then the folders) and returns at once.
fn start_flush(ops: Vec<FlushOp>, threads: usize) -> *mut IoJob {
    let inner = Inner::new(0);
    let ops = Arc::new(ops);
    let files: Arc<Vec<usize>> = Arc::new(
        (0..ops.len())
            .filter(|&i| ops[i].kind != FLUSH_DIR)
            .collect(),
    );
    let (b_inner, b_ops, b_files) = (Arc::clone(&inner), Arc::clone(&ops), Arc::clone(&files));
    let body = move |k: usize| {
        if let Err(f) = run_flush(&b_ops[b_files[k]]) {
            b_inner.fail(f);
        }
    };
    let post = move || {
        for d in ops.iter().filter(|o| o.kind == FLUSH_DIR) {
            sync_dir(&d.path);
        }
    };
    let n = files.len();
    let launched = launch(&inner, n, threads, body, post);
    job_of(inner, launched)
}

/// Starts the copy of `ops` (the folders first, in order, then the files side by side).
fn start_copy(ops: Vec<CopyOp>, threads: usize) -> *mut IoJob {
    let inner = Inner::new(ops.len());
    // the folders first, on this thread: a few cheap calls, and the files below need them
    for (i, op) in ops.iter().enumerate().filter(|(_, o)| o.mode == MODE_MKDIR) {
        match run_copy(op) {
            Ok(o) => inner.outcomes[i].store(o, Ordering::Release),
            Err(f) => {
                inner.fail(f);
                inner.end();
                return job_of(inner, true);
            }
        }
    }
    let ops = Arc::new(ops);
    let files: Arc<Vec<usize>> = Arc::new(
        (0..ops.len())
            .filter(|&i| ops[i].mode != MODE_MKDIR)
            .collect(),
    );
    let (b_inner, b_files) = (Arc::clone(&inner), Arc::clone(&files));
    let body = move |k: usize| {
        let i = b_files[k];
        match run_copy(&ops[i]) {
            Ok(o) => {
                b_inner.outcomes[i].store(o, Ordering::Release);
                b_inner.bytes.fetch_add(ops[i].size, Ordering::Relaxed);
            }
            Err(f) => b_inner.fail(f),
        }
    };
    let n = files.len();
    let launched = launch(&inner, n, threads, body, || {});
    job_of(inner, launched)
}

// ---------------------------------------------------------------- C ABI

/// The `hydra_io_*` ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_io_abi_version() -> u32 {
    IO_ABI_VERSION
}

/// # Safety
/// `blob` must be valid for `len` bytes (or `len` 0).
unsafe fn blob_of<'a>(blob: *const u8, len: u64) -> Option<&'a [u8]> {
    let len = usize::try_from(len).ok()?;
    if blob.is_null() {
        return (len == 0).then_some(&[]);
    }
    // SAFETY: guaranteed by the caller, pointer and length together.
    Some(unsafe { std::slice::from_raw_parts(blob, len) })
}

/// Starts a flush job described by `blob` on up to `threads` threads. Null when the blob is
/// malformed or no thread can be made; the caller then flushes in Java. Free with
/// [`hydra_io_free`].
///
/// # Safety
/// `blob` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_flush_start(
    blob: *const u8,
    len: u64,
    threads: u32,
) -> *mut IoJob {
    // SAFETY: forwarded from the caller.
    let Some(bytes) = (unsafe { blob_of(blob, len) }) else {
        return std::ptr::null_mut();
    };
    match parse_flush(bytes) {
        Some(ops) => start_flush(ops, threads as usize),
        None => std::ptr::null_mut(),
    }
}

/// Starts a copy job described by `blob`; see [`hydra_io_flush_start`].
///
/// # Safety
/// `blob` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_copy_start(
    blob: *const u8,
    len: u64,
    threads: u32,
) -> *mut IoJob {
    // SAFETY: forwarded from the caller.
    let Some(bytes) = (unsafe { blob_of(blob, len) }) else {
        return std::ptr::null_mut();
    };
    match parse_copy(bytes) {
        Some(ops) => start_copy(ops, threads as usize),
        None => std::ptr::null_mut(),
    }
}

/// Waits up to `timeout_ms` for the job to end: [`JOB_RUNNING`], [`JOB_OK`] or [`JOB_FAILED`].
///
/// # Safety
/// `job` must come from a `hydra_io_*_start` and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_wait(job: *const IoJob, timeout_ms: u32) -> i32 {
    // SAFETY: guaranteed by the caller.
    let Some(job) = (unsafe { job.as_ref() }) else {
        return JOB_FAILED;
    };
    let inner = &job.inner;
    if let Ok(g) = inner.ended.lock() {
        let _ = inner.done_cv.wait_timeout_while(
            g,
            Duration::from_millis(u64::from(timeout_ms)),
            |e| !*e,
        );
    }
    inner.state()
}

/// The bytes of the files done so far (copy jobs).
///
/// # Safety
/// `job` must come from a `hydra_io_*_start` and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_progress(job: *const IoJob) -> u64 {
    // SAFETY: guaranteed by the caller.
    unsafe { job.as_ref() }.map_or(0, |j| j.inner.bytes.load(Ordering::Relaxed))
}

/// Asks the job to stop at its next op; ops under way end. The job then ends as failed with
/// kind [`KIND_CANCELLED`] unless it had already ended.
///
/// # Safety
/// `job` must come from a `hydra_io_*_start` and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_cancel(job: *const IoJob) {
    // SAFETY: guaranteed by the caller.
    if let Some(j) = unsafe { job.as_ref() } {
        j.inner.fail(Failure::cancelled());
    }
}

/// The failure of an ended job: its kind in `*kind` and its message (UTF-8, cut to `cap`) in
/// `out`; returns the full length of the message. 0 and [`KIND_NONE`] when the job did not fail.
///
/// # Safety
/// `job` must be live, `kind` valid for one `i32` (or null), `out` valid for `cap` bytes (or
/// null with `cap` 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_error(
    job: *const IoJob,
    kind: *mut i32,
    out: *mut u8,
    cap: u64,
) -> u64 {
    // SAFETY: guaranteed by the caller.
    let Some(j) = (unsafe { job.as_ref() }) else {
        return 0;
    };
    let failure = j.inner.failure.lock().ok().and_then(|f| f.clone());
    let Some(f) = failure else {
        if !kind.is_null() {
            // SAFETY: `kind` is valid for one i32.
            unsafe { *kind = KIND_NONE };
        }
        return 0;
    };
    if !kind.is_null() {
        // SAFETY: `kind` is valid for one i32.
        unsafe { *kind = f.kind };
    }
    let msg = f.message.as_bytes();
    if !out.is_null() {
        let n = msg.len().min(usize::try_from(cap).unwrap_or(usize::MAX));
        // SAFETY: `out` is valid for `cap` bytes and `n <= cap`; `msg` has `n` bytes.
        unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr(), out, n) };
    }
    msg.len() as u64
}

/// The outcome bytes of an ended copy job, one per record, cut to `cap`; returns their count.
///
/// # Safety
/// `job` must be live and `out` valid for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_outcomes(job: *const IoJob, out: *mut u8, cap: u64) -> u64 {
    // SAFETY: guaranteed by the caller.
    let Some(j) = (unsafe { job.as_ref() }) else {
        return 0;
    };
    let n = j.inner.outcomes.len();
    if !out.is_null() {
        let m = n.min(usize::try_from(cap).unwrap_or(usize::MAX));
        for (i, o) in j.inner.outcomes.iter().take(m).enumerate() {
            // SAFETY: `i < m <= cap`, so the byte is inside the caller's buffer.
            unsafe { *out.add(i) = o.load(Ordering::Acquire) };
        }
    }
    n as u64
}

/// Frees a job. A job still running is cancelled and finishes on its own threads; it holds what it
/// needs, so the caller may free it at once.
///
/// # Safety
/// `job` must come from a `hydra_io_*_start`, once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_io_free(job: *mut IoJob) {
    if job.is_null() {
        return;
    }
    // SAFETY: made by Box::into_raw in `start`, freed once.
    let j = unsafe { Box::from_raw(job) };
    if j.inner.state() == JOB_RUNNING {
        j.inner.fail(Failure::cancelled());
    }
}

#[cfg(test)]
mod tests;
