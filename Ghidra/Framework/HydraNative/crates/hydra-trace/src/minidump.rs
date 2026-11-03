//! Minidump importer (spec 15.9): a Windows minidump becomes trace evidence. The parser reads
//! the header, stream directory, system info, thread list (with each thread's stack bytes and
//! x64 context), module list, exception and misc-info streams. Threads are symbolized against a
//! [`Symbolizer`] through the module list, and the reported patterns are
//! `all threads suspended by thread T`, `N threads waiting at one site` and `thread inside the
//! host's fault handler`, each with citations (thread ids and frame addresses).
//!
//! A dump has no unwind data here, so a thread's frames are a conservative scan of its stack for
//! values that fall inside a module: they are marked `inferred`, never `exact`.

use crate::symbolize::{ModuleRef, Resolution, Symbolizer};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SIGNATURE: u32 = 0x504d_444d; // "MDMP"
const STREAM_THREADS: u32 = 3;
const STREAM_MEMORY: u32 = 5;
const STREAM_MEMORY64: u32 = 9;
const MAX_MEMORY_BYTES: usize = 256 << 20;
const MAX_RANGES: usize = 65_536;
const STREAM_MODULES: u32 = 4;
const STREAM_EXCEPTION: u32 = 6;
const STREAM_SYSTEM: u32 = 7;
const STREAM_MISC: u32 = 15;
const MAX_FRAMES: usize = 64;
const MAX_THREADS: u32 = 16_384;
const MAX_MODULES: u32 = 16_384;

#[derive(Debug, PartialEq, Eq)]
pub enum DumpError {
    Truncated(&'static str),
    NotMinidump,
    Unsupported(&'static str),
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DumpError::Truncated(w) => write!(f, "minidump truncated: {w}"),
            DumpError::NotMinidump => write!(f, "not a minidump (bad signature)"),
            DumpError::Unsupported(w) => write!(f, "unsupported minidump: {w}"),
        }
    }
}

impl std::error::Error for DumpError {}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DumpModule {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub timestamp: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DumpThread {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub teb: u64,
    pub stack_base: u64,
    pub stack_size: u32,
    pub rip: Option<u64>,
    pub rsp: Option<u64>,
    /// Return-address candidates found on the stack, innermost first (inferred).
    pub frames: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DumpException {
    pub thread_id: u32,
    pub code: u32,
    pub address: u64,
}

/// Memory the dump carries (thread stacks and, for a dump written with data segments, module data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRange {
    pub base: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Dump {
    pub timestamp: u32,
    pub architecture: u16,
    pub process_id: Option<u32>,
    pub modules: Vec<DumpModule>,
    pub threads: Vec<DumpThread>,
    pub exception: Option<DumpException>,
    #[serde(skip)]
    pub memory: Vec<MemoryRange>,
}

impl Dump {
    /// `len` bytes at `addr`, when one memory range of the dump holds all of them.
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let end = addr.checked_add(len as u64)?;
        self.memory.iter().find_map(|r| {
            let top = r.base.checked_add(r.data.len() as u64)?;
            if r.base <= addr && end <= top {
                let at = (addr - r.base) as usize;
                r.data.get(at..at + len)
            } else {
                None
            }
        })
    }
}

struct Rd<'a>(&'a [u8]);

impl Rd<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(at, 2)?.try_into().ok()?))
    }
    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(at, 4)?.try_into().ok()?))
    }
    fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(at, 8)?.try_into().ok()?))
    }
    fn bytes(&self, at: usize, len: usize) -> Option<&[u8]> {
        self.0.get(at..at.checked_add(len)?)
    }
}

fn utf16_string(rd: &Rd<'_>, rva: usize) -> Option<String> {
    let len = rd.u32(rva)? as usize;
    let raw = rd.bytes(rva + 4, len.min(2048))?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Parse a minidump. Every offset is checked; a damaged dump is an error, never a panic.
pub fn parse(data: &[u8]) -> Result<Dump, DumpError> {
    let rd = Rd(data);
    if rd.u32(0).ok_or(DumpError::Truncated("header"))? != SIGNATURE {
        return Err(DumpError::NotMinidump);
    }
    let n_streams = rd.u32(8).ok_or(DumpError::Truncated("header"))? as usize;
    let dir = rd.u32(12).ok_or(DumpError::Truncated("header"))? as usize;
    let timestamp = rd.u32(20).ok_or(DumpError::Truncated("header"))?;
    if n_streams > 4096 {
        return Err(DumpError::Unsupported("too many streams"));
    }
    let mut streams: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
    for i in 0..n_streams {
        let at = dir + i * 12;
        let ty = rd.u32(at).ok_or(DumpError::Truncated("stream directory"))?;
        let size = rd
            .u32(at + 4)
            .ok_or(DumpError::Truncated("stream directory"))? as usize;
        let rva = rd
            .u32(at + 8)
            .ok_or(DumpError::Truncated("stream directory"))? as usize;
        streams.entry(ty).or_insert((rva, size));
    }
    let architecture = streams
        .get(&STREAM_SYSTEM)
        .and_then(|(rva, _)| rd.u16(*rva))
        .unwrap_or(0xffff);
    if architecture != 9 {
        return Err(DumpError::Unsupported("only x64 dumps are read"));
    }
    let process_id = streams
        .get(&STREAM_MISC)
        .and_then(|(rva, _)| rd.u32(*rva + 8));

    let mut modules = Vec::new();
    if let Some(&(rva, _)) = streams.get(&STREAM_MODULES) {
        let n = rd.u32(rva).ok_or(DumpError::Truncated("module list"))?;
        if n > MAX_MODULES {
            return Err(DumpError::Unsupported("too many modules"));
        }
        for i in 0..n as usize {
            let at = rva + 4 + i * 108;
            let base = rd.u64(at).ok_or(DumpError::Truncated("module"))?;
            let size = rd.u32(at + 8).ok_or(DumpError::Truncated("module"))?;
            let checksum = rd.u32(at + 12).ok_or(DumpError::Truncated("module"))?;
            let stamp = rd.u32(at + 16).ok_or(DumpError::Truncated("module"))?;
            let name_rva = rd.u32(at + 20).ok_or(DumpError::Truncated("module"))? as usize;
            let name = utf16_string(&rd, name_rva).ok_or(DumpError::Truncated("module name"))?;
            modules.push(DumpModule {
                name: name.rsplit(['\\', '/']).next().unwrap_or(&name).to_string(),
                base,
                size,
                checksum,
                timestamp: stamp,
            });
        }
    }

    let mut threads = Vec::new();
    let mut stacks: Vec<(u64, Vec<u8>)> = Vec::new();
    if let Some(&(rva, _)) = streams.get(&STREAM_THREADS) {
        let n = rd.u32(rva).ok_or(DumpError::Truncated("thread list"))?;
        if n > MAX_THREADS {
            return Err(DumpError::Unsupported("too many threads"));
        }
        for i in 0..n as usize {
            let at = rva + 4 + i * 48;
            let thread_id = rd.u32(at).ok_or(DumpError::Truncated("thread"))?;
            let suspend_count = rd.u32(at + 4).ok_or(DumpError::Truncated("thread"))?;
            let teb = rd.u64(at + 16).ok_or(DumpError::Truncated("thread"))?;
            let stack_base = rd.u64(at + 24).ok_or(DumpError::Truncated("thread"))?;
            let stack_size = rd.u32(at + 32).ok_or(DumpError::Truncated("thread"))?;
            let stack_rva = rd.u32(at + 36).ok_or(DumpError::Truncated("thread"))? as usize;
            let ctx_size = rd.u32(at + 40).ok_or(DumpError::Truncated("thread"))? as usize;
            let ctx_rva = rd.u32(at + 44).ok_or(DumpError::Truncated("thread"))? as usize;
            let (rip, rsp) = match rd.bytes(ctx_rva, ctx_size.min(0x4d0)) {
                Some(ctx) if ctx.len() >= 0x100 => {
                    let c = Rd(ctx);
                    (c.u64(0xf8), c.u64(0x98))
                }
                _ => (None, None),
            };
            let stack = rd.bytes(stack_rva, stack_size as usize);
            if let Some(bytes) = stack {
                stacks.push((stack_base, bytes.to_vec()));
            }
            let frames = match (stack, rsp) {
                (Some(stack), Some(rsp)) => scan_stack(stack, stack_base, rsp, rip, &modules),
                _ => Vec::new(),
            };
            threads.push(DumpThread {
                thread_id,
                suspend_count,
                teb,
                stack_base,
                stack_size,
                rip,
                rsp,
                frames,
            });
        }
    }

    let mut memory: Vec<MemoryRange> = Vec::new();
    let mut total = 0usize;
    let mut keep = |base: u64, data: Option<&[u8]>| {
        if let Some(d) = data
            && memory.len() < MAX_RANGES
            && total + d.len() <= MAX_MEMORY_BYTES
            && !d.is_empty()
        {
            total += d.len();
            memory.push(MemoryRange {
                base,
                data: d.to_vec(),
            });
        }
    };
    if let Some(&(rva, _)) = streams.get(&STREAM_MEMORY) {
        let n = rd.u32(rva).unwrap_or(0) as usize;
        for i in 0..n.min(MAX_RANGES) {
            let at = rva + 4 + i * 16;
            if let (Some(start), Some(size), Some(data_rva)) =
                (rd.u64(at), rd.u32(at + 8), rd.u32(at + 12))
            {
                keep(start, rd.bytes(data_rva as usize, size as usize));
            }
        }
    }
    if let Some(&(rva, _)) = streams.get(&STREAM_MEMORY64) {
        let n = rd.u64(rva).unwrap_or(0) as usize;
        let mut data_at = rd.u64(rva + 8).unwrap_or(0) as usize;
        for i in 0..n.min(MAX_RANGES) {
            let at = rva + 16 + i * 16;
            if let (Some(start), Some(size)) = (rd.u64(at), rd.u64(at + 8)) {
                keep(start, rd.bytes(data_at, size as usize));
                data_at = data_at.saturating_add(size as usize);
            }
        }
    }
    for (base, bytes) in &stacks {
        keep(*base, Some(bytes));
    }
    let exception = streams.get(&STREAM_EXCEPTION).and_then(|&(rva, _)| {
        Some(DumpException {
            thread_id: rd.u32(rva)?,
            code: rd.u32(rva + 8)?,
            address: rd.u64(rva + 24)?,
        })
    });
    Ok(Dump {
        timestamp,
        architecture,
        process_id,
        modules,
        threads,
        exception,
        memory,
    })
}

fn in_module(modules: &[DumpModule], addr: u64) -> bool {
    modules
        .iter()
        .any(|m| m.base <= addr && addr < m.base.saturating_add(u64::from(m.size)))
}

/// Frames of one thread: the instruction pointer, then stack values that fall in a module, from
/// the stack pointer upward.
fn scan_stack(
    stack: &[u8],
    base: u64,
    rsp: u64,
    rip: Option<u64>,
    modules: &[DumpModule],
) -> Vec<u64> {
    let mut frames = Vec::new();
    if let Some(rip) = rip.filter(|r| in_module(modules, *r)) {
        frames.push(rip);
    }
    // `rsp` and `base` both come from the dump: an offset past the end of the stack (or past `usize`) means
    // "no frames", never an overflow or an inverted slice range.
    let start = usize::try_from(rsp.saturating_sub(base)).unwrap_or(usize::MAX);
    let mut off = start & !7;
    while frames.len() < MAX_FRAMES {
        let Some(word) = stack.get(off..).and_then(|s| s.first_chunk::<8>()) else {
            break;
        };
        let v = u64::from_le_bytes(*word);
        if in_module(modules, v) {
            frames.push(v);
        }
        let Some(next) = off.checked_add(8) else {
            break;
        };
        off = next;
    }
    frames
}

/// The trace events of a dump, as append payloads for source `source`: one `core.capture.source`,
/// a `core.module.load` per module, and a `dump.thread` per thread (with `va` = the instruction
/// pointer and `callstack` = the inferred frames), plus `dump.exception`.
pub fn to_events(dump: &Dump, source: &str) -> Vec<Value> {
    let mut seq = 0u64;
    let mut out = Vec::new();
    let t = u64::from(dump.timestamp) * 1_000_000_000;
    let mut push = |kind: &str, extra: Value, payload: Value| {
        let mut e = json!({
            "kind": kind, "source_id": source, "source_seq": seq, "producer_gen": 1,
            "clock_domain": "dump-wall", "t_mono_ns": t, "t_wall_ns": t, "confidence": "exact",
            "payload": payload,
        });
        if let (Some(o), Some(x)) = (e.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                o.insert(k.clone(), v.clone());
            }
        }
        out.push(e);
        seq += 1;
    };
    push(
        "core.capture.source",
        json!({}),
        json!({"state": "observing", "source_type": "minidump", "reason": "snapshot",
               "clock": {"unit": "unix-s", "resolution_ns": 1_000_000_000u64}}),
    );
    for m in &dump.modules {
        let mut extra = json!({"module": m.name});
        if let Some(pid) = dump.process_id {
            extra["process_id"] = pid.into();
        }
        push(
            "core.module.load",
            extra,
            json!({"name": m.name, "base": m.base, "size": m.size,
                   "build": format!("{:08x}-{:08x}-{:x}", m.timestamp, m.checksum, m.size)}),
        );
    }
    for th in &dump.threads {
        let mut extra = json!({"thread_id": th.thread_id, "callstack": th.frames,
                               "acquisition": "snapshot", "confidence": "inferred"});
        if let Some(pid) = dump.process_id {
            extra["process_id"] = pid.into();
        }
        if let Some(rip) = th.rip {
            extra["va"] = rip.into();
        }
        push(
            "dump.thread",
            extra,
            json!({"suspend_count": th.suspend_count, "teb": th.teb, "stack_base": th.stack_base,
                   "stack_size": th.stack_size, "rsp": th.rsp}),
        );
    }
    if let Some(ex) = &dump.exception {
        let mut extra = json!({"thread_id": ex.thread_id, "va": ex.address});
        if let Some(pid) = dump.process_id {
            extra["process_id"] = pid.into();
        }
        push(
            "dump.exception",
            extra,
            json!({"code": ex.code, "address": ex.address}),
        );
    }
    out
}

/// What the pattern pass needs to know about the host.
#[derive(Clone, Debug, Default)]
pub struct PatternConfig {
    /// Function names that mean "waiting on a lock or object".
    pub wait_functions: Vec<String>,
    /// The host's own fault handler (spec 15.1) function names.
    pub fault_handler_functions: Vec<String>,
    /// Functions whose presence on a stack means "this thread suspended the others".
    pub suspend_functions: Vec<String>,
}

impl PatternConfig {
    /// Defaults for Windows user mode.
    pub fn windows() -> Self {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect();
        Self {
            wait_functions: own(&[
                "NtWaitForSingleObject",
                "NtWaitForMultipleObjects",
                "WaitForSingleObject",
                "WaitForMultipleObjects",
                "RtlEnterCriticalSection",
                "RtlpWaitOnCriticalSection",
                "RtlAcquireSRWLockExclusive",
                "RtlSleepConditionVariableCS",
                "NtWaitForAlertByThreadId",
                "EnterCriticalSection",
            ]),
            fault_handler_functions: Vec::new(),
            suspend_functions: own(&["SuspendThread", "NtSuspendThread", "NtSuspendProcess"]),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Pattern {
    pub pattern: String,
    pub summary: String,
    /// Thread ids the pattern cites.
    pub threads: Vec<u32>,
    /// Frame addresses the pattern cites.
    pub frames: Vec<u64>,
    /// Limitation codes that weaken the claim.
    pub limitations: Vec<String>,
    /// Pattern-specific evidence (for a wait: the lock, its owner and the stack slot that held the lock pointer).
    #[serde(skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

/// Resolve a frame to a function name through the dump's modules.
pub fn resolve(dump: &Dump, symbolizer: &dyn Symbolizer, addr: u64) -> Option<String> {
    let m = dump
        .modules
        .iter()
        .find(|m| m.base <= addr && addr < m.base.saturating_add(u64::from(m.size)))?;
    let module = ModuleRef {
        name: &m.name,
        build: None,
        instance: 0,
    };
    match symbolizer.resolve(&module, addr - m.base) {
        Resolution::Symbol { function, .. } => Some(function),
        _ => None,
    }
}

struct LockWait {
    lock: Option<u64>,
    owner: Option<u32>,
    evidence: String,
}

/// The lock a waiting thread waits for, when its stack and the dump's data say so: a word on the stack that points at a
/// critical section (found in dump memory) whose OwningThread is another thread of the dump and whose recursion count is
/// positive. One such lock is the answer; several distinct ones are `lock-ambiguous`, none is `lock-owner-unresolved`.
fn lock_wait(dump: &Dump, th: &DumpThread) -> LockWait {
    let unresolved = |why: &str| LockWait {
        lock: None,
        owner: None,
        evidence: why.to_string(),
    };
    let Some(rsp) = th.rsp else {
        return unresolved("no stack pointer in the dump");
    };
    let top = th.stack_base.saturating_add(u64::from(th.stack_size));
    let len = (top.saturating_sub(rsp)).min(8192) as usize;
    let Some(stack) = dump.read(rsp, len) else {
        return unresolved("the thread's stack is not in the dump");
    };
    let mut found: Vec<(u64, u32, u64)> = Vec::new();
    for (i, word) in stack.as_chunks::<8>().0.iter().enumerate() {
        let v = u64::from_le_bytes(*word);
        if !(0x1_0000..=0x7fff_ffff_ffff).contains(&v) || (th.stack_base..top).contains(&v) {
            continue;
        }
        let Some(cs) = dump.read(v, 40) else { continue };
        let recursion = i32::from_le_bytes(cs[12..16].try_into().unwrap_or([0; 4]));
        let owning = u64::from_le_bytes(cs[16..24].try_into().unwrap_or([0; 8]));
        if recursion >= 1
            && owning != u64::from(th.thread_id)
            && dump
                .threads
                .iter()
                .any(|t| u64::from(t.thread_id) == owning)
            && !found.iter().any(|f| f.0 == v)
        {
            found.push((v, owning as u32, rsp + i as u64 * 8));
        }
    }
    match found.as_slice() {
        [] => unresolved("no critical section held by another thread is referenced from the stack"),
        [(lock, owner, slot)] => LockWait {
            lock: Some(*lock),
            owner: Some(*owner),
            evidence: format!(
                "stack slot {slot:#x} holds {lock:#x}, a critical section whose OwningThread is {owner}"
            ),
        },
        many => LockWait {
            lock: None,
            owner: None,
            evidence: format!("lock-ambiguous: {} candidate critical sections", many.len()),
        },
    }
}

/// Report the patterns of spec 15.9.
pub fn patterns(
    dump: &Dump,
    symbolizer: Option<&dyn Symbolizer>,
    cfg: &PatternConfig,
) -> Vec<Pattern> {
    let mut out = Vec::new();
    let names = |th: &DumpThread| -> Vec<(u64, Option<String>)> {
        th.frames
            .iter()
            .map(|&a| (a, symbolizer.and_then(|s| resolve(dump, s, a))))
            .collect()
    };
    let unsymbolized = |limits: &mut Vec<String>| {
        if symbolizer.is_none() {
            limits.push("no-symbol".into());
        }
    };

    // all threads suspended by thread T
    let running: Vec<&DumpThread> = dump
        .threads
        .iter()
        .filter(|t| t.suspend_count == 0)
        .collect();
    if dump.threads.len() >= 2 && running.len() == 1 {
        let t = running[0];
        let suspend_frames: Vec<u64> = names(t)
            .into_iter()
            .filter(|(_, n)| {
                n.as_ref()
                    .is_some_and(|n| cfg.suspend_functions.contains(n))
            })
            .map(|(a, _)| a)
            .collect();
        let mut limitations = Vec::new();
        unsymbolized(&mut limitations);
        out.push(Pattern {
            pattern: "all-threads-suspended".into(),
            summary: format!(
                "all {} other threads are suspended; thread {} is the only one running{}",
                dump.threads.len() - 1,
                t.thread_id,
                if suspend_frames.is_empty() {
                    " (no suspend call found on its stack)"
                } else {
                    " and its stack holds a suspend call"
                }
            ),
            threads: dump.threads.iter().map(|t| t.thread_id).collect(),
            frames: suspend_frames,
            limitations,
            detail: Value::Null,
        });
    }

    // N threads waiting at one site, and who holds what they wait for
    let mut waiters: Vec<(u32, String, u64)> = Vec::new();
    for th in &dump.threads {
        if let Some((addr, Some(name))) = names(th)
            .into_iter()
            .find(|(_, n)| n.as_ref().is_some_and(|n| cfg.wait_functions.contains(n)))
        {
            waiters.push((th.thread_id, name, addr));
        }
    }
    let locks: BTreeMap<u32, LockWait> = dump
        .threads
        .iter()
        .filter(|th| waiters.iter().any(|w| w.0 == th.thread_id))
        .map(|th| (th.thread_id, lock_wait(dump, th)))
        .collect();
    let wait_detail = |who: &[&(u32, String, u64)]| -> Value {
        Value::Array(
            who.iter()
                .map(|w| {
                    let l = &locks[&w.0];
                    json!({"thread": w.0, "site": w.1, "frame": w.2, "lock": l.lock,
                           "owner": l.owner, "evidence": l.evidence})
                })
                .collect(),
        )
    };
    let mut by_name: BTreeMap<&str, Vec<&(u32, String, u64)>> = BTreeMap::new();
    for w in &waiters {
        by_name.entry(w.1.as_str()).or_default().push(w);
    }
    for (name, who) in by_name {
        if who.len() >= 2 {
            let mut limitations = Vec::new();
            if who.iter().any(|w| locks[&w.0].owner.is_none()) {
                limitations.push("lock-owner-unresolved".to_string());
            }
            out.push(Pattern {
                pattern: "threads-waiting-on-one-site".into(),
                summary: format!("{} threads wait in {name}", who.len()),
                threads: who.iter().map(|w| w.0).collect(),
                frames: who.iter().map(|w| w.2).collect(),
                limitations,
                detail: wait_detail(&who),
            });
        }
    }
    // a cycle in "waits for a lock that thread X holds"
    let owner_of: BTreeMap<u32, u32> = locks
        .iter()
        .filter_map(|(t, l)| l.owner.map(|o| (*t, o)))
        .collect();
    let mut reported: Vec<Vec<u32>> = Vec::new();
    for start in owner_of.keys() {
        let mut chain = vec![*start];
        let mut at = *start;
        while let Some(next) = owner_of.get(&at) {
            if *next == *start {
                let mut key = chain.clone();
                key.sort_unstable();
                if !reported.contains(&key) {
                    reported.push(key);
                    let who: Vec<&(u32, String, u64)> = chain
                        .iter()
                        .filter_map(|t| waiters.iter().find(|w| w.0 == *t))
                        .collect();
                    out.push(Pattern {
                        pattern: "lock-wait-cycle".into(),
                        summary: format!(
                            "{} threads each wait for a lock another of them holds",
                            chain.len()
                        ),
                        threads: chain.clone(),
                        frames: who.iter().map(|w| w.2).collect(),
                        limitations: Vec::new(),
                        detail: wait_detail(&who),
                    });
                }
                break;
            }
            if chain.contains(next) || chain.len() > waiters.len() {
                break;
            }
            chain.push(*next);
            at = *next;
        }
    }

    // thread inside the host's fault handler
    for th in &dump.threads {
        let hits: Vec<u64> = names(th)
            .into_iter()
            .filter(|(_, n)| {
                n.as_ref()
                    .is_some_and(|n| cfg.fault_handler_functions.contains(n))
            })
            .map(|(a, _)| a)
            .collect();
        if !hits.is_empty() {
            out.push(Pattern {
                pattern: "thread-in-fault-handler".into(),
                summary: format!("thread {} is inside the host's fault handler", th.thread_id),
                threads: vec![th.thread_id],
                frames: hits,
                limitations: Vec::new(),
                detail: Value::Null,
            });
        }
    }
    out
}

/// The session event that last preceded the dump, joined by wall time. Events must carry
/// `t_wall_ns`; with none, the join is `clock-uncalibrated` and says so.
pub fn last_event_before(store: &crate::store::Store, dump: &Dump) -> crate::store::Result<Value> {
    let t = i64::from(dump.timestamp) * 1_000_000_000;
    let hit = store.conn().query_row(
        "SELECT event_id,kind,process_gen FROM events
         WHERE t_wall_ns IS NOT NULL AND t_wall_ns<=?1 AND source_id NOT LIKE 'minidump%'
         ORDER BY t_wall_ns DESC, seq DESC LIMIT 1",
        rusqlite::params![t],
        |r| {
            Ok(
                json!({"event_id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?,
                      "process_gen": r.get::<_, Option<i64>>(2)?}),
            )
        },
    );
    Ok(match hit {
        Ok(v) => json!({"last_event": v, "joined_by": "wall time (whole seconds)"}),
        Err(_) => json!({"last_event": null, "limitation": "clock-uncalibrated"}),
    })
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// A minimal x64 minidump builder for tests.
    pub struct Builder {
        pub modules: Vec<(String, u64, u32)>,
        /// (thread id, suspend count, stack base, rsp offset into the stack, stack words)
        pub threads: Vec<(u32, u32, u64, u64, Vec<u64>)>,
        pub pid: Option<u32>,
        pub exception: Option<(u32, u32, u64)>,
        pub timestamp: u32,
    }

    fn put32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    impl Builder {
        pub fn build(&self) -> Vec<u8> {
            let mut streams: Vec<(u32, Vec<u8>)> = Vec::new();
            // Data placed after the directory; patch RVAs once the layout is known.
            let mut data: Vec<u8> = Vec::new();
            let n_streams =
                3 + usize::from(self.pid.is_some()) + usize::from(self.exception.is_some());
            let base = 32 + n_streams * 12;
            let place = |data: &mut Vec<u8>, bytes: &[u8]| -> u32 {
                let at = base + data.len();
                data.extend_from_slice(bytes);
                while !data.len().is_multiple_of(8) {
                    data.push(0);
                }
                at as u32
            };
            // system info: arch 9
            let mut sys = vec![0u8; 56];
            sys[0..2].copy_from_slice(&9u16.to_le_bytes());
            streams.push((STREAM_SYSTEM, sys));
            // module names + list
            let mut list = Vec::new();
            put32(&mut list, self.modules.len() as u32);
            for (name, b, size) in &self.modules {
                let mut s = Vec::new();
                let units: Vec<u16> = name.encode_utf16().collect();
                put32(&mut s, (units.len() * 2) as u32);
                for u in units {
                    s.extend_from_slice(&u.to_le_bytes());
                }
                s.extend_from_slice(&[0, 0]);
                let name_rva = place(&mut data, &s);
                let mut m = Vec::new();
                put64(&mut m, *b);
                put32(&mut m, *size);
                put32(&mut m, 0xabcd);
                put32(&mut m, 0x1234_5678);
                put32(&mut m, name_rva);
                m.resize(108, 0);
                list.extend_from_slice(&m);
            }
            streams.push((STREAM_MODULES, list));
            // threads
            let mut tl = Vec::new();
            put32(&mut tl, self.threads.len() as u32);
            for (tid, suspend, sbase, rsp_off, words) in &self.threads {
                let mut stack = Vec::new();
                for w in words {
                    put64(&mut stack, *w);
                }
                let stack_rva = place(&mut data, &stack);
                let mut ctx = vec![0u8; 0x4d0];
                let rsp = sbase + rsp_off;
                ctx[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
                ctx[0xf8..0x100]
                    .copy_from_slice(&words.first().copied().unwrap_or(0).to_le_bytes());
                // rip is overwritten below by the first module address when requested
                let ctx_rva = place(&mut data, &ctx);
                let mut t = Vec::new();
                put32(&mut t, *tid);
                put32(&mut t, *suspend);
                put32(&mut t, 0);
                put32(&mut t, 0);
                put64(&mut t, 0x7ff0_0000 + u64::from(*tid));
                put64(&mut t, *sbase);
                put32(&mut t, stack.len() as u32);
                put32(&mut t, stack_rva);
                put32(&mut t, ctx.len() as u32);
                put32(&mut t, ctx_rva);
                tl.extend_from_slice(&t);
            }
            streams.push((STREAM_THREADS, tl));
            if let Some(pid) = self.pid {
                let mut misc = vec![0u8; 24];
                misc[0..4].copy_from_slice(&24u32.to_le_bytes());
                misc[4..8].copy_from_slice(&1u32.to_le_bytes());
                misc[8..12].copy_from_slice(&pid.to_le_bytes());
                streams.push((STREAM_MISC, misc));
            }
            if let Some((tid, code, addr)) = self.exception {
                let mut ex = vec![0u8; 168];
                ex[0..4].copy_from_slice(&tid.to_le_bytes());
                ex[8..12].copy_from_slice(&code.to_le_bytes());
                ex[24..32].copy_from_slice(&addr.to_le_bytes());
                streams.push((STREAM_EXCEPTION, ex));
            }
            let mut dir = Vec::new();
            let mut body = Vec::new();
            let streams_base = base + data.len();
            for (ty, bytes) in &streams {
                let rva = streams_base + body.len();
                body.extend_from_slice(bytes);
                while !body.len().is_multiple_of(8) {
                    body.push(0);
                }
                put32(&mut dir, *ty);
                put32(&mut dir, bytes.len() as u32);
                put32(&mut dir, rva as u32);
            }
            let mut out = Vec::new();
            put32(&mut out, SIGNATURE);
            put32(&mut out, 0xa793);
            put32(&mut out, streams.len() as u32);
            put32(&mut out, 32);
            put32(&mut out, 0);
            put32(&mut out, self.timestamp);
            put64(&mut out, 0);
            out.extend_from_slice(&dir);
            out.extend_from_slice(&data);
            out.extend_from_slice(&body);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::Builder;
    use super::*;
    use crate::symbolize::{FunctionRange, ModuleTable, TableSymbolizer};

    const BASE: u64 = 0x7ff6_0000_0000;

    fn table() -> TableSymbolizer {
        let mut t = TableSymbolizer::default();
        t.modules.insert(
            "game.exe".into(),
            ModuleTable {
                code: vec![],
                functions: vec![
                    FunctionRange {
                        start: 0x1000,
                        end: 0x1100,
                        name: "WaitForSingleObject".into(),
                        type_name: None,
                    },
                    FunctionRange {
                        start: 0x2000,
                        end: 0x2100,
                        name: "SuspendThread".into(),
                        type_name: None,
                    },
                    FunctionRange {
                        start: 0x3000,
                        end: 0x3100,
                        name: "HostFaultHandler".into(),
                        type_name: None,
                    },
                    FunctionRange {
                        start: 0x4000,
                        end: 0x4100,
                        name: "MainLoop".into(),
                        type_name: None,
                    },
                ],
            },
        );
        t
    }

    /// Stack words: values in the module are return addresses; others are noise.
    fn thread(tid: u32, suspend: u32, words: &[u64]) -> (u32, u32, u64, u64, Vec<u64>) {
        (
            tid,
            suspend,
            0x1000_0000 * u64::from(tid),
            0,
            words.to_vec(),
        )
    }

    fn dump(threads: Vec<(u32, u32, u64, u64, Vec<u64>)>) -> Vec<u8> {
        Builder {
            modules: vec![("C:\\bin\\game.exe".into(), BASE, 0x10000)],
            threads,
            pid: Some(4242),
            exception: Some((1, 0xc000_0005, BASE + 0x4010)),
            timestamp: 1_800_000_000,
        }
        .build()
    }

    #[test]
    fn parses_modules_threads_exception_and_scans_frames() {
        let bytes = dump(vec![
            thread(1, 0, &[BASE + 0x4010, 0xdead, BASE + 0x1010, 7]),
            thread(2, 1, &[BASE + 0x2010]),
        ]);
        let d = parse(&bytes).unwrap();
        assert_eq!(d.process_id, Some(4242));
        assert_eq!(d.modules[0].name, "game.exe");
        assert_eq!(d.modules[0].base, BASE);
        assert_eq!(d.threads.len(), 2);
        assert_eq!(
            d.threads[0].frames,
            vec![BASE + 0x4010, BASE + 0x4010, BASE + 0x1010]
        );
        assert_eq!(
            d.exception,
            Some(DumpException {
                thread_id: 1,
                code: 0xc000_0005,
                address: BASE + 0x4010
            })
        );
    }

    #[test]
    fn damaged_and_foreign_input_is_an_error_not_a_panic() {
        assert_eq!(parse(b"no").unwrap_err(), DumpError::Truncated("header"));
        assert_eq!(parse(b"nope").unwrap_err(), DumpError::NotMinidump);
        let mut junk = vec![0u8; 64];
        assert_eq!(parse(&junk).unwrap_err(), DumpError::NotMinidump);
        junk[0..4].copy_from_slice(&SIGNATURE.to_le_bytes());
        assert!(parse(&junk).is_err());
        let good = dump(vec![thread(1, 0, &[BASE + 0x1010])]);
        for cut in [10, 40, 100, good.len() - 5] {
            // every truncation either parses (when the cut is in padding) or errors
            let _ = parse(&good[..cut.min(good.len())]);
        }
        // a stream directory that points far outside the file
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn a_crafted_stack_pointer_cannot_overflow_the_frame_scan() {
        // rsp - base is near u64::MAX (rsp = u64::MAX - 7, base = 0x1000): the offset arithmetic must not wrap.
        for (sbase, rsp_off) in [
            (0x1000u64, u64::MAX - 0x1000 - 7),
            (0, u64::MAX),
            (0, u64::MAX - 7),
        ] {
            let bytes = dump(vec![(
                1,
                0,
                sbase,
                rsp_off,
                vec![BASE + 0x1010, BASE + 0x2010],
            )]);
            let d = parse(&bytes)
                .unwrap_or_else(|e| panic!("sbase {sbase:#x} rsp_off {rsp_off:#x}: {e:?}"));
            assert_eq!(d.threads.len(), 1);
            assert!(
                d.threads[0].frames.len() <= 1,
                "no stack words are reachable from rsp {:#x}",
                d.threads[0].rsp.unwrap_or(0)
            );
        }
        // base == rsp == u64::MAX is a valid zero offset: the words are scanned and nothing wraps
        let bytes = dump(vec![(
            1,
            0,
            u64::MAX,
            0,
            vec![BASE + 0x1010, BASE + 0x2010],
        )]);
        assert!(parse(&bytes).unwrap().threads[0].frames.len() >= 2);
        // the scan itself, directly, with the extreme offsets
        let stack = [0u8; 64];
        assert!(scan_stack(&stack, 0, u64::MAX, None, &[]).is_empty());
        assert!(scan_stack(&stack, 0, u64::MAX - 7, None, &[]).is_empty());
        assert!(scan_stack(&stack, 8, 7, None, &[]).len() <= MAX_FRAMES);
    }

    #[test]
    fn truncated_flipped_and_garbage_dumps_never_panic() {
        let good = dump(vec![
            thread(1, 0, &[BASE + 0x4010, 0xdead, BASE + 0x1010, 7]),
            thread(2, 1, &[BASE + 0x2010]),
        ]);
        // every possible truncation
        for cut in 0..=good.len() {
            let _ = parse(&good[..cut]);
        }
        // deterministic mutation fuzz: random bytes (biased to 0x00/0xff, the values that overflow) written into the
        // header, directory, stream bodies and thread records
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let mut bytes = good.clone();
            for _ in 0..1 + next() % 6 {
                let at = (next() % bytes.len() as u64) as usize;
                bytes[at] = match next() % 4 {
                    0 => 0x00,
                    1 => 0xff,
                    2 => 0x80,
                    _ => next() as u8,
                };
            }
            if next() % 4 == 0 {
                bytes.truncate((next() % bytes.len() as u64) as usize);
            }
            if let Ok(d) = parse(&bytes) {
                let _ = to_events(&d, "fuzz");
            }
        }
        // pure garbage with a valid signature
        for len in [0usize, 4, 32, 64, 4096] {
            let mut junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len >= 4 {
                junk[0..4].copy_from_slice(&SIGNATURE.to_le_bytes());
            }
            let _ = parse(&junk);
        }
    }

    #[test]
    fn all_threads_suspended_by_one_is_reported_with_citations() {
        // thread 3 runs and holds a SuspendThread frame; 1 and 2 are suspended.
        let bytes = dump(vec![
            thread(1, 1, &[BASE + 0x1010]),
            thread(2, 1, &[BASE + 0x1010]),
            thread(3, 0, &[BASE + 0x2010, BASE + 0x4010]),
        ]);
        let d = parse(&bytes).unwrap();
        let sym = table();
        let ps = patterns(&d, Some(&sym), &PatternConfig::windows());
        let p = ps
            .iter()
            .find(|p| p.pattern == "all-threads-suspended")
            .unwrap();
        assert!(p.summary.contains("thread 3"));
        assert!(p.summary.contains("suspend call"));
        assert!(p.frames.contains(&(BASE + 0x2010)));
        // no symbols: the claim is weaker and says so
        let weak = patterns(&d, None, &PatternConfig::windows());
        assert!(
            weak.iter()
                .find(|p| p.pattern == "all-threads-suspended")
                .unwrap()
                .limitations
                .contains(&"no-symbol".to_string())
        );
    }

    #[test]
    fn threads_waiting_at_one_site_and_the_fault_handler() {
        let bytes = dump(vec![
            thread(1, 0, &[BASE + 0x1010, BASE + 0x4010]),
            thread(2, 0, &[BASE + 0x1020, BASE + 0x4010]),
            thread(3, 0, &[BASE + 0x1030]),
            thread(4, 0, &[BASE + 0x3010, BASE + 0x4010]),
        ]);
        let d = parse(&bytes).unwrap();
        let sym = table();
        let cfg = PatternConfig {
            fault_handler_functions: vec!["HostFaultHandler".into()],
            ..PatternConfig::windows()
        };
        let ps = patterns(&d, Some(&sym), &cfg);
        let wait = ps
            .iter()
            .find(|p| p.pattern == "threads-waiting-on-one-site")
            .unwrap();
        assert_eq!(wait.threads, vec![1, 2, 3]);
        assert!(
            wait.limitations
                .contains(&"lock-owner-unresolved".to_string())
        );
        let fault = ps
            .iter()
            .find(|p| p.pattern == "thread-in-fault-handler")
            .unwrap();
        assert_eq!(fault.threads, vec![4]);
        assert!(!ps.iter().any(|p| p.pattern == "all-threads-suspended"));
    }

    /// A critical section as the dump's memory holds it: LockCount, RecursionCount and OwningThread are what is read.
    fn critical_section(owner: u64) -> MemoryRange {
        let mut data = vec![0u8; 40];
        data[12..16].copy_from_slice(&1i32.to_le_bytes());
        data[16..24].copy_from_slice(&owner.to_le_bytes());
        MemoryRange { base: 0, data }
    }

    #[test]
    fn a_lock_wait_cycle_is_found_from_the_stacks_and_the_dump_memory() {
        let (lock_a, lock_b) = (0x5000_0000u64, 0x5000_0100u64);
        // thread 1 owns A and waits for B (owned by 2); thread 2 owns B and waits for A; thread 3 waits for nothing it can name
        let bytes = dump(vec![
            thread(1, 0, &[BASE + 0x1010, lock_b]),
            thread(2, 0, &[BASE + 0x1020, lock_a]),
            thread(3, 0, &[BASE + 0x1030]),
        ]);
        let mut d = parse(&bytes).unwrap();
        d.memory.push(MemoryRange {
            base: lock_a,
            ..critical_section(1)
        });
        d.memory.push(MemoryRange {
            base: lock_b,
            ..critical_section(2)
        });
        let sym = table();
        let ps = patterns(&d, Some(&sym), &PatternConfig::windows());
        let cycle = ps.iter().find(|p| p.pattern == "lock-wait-cycle").unwrap();
        assert_eq!(cycle.threads, vec![1, 2]);
        assert!(cycle.limitations.is_empty());
        let detail = cycle.detail.as_array().unwrap();
        assert_eq!(detail[0]["owner"], 2);
        assert_eq!(detail[0]["lock"], lock_b);
        assert_eq!(detail[1]["owner"], 1);
        assert!(
            detail[0]["evidence"]
                .as_str()
                .unwrap()
                .contains("OwningThread is 2")
        );
        // thread 3 is still reported as waiting at the same site, with its owner unresolved
        let wait = ps
            .iter()
            .find(|p| p.pattern == "threads-waiting-on-one-site")
            .unwrap();
        assert_eq!(wait.threads, vec![1, 2, 3]);
        assert!(
            wait.limitations
                .contains(&"lock-owner-unresolved".to_string())
        );
    }

    #[test]
    fn two_candidate_locks_on_one_stack_are_ambiguous_not_guessed() {
        let (lock_a, lock_b) = (0x5000_0000u64, 0x5000_0100u64);
        let bytes = dump(vec![
            thread(1, 0, &[BASE + 0x1010, lock_a, lock_b]),
            thread(2, 0, &[BASE + 0x1020]),
        ]);
        let mut d = parse(&bytes).unwrap();
        d.memory.push(MemoryRange {
            base: lock_a,
            ..critical_section(2)
        });
        d.memory.push(MemoryRange {
            base: lock_b,
            ..critical_section(2)
        });
        let ps = patterns(&d, Some(&table()), &PatternConfig::windows());
        assert!(!ps.iter().any(|p| p.pattern == "lock-wait-cycle"));
        let wait = ps
            .iter()
            .find(|p| p.pattern == "threads-waiting-on-one-site")
            .unwrap();
        assert!(
            wait.detail[0]["evidence"]
                .as_str()
                .unwrap()
                .contains("lock-ambiguous")
        );
        assert_eq!(wait.detail[0]["owner"], serde_json::Value::Null);
    }

    #[test]
    fn dump_memory_is_read_only_inside_one_range() {
        let d = Dump {
            timestamp: 0,
            architecture: 9,
            process_id: None,
            modules: Vec::new(),
            threads: Vec::new(),
            exception: None,
            memory: vec![MemoryRange {
                base: 0x100,
                data: vec![1, 2, 3, 4],
            }],
        };
        assert_eq!(d.read(0x101, 2), Some(&[2u8, 3][..]));
        assert_eq!(
            d.read(0x102, 3),
            None,
            "a read that runs past the range is not answered"
        );
        assert_eq!(d.read(0xff, 1), None);
        assert_eq!(d.read(u64::MAX, 8), None);
    }

    #[test]
    fn events_import_into_a_session_and_symbolize() {
        use crate::store::{Budget, Options, Store};
        use std::sync::Arc;
        let bytes = dump(vec![
            thread(1, 0, &[BASE + 0x1010, BASE + 0x4010]),
            thread(2, 1, &[BASE + 0x2010]),
        ]);
        let d = parse(&bytes).unwrap();
        let events = to_events(&d, "minidump");
        let mut store = Store::memory("dump").unwrap();
        store
            .set_options(Options {
                symbolizer: Some(Arc::new(table())),
                symbol_revision: "p@1".into(),
                budget: Budget::default(),
            })
            .unwrap();
        let mut chain = crate::raw::Chain::new("minidump");
        let bytes: Vec<u8> = events
            .iter()
            .flat_map(|e| chain.push(e.as_object().unwrap().clone()).unwrap())
            .collect();
        let scan = crate::raw::scan(&bytes, "minidump");
        let stats = store.ingest("minidump", 0, &scan.records).unwrap();
        assert_eq!(stats.rejected, 0, "{events:?}");
        let c = crate::symbolize::counts(&store, None).unwrap().unwrap();
        // thread 1's rip resolves to WaitForSingleObject, thread 2's to SuspendThread
        assert_eq!(c.symbolized, 2 + 1 /* exception address */);
        assert_eq!(store.event_count().unwrap(), 1 + 1 + 2 + 1);
    }
}
