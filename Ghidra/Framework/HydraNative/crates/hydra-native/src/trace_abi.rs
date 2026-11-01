//! The trace C ABI (`hydra_trace_*` in `include/hydra_native.h`): request bytes in, reply bytes out.
//!
//! Java (`TraceCommands`) routes a protocol 3 `trace_*` request to [`hydra_trace_call`] and sends
//! the reply bytes back through the direct-reply path. The ABI is the contract between lanes
//! L-proto (Java, clients) and L-store (this crate's engine). **This file is the L-proto stub
//! implementation** of that contract on top of the `hydra-trace` store: it implements all twelve
//! commands with the TRACE-1 semantics that fit a thin layer, so the protocol, the writer lease,
//! the clients and the tests run end to end. L-store replaces the bodies of [`dispatch`] with the
//! real engine (group-commit ingest, relations, aligned diff, artifacts) and keeps the names, the
//! argument and reply shapes of `PROTOCOL-3.md` "Trace commands".
//!
//! Rules this layer keeps:
//!
//! * the raw segment is written first, then the index commits the same records as one group
//!   (so a reader sees whole batches only, and a writer killed between the two leaves a tail
//!   that the next owner's open indexes again);
//! * a reply never contains a time, a pid or an address of this process, so the same input gives
//!   the same bytes;
//! * no panic crosses the ABI (the release profile aborts on panic): every failure is a status.

use hydra_trace::model::{Event, kind_is_valid};
use hydra_trace::query::{self, Assertion, Filter};
use hydra_trace::raw::{self, Chain, Damage};
use hydra_trace::store::{self, Store};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The version of the `hydra_trace_*` ABI; it changes when a function or a shape below changes.
pub const TRACE_ABI_VERSION: u32 = 1;

/// A symbolizer callback (see `hydra_native.h`): fills `out` with a JSON object and returns its
/// length; 0 is "no symbol", -1 "module unknown", -2 "not code", -3 "revision unknown".
pub type SymbolizeFn = unsafe extern "C" fn(
    session: *const u8,
    session_len: usize,
    revision: u64,
    module: *const u8,
    module_len: usize,
    va: u64,
    out: *mut u8,
    out_cap: usize,
) -> i32;

static SYMBOLIZER: Mutex<Option<SymbolizeFn>> = Mutex::new(None);

/// One reply: a status (0 ok) and the JSON bytes of the result, or of the error object.
pub struct TraceReply {
    status: i32,
    bytes: Vec<u8>,
}

/// `HYDRA_TRACE_ABI_VERSION`.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_trace_abi_version() -> u32 {
    TRACE_ABI_VERSION
}

/// Installs the process-wide symbolizer (NULL removes it). It may be called from any thread the
/// engine uses to ingest.
///
/// # Safety
/// `cb` must stay valid until it is replaced or removed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_set_symbolizer(cb: Option<SymbolizeFn>) {
    if let Ok(mut slot) = SYMBOLIZER.lock() {
        *slot = cb;
    }
}

/// Runs one trace command.
///
/// `cmd` is the command name (`trace_open`, ...), `ctx` a small JSON object the engine adds
/// (`root`, `session`, `producerGen`, `lease`, `symbolRevision`, `budget`), `req` the client's
/// request object. `cancel` is NULL or points to an int the caller sets non-zero to cancel; long
/// work polls it. Never returns NULL for valid arguments: free with [`hydra_trace_reply_free`].
///
/// # Safety
/// Each pointer is valid for its length (or NULL with length 0); `cancel`, if not NULL, stays
/// valid until this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_call(
    cmd: *const u8,
    cmd_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    req: *const u8,
    req_len: usize,
    cancel: *const i32,
) -> *mut TraceReply {
    // SAFETY: pointer and length are given together by the caller.
    let (cmd, ctx, req) = unsafe {
        (
            bytes(cmd, cmd_len),
            bytes(ctx, ctx_len),
            bytes(req, req_len),
        )
    };
    let flag = Cancel(cancel);
    let reply = match run(cmd, ctx, req, &flag) {
        Ok(value) => TraceReply {
            status: 0,
            bytes: value.to_string().into_bytes(),
        },
        Err(fail) => TraceReply {
            status: 1,
            bytes: fail.to_json().to_string().into_bytes(),
        },
    };
    Box::into_raw(Box::new(reply))
}

/// 0 for a result, non-zero for an error object (`{"code","message","details"}`).
///
/// # Safety
/// `r` comes from [`hydra_trace_call`] and is not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_reply_status(r: *const TraceReply) -> i32 {
    // SAFETY: guaranteed by the caller.
    unsafe { r.as_ref() }.map_or(-1, |r| r.status)
}

/// The reply bytes (valid until [`hydra_trace_reply_free`]).
///
/// # Safety
/// As [`hydra_trace_reply_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_reply_ptr(r: *const TraceReply) -> *const u8 {
    // SAFETY: guaranteed by the caller.
    unsafe { r.as_ref() }.map_or(std::ptr::null(), |r| r.bytes.as_ptr())
}

/// The length of the reply bytes.
///
/// # Safety
/// As [`hydra_trace_reply_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_reply_len(r: *const TraceReply) -> usize {
    // SAFETY: guaranteed by the caller.
    unsafe { r.as_ref() }.map_or(0, |r| r.bytes.len())
}

/// Frees a reply.
///
/// # Safety
/// `r` comes from [`hydra_trace_call`] and is freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_trace_reply_free(r: *mut TraceReply) {
    if !r.is_null() {
        // SAFETY: guaranteed by the caller.
        drop(unsafe { Box::from_raw(r) });
    }
}

/// # Safety
/// `p` is valid for `len` bytes, or NULL.
unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: guaranteed by the caller.
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

struct Cancel(*const i32);

impl Cancel {
    fn is_set(&self) -> bool {
        if self.0.is_null() {
            return false;
        }
        // SAFETY: the caller of `hydra_trace_call` keeps the int valid until the call returns.
        unsafe { AtomicI32::from_ptr(self.0.cast_mut()) }.load(Ordering::Acquire) != 0
    }
}

// ---------------------------------------------------------------------------------- failures

struct Fail {
    code: &'static str,
    message: String,
    details: Option<Value>,
}

impl Fail {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    fn with(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    fn to_json(&self) -> Value {
        let mut o = json!({"code": self.code, "message": self.message});
        if let Some(d) = &self.details {
            o["details"] = d.clone();
        }
        o
    }
}

impl From<store::Error> for Fail {
    fn from(e: store::Error) -> Self {
        Self::new("failed", format!("trace store: {e}"))
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Self::new("failed", format!("trace io: {e}"))
    }
}

type Res<T> = Result<T, Fail>;

// ---------------------------------------------------------------------------------- routing

fn run(cmd: &[u8], ctx: &[u8], req: &[u8], cancel: &Cancel) -> Res<Value> {
    let cmd = std::str::from_utf8(cmd).map_err(|_| Fail::bad("cmd is not UTF-8"))?;
    let ctx: Value = if ctx.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(ctx).map_err(|e| Fail::bad(format!("ctx: {e}")))?
    };
    let req: Value = if req.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(req).map_err(|e| Fail::bad(format!("request: {e}")))?
    };
    if !req.is_object() || !ctx.is_object() {
        return Err(Fail::bad("a request is a JSON object"));
    }
    dispatch(cmd, &ctx, &req, cancel)
}

fn dispatch(cmd: &str, ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    match cmd {
        "trace_open" => cmd_open(ctx, req),
        "trace_append" => cmd_append(ctx, req, cancel),
        "trace_mark" => cmd_mark(ctx, req),
        "trace_query" => cmd_query(ctx, req, cancel),
        "trace_explain" => cmd_explain(ctx, req, cancel),
        "trace_diff" => cmd_diff(ctx, req, cancel),
        "trace_check" => cmd_check(ctx, req),
        "trace_export" => cmd_export(ctx, req, cancel),
        "trace_close" => cmd_close(ctx, req),
        "trace_list" => cmd_list(ctx),
        "trace_info" => cmd_info(ctx, req),
        "trace_resymbolize" => cmd_resymbolize(ctx, req, cancel),
        other => Err(Fail::new(
            "unknown_command",
            format!("unknown trace command '{other}'"),
        )),
    }
}

// ---------------------------------------------------------------------------------- helpers

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn number(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

/// `[A-Za-z0-9_-]{1,64}`: a session id is a folder name, never a path.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_source(id: &str) -> bool {
    valid_id(&id.replace('.', "_"))
}

fn root_of(ctx: &Value) -> Res<PathBuf> {
    text(ctx, "root")
        .map(PathBuf::from)
        .ok_or_else(|| Fail::new("failed", "the engine gave no trace root"))
}

fn session_of(ctx: &Value) -> Res<String> {
    let id = text(ctx, "session").ok_or_else(|| Fail::bad("missing field: session"))?;
    if !valid_id(id) {
        return Err(Fail::bad(
            "session must be 1 to 64 of letters, digits, _ and -",
        ));
    }
    Ok(id.to_owned())
}

fn dir_of(ctx: &Value, session: &str) -> Res<PathBuf> {
    Ok(root_of(ctx)?.join(session))
}

fn not_found(session: &str) -> Fail {
    Fail::new("not_found", format!("no trace session '{session}'"))
        .with(json!({"session": session}))
}

fn reader_of(ctx: &Value, session: &str) -> Res<Store> {
    let dir = dir_of(ctx, session)?;
    if !dir.join("session.json").is_file() {
        return Err(not_found(session));
    }
    let db = dir.join("index.db");
    if !db.is_file() {
        return Err(Fail::new(
            "not_found",
            format!("trace session '{session}' has no index yet"),
        ));
    }
    Ok(Store::reader(&db, session)?)
}

fn check_cancel(cancel: &Cancel) -> Res<()> {
    if cancel.is_set() {
        Err(Fail::new("cancelled", "trace request cancelled"))
    } else {
        Ok(())
    }
}

fn require_owner(ctx: &Value, cmd: &str) -> Res<()> {
    let role = ctx.get("lease").and_then(|l| text(l, "role"));
    if role == Some("owner") {
        Ok(())
    } else {
        Err(Fail::new(
            "not_owner",
            format!("{cmd} needs the writer lease of the session"),
        ))
    }
}

fn session_meta(dir: &Path) -> Res<Value> {
    let bytes = fs::read(dir.join("session.json"))?;
    serde_json::from_slice(&bytes).map_err(|e| Fail::new("failed", format!("session.json: {e}")))
}

fn write_meta(dir: &Path, meta: &Value) -> Res<()> {
    let tmp = dir.join("session.json.tmp");
    fs::write(&tmp, meta.to_string())?;
    fs::rename(&tmp, dir.join("session.json"))?;
    Ok(())
}

// ---------------------------------------------------------------------------------- live writers

/// The state of one session's writer in this process.
struct Live {
    dir: PathBuf,
    store: Store,
    sources: HashMap<String, Source>,
    session: String,
}

struct Source {
    chain: Chain,
    file: File,
    records: u64,
    last: Option<(u32, u64)>,
    frozen: Option<String>,
}

static LIVE: OnceLock<Mutex<HashMap<String, Arc<Mutex<Live>>>>> = OnceLock::new();

fn live_map() -> &'static Mutex<HashMap<String, Arc<Mutex<Live>>>> {
    LIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn seg_path(dir: &Path, source: &str) -> PathBuf {
    dir.join(format!("seg-{source}.trace"))
}

/// What opening a writer found on disk.
#[derive(Default)]
struct Recovered {
    segments: u64,
    records: u64,
    reindexed: u64,
    torn_bytes: u64,
    damaged: Vec<Value>,
}

fn attach(dir: &Path, session: &str) -> Res<(Arc<Mutex<Live>>, Recovered)> {
    let mut map = live_map()
        .lock()
        .map_err(|_| Fail::new("failed", "trace registry poisoned"))?;
    if let Some(live) = map.get(session) {
        return Ok((live.clone(), Recovered::default()));
    }
    let mut store = Store::open(&dir.join("index.db"), session)?;
    let mut recovered = Recovered::default();
    let mut sources = HashMap::new();
    let indexed: HashMap<String, u64> =
        store
            .batches()?
            .into_iter()
            .fold(HashMap::new(), |mut m, b| {
                *m.entry(b.source_id).or_insert(0) += b.count;
                m
            });
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".trace"))
        })
        .collect();
    files.sort();
    for path in files {
        let Some(source) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("seg-"))
            .and_then(|n| n.strip_suffix(".trace"))
            .map(str::to_owned)
        else {
            continue;
        };
        let data = fs::read(&path)?;
        let scan = raw::scan(&data, &source);
        recovered.segments += 1;
        recovered.records += scan.records.len() as u64;
        let mut frozen = None;
        match &scan.damage {
            Some(Damage::TornTail { bytes, .. }) => {
                // the previous writer died mid-line: the owner cuts the tail so appends chain on
                recovered.torn_bytes += *bytes as u64;
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(scan.valid_end as u64)?;
            }
            Some(other) => {
                frozen = Some(format!("{other:?}"));
                recovered
                    .damaged
                    .push(json!({"source": source, "damage": format!("{other:?}")}));
            }
            None => {}
        }
        let have = indexed.get(&source).copied().unwrap_or(0);
        if (have as usize) < scan.records.len() {
            let tail = &scan.records[have as usize..];
            store.ingest(&source, have, tail)?;
            recovered.reindexed += tail.len() as u64;
        }
        let mut chain = Chain::new(&source);
        let mut last = None;
        for record in &scan.records {
            let mut body = record.clone();
            for field in ["n", "prev", "hash"] {
                body.remove(field);
            }
            last = body
                .get("source_seq")
                .and_then(Value::as_u64)
                .zip(body.get("producer_gen").and_then(Value::as_u64))
                .map(|(s, g)| (g as u32, s));
            if chain.push(body).is_err() {
                frozen = Some("segment cannot be re-chained".into());
            }
        }
        if frozen.is_none() && chain.head() != scan.head {
            frozen = Some("chain head differs after replay".into());
        }
        let file = OpenOptions::new().append(true).create(true).open(&path)?;
        sources.insert(
            source,
            Source {
                chain,
                file,
                records: scan.records.len() as u64,
                last,
                frozen,
            },
        );
    }
    let live = Arc::new(Mutex::new(Live {
        dir: dir.to_path_buf(),
        store,
        sources,
        session: session.to_owned(),
    }));
    map.insert(session.to_owned(), live.clone());
    Ok((live, recovered))
}

fn detach(session: &str) {
    if let Ok(mut map) = live_map().lock() {
        map.remove(session);
    }
}

// ---------------------------------------------------------------------------------- symbols

fn symbolize(session: &str, revision: u64, module: &str, va: u64) -> Value {
    let cb = SYMBOLIZER.lock().ok().and_then(|g| *g);
    let Some(cb) = cb else {
        return json!({"function": null, "reason": "no-symbol"});
    };
    let mut out = vec![0u8; 512];
    // SAFETY: the callback's contract (hydra_native.h): it reads the inputs for the call only
    // and writes at most `out_cap` bytes into `out`.
    let n = unsafe {
        cb(
            session.as_ptr(),
            session.len(),
            revision,
            module.as_ptr(),
            module.len(),
            va,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    match n {
        n if n > 0 && (n as usize) <= out.len() => {
            serde_json::from_slice::<Value>(&out[..n as usize])
                .map(|mut v| {
                    v["reason"] = Value::Null;
                    v
                })
                .unwrap_or_else(|_| json!({"function": null, "reason": "no-symbol"}))
        }
        -1 => json!({"function": null, "reason": "module-unknown"}),
        -2 => json!({"function": null, "reason": "not-code"}),
        _ => json!({"function": null, "reason": "no-symbol"}),
    }
}

/// Appends interpretation rows (`interp-<revision>.jsonl`): the raw observations stay as written.
fn write_interp(dir: &Path, revision: u64, rows: &[Value]) -> Res<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(dir.join(format!("interp-{revision}.jsonl")))?;
    let mut buf = Vec::new();
    for row in rows {
        buf.extend_from_slice(row.to_string().as_bytes());
        buf.push(b'\n');
    }
    f.write_all(&buf)?;
    Ok(())
}

// ---------------------------------------------------------------------------------- commands

fn cmd_open(ctx: &Value, req: &Value) -> Res<Value> {
    let session = session_of(ctx)?;
    let dir = dir_of(ctx, &session)?;
    let exists = dir.join("session.json").is_file();
    let create = req.get("create").and_then(Value::as_bool).unwrap_or(false);
    let owner = ctx.get("lease").and_then(|l| text(l, "role")) == Some("owner");
    if !exists && !create {
        return Err(not_found(&session));
    }
    let mut created = false;
    if !exists {
        fs::create_dir_all(&dir)?;
        let meta = json!({
            "schema": "hydra.trace.session/1",
            "session": session,
            "name": text(req, "name").unwrap_or(""),
            "program": text(req, "program"),
            "profile": text(req, "profile"),
            "symbolRevision": number(ctx, "symbolRevision"),
            "closed": false,
        });
        write_meta(&dir, &meta)?;
        created = true;
    }
    let mut meta = session_meta(&dir)?;
    let mut recovered = Recovered::default();
    if owner {
        let (_, r) = attach(&dir, &session)?;
        recovered = r;
        if meta["closed"] == json!(true) {
            meta["closed"] = json!(false);
            write_meta(&dir, &meta)?;
        }
    }
    let (revision, events) = counts(&dir, &session);
    Ok(json!({
        "session": session,
        "created": created,
        "name": meta["name"],
        "closed": meta["closed"],
        "revision": revision,
        "events": events,
        "symbolRevision": number(ctx, "symbolRevision"),
        "symbols": ctx.get("symbols").cloned().unwrap_or(Value::Null),
        "lease": ctx.get("lease").cloned().unwrap_or(Value::Null),
        "recovered": {
            "segments": recovered.segments,
            "records": recovered.records,
            "reindexed": recovered.reindexed,
            "tornTailBytes": recovered.torn_bytes,
            "damaged": recovered.damaged,
        },
    }))
}

fn counts(dir: &Path, session: &str) -> (u64, u64) {
    let db = dir.join("index.db");
    if !db.is_file() {
        return (0, 0);
    }
    match Store::reader(&db, session) {
        Ok(s) => (s.revision().unwrap_or(0), s.event_count().unwrap_or(0)),
        Err(_) => (0, 0),
    }
}

const MAX_APPEND_EVENTS: usize = 10_000;

fn cmd_append(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    require_owner(ctx, "trace_append")?;
    let session = session_of(ctx)?;
    let dir = dir_of(ctx, &session)?;
    if !dir.join("session.json").is_file() {
        return Err(not_found(&session));
    }
    let events = req
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| Fail::bad("events must be an array"))?;
    if events.len() > MAX_APPEND_EVENTS {
        return Err(Fail::bad(format!(
            "events: at most {MAX_APPEND_EVENTS} per request"
        )));
    }
    let producer_gen = number(ctx, "producerGen").unwrap_or(1) as u32;
    let revision = number(ctx, "symbolRevision").unwrap_or(0);
    let default_source = text(req, "source").unwrap_or("api").to_owned();
    let (live, _) = attach(&dir, &session)?;
    let mut live = live
        .lock()
        .map_err(|_| Fail::new("failed", "trace session poisoned"))?;
    let mut rejected: Vec<Value> = Vec::new();
    let mut per_source: Vec<(String, Vec<Map<String, Value>>)> = Vec::new();
    // validate and number; nothing is written until the whole request is checked
    let mut pending_seq: HashMap<String, u64> = HashMap::new();
    for (index, raw_event) in events.iter().enumerate() {
        check_cancel(cancel)?;
        let mut o = match raw_event {
            Value::Object(o) => o.clone(),
            _ => {
                rejected.push(json!({"index": index, "reason": "an event is an object"}));
                continue;
            }
        };
        let source = o
            .get("source_id")
            .and_then(Value::as_str)
            .unwrap_or(&default_source)
            .to_owned();
        if !valid_source(&source) {
            rejected.push(json!({"index": index, "reason": "bad source_id"}));
            continue;
        }
        for forbidden in ["seq", "event_id", "static", "revision"] {
            if o.remove(forbidden).is_some() {
                rejected.push(json!({"index": index, "reason": format!("a producer must not set {forbidden}")}));
            }
        }
        if rejected.last().is_some_and(|r| r["index"] == json!(index)) {
            continue;
        }
        if let Some(g) = o.get("producer_gen").and_then(Value::as_u64)
            && g as u32 != producer_gen
        {
            rejected.push(json!({"index": index, "reason": format!(
                "producer_gen {g} is not the lease's generation {producer_gen}")}));
            continue;
        }
        o.insert("source_id".into(), json!(source));
        o.insert("producer_gen".into(), json!(producer_gen));
        o.entry("clock_domain").or_insert(json!("external"));
        o.entry("t_mono_ns").or_insert(json!(0));
        o.entry("confidence").or_insert(json!("exact"));
        if !o.contains_key("source_seq") {
            let src = live.sources.get(&source);
            let base = pending_seq.get(&source).copied().unwrap_or_else(|| {
                src.and_then(|s| s.last)
                    .filter(|(g, _)| *g == producer_gen)
                    .map_or(0, |(_, s)| s)
            });
            o.insert("source_seq".into(), json!(base + 1));
        }
        let seq = o["source_seq"].as_u64().unwrap_or(0);
        let event: Event = match serde_json::from_value(Value::Object(o)) {
            Ok(e) => e,
            Err(e) => {
                rejected.push(json!({"index": index, "reason": format!("schema: {e}")}));
                continue;
            }
        };
        if !kind_is_valid(&event.kind) {
            rejected
                .push(json!({"index": index, "reason": format!("unknown kind {}", event.kind)}));
            continue;
        }
        // only an accepted event uses up its number: a refused one leaves no gap
        pending_seq.insert(source.clone(), seq);
        match per_source.iter_mut().find(|(s, _)| *s == source) {
            Some((_, v)) => v.push(event.to_record()),
            None => per_source.push((source, vec![event.to_record()])),
        }
    }
    let mut appended = 0u64;
    let mut stats = store::IngestStats::default();
    let (mut symbolized, mut unresolved) = (0u64, 0u64);
    let mut interp: Vec<Value> = Vec::new();
    for (source, records) in per_source {
        check_cancel(cancel)?;
        if !live.sources.contains_key(&source) {
            let path = seg_path(&live.dir, &source);
            let file = OpenOptions::new().append(true).create(true).open(&path)?;
            live.sources.insert(
                source.clone(),
                Source {
                    chain: Chain::new(&source),
                    file,
                    records: 0,
                    last: None,
                    frozen: None,
                },
            );
        }
        let session_id = live.session.clone();
        let src = live
            .sources
            .get_mut(&source)
            .ok_or_else(|| Fail::new("failed", "source"))?;
        if let Some(why) = &src.frozen {
            return Err(Fail::new(
                "conflict",
                format!("segment {source} is damaged ({why}); start a new source"),
            ));
        }
        let first_n = src.records;
        let mut chained = Vec::with_capacity(records.len());
        let mut buf = Vec::new();
        let mut chain = Chain::new(&source);
        std::mem::swap(&mut chain, &mut src.chain);
        let mut chain_failed = None;
        for (i, record) in records.into_iter().enumerate() {
            let va = record.get("va").and_then(Value::as_u64);
            let module = record
                .get("module")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let sseq = record
                .get("source_seq")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            match chain.push(record) {
                Ok(line) => {
                    if let Ok(Value::Object(m)) =
                        serde_json::from_slice::<Value>(&line[9..line.len() - 1])
                    {
                        chained.push(m);
                    }
                    buf.extend_from_slice(&line);
                    if let Some(va) = va {
                        let mut s = symbolize(&session_id, revision, &module, va);
                        if s["function"].is_null() {
                            unresolved += 1;
                        } else {
                            symbolized += 1;
                        }
                        s["source"] = json!(source);
                        s["n"] = json!(first_n + i as u64);
                        s["va"] = json!(va);
                        interp.push(s);
                    }
                    src.last = Some((producer_gen, sseq));
                }
                Err(_) => {
                    chain_failed = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = chain_failed {
            // a record with a floating point number: the whole source batch is refused, nothing
            // was written and the chain is rebuilt from the segment on the next open
            drop(chain);
            live.sources.remove(&source);
            detach(&session_id);
            return Err(Fail::bad(format!(
                "event {i} of source {source} is not canonical (floating point numbers are not allowed; use integers)"
            )));
        }
        src.chain = chain;
        src.file.write_all(&buf)?;
        src.file.flush()?;
        src.records += chained.len() as u64;
        let s = live.store.ingest(&source, first_n, &chained)?;
        stats.stored += s.stored;
        stats.rejected += s.rejected;
        stats.gaps_found += s.gaps_found;
        stats.revision = s.revision;
        appended += chained.len() as u64;
    }
    write_interp(&live.dir, revision, &interp)?;
    let (rev, total) = (live.store.revision()?, live.store.event_count()?);
    Ok(json!({
        "session": session,
        "appended": appended,
        "stored": stats.stored,
        "rejected": rejected.len() as u64 + stats.rejected,
        "rejectedEvents": rejected.into_iter().take(20).collect::<Vec<_>>(),
        "gapsFound": stats.gaps_found,
        "symbolized": symbolized,
        "unresolved": unresolved,
        "revision": rev,
        "events": total,
        "producerGen": producer_gen,
    }))
}

fn cmd_mark(ctx: &Value, req: &Value) -> Res<Value> {
    require_owner(ctx, "trace_mark")?;
    let label = text(req, "label").ok_or_else(|| Fail::bad("missing field: label"))?;
    let mut payload = Map::new();
    payload.insert("label".into(), json!(label));
    if let Some(note) = text(req, "note") {
        payload.insert("note".into(), json!(note));
    }
    let event = json!({
        "kind": "core.marker",
        "source_id": "marks",
        "clock_domain": "marks",
        "t_mono_ns": number(req, "t_mono_ns").unwrap_or(0),
        "payload": payload,
    });
    let inner = json!({"source": "marks", "events": [event]});
    let mut out = cmd_append(ctx, &inner, &Cancel(std::ptr::null()))?;
    out["label"] = json!(label);
    Ok(out)
}

fn kinds_of(req: &Value) -> Vec<String> {
    req.get("kinds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn row_json(row: &query::Row) -> Value {
    let payload: Value = serde_json::from_str(&row.payload).unwrap_or(Value::Null);
    json!({
        "seq": row.seq,
        "event_id": row.event_id,
        "kind": row.kind,
        "source_id": row.source_id,
        "t_mono_ns": row.t_mono_ns,
        "process_id": row.process_id,
        "thread_id": row.thread_id,
        "payload": payload,
    })
}

fn cmd_query(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    let session = session_of(ctx)?;
    let store = reader_of(ctx, &session)?;
    check_cancel(cancel)?;
    let kinds = kinds_of(req);
    let high = store.event_count()?;
    if let Some(by) = text(req, "group_by") {
        if query::group_column(by).is_none() {
            return Err(Fail::bad("group_by must be one of kind, resource, state, module, source")
                .with(json!({"field": "group_by", "allowed": ["kind", "resource", "state", "module", "source"]})));
        }
        let groups = query::groups(&store, by, &kinds)?;
        return Ok(json!({
            "session": session,
            "revision": store.revision()?,
            "highWater": high,
            "groupBy": by,
            "groups": groups,
        }));
    }
    let up_to = number(req, "upTo").unwrap_or(high).min(high);
    let limit = number(req, "limit").unwrap_or(100) as usize;
    let filter = Filter {
        kinds,
        process_gen: number(req, "process_gen").map(|g| g as u32),
        resource_key: text(req, "resource").map(str::to_owned),
        state_key: text(req, "state").map(str::to_owned),
        corr: text(req, "corr").map(str::to_owned),
        after: req.get("after").and_then(Value::as_i64).unwrap_or(0),
        limit,
    };
    let mut page = query::query(&store, &filter)?;
    let before = page.rows.len();
    page.rows.retain(|r| r.seq as u64 <= up_to);
    let clipped = page.rows.len() < before;
    let next = if clipped {
        None
    } else {
        page.next.filter(|n| (*n as u64) < up_to)
    };
    let rows: Vec<Value> = page.rows.iter().map(row_json).collect();
    Ok(json!({
        "session": session,
        "revision": page.revision,
        "highWater": high,
        "upTo": up_to,
        "rows": rows,
        "returned": rows.len(),
        "next": next,
        "truncated": page.truncated || (next.is_some()),
    }))
}

fn cmd_explain(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    let session = session_of(ctx)?;
    let store = reader_of(ctx, &session)?;
    let id = text(req, "event").ok_or_else(|| Fail::bad("missing field: event"))?;
    let seq: i64 = id
        .strip_prefix(&format!("ev_{session}_"))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Fail::bad("event is not an event id of this session"))?;
    let limit = number(req, "limit").unwrap_or(50).min(500) as usize;
    let direction = text(req, "direction").unwrap_or("upstream");
    if direction != "upstream" && direction != "downstream" {
        return Err(Fail::bad("direction must be upstream or downstream")
            .with(json!({"field": "direction", "allowed": ["upstream", "downstream"]})));
    }
    check_cancel(cancel)?;
    let anchor = query::query(
        &store,
        &Filter {
            after: seq - 1,
            limit: 1,
            ..Filter::default()
        },
    )?;
    let Some(row) = anchor.rows.first().filter(|r| r.seq == seq) else {
        return Err(Fail::new("not_found", format!("no event {id}")));
    };
    let payload: Value = serde_json::from_str(&row.payload).unwrap_or(Value::Null);
    let corr = text(&payload, "corr").map(str::to_owned);
    let mut related = Vec::new();
    let mut unresolved: Vec<&str> = Vec::new();
    match corr {
        Some(corr) => {
            let page = query::query(
                &store,
                &Filter {
                    corr: Some(corr),
                    limit: 1000,
                    ..Filter::default()
                },
            )?;
            for r in page.rows {
                let keep = if direction == "upstream" {
                    r.seq < seq
                } else {
                    r.seq > seq
                };
                if keep {
                    related.push(r);
                }
            }
            if direction == "upstream" {
                let skip = related.len().saturating_sub(limit);
                related.drain(..skip);
            } else {
                related.truncate(limit);
            }
        }
        None => unresolved.push("no-correlation"),
    }
    Ok(json!({
        "session": session,
        "event": id,
        "direction": direction,
        "revision": store.revision()?,
        "events": related.iter().map(row_json).collect::<Vec<_>>(),
        "paths": if related.is_empty() { 0 } else { 1 },
        "basis": "correlation-id",
        "unresolved": unresolved,
    }))
}

fn cmd_diff(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    let a = session_of(ctx)?;
    let b = text(req, "other").ok_or_else(|| Fail::bad("missing field: other"))?;
    if !valid_id(b) {
        return Err(Fail::bad("other is not a session id"));
    }
    let by = text(req, "by").unwrap_or("kind");
    if query::group_column(by).is_none() {
        return Err(Fail::bad("by must be one of kind, resource, state, module, source")
            .with(json!({"field": "by", "allowed": ["kind", "resource", "state", "module", "source"]})));
    }
    let sa = reader_of(ctx, &a)?;
    let sb = reader_of(ctx, b)?;
    check_cancel(cancel)?;
    let d = query::diff(&sa, &sb, by, &kinds_of(req))?;
    let mut v = serde_json::to_value(&d).map_err(|e| Fail::new("failed", e.to_string()))?;
    v["a"] = json!(a);
    v["b"] = json!(b);
    Ok(v)
}

fn assertion_of(req: &Value) -> Res<Assertion> {
    let spec = req
        .get("assertion")
        .filter(|a| a.is_object())
        .ok_or_else(|| Fail::bad("assertion must be an object"))?;
    let name = text(spec, "name").unwrap_or("assertion").to_owned();
    let rev = number(spec, "rev").unwrap_or(1) as u32;
    let kind = || {
        text(spec, "kind")
            .map(str::to_owned)
            .ok_or_else(|| Fail::bad("assertion.kind is missing"))
    };
    match text(spec, "type").unwrap_or("") {
        "cardinality" => Ok(Assertion::Cardinality {
            name,
            rev,
            kind: kind()?,
            min: number(spec, "min").unwrap_or(0),
            max: number(spec, "max").unwrap_or(u64::MAX),
        }),
        "forbidden" => Ok(Assertion::Forbidden {
            name,
            rev,
            kind: kind()?,
        }),
        "request_completion" => Ok(Assertion::RequestCompletion {
            name,
            rev,
            request: text(spec, "request")
                .ok_or_else(|| Fail::bad("assertion.request is missing"))?
                .to_owned(),
            completion: text(spec, "completion")
                .ok_or_else(|| Fail::bad("assertion.completion is missing"))?
                .to_owned(),
        }),
        _ => Err(
            Fail::bad("assertion.type must be cardinality, forbidden or request_completion")
                .with(json!({"field": "assertion.type",
                         "allowed": ["cardinality", "forbidden", "request_completion"]})),
        ),
    }
}

fn cmd_check(ctx: &Value, req: &Value) -> Res<Value> {
    let session = session_of(ctx)?;
    let store = reader_of(ctx, &session)?;
    let assertion = assertion_of(req)?;
    let result = query::check(&store, &assertion)?;
    let mut v = serde_json::to_value(&result).map_err(|e| Fail::new("failed", e.to_string()))?;
    v["session"] = json!(session);
    Ok(v)
}

fn cmd_export(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    let session = session_of(ctx)?;
    let store = reader_of(ctx, &session)?;
    let dir = dir_of(ctx, &session)?;
    let format = text(req, "format").unwrap_or("jsonl");
    if format != "jsonl" {
        return Err(Fail::bad("format must be jsonl")
            .with(json!({"field": "format", "allowed": ["jsonl"]})));
    }
    let name = text(req, "name").unwrap_or("export");
    if !valid_id(name) {
        return Err(Fail::bad(
            "name must be 1 to 64 of letters, digits, _ and -",
        ));
    }
    let out_dir = dir.join("export");
    fs::create_dir_all(&out_dir)?;
    let path = out_dir.join(format!("{name}.jsonl"));
    let tmp = out_dir.join(format!("{name}.jsonl.tmp"));
    let mut file = File::create(&tmp)?;
    let mut hasher = Sha256::new();
    let mut after = 0i64;
    let mut count = 0u64;
    let high = store.event_count()?;
    loop {
        if cancel.is_set() {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(Fail::new("cancelled", "trace export cancelled"));
        }
        let page = query::query(
            &store,
            &Filter {
                after,
                limit: query::MAX_LIMIT,
                ..Filter::default()
            },
        )?;
        for row in page.rows.iter().filter(|r| r.seq as u64 <= high) {
            let mut line = row_json(row).to_string().into_bytes();
            line.push(b'\n');
            hasher.update(&line);
            file.write_all(&line)?;
            count += 1;
        }
        match page.next {
            Some(n) if (n as u64) < high => after = n,
            _ => break,
        }
    }
    file.flush()?;
    drop(file);
    fs::rename(&tmp, &path)?;
    let sha: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(json!({
        "session": session,
        "format": format,
        "events": count,
        "revision": store.revision()?,
        "sha256": sha,
        "file": path.to_string_lossy(),
        "payloadArtifacts": "omitted",
    }))
}

fn cmd_close(ctx: &Value, req: &Value) -> Res<Value> {
    require_owner(ctx, "trace_close")?;
    let session = session_of(ctx)?;
    let dir = dir_of(ctx, &session)?;
    if !dir.join("session.json").is_file() {
        return Err(not_found(&session));
    }
    let mut meta = session_meta(&dir)?;
    detach(&session);
    meta["closed"] = json!(true);
    if let Some(label) = text(req, "label") {
        meta["closeLabel"] = json!(label);
    }
    write_meta(&dir, &meta)?;
    let (revision, events) = counts(&dir, &session);
    Ok(json!({"session": session, "closed": true, "revision": revision, "events": events}))
}

fn cmd_list(ctx: &Value) -> Res<Value> {
    let root = root_of(ctx)?;
    let leases = ctx.get("leases").cloned().unwrap_or(json!({}));
    let mut rows = Vec::new();
    if root.is_dir() {
        let mut names: Vec<String> = fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|e| e.path().join("session.json").is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            let dir = root.join(&name);
            let meta = session_meta(&dir).unwrap_or(Value::Null);
            let (revision, events) = counts(&dir, &name);
            rows.push(json!({
                "session": name,
                "name": meta["name"],
                "closed": meta["closed"],
                "revision": revision,
                "events": events,
                "lease": leases.get(&name).cloned().unwrap_or(Value::Null),
            }));
        }
    }
    Ok(json!({"sessions": rows, "count": rows.len()}))
}

fn cmd_info(ctx: &Value, req: &Value) -> Res<Value> {
    let session = session_of(ctx)?;
    let dir = dir_of(ctx, &session)?;
    if !dir.join("session.json").is_file() {
        return Err(not_found(&session));
    }
    let meta = session_meta(&dir)?;
    let mut segments = Vec::new();
    let mut names: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    names.sort();
    let mut interps = Vec::new();
    for p in names {
        let Some(n) = p.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        if let Some(source) = n
            .strip_prefix("seg-")
            .and_then(|n| n.strip_suffix(".trace"))
        {
            let data = fs::read(&p)?;
            let scan = raw::scan(&data, source);
            segments.push(json!({
                "source": source,
                "records": scan.records.len(),
                "bytes": scan.size,
                "clean": scan.is_clean(),
                "damage": scan.damage.as_ref().map(|d| format!("{d:?}")),
            }));
        } else if let Some(rev) = n
            .strip_prefix("interp-")
            .and_then(|n| n.strip_suffix(".jsonl"))
        {
            let rows = fs::read(&p)?.iter().filter(|b| **b == b'\n').count();
            interps.push(json!({"symbolRevision": rev.parse::<u64>().unwrap_or(0), "rows": rows}));
        }
    }
    let (revision, events) = counts(&dir, &session);
    let digest = if req.get("digest").and_then(Value::as_bool) == Some(true) {
        reader_of(ctx, &session).ok().and_then(|s| s.digest().ok())
    } else {
        None
    };
    Ok(json!({
        "session": session,
        "name": meta["name"],
        "closed": meta["closed"],
        "program": meta["program"],
        "revision": revision,
        "events": events,
        "segments": segments,
        "interpretations": interps,
        "digest": digest,
        "symbols": ctx.get("symbols").cloned().unwrap_or(Value::Null),
        "lease": ctx.get("lease").cloned().unwrap_or(Value::Null),
    }))
}

fn cmd_resymbolize(ctx: &Value, req: &Value, cancel: &Cancel) -> Res<Value> {
    require_owner(ctx, "trace_resymbolize")?;
    let session = session_of(ctx)?;
    let dir = dir_of(ctx, &session)?;
    if !dir.join("session.json").is_file() {
        return Err(not_found(&session));
    }
    let revision = number(ctx, "symbolRevision")
        .ok_or_else(|| Fail::bad("trace_resymbolize needs a program to resolve against"))?;
    let sample_cap = number(req, "sample").unwrap_or(10).min(100) as usize;
    let mut sources: Vec<(String, PathBuf)> = fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            let s = n.strip_prefix("seg-")?.strip_suffix(".trace")?.to_owned();
            Some((s, e.path()))
        })
        .collect();
    sources.sort();
    let target = dir.join(format!("interp-{revision}.jsonl"));
    let tmp = dir.join(format!("interp-{revision}.jsonl.tmp"));
    let mut out = File::create(&tmp)?;
    let (mut seen, mut resolved, mut unresolved) = (0u64, 0u64, 0u64);
    let mut sample = Vec::new();
    let mut reasons: std::collections::BTreeMap<String, u64> = Default::default();
    for (source, path) in sources {
        let data = fs::read(&path)?;
        let scan = raw::scan(&data, &source);
        for record in &scan.records {
            if cancel.is_set() {
                drop(out);
                let _ = fs::remove_file(&tmp);
                return Err(Fail::new("cancelled", "trace_resymbolize cancelled"));
            }
            let Some(va) = record.get("va").and_then(Value::as_u64) else {
                continue;
            };
            let module = record.get("module").and_then(Value::as_str).unwrap_or("");
            let mut s = symbolize(&session, revision, module, va);
            seen += 1;
            if s["function"].is_null() {
                unresolved += 1;
                *reasons
                    .entry(s["reason"].as_str().unwrap_or("no-symbol").to_owned())
                    .or_insert(0) += 1;
            } else {
                resolved += 1;
            }
            s["source"] = json!(source);
            s["n"] = record.get("n").cloned().unwrap_or(Value::Null);
            s["va"] = json!(va);
            out.write_all(s.to_string().as_bytes())?;
            out.write_all(b"\n")?;
            if sample.len() < sample_cap {
                sample.push(s);
            }
        }
    }
    out.flush()?;
    drop(out);
    fs::rename(&tmp, &target)?;
    Ok(json!({
        "session": session,
        "symbolRevision": revision,
        "symbols": ctx.get("symbols").cloned().unwrap_or(Value::Null),
        "events": seen,
        "resolved": resolved,
        "unresolved": unresolved,
        "reasons": reasons,
        "sample": sample,
        "originals": "unchanged",
    }))
}

#[cfg(test)]
mod tests;
