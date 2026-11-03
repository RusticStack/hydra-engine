//! The router in front of [`Service`]: what the daemon used to do in Java around every `trace_*`
//! command, so that the daemon only reads a line, hands its bytes here and writes the reply.
//!
//! * **Validation** of the fields the daemon itself reads (session ids, `cap`, `mode`, export
//!   names), with the messages and `details` the Java checks gave.
//! * **Lanes**: which commands run in the quick lane and which in the long one ([`Router::lane`]).
//! * **The writer lease** (TRACE-1 section 2): one owner capability per session, kept here with
//!   its `lease.json`; a writing command carries the capability and must come from the connection
//!   that holds the lease.
//! * **Request shaping** (the fields only the daemon reads are not the engine's), the **disk
//!   room** decision (the caller supplies the headroom of the volume), **reply wrapping**
//!   (`trace_open`, `trace_info`, `trace_list`, `trace_resymbolize`, `trace_evict`) and the
//!   symbol revision record (`symbols.json`).
//!
//! Replies are the engine's bytes whenever the daemon added nothing; where it adds fields they are
//! spliced into the engine's text, so nothing is parsed and printed again.
//!
//! The one thing the router cannot do is walk a program: for `trace_open` and `trace_resymbolize`
//! with a `program` it asks the caller through [`Symbols`] for the function table, at the point
//! the Java code built it, and rolls a failed creation back exactly as before.

use crate::service::Service;
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A diff of sessions whose indexes together exceed `trace.quickMB` megabytes runs in the long lane.
pub const DEFAULT_QUICK_MB: u64 = 64;
/// The room a new session (and a resymbolization) needs.
const NEW_SESSION_BYTES: u64 = 16 << 20;
/// The headroom that means "enough room, no need to look" (the caller did not measure).
pub const HEADROOM_UNKNOWN: i64 = i64::MAX;
/// Request fields only the daemon reads; the engine never sees them.
const JAVA_FIELDS: [&str; 9] = [
    "create",
    "mode",
    "cap",
    "takeover",
    "program",
    "project",
    "modules",
    "background",
    "name",
];

/// What the caller of a route knows about the request.
pub struct Ctx<'a> {
    /// The connection (a writer lease belongs to one).
    pub client: u64,
    /// The connection's label, needed when a lease is acquired (the holder shown in `trace_info`).
    pub label: &'a str,
    /// Whether the connection speaks protocol 3 (trace commands need it).
    pub v3: bool,
    /// Free bytes of the store's volume above the daemon's reserve, or [`HEADROOM_UNKNOWN`].
    pub headroom: i64,
}

/// The lane of a command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Reads and small writes.
    Quick,
    /// Everything that reads or writes the whole session.
    Long,
    /// Decided by the request itself (only returned when no request is given).
    Dynamic,
}

/// An error in the daemon's terms: `code` is a `SessionException` code, or `cancelled`.
#[derive(Debug)]
pub struct RouteError {
    /// `bad_request`, `not_found`, `not_owner`, `busy`, `conflict`, `failed`, `unknown_command`
    /// or `cancelled`.
    pub code: String,
    /// The message the client sees.
    pub message: String,
    /// The `details` object as JSON text, in the order it is sent, when there is one.
    pub details: Option<String>,
}

impl RouteError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    fn with(mut self, details: Obj) -> Self {
        self.details = Some(details.done());
        self
    }

    /// The error as `{"code":..,"message":..[,"details":{..}]}`.
    pub fn json(&self) -> Vec<u8> {
        let mut o = Obj::new()
            .str("code", &self.code)
            .str("message", &self.message);
        if let Some(d) = &self.details {
            o = o.raw("details", d);
        }
        o.done().into_bytes()
    }
}

/// What a route decided.
#[derive(Debug)]
pub enum Outcome {
    /// The reply bytes, as the client's `result`.
    Reply(Vec<u8>),
    /// A refusal.
    Error(RouteError),
    /// The request needs `estimate` bytes plus the reserve free for `what`, and the caller's
    /// headroom said there is not enough: the caller makes the exact check (and its error) and,
    /// when it passes after all, asks again with [`HEADROOM_UNKNOWN`].
    Disk {
        /// Bytes the request needs.
        estimate: u64,
        /// What for, for the message.
        what: String,
    },
    /// The symbol callback failed; the caller holds the reason.
    Callback,
}

/// A function table built by the caller: `symbols` is the engine's `TableSymbolizer` JSON and
/// `summary` the `symbols` block of the reply (its `revision` is the symbol revision).
pub struct Built {
    /// The table.
    pub symbols: String,
    /// The summary object.
    pub summary: String,
}

impl Built {
    /// A table from the caller's payload `{"symbols":{..},"summary":{..}}`.
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct Payload {
            symbols: Box<RawValue>,
            summary: Box<RawValue>,
        }
        let p: Payload = serde_json::from_slice(payload).ok()?;
        Some(Self {
            symbols: p.symbols.get().to_string(),
            summary: p.summary.get().to_string(),
        })
    }
}

/// The bytes that tell a caller how much room a request needs: `{"estimate":n,"what":".."}`.
pub fn disk_json(estimate: u64, what: &str) -> Vec<u8> {
    Obj::new()
        .num("estimate", estimate)
        .str("what", what)
        .done()
        .into_bytes()
}

/// Builds function tables (the caller walks the program).
pub trait Symbols {
    /// The table of the request's program at symbol revision `revision` of `session`; `None` when
    /// it failed (the caller keeps the error).
    fn build(&self, session: &str, revision: u64) -> Option<Built>;
}

/// The error of a step: a refusal, a disk question, or a failed callback.
enum Stop {
    Err(RouteError),
    Disk(u64, String),
    Callback,
}

impl From<RouteError> for Stop {
    fn from(e: RouteError) -> Self {
        Stop::Err(e)
    }
}

type Step<T> = std::result::Result<T, Stop>;
type Fail<T> = std::result::Result<T, RouteError>;

// ---- JSON text helpers -----------------------------------------------------------------------

/// A JSON object in insertion order, as text (the order the Java code sent its fields in).
struct Obj(String);

impl Obj {
    fn new() -> Self {
        Self(String::from("{"))
    }

    fn key(&mut self, k: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        self.0.push_str(&js(k));
        self.0.push(':');
    }

    fn raw(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        self.0.push_str(v);
        self
    }

    fn str(self, k: &str, v: &str) -> Self {
        self.raw(k, &js(v))
    }

    fn opt_str(self, k: &str, v: Option<&str>) -> Self {
        match v {
            Some(s) => self.str(k, s),
            None => self.raw(k, "null"),
        }
    }

    fn num(self, k: &str, v: impl std::fmt::Display) -> Self {
        self.raw(k, &v.to_string())
    }

    fn bool(self, k: &str, v: bool) -> Self {
        self.raw(k, if v { "true" } else { "false" })
    }

    fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn bad(message: impl Into<String>) -> RouteError {
    RouteError::new("bad_request", message)
}

/// A v3 `bad_request` naming the field (and, optionally, the values allowed).
fn bad_field(message: &str, field: &str, allowed: Option<&[&str]>) -> RouteError {
    let mut d = Obj::new().str("field", field);
    if let Some(a) = allowed {
        let list: Vec<String> = a.iter().map(|x| js(x)).collect();
        d = d.raw("allowed", &format!("[{}]", list.join(",")));
    }
    bad(message).with(d)
}

fn not_found(session: &str) -> RouteError {
    RouteError::new("not_found", format!("no trace session '{session}'"))
        .with(Obj::new().str("session", session))
}

fn failed(message: impl Into<String>, reason: &str) -> RouteError {
    RouteError::new("failed", message).with(Obj::new().str("reason", reason))
}

/// The members of the top level of a JSON object as `(key, start, end)` spans of `"key":value`.
fn top_members(b: &[u8]) -> Option<Vec<(String, usize, usize)>> {
    fn ws(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        i
    }
    fn string_end(b: &[u8], mut i: usize) -> Option<usize> {
        // i is on the opening quote
        i += 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    }
    fn value_end(b: &[u8], mut i: usize) -> Option<usize> {
        match *b.get(i)? {
            b'"' => string_end(b, i),
            b'{' | b'[' => {
                let mut depth = 0usize;
                while i < b.len() {
                    match b[i] {
                        b'"' => i = string_end(b, i)?,
                        b'{' | b'[' => {
                            depth += 1;
                            i += 1;
                        }
                        b'}' | b']' => {
                            depth -= 1;
                            i += 1;
                            if depth == 0 {
                                return Some(i);
                            }
                        }
                        _ => i += 1,
                    }
                }
                None
            }
            _ => {
                while i < b.len() && !matches!(b[i], b',' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
                Some(i)
            }
        }
    }
    let mut i = ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i = ws(b, i + 1);
    let mut out = Vec::new();
    if b.get(i) == Some(&b'}') {
        return Some(out);
    }
    loop {
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let start = i;
        let kend = string_end(b, i)?;
        let key: String = serde_json::from_slice(&b[start..kend]).ok()?;
        i = ws(b, kend);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i = ws(b, i + 1);
        let vend = value_end(b, i)?;
        out.push((key, start, vend));
        i = ws(b, vend);
        match b.get(i)? {
            b',' => i = ws(b, i + 1),
            b'}' => return Some(out),
            _ => return None,
        }
    }
}

/// `reply` without the top-level members named in `remove`, and `extra` (`"k":v` pieces) added at
/// the end. The remaining members keep their bytes and order.
fn rewrite_top(reply: &[u8], remove: &[&str], extra: &[String]) -> Fail<Vec<u8>> {
    let members = top_members(reply)
        .ok_or_else(|| failed("the trace engine gave an unreadable reply", "engine_reply"))?;
    let mut out = Vec::with_capacity(reply.len() + 128);
    out.push(b'{');
    let mut first = true;
    for (key, s, e) in &members {
        if remove.contains(&key.as_str()) {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        out.extend_from_slice(&reply[*s..*e]);
    }
    for piece in extra {
        if !first {
            out.push(b',');
        }
        first = false;
        out.extend_from_slice(piece.as_bytes());
    }
    out.push(b'}');
    Ok(out)
}

fn member(k: &str, v: &str) -> String {
    format!("{}:{v}", js(k))
}

// ---- the request -----------------------------------------------------------------------------

/// A request as its top-level members; values stay as text (an `events` array is never built).
struct Req<'a> {
    raw: &'a [u8],
    map: BTreeMap<String, &'a RawValue>,
}

enum Scalar {
    Str(String),
    Bool(bool),
    Num(String),
}

impl Scalar {
    /// `JsonPrimitive.getAsString()`.
    fn text(&self) -> String {
        match self {
            Scalar::Str(s) | Scalar::Num(s) => s.clone(),
            Scalar::Bool(b) => b.to_string(),
        }
    }
}

impl<'a> Req<'a> {
    fn parse(raw: &'a [u8]) -> Fail<Self> {
        let map: BTreeMap<String, &RawValue> =
            serde_json::from_slice(raw).map_err(|e| bad(format!("not a JSON object: {e}")))?;
        Ok(Self { raw, map })
    }

    /// Present and not `null` (`Json.has`).
    fn has(&self, k: &str) -> bool {
        self.map.get(k).is_some_and(|v| v.get() != "null")
    }

    fn scalar(&self, k: &str) -> Fail<Option<Scalar>> {
        if !self.has(k) {
            return Ok(None);
        }
        let t = self.map[k].get();
        match t.as_bytes()[0] {
            b'{' | b'[' => Err(bad(format!("{k} must be a scalar"))),
            b'"' => Ok(Some(Scalar::Str(
                serde_json::from_str(t).map_err(|e| bad(e.to_string()))?,
            ))),
            b't' => Ok(Some(Scalar::Bool(true))),
            b'f' => Ok(Some(Scalar::Bool(false))),
            _ => Ok(Some(Scalar::Num(t.to_string()))),
        }
    }

    /// `Json.str(req, k)`.
    fn str(&self, k: &str) -> Fail<String> {
        match self.scalar(k)? {
            Some(s) => Ok(s.text()),
            None => Err(bad(format!("missing field: {k}"))),
        }
    }

    /// `Json.str(req, k, null)`.
    fn str_opt(&self, k: &str) -> Fail<Option<String>> {
        Ok(self.scalar(k)?.map(|s| s.text()))
    }

    /// `Json.bool(req, k, dflt)`.
    fn bool(&self, k: &str, dflt: bool) -> Fail<bool> {
        match self.scalar(k)? {
            None => Ok(dflt),
            Some(Scalar::Bool(b)) => Ok(b),
            Some(_) => Err(bad(format!("{k} must be true or false"))),
        }
    }

    /// `Json.strings(req, k)`.
    fn strings(&self, k: &str) -> Fail<Vec<String>> {
        if !self.has(k) {
            return Ok(Vec::new());
        }
        let t = self.map[k].get();
        if !t.starts_with('[') {
            return Err(bad(format!("{k} must be an array")));
        }
        let items: Vec<&RawValue> = serde_json::from_str(t).map_err(|e| bad(e.to_string()))?;
        let mut out = Vec::new();
        for it in items {
            let s = it.get();
            match s.as_bytes()[0] {
                b'{' | b'[' => return Err(bad(format!("{k} must be an array of strings"))),
                b'"' => out.push(serde_json::from_str(s).map_err(|e| bad(e.to_string()))?),
                b'n' => return Err(bad(format!("{k} must be an array of strings"))),
                _ => out.push(s.to_string()),
            }
        }
        Ok(out)
    }

    /// The request as the engine takes it: without the fields only the daemon reads, plus
    /// `extra`. The client's own bytes when there is nothing to take out or add (an `events`
    /// array is then never copied).
    fn engine(&self, extra: &[(&str, String)]) -> Vec<u8> {
        let only_cap = !JAVA_FIELDS
            .iter()
            .any(|f| *f != "cap" && self.map.contains_key(*f));
        if extra.is_empty() && only_cap {
            return self.raw.to_vec();
        }
        let mut out = String::from("{");
        let mut first = true;
        for (k, v) in &self.map {
            if JAVA_FIELDS.contains(&k.as_str()) || extra.iter().any(|(e, _)| e == k) {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(out, "{}:{}", js(k), v.get());
        }
        for (k, v) in extra {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(out, "{}:{v}", js(k));
        }
        out.push('}');
        out.into_bytes()
    }
}

fn session_id(id: &str) -> Fail<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(bad_field(
            "a session id is 1 to 64 letters, digits, _ and -",
            "session",
            None,
        ))
    }
}

fn export_name(req: &Req) -> Fail<String> {
    let n = req.str_opt("name")?.unwrap_or_else(|| "export".into());
    let b = n.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
    if ok {
        Ok(n)
    } else {
        Err(bad_field(
            "an export name is 1 to 64 of letters, digits, _ . - and does not start with . or -",
            "name",
            None,
        ))
    }
}

/// The checks the daemon makes before a command reaches the engine.
fn validate(cmd: &str, req: &Req) -> Fail<()> {
    if cmd == "trace_diff" {
        session_id(&req.str("a")?)?;
        session_id(&req.str("b")?)?;
    } else if cmd == "trace_evict" {
        if req.has("session") {
            session_id(&req.str("session")?)?;
        }
        return Ok(());
    } else if cmd == "trace_bundle" {
        req.str("path")?;
        return Ok(());
    } else if req.has("session") {
        session_id(&req.str("session")?)?;
    } else if cmd != "trace_open" && cmd != "trace_list" {
        return Err(bad("missing field: session"));
    }
    match cmd {
        "trace_open" => {
            req.bool("create", false)?;
            req.bool("takeover", false)?;
            if let Some(mode) = req.str_opt("mode")?
                && mode != "read"
                && mode != "write"
            {
                return Err(bad_field(
                    "mode must be \"read\" or \"write\"",
                    "mode",
                    Some(&["read", "write"]),
                ));
            }
        }
        "trace_append" => {
            if !req.has("events") || !req.map["events"].get().starts_with('[') {
                return Err(bad_field("events must be an array", "events", None));
            }
            req.str("cap")?;
        }
        "trace_mark" => {
            req.str("cap")?;
            req.str("label")?;
        }
        "trace_close" | "trace_resymbolize" | "trace_reprocess" | "trace_artifact" => {
            req.str("cap")?;
        }
        "trace_export" => {
            if req.has("out") {
                return Err(bad_field(
                    "an export goes under the session's export folder: give name, not out",
                    "out",
                    None,
                ));
            }
            export_name(req)?;
        }
        _ => {}
    }
    Ok(())
}

/// The error a failed engine reply stands for.
fn engine_error(cmd: &str, bytes: &[u8]) -> RouteError {
    let parsed: Option<(String, String)> =
        serde_json::from_slice::<Value>(bytes).ok().and_then(|v| {
            let e = v.get("error")?;
            let code = e.get("code").and_then(Value::as_str).unwrap_or("internal");
            let message = e
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the trace engine failed");
            Some((code.to_string(), message.to_string()))
        });
    let Some((code, message)) = parsed else {
        return failed("the trace engine gave an unreadable error", "engine_reply");
    };
    let engine = |o: Obj| o.str("engineCode", &code);
    match code.as_str() {
        "cancelled" => RouteError::new("cancelled", message),
        "refused" if message.contains("no session") => RouteError::new("not_found", message),
        "refused" | "bad_request" | "too_large" => {
            RouteError::new("bad_request", message).with(engine(Obj::new()))
        }
        "busy" => RouteError::new("busy", message).with(engine(Obj::new()).str("reason", "busy")),
        "not_open" => RouteError::new("conflict", message)
            .with(engine(Obj::new()).str("suggest", "trace_open")),
        _ => RouteError::new("failed", message).with(engine(Obj::new()).str("command", cmd)),
    }
}

fn is_error(reply: &[u8]) -> bool {
    reply.starts_with(b"{\"error\":")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ---- the writer lease ------------------------------------------------------------------------

struct Lease {
    owner: Option<u64>,
    owner_label: String,
    cap_hash: String,
    producer_gen: u32,
    since: u64,
    orphaned_at: u64,
}

struct Grant {
    cap: Option<String>,
    reclaimed: bool,
    took_over: bool,
    producer_gen: u32,
    holder: String,
}

#[derive(Default)]
struct LeaseTable {
    leases: HashMap<String, Lease>,
    /// Connections that are ending: a lease they hold is as good as orphaned.
    leaving: HashSet<u64>,
}

impl LeaseTable {
    fn alive(&self, l: &Lease) -> bool {
        l.owner.is_some_and(|o| !self.leaving.contains(&o))
    }

    fn load(&mut self, dir: &Path, session: &str) -> Fail<bool> {
        if self.leases.contains_key(session) {
            return Ok(true);
        }
        let f = dir.join("lease.json");
        if !f.is_file() {
            return Ok(false);
        }
        let record = || -> Option<(String, u32)> {
            let v: Value = serde_json::from_slice(&std::fs::read(&f).ok()?).ok()?;
            Some((
                v.get("capSha256")?.as_str()?.to_string(),
                u32::try_from(v.get("producerGen")?.as_u64()?).ok()?,
            ))
        };
        let (cap_hash, producer_gen) = record().ok_or_else(|| {
            failed(
                format!("the lease record of trace session {session} is unreadable"),
                "lease_record",
            )
        })?;
        self.leases.insert(
            session.to_string(),
            Lease {
                owner: None,
                owner_label: String::new(),
                cap_hash,
                producer_gen,
                since: 0,
                orphaned_at: now_ms(),
            },
        );
        Ok(true)
    }

    fn persist(dir: &Path, session: &str, l: &Lease) -> Fail<()> {
        let body = Obj::new()
            .str("capSha256", &l.cap_hash)
            .num("producerGen", l.producer_gen)
            .done();
        let write = || -> std::io::Result<()> {
            std::fs::create_dir_all(dir)?;
            let tmp = dir.join("lease.json.tmp");
            std::fs::write(&tmp, body.as_bytes())?;
            std::fs::rename(&tmp, dir.join("lease.json"))
        };
        write().map_err(|e| {
            failed(
                format!("cannot record the lease of trace session {session}: {e}"),
                "lease_record",
            )
        })
    }

    fn not_owner(
        l: Option<&Lease>,
        session: Option<&str>,
        message: String,
        suggest: &str,
    ) -> RouteError {
        RouteError::new("not_owner", message).with(
            Obj::new()
                .opt_str("session", session)
                .opt_str(
                    "holder",
                    l.and_then(|l| l.owner.map(|_| l.owner_label.as_str())),
                )
                .bool("orphan", l.is_some_and(|l| l.owner.is_none()))
                .num("producerGen", l.map_or(0, |l| l.producer_gen))
                .str("suggest", suggest),
        )
    }

    fn acquire(
        &mut self,
        dir: &Path,
        session: &str,
        client: u64,
        label: &str,
        cap: Option<&str>,
        takeover: bool,
    ) -> Fail<Grant> {
        let known = self.load(dir, session)?;
        if !known {
            let fresh = new_cap()?;
            let l = Lease {
                owner: Some(client),
                owner_label: label.to_string(),
                cap_hash: sha(&fresh),
                producer_gen: 1,
                since: now_ms(),
                orphaned_at: 0,
            };
            Self::persist(dir, session, &l)?;
            self.leases.insert(session.to_string(), l);
            return Ok(Grant {
                cap: Some(fresh),
                reclaimed: false,
                took_over: false,
                producer_gen: 1,
                holder: label.to_string(),
            });
        }
        let alive = {
            let l = &self.leases[session];
            self.alive(l)
        };
        let l = self.leases.get_mut(session).expect("loaded above");
        let cap_ok = cap.is_some_and(|c| sha(c) == l.cap_hash);
        let grant = |l: &Lease, cap, reclaimed, took_over| Grant {
            cap,
            reclaimed,
            took_over,
            producer_gen: l.producer_gen,
            holder: l.owner_label.clone(),
        };
        if l.owner == Some(client) && cap_ok {
            return Ok(grant(l, None, false, false));
        }
        if alive && !cap_ok {
            return Err(Self::not_owner(
                Some(l),
                Some(session),
                format!(
                    "trace session {session} is written by {}; open it with mode \"read\" to read it, or wait for its writer to end",
                    l.owner_label
                ),
                "read",
            ));
        }
        if alive || cap_ok {
            l.owner = Some(client);
            l.owner_label = label.to_string();
            l.producer_gen += 1;
            l.since = now_ms();
            Self::persist(dir, session, l)?;
            return Ok(grant(l, None, true, false));
        }
        if !takeover {
            return Err(Self::not_owner(
                Some(l),
                Some(session),
                format!(
                    "the writer of trace session {session} is gone; present its capability to continue, or open with \"takeover\":true"
                ),
                "takeover",
            ));
        }
        let fresh = new_cap()?;
        l.cap_hash = sha(&fresh);
        l.owner = Some(client);
        l.owner_label = label.to_string();
        l.producer_gen += 1;
        l.since = now_ms();
        Self::persist(dir, session, l)?;
        Ok(grant(l, Some(fresh), false, true))
    }

    fn require(&self, session: &str, client: u64, cap: &str, what: &str) -> Fail<()> {
        let l = self.leases.get(session);
        let Some(held) = l.filter(|l| l.owner.is_some()) else {
            return Err(Self::not_owner(
                l,
                Some(session),
                format!(
                    "{what} needs the writer lease of trace session {session}; open it with trace_open (mode \"write\")"
                ),
                if l.is_none() { "open" } else { "takeover" },
            ));
        };
        if held.owner != Some(client) || sha(cap) != held.cap_hash {
            return Err(Self::not_owner(
                l,
                Some(session),
                format!(
                    "{what} needs the writer lease of trace session {session}, held by {}",
                    held.owner_label
                ),
                "read",
            ));
        }
        Ok(())
    }

    /// The state of a lease, for `trace_info` and `trace_list`: never the capability, never a time.
    fn describe(&mut self, session: &str, dir: &Path) -> Obj {
        if self.load(dir, session).is_err() {
            return Obj::new().str("state", "unknown");
        }
        let Some(l) = self.leases.get(session) else {
            return Obj::new().str("state", "none");
        };
        if self.alive(l) {
            Obj::new()
                .str("state", "held")
                .str("holder", &l.owner_label)
                .num("producerGen", l.producer_gen)
        } else {
            Obj::new()
                .str("state", "orphan")
                .num("producerGen", l.producer_gen)
        }
    }
}

fn sha(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_random(n: usize) -> Fail<String> {
    let mut b = vec![0u8; n];
    crate::corrid::random_fill(&mut b)
        .map_err(|e| failed(format!("no random bytes: {e}"), "random"))?;
    let mut out = String::with_capacity(n * 2);
    for x in b {
        let _ = write!(out, "{x:02x}");
    }
    Ok(out)
}

fn new_cap() -> Fail<String> {
    Ok(format!("cap_{}", hex_random(16)?))
}

// ---- the router ------------------------------------------------------------------------------

/// The state the routes keep: the lease table and the daemon's settings.
pub struct Router {
    leases: Mutex<LeaseTable>,
    quick_bytes: AtomicU64,
    quota_bytes: AtomicU64,
    /// The last symbol revision recorded per session (the file is read once).
    revisions: Mutex<HashMap<String, u64>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    /// A router with the default settings.
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(LeaseTable::default()),
            quick_bytes: AtomicU64::new(DEFAULT_QUICK_MB << 20),
            quota_bytes: AtomicU64::new(0),
            revisions: Mutex::new(HashMap::new()),
        }
    }

    /// `trace.quickMB` and `trace.quotaMB` (megabytes; quota 0: none).
    pub fn configure(&self, quick_mb: u64, quota_mb: u64) {
        self.quick_bytes.store(quick_mb << 20, Ordering::Relaxed);
        self.quota_bytes.store(quota_mb << 20, Ordering::Relaxed);
    }

    fn table(&self) -> std::sync::MutexGuard<'_, LeaseTable> {
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sessions with a lease record in memory.
    pub fn lease_count(&self) -> usize {
        self.table().leases.len()
    }

    /// A connection is ending: a lease it holds counts as orphaned from now.
    pub fn client_leaving(&self, client: u64) {
        self.table().leaving.insert(client);
    }

    /// A connection ended: every lease it held is orphaned.
    pub fn client_gone(&self, client: u64) {
        let mut t = self.table();
        for l in t.leases.values_mut() {
            if l.owner == Some(client) {
                l.owner = None;
                l.orphaned_at = now_ms();
            }
        }
        t.leaving.remove(&client);
    }

    /// The lane of `cmd`. Without a request, a command that depends on it is [`Lane::Dynamic`].
    pub fn lane(&self, root: &Path, cmd: &str, request: Option<&[u8]>) -> Lane {
        match cmd {
            "trace_resymbolize" | "trace_export" | "trace_reprocess" | "trace_evict" => Lane::Long,
            "trace_relations" | "trace_diff" if request.is_none() => Lane::Dynamic,
            "trace_relations" => {
                let status = request
                    .and_then(|r| Req::parse(r).ok())
                    .and_then(|r| r.str_opt("op").ok().flatten())
                    .is_some_and(|op| op == "status");
                if status { Lane::Quick } else { Lane::Long }
            }
            "trace_diff" => {
                let Some(req) = request.and_then(|r| Req::parse(r).ok()) else {
                    return Lane::Quick;
                };
                if req.bool("background", false).unwrap_or(false) {
                    return Lane::Long;
                }
                let size = |k: &str| -> u64 {
                    req.str_opt(k)
                        .ok()
                        .flatten()
                        .filter(|id| session_id(id).is_ok())
                        .and_then(|id| std::fs::metadata(root.join(id).join("index.db")).ok())
                        .map_or(0, |m| m.len())
                };
                if size("a") + size("b") > self.quick_bytes.load(Ordering::Relaxed) {
                    Lane::Long
                } else {
                    Lane::Quick
                }
            }
            _ => Lane::Quick,
        }
    }

    /// Checks `request` as a preflight does (before a queueing request waits), without running it.
    pub fn check(&self, cmd: &str, request: &[u8]) -> Option<RouteError> {
        Req::parse(request).and_then(|r| validate(cmd, &r)).err()
    }

    /// Runs one command for a connection.
    pub fn route(
        &self,
        svc: &Service,
        ctx: &Ctx,
        cmd: &str,
        request: &[u8],
        symbols: &dyn Symbols,
    ) -> Outcome {
        match self.run(svc, ctx, cmd, request, symbols) {
            Ok(reply) => Outcome::Reply(reply),
            Err(Stop::Err(e)) => Outcome::Error(e),
            Err(Stop::Disk(estimate, what)) => Outcome::Disk { estimate, what },
            Err(Stop::Callback) => Outcome::Callback,
        }
    }

    fn run(
        &self,
        svc: &Service,
        ctx: &Ctx,
        cmd: &str,
        request: &[u8],
        symbols: &dyn Symbols,
    ) -> Step<Vec<u8>> {
        if !ctx.v3 {
            return Err(RouteError::new(
                "unknown_command",
                "trace commands need protocol 3: send hello with \"protocol\":3 first",
            )
            .into());
        }
        let req = Req::parse(request)?;
        validate(cmd, &req)?;
        let root = svc.root();
        match cmd {
            "trace_open" => self.open(svc, ctx, &req, symbols),
            "trace_list" => self.list(svc, root, &req),
            "trace_info" => self.info(svc, root, &req),
            "trace_append" | "trace_mark" | "trace_reprocess" | "trace_artifact" => {
                self.write(svc, ctx, cmd, &req, false)
            }
            "trace_relations" => {
                if req.str_opt("op")?.as_deref() == Some("status") {
                    Ok(pass(svc, cmd, &req.engine(&[]))?)
                } else {
                    self.write(svc, ctx, cmd, &req, false)
                }
            }
            "trace_evict" => self.evict(svc, &req),
            "trace_close" => self.write(svc, ctx, cmd, &req, true),
            "trace_resymbolize" => self.resymbolize(svc, ctx, &req, symbols),
            "trace_check" => self.check_cmd(svc, ctx, &req),
            "trace_export" => self.export(svc, ctx, &req),
            _ => Ok(pass(svc, cmd, &req.engine(&[]))?),
        }
    }

    fn need_disk(&self, root: &Path, ctx: &Ctx, estimate: u64, what: &str) -> Step<()> {
        if let Err(e) = std::fs::create_dir_all(root) {
            return Err(failed(
                format!(
                    "cannot check the free space for {what} under {}: {e}",
                    root.display()
                ),
                "disk_check",
            )
            .into());
        }
        if !i64::try_from(estimate).is_ok_and(|e| e <= ctx.headroom) {
            return Err(Stop::Disk(estimate, what.to_string()));
        }
        Ok(())
    }

    fn last_revision(&self, root: &Path, session: &str) -> u64 {
        let mut cache = self
            .revisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(r) = cache.get(session) {
            return *r;
        }
        let read = || -> Option<u64> {
            let b = std::fs::read(root.join(session).join("symbols.json")).ok()?;
            serde_json::from_slice::<Value>(&b)
                .ok()?
                .get("lastRevision")?
                .as_u64()
        };
        match read() {
            Some(r) => {
                cache.insert(session.to_string(), r);
                r
            }
            None => 0,
        }
    }

    fn record_revision(&self, dir: &Path, session: &str, summary: &str) {
        #[derive(serde::Deserialize)]
        struct File {
            revisions: Vec<Box<RawValue>>,
        }
        let Some(revision) = serde_json::from_str::<Value>(summary)
            .ok()
            .and_then(|v| v.get("revision")?.as_u64())
        else {
            return;
        };
        let mut cache = self
            .revisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f = dir.join("symbols.json");
        let mut revisions: Vec<String> = std::fs::read(&f)
            .ok()
            .and_then(|b| serde_json::from_slice::<File>(&b).ok())
            .map(|f| f.revisions.iter().map(|r| r.get().to_string()).collect())
            .unwrap_or_default();
        revisions.push(summary.to_string());
        let body = format!(
            "{{\"lastRevision\":{revision},\"revisions\":[{}]}}",
            revisions.join(",")
        );
        let tmp = dir.join("symbols.json.tmp");
        if std::fs::write(&tmp, body)
            .and_then(|()| std::fs::rename(&tmp, &f))
            .is_ok()
        {
            cache.insert(session.to_string(), revision);
        }
    }

    // ---- the commands --------------------------------------------------------------------------

    fn open(&self, svc: &Service, ctx: &Ctx, req: &Req, symbols: &dyn Symbols) -> Step<Vec<u8>> {
        let root = svc.root();
        let given = req.str_opt("session")?;
        let create = req.bool("create", given.is_none())?;
        let session = match given {
            Some(g) => g,
            None => format!("tr_{}", hex_random(6)?),
        };
        let dir = root.join(&session);
        let exists = dir.join("session.json").is_file();
        if create && exists {
            return Err(RouteError::new(
                "conflict",
                format!("trace session {session} already exists; open it without \"create\""),
            )
            .with(Obj::new().str("session", &session).str("suggest", "open"))
            .into());
        }
        if !create && !exists {
            return Err(not_found(&session).into());
        }
        let mode = req
            .str_opt("mode")?
            .unwrap_or_else(|| if create { "write" } else { "read" }.into());
        let write = mode == "write";
        if !write && (req.has("cap") || req.bool("takeover", false)?) {
            return Err(bad_field(
                "cap and takeover need mode \"write\"",
                "mode",
                Some(&["write"]),
            )
            .into());
        }
        if create {
            self.need_disk(root, ctx, NEW_SESSION_BYTES, "a new trace session")?;
        }
        if !write {
            let info = pass(svc, "trace_info", &session_only(&session))?;
            let out: Value = serde_json::from_slice(&info)
                .map_err(|_| failed("the trace engine gave an unreadable reply", "engine_reply"))?;
            let lease = self
                .table()
                .describe(&session, &dir)
                .str("role", "reader")
                .done();
            let body = Obj::new()
                .str("session", &session)
                .bool("created", false)
                .raw(
                    "revision",
                    &out.get("revision").unwrap_or(&Value::Null).to_string(),
                )
                .raw(
                    "events",
                    &out.get("events").unwrap_or(&Value::Null).to_string(),
                )
                .raw("lease", &lease)
                .done();
            return Ok(body.into_bytes());
        }
        let cap = req.str_opt("cap")?;
        let grant = {
            let mut t = self.table();
            t.acquire(
                &dir,
                &session,
                ctx.client,
                ctx.label,
                cap.as_deref(),
                req.bool("takeover", false)?,
            )?
        };
        let done = self.open_acquired(svc, req, &session, &grant, create, symbols);
        if done.is_err() && create {
            self.table().leases.remove(&session);
            let _ = svc.handle("trace_close", &session_only(&session));
            let _ = std::fs::remove_dir_all(&dir);
        }
        done
    }

    fn open_acquired(
        &self,
        svc: &Service,
        req: &Req,
        session: &str,
        grant: &Grant,
        create: bool,
        symbols: &dyn Symbols,
    ) -> Step<Vec<u8>> {
        let root = svc.root();
        let dir = root.join(session);
        let built = if req.has("program") {
            Some(self.build_symbols(root, req, session, &dir, symbols)?)
        } else {
            None
        };
        let mut extra: Vec<(&str, String)> = vec![("session", js(session))];
        let quota = self.quota_bytes.load(Ordering::Relaxed);
        if quota > 0 && !req.map.contains_key("quota_bytes") {
            extra.push(("quota_bytes", quota.to_string()));
        }
        if let Some((b, revision)) = &built {
            extra.push(("symbols", b.symbols.clone()));
            extra.push(("symbol_revision", js(&format!("r{revision}"))));
        }
        let reply = pass(svc, "trace_open", &req.engine(&extra))?;
        let mut lease = Obj::new()
            .str("role", "owner")
            .num("producerGen", grant.producer_gen)
            .str("holder", &grant.holder);
        if let Some(c) = &grant.cap {
            lease = lease.str("cap", c);
        }
        let lease = lease
            .bool("reclaimed", grant.reclaimed)
            .bool("tookOver", grant.took_over)
            .done();
        let mut add = vec![
            member("created", if create { "true" } else { "false" }),
            member("lease", &lease),
        ];
        if let Some((b, _)) = &built {
            add.push(member("symbols", &b.summary));
        }
        Ok(rewrite_top(
            &reply,
            &["ok", "created", "lease", "symbols"],
            &add,
        )?)
    }

    /// The function table of the request's program at the next revision of the session.
    fn build_symbols(
        &self,
        root: &Path,
        req: &Req,
        session: &str,
        dir: &Path,
        symbols: &dyn Symbols,
    ) -> Step<(Built, u64)> {
        req.strings("modules")?;
        let revision = self.last_revision(root, session) + 1;
        let Some(built) = symbols.build(session, revision) else {
            return Err(Stop::Callback);
        };
        self.record_revision(dir, session, &built.summary);
        Ok((built, revision))
    }

    fn list(&self, svc: &Service, root: &Path, req: &Req) -> Step<Vec<u8>> {
        let reply = pass(svc, "trace_list", &req.engine(&[]))?;
        let unreadable = || failed("the trace engine gave an unreadable reply", "engine_reply");
        let out: Value = serde_json::from_slice(&reply).map_err(|_| unreadable())?;
        let map = out.as_object().ok_or_else(unreadable)?;
        let count = map.get("sessions").and_then(Value::as_array).map(Vec::len);
        let mut text = String::from("{");
        for (k, v) in map {
            if k == "ok" || (k == "count" && count.is_some()) {
                continue;
            }
            if text.len() > 1 {
                text.push(',');
            }
            let _ = write!(text, "{}:", js(k));
            match (k.as_str(), v) {
                ("sessions", Value::Array(items)) => {
                    text.push('[');
                    for (n, item) in items.iter().enumerate() {
                        if n > 0 {
                            text.push(',');
                        }
                        let id = item
                            .get("session")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let lease = self.table().describe(id, &root.join(id)).done();
                        text.push('{');
                        for (k, v) in item.as_object().into_iter().flatten() {
                            let _ = write!(text, "{}:{v},", js(k));
                        }
                        let _ = write!(text, "\"lease\":{lease}}}");
                    }
                    text.push(']');
                }
                _ => {
                    let _ = write!(text, "{v}");
                }
            }
        }
        if let Some(n) = count {
            if text.len() > 1 {
                text.push(',');
            }
            let _ = write!(text, "\"count\":{n}");
        }
        text.push('}');
        Ok(text.into_bytes())
    }

    fn info(&self, svc: &Service, root: &Path, req: &Req) -> Step<Vec<u8>> {
        let session = req.str("session")?;
        let reply = pass(svc, "trace_info", &req.engine(&[]))?;
        let lease = self.table().describe(&session, &root.join(&session)).done();
        let mut add = vec![member("lease", &lease)];
        let r = self.last_revision(root, &session);
        if r > 0 {
            add.push(member("symbolRevision", &js(&format!("r{r}"))));
        }
        Ok(rewrite_top(
            &reply,
            &["ok", "lease", "symbolRevision"],
            &add,
        )?)
    }

    /// A command of the writer.
    fn write(
        &self,
        svc: &Service,
        ctx: &Ctx,
        cmd: &str,
        req: &Req,
        closing: bool,
    ) -> Step<Vec<u8>> {
        let root = svc.root();
        let session = req.str("session")?;
        if !root.join(&session).join("index.db").is_file() {
            return Err(not_found(&session).into());
        }
        self.table()
            .require(&session, ctx.client, &req.str("cap")?, cmd)?;
        let er = req.engine(&[]);
        if !closing {
            // a rough bound on what the request adds to the segment, the index and the log
            self.need_disk(root, ctx, 4 * er.len() as u64 + (1 << 20), cmd)?;
        }
        let out = pass(svc, cmd, &er)?;
        if closing {
            let mut t = self.table();
            if let Some(l) = t.leases.get_mut(&session)
                && l.owner == Some(ctx.client)
            {
                l.owner = None;
                l.orphaned_at = now_ms();
            }
        }
        Ok(out)
    }

    fn resymbolize(
        &self,
        svc: &Service,
        ctx: &Ctx,
        req: &Req,
        symbols: &dyn Symbols,
    ) -> Step<Vec<u8>> {
        let root = svc.root();
        let session = req.str("session")?;
        let dir = root.join(&session);
        if !dir.join("index.db").is_file() {
            return Err(not_found(&session).into());
        }
        self.table()
            .require(&session, ctx.client, &req.str("cap")?, "trace_resymbolize")?;
        if !req.has("program") {
            return Err(
                bad("missing field: program (the program to resolve addresses against)").into(),
            );
        }
        self.need_disk(root, ctx, NEW_SESSION_BYTES, "trace_resymbolize")?;
        let (built, revision) = self.build_symbols(root, req, &session, &dir, symbols)?;
        let er = Obj::new()
            .str("session", &session)
            .str("symbol_revision", &format!("r{revision}"))
            .raw("symbols", &built.symbols)
            .done();
        let reply = pass(svc, "trace_resymbolize", er.as_bytes())?;
        Ok(rewrite_top(
            &reply,
            &["ok", "symbols"],
            &[member("symbols", &built.summary)],
        )?)
    }

    /// `trace_check` persists its results through the writer, so only the lease holder may ask
    /// for that; anyone else gets the verdicts without them being stored.
    fn check_cmd(&self, svc: &Service, ctx: &Ctx, req: &Req) -> Step<Vec<u8>> {
        let session = req.str("session")?;
        let extra: Vec<(&str, String)> = if req.bool("persist", true)? && req.has("cap") {
            self.table().require(
                &session,
                ctx.client,
                &req.str("cap")?,
                "trace_check with persist",
            )?;
            Vec::new()
        } else {
            vec![("persist", "false".into())]
        };
        Ok(pass(svc, "trace_check", &req.engine(&extra))?)
    }

    /// Evicts closed sessions (a tombstone each); the leases of the evicted ones are dropped.
    fn evict(&self, svc: &Service, req: &Req) -> Step<Vec<u8>> {
        if let Some(session) = req.str_opt("session")? {
            let t = self.table();
            if t.leases.get(&session).is_some_and(|l| t.alive(l)) {
                return Err(RouteError::new(
                    "busy",
                    format!("session {session} has a writer lease: close it first"),
                )
                .with(Obj::new().str("reason", "busy").str("session", &session))
                .into());
            }
        }
        let out = pass(svc, "trace_evict", &req.engine(&[]))?;
        if let Ok(v) = serde_json::from_slice::<Value>(&out)
            && let Some(list) = v.get("evicted").and_then(Value::as_array)
        {
            let mut t = self.table();
            for e in list {
                if let Some(s) = e.get("session").and_then(Value::as_str) {
                    t.leases.remove(s);
                }
            }
        }
        Ok(out)
    }

    fn export(&self, svc: &Service, ctx: &Ctx, req: &Req) -> Step<Vec<u8>> {
        let root = svc.root();
        let session = req.str("session")?;
        let dir = root.join(&session);
        let index = std::fs::metadata(dir.join("index.db"))
            .map_err(|_| not_found(&session))?
            .len();
        self.need_disk(root, ctx, 2 * index + (1 << 20), "trace_export")?;
        let out = dir.join("export").join(export_name(req)?);
        let reply = pass(
            svc,
            "trace_export",
            &req.engine(&[("out", js(&out.to_string_lossy()))]),
        )?;
        Ok(reply)
    }
}

fn session_only(session: &str) -> Vec<u8> {
    Obj::new().str("session", session).done().into_bytes()
}

/// One engine call: its reply as it is, or the error it stands for.
fn pass(svc: &Service, cmd: &str, request: &[u8]) -> Fail<Vec<u8>> {
    let reply = svc.handle(cmd, request);
    if is_error(&reply) {
        Err(engine_error(cmd, &reply))
    } else {
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct NoSymbols;
    impl Symbols for NoSymbols {
        fn build(&self, _: &str, _: u64) -> Option<Built> {
            None
        }
    }

    struct Table;
    impl Symbols for Table {
        fn build(&self, _: &str, revision: u64) -> Option<Built> {
            Some(Built {
                symbols: r#"{"modules":{"m":{"code":[[0,4096]],"functions":[{"start":0,"end":16,"name":"f"}]}}}"#.into(),
                summary: format!(
                    r#"{{"revision":{revision},"symbolRevision":"r{revision}","program":"p","modification":1,"functions":1,"modules":["m"]}}"#
                ),
            })
        }
    }

    fn ctx(client: u64) -> Ctx<'static> {
        Ctx {
            client,
            label: "agent-a",
            v3: true,
            headroom: HEADROOM_UNKNOWN,
        }
    }

    fn setup(name: &str) -> (Service, Router, PathBuf) {
        let dir = std::env::temp_dir().join(format!("hydra-route-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Service::new(&dir), Router::new(), dir)
    }

    fn reply(o: Outcome) -> Value {
        match o {
            Outcome::Reply(b) => serde_json::from_slice(&b).unwrap(),
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    fn error(o: Outcome) -> RouteError {
        match o {
            Outcome::Error(e) => e,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn go(r: &Router, s: &Service, c: &Ctx, cmd: &str, req: &str) -> Outcome {
        r.route(s, c, cmd, req.as_bytes(), &NoSymbols)
    }

    const EV: &str = r#"{"kind":"core.marker","source_id":"p","source_seq":0,"producer_gen":1,"clock_domain":"c","t_mono_ns":1,"confidence":"exact","payload":{"corr":"x"}}"#;

    #[test]
    fn a_session_has_one_writer_and_the_capability_moves_with_it() {
        let (s, r, dir) = setup("lease");
        let a = ctx(1);
        let opened = reply(go(
            &r,
            &s,
            &a,
            "trace_open",
            r#"{"session":"s1","create":true}"#,
        ));
        assert_eq!(opened["created"], true);
        let cap = opened["lease"]["cap"].as_str().unwrap().to_string();
        assert_eq!(opened["lease"]["role"], "owner");
        assert_eq!(opened["lease"]["producerGen"], 1);
        assert_eq!(opened["lease"]["holder"], "agent-a");
        // the writer appends; another connection does not
        let append = format!(r#"{{"session":"s1","cap":"{cap}","events":[{EV}]}}"#);
        assert_eq!(
            reply(go(&r, &s, &a, "trace_append", &append))["accepted"],
            1
        );
        let b = ctx(2);
        let e = error(go(&r, &s, &b, "trace_append", &append));
        assert_eq!(e.code, "not_owner");
        assert!(e.details.unwrap().contains("\"suggest\":\"read\""));
        // a live holder is never taken over
        let e = error(go(
            &r,
            &s,
            &b,
            "trace_open",
            r#"{"session":"s1","mode":"write","takeover":true}"#,
        ));
        assert_eq!(e.code, "not_owner");
        // the holder ends: an orphan, the capability continues it, anyone may take it over
        r.client_gone(1);
        let info = reply(go(&r, &s, &b, "trace_info", r#"{"session":"s1"}"#));
        assert_eq!(info["lease"]["state"], "orphan");
        let e = error(go(
            &r,
            &s,
            &b,
            "trace_open",
            r#"{"session":"s1","mode":"write"}"#,
        ));
        assert!(e.message.contains("takeover"), "{}", e.message);
        let back = reply(go(
            &r,
            &s,
            &b,
            "trace_open",
            &format!(r#"{{"session":"s1","mode":"write","cap":"{cap}"}}"#),
        ));
        assert_eq!(back["lease"]["reclaimed"], true);
        assert_eq!(back["lease"]["producerGen"], 2);
        r.client_gone(2);
        let c = ctx(3);
        let taken = reply(go(
            &r,
            &s,
            &c,
            "trace_open",
            r#"{"session":"s1","mode":"write","takeover":true}"#,
        ));
        assert_eq!(taken["lease"]["tookOver"], true);
        assert_eq!(taken["lease"]["producerGen"], 3);
        assert_ne!(taken["lease"]["cap"].as_str().unwrap(), cap);
        // a restart: the record on disk is an orphan
        let again = Router::new();
        let info = reply(go(&again, &s, &c, "trace_info", r#"{"session":"s1"}"#));
        assert_eq!(info["lease"]["state"], "orphan");
        assert_eq!(info["lease"]["producerGen"], 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_leaving_holder_is_not_alive() {
        let (s, r, dir) = setup("leaving");
        let a = ctx(1);
        let opened = reply(go(
            &r,
            &s,
            &a,
            "trace_open",
            r#"{"session":"s","create":true}"#,
        ));
        let cap = opened["lease"]["cap"].as_str().unwrap().to_string();
        r.client_leaving(1);
        let b = ctx(2);
        let info = reply(go(&r, &s, &b, "trace_info", r#"{"session":"s"}"#));
        assert_eq!(info["lease"]["state"], "orphan");
        let back = reply(go(
            &r,
            &s,
            &b,
            "trace_open",
            &format!(r#"{{"session":"s","mode":"write","cap":"{cap}"}}"#),
        ));
        assert_eq!(back["lease"]["reclaimed"], true);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrapped_replies_keep_the_engine_bytes_and_the_order_of_the_fields() {
        let (s, r, dir) = setup("wrap");
        let a = ctx(1);
        let opened = go(&r, &s, &a, "trace_open", r#"{"session":"w","create":true}"#);
        let Outcome::Reply(bytes) = opened else {
            panic!()
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("\"ok\""), "{text}");
        let created = text.find("\"created\":true").unwrap();
        let lease = text.find("\"lease\":{\"role\":\"owner\",\"producerGen\":1,\"holder\":\"agent-a\",\"cap\":\"cap_").unwrap();
        assert!(created < lease, "{text}");
        assert!(
            text.ends_with("\"reclaimed\":false,\"tookOver\":false}}"),
            "{text}"
        );
        let list = go(&r, &s, &a, "trace_list", "{}");
        let Outcome::Reply(bytes) = list else {
            panic!()
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains(
                "\"lease\":{\"state\":\"held\",\"holder\":\"agent-a\",\"producerGen\":1}}"
            ),
            "{text}"
        );
        assert!(text.ends_with("\"count\":1}"), "{text}");
        assert!(!text.contains("\"ok\""), "{text}");
        // a reader open
        let rd = go(
            &r,
            &s,
            &ctx(2),
            "trace_open",
            r#"{"session":"w","mode":"read"}"#,
        );
        let Outcome::Reply(bytes) = rd else { panic!() };
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.starts_with("{\"session\":\"w\",\"created\":false,\"revision\":"),
            "{text}"
        );
        assert!(text.ends_with("\"lease\":{\"state\":\"held\",\"holder\":\"agent-a\",\"producerGen\":1,\"role\":\"reader\"}}"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn requests_are_validated_with_the_messages_the_daemon_gave() {
        let (s, r, dir) = setup("validate");
        let a = ctx(1);
        for (cmd, req, msg) in [
            ("trace_query", "{}", "missing field: session"),
            (
                "trace_query",
                r#"{"session":"a b"}"#,
                "a session id is 1 to 64 letters, digits, _ and -",
            ),
            ("trace_diff", r#"{"a":"x"}"#, "missing field: b"),
            (
                "trace_open",
                r#"{"mode":"both"}"#,
                "mode must be \"read\" or \"write\"",
            ),
            (
                "trace_open",
                r#"{"create":"yes"}"#,
                "create must be true or false",
            ),
            (
                "trace_append",
                r#"{"session":"x","events":{}}"#,
                "events must be an array",
            ),
            (
                "trace_append",
                r#"{"session":"x","events":[]}"#,
                "missing field: cap",
            ),
            (
                "trace_mark",
                r#"{"session":"x","cap":"c"}"#,
                "missing field: label",
            ),
            (
                "trace_export",
                r#"{"session":"x","out":"p"}"#,
                "an export goes under the session's export folder: give name, not out",
            ),
            (
                "trace_export",
                r#"{"session":"x","name":".hidden"}"#,
                "an export name is 1 to 64 of letters, digits, _ . - and does not start with . or -",
            ),
            ("trace_bundle", "{}", "missing field: path"),
            (
                "trace_query",
                r#"{"session":{"a":1}}"#,
                "session must be a scalar",
            ),
        ] {
            let e = error(go(&r, &s, &a, cmd, req));
            assert_eq!(e.code, "bad_request", "{cmd} {req}");
            assert_eq!(e.message, msg, "{cmd} {req}");
        }
        let e = error(go(&r, &s, &a, "trace_query", r#"{"session":"a b"}"#));
        assert_eq!(e.details.as_deref(), Some(r#"{"field":"session"}"#));
        let mut v2 = ctx(1);
        v2.v3 = false;
        assert_eq!(
            error(go(&r, &s, &v2, "trace_list", "{}")).code,
            "unknown_command"
        );
        assert_eq!(
            error(go(&r, &s, &a, "trace_info", r#"{"session":"ghost"}"#)).code,
            "not_found"
        );
        assert!(r.check("trace_mark", br#"{"session":"x"}"#).is_some());
        assert!(r.check("trace_info", br#"{"session":"x"}"#).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lanes_follow_the_command_and_the_size_of_a_diff() {
        let (_s, r, dir) = setup("lanes");
        for c in [
            "trace_resymbolize",
            "trace_export",
            "trace_reprocess",
            "trace_evict",
        ] {
            assert_eq!(r.lane(&dir, c, None), Lane::Long);
        }
        for c in [
            "trace_open",
            "trace_append",
            "trace_query",
            "trace_info",
            "trace_check",
            "trace_bundle",
        ] {
            assert_eq!(r.lane(&dir, c, None), Lane::Quick);
        }
        assert_eq!(r.lane(&dir, "trace_diff", None), Lane::Dynamic);
        assert_eq!(r.lane(&dir, "trace_relations", None), Lane::Dynamic);
        assert_eq!(
            r.lane(&dir, "trace_relations", Some(br#"{"op":"status"}"#)),
            Lane::Quick
        );
        assert_eq!(
            r.lane(&dir, "trace_relations", Some(br#"{"op":"build"}"#)),
            Lane::Long
        );
        assert_eq!(
            r.lane(
                &dir,
                "trace_diff",
                Some(br#"{"a":"x","b":"y","background":true}"#)
            ),
            Lane::Long
        );
        assert_eq!(
            r.lane(&dir, "trace_diff", Some(br#"{"a":"x","b":"y"}"#)),
            Lane::Quick
        );
        std::fs::create_dir_all(dir.join("x")).unwrap();
        std::fs::write(dir.join("x").join("index.db"), vec![0u8; 2 << 20]).unwrap();
        r.configure(1, 0);
        assert_eq!(
            r.lane(&dir, "trace_diff", Some(br#"{"a":"x","b":"y"}"#)),
            Lane::Long
        );
        r.configure(64, 0);
        assert_eq!(
            r.lane(&dir, "trace_diff", Some(br#"{"a":"x","b":"y"}"#)),
            Lane::Quick
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_write_that_does_not_fit_the_disk_is_a_question_for_the_caller() {
        let (s, r, dir) = setup("disk");
        let mut a = ctx(1);
        a.headroom = 1 << 20;
        match go(&r, &s, &a, "trace_open", r#"{"session":"d","create":true}"#) {
            Outcome::Disk { estimate, what } => {
                assert_eq!(estimate, 16 << 20);
                assert_eq!(what, "a new trace session");
            }
            other => panic!("{other:?}"),
        }
        assert!(!dir.join("d").exists(), "nothing was created");
        a.headroom = HEADROOM_UNKNOWN;
        assert_eq!(
            reply(go(
                &r,
                &s,
                &a,
                "trace_open",
                r#"{"session":"d","create":true}"#
            ))["created"],
            true
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_program_is_symbolized_by_the_caller_and_the_revision_is_recorded() {
        let (s, r, dir) = setup("symbols");
        let a = ctx(1);
        let o = r.route(
            &s,
            &a,
            "trace_open",
            br#"{"session":"y","create":true,"program":"p.exe","modules":["m"]}"#,
            &Table,
        );
        let v = reply(o);
        assert_eq!(v["symbols"]["symbolRevision"], "r1");
        assert_eq!(v["symbols"]["modules"][0], "m");
        let cap = v["lease"]["cap"].as_str().unwrap().to_string();
        let info = reply(go(&r, &s, &a, "trace_info", r#"{"session":"y"}"#));
        assert_eq!(info["symbolRevision"], "r1");
        let re = r.route(
            &s,
            &a,
            "trace_resymbolize",
            format!(r#"{{"session":"y","cap":"{cap}","program":"p.exe"}}"#).as_bytes(),
            &Table,
        );
        assert_eq!(reply(re)["symbols"]["symbolRevision"], "r2");
        let file: Value =
            serde_json::from_slice(&std::fs::read(dir.join("y").join("symbols.json")).unwrap())
                .unwrap();
        assert_eq!(file["lastRevision"], 2);
        assert_eq!(file["revisions"].as_array().unwrap().len(), 2);
        // a failed build of a new session leaves nothing behind and no lease
        let o = r.route(
            &s,
            &a,
            "trace_open",
            br#"{"session":"z","create":true,"program":"p.exe"}"#,
            &NoSymbols,
        );
        assert!(matches!(o, Outcome::Callback));
        assert!(!dir.join("z").exists());
        assert_eq!(r.lease_count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn close_orphans_and_evict_forgets() {
        let (s, r, dir) = setup("close");
        let a = ctx(1);
        let o = reply(go(
            &r,
            &s,
            &a,
            "trace_open",
            r#"{"session":"c","create":true}"#,
        ));
        let cap = o["lease"]["cap"].as_str().unwrap().to_string();
        let e = error(go(&r, &s, &a, "trace_evict", r#"{"session":"c"}"#));
        assert_eq!(e.code, "busy");
        let closed = go(
            &r,
            &s,
            &a,
            "trace_close",
            &format!(r#"{{"session":"c","cap":"{cap}"}}"#),
        );
        assert!(matches!(closed, Outcome::Reply(_)));
        let info = reply(go(&r, &s, &a, "trace_info", r#"{"session":"c"}"#));
        assert_eq!(info["lease"]["state"], "orphan");
        let ev = reply(go(&r, &s, &a, "trace_evict", r#"{"session":"c"}"#));
        assert_eq!(ev["evicted"][0]["session"], "c");
        assert_eq!(r.lease_count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn check_persists_only_for_the_lease_holder() {
        let (s, r, dir) = setup("check");
        let a = ctx(1);
        let o = reply(go(
            &r,
            &s,
            &a,
            "trace_open",
            r#"{"session":"k","create":true}"#,
        ));
        let cap = o["lease"]["cap"].as_str().unwrap().to_string();
        let chk = r#""assertions":[{"type":"cardinality","name":"c","kind":"core.marker","min":0,"max":5}]"#;
        let own = reply(go(
            &r,
            &s,
            &a,
            "trace_check",
            &format!(r#"{{"session":"k","cap":"{cap}",{chk}}}"#),
        ));
        assert_eq!(own["ok"], true);
        let e = error(go(
            &r,
            &s,
            &ctx(2),
            "trace_check",
            &format!(r#"{{"session":"k","cap":"{cap}",{chk}}}"#),
        ));
        assert_eq!(e.code, "not_owner");
        assert_eq!(
            reply(go(
                &r,
                &s,
                &ctx(2),
                "trace_check",
                &format!(r#"{{"session":"k",{chk}}}"#)
            ))["ok"],
            true
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
