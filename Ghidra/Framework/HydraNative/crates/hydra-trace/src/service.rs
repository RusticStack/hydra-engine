//! The request service behind the C ABI and the CLI: every `trace_*` command takes request bytes
//! (JSON) and returns reply bytes (JSON). Java routes the bytes and nothing more. Replies are
//! deterministic (sorted keys, no floats). Readers open their own read-only connection on the
//! committed index and never wait on a writer; a second request for a writer that is busy is
//! answered `busy`, like the engine's other owner-only operations.

use crate::align::{self, AlignSpec};
use crate::artifact::{self, Artifacts};
use crate::explain::{self, Budget as ExplainBudget, Direction};
use crate::export::{self, ExportOptions};
use crate::interp::{self, Codec, Context, ContextRule};
use crate::query::{self, Assertion, Filter};
use crate::retention;
use crate::session::{self, Session};
use crate::store::{Budget, Error, Options, Store};
use crate::symbolize::{self, TableSymbolizer};
use crate::{checks, relations};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

/// The largest request the service reads.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// The commands this service answers.
pub const COMMANDS: [&str; 17] = [
    "trace_open",
    "trace_append",
    "trace_mark",
    "trace_query",
    "trace_explain",
    "trace_diff",
    "trace_check",
    "trace_export",
    "trace_close",
    "trace_list",
    "trace_info",
    "trace_resymbolize",
    "trace_reprocess",
    "trace_relations",
    "trace_artifact",
    "trace_evict",
    "trace_bundle",
];

/// How long a measured size of the store is trusted when the quota is checked on append.
const QUOTA_REFRESH: Duration = Duration::from_secs(2);
/// The room a new session needs before it is created (matches the Java admission check).
const NEW_SESSION_BYTES: u64 = 16 << 20;

struct Failure {
    code: &'static str,
    message: String,
}

type Reply = std::result::Result<Value, Failure>;

fn fail(code: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let message = e.to_string();
        let code = match &e {
            Error::Refused(_) => "refused",
            Error::Cancelled => "cancelled",
            Error::Json(_) => "bad_request",
            Error::Sql(rusqlite::Error::SqliteFailure(f, _))
                if matches!(
                    f.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                "busy"
            }
            Error::Segment(_) => "corrupt",
            _ => "internal",
        };
        Failure { code, message }
    }
}

impl From<serde_json::Error> for Failure {
    fn from(e: serde_json::Error) -> Self {
        fail("bad_request", e.to_string())
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        fail("io", e.to_string())
    }
}

impl From<rusqlite::Error> for Failure {
    fn from(e: rusqlite::Error) -> Self {
        Error::from(e).into()
    }
}

fn parse<T: for<'de> Deserialize<'de>>(req: &Value) -> std::result::Result<T, Failure> {
    Ok(serde_json::from_value(req.clone())?)
}

/// The request bytes straight into the command's own type: one pass, no intermediate tree and no
/// clone of it. Whatever this cannot take (not JSON, a duplicate key, a wrong type) is parsed the
/// long way, `Value` then [`parse`], so the error text and the last-key-wins rule are unchanged.
fn typed<T: for<'de> Deserialize<'de>>(request: &[u8]) -> std::result::Result<T, Failure> {
    let bytes: &[u8] = if request.is_empty() { b"{}" } else { request };
    match serde_json::from_slice::<T>(bytes) {
        Ok(v) => Ok(v),
        Err(_) => {
            let value: Value = serde_json::from_slice(bytes)?;
            parse(&value)
        }
    }
}

/// Where the sessions of this service live and which writers are open.
pub struct Service {
    root: PathBuf,
    writers: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    /// The store-wide quota in bytes (0: none), set by `trace_open`.
    quota: AtomicU64,
    /// The last measured size of the store and when.
    measured: Mutex<Option<(Instant, u64)>>,
    /// Digest of a session at a revision, so `trace_info` with `digest` is paid once per revision.
    digests: Mutex<HashMap<String, (u64, String)>>,
}

#[derive(Deserialize)]
struct OpenReq {
    session: String,
    #[serde(default)]
    max_events: Option<u64>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    symbols: Option<TableSymbolizer>,
    #[serde(default)]
    symbol_revision: Option<String>,
    #[serde(default)]
    preview: bool,
    /// Session metadata (profile id and hash, scope, limitations, target, capture config,
    /// scenario): merged into what the session already holds, persisted, returned by `trace_info`.
    #[serde(default)]
    meta: Option<serde_json::Map<String, Value>>,
    /// An explicitly shared correlation scope: `{name, key}` (key: 64 hex digits).
    #[serde(default)]
    shared_scope: Option<SharedScope>,
    /// Store-wide quota in bytes (0 removes it).
    #[serde(default)]
    quota_bytes: Option<u64>,
}

#[derive(Deserialize)]
struct SharedScope {
    name: String,
    key: String,
}

#[derive(Deserialize)]
struct SessionReq {
    session: String,
    /// `trace_info` only: include the store digest (O(session size), cached per revision).
    #[serde(default)]
    digest: bool,
}

#[derive(Deserialize)]
struct ContextReq {
    from_seq: i64,
    #[serde(default)]
    to_seq: Option<i64>,
    layout: String,
}

#[derive(Deserialize)]
struct ReprocessReq {
    session: String,
    codecs: BTreeMap<String, Codec>,
    #[serde(default)]
    context: Option<ContextRule>,
    #[serde(default)]
    contexts: Vec<ContextReq>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    bytes_field: Option<String>,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
struct RelationsReq {
    session: String,
    #[serde(default)]
    op: Option<String>,
}

#[derive(Deserialize)]
struct ArtifactReq {
    session: String,
    scope: String,
    max_bytes: u64,
    data_hex: String,
    #[serde(default)]
    retention_secs: Option<u64>,
    #[serde(default)]
    redact: Vec<(u64, u64)>,
}

#[derive(Deserialize)]
struct EvictReq {
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    to_quota: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct BundleReq {
    path: String,
}

#[derive(Deserialize)]
struct AppendReq {
    session: String,
    events: Vec<Value>,
}

#[derive(Deserialize)]
struct MarkReq {
    session: String,
    label: String,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    frame: Option<i64>,
}

#[derive(Deserialize)]
struct QueryReq {
    session: String,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    process_gen: Option<u32>,
    #[serde(default)]
    resource_key: Option<String>,
    #[serde(default)]
    state_key: Option<String>,
    #[serde(default)]
    corr: Option<String>,
    #[serde(default)]
    after: i64,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    group_by: Option<String>,
    #[serde(default)]
    with_symbols: bool,
    #[serde(default)]
    interp: Option<i64>,
    /// Pin: only events with `seq <= up_to` (a first page answers its own `up_to`).
    #[serde(default)]
    up_to: Option<i64>,
    /// `processes`, `threads`, `modules` or `objects`: the lifetime table instead of events.
    #[serde(default)]
    lifetimes: Option<String>,
    /// Include the decoded fields of each row under a decode revision.
    #[serde(default)]
    decoded: bool,
    /// The decode revision to read (the latest when absent).
    #[serde(default)]
    decode_interp: Option<i64>,
}

#[derive(Deserialize)]
struct ExplainReq {
    session: String,
    event_id: String,
    #[serde(default = "downstream")]
    direction: Direction,
    #[serde(default)]
    max_depth: Option<u32>,
    #[serde(default)]
    max_events: Option<usize>,
    #[serde(default)]
    max_bytes: Option<usize>,
}

fn downstream() -> Direction {
    Direction::Downstream
}

#[derive(Deserialize)]
struct DiffReq {
    a: String,
    b: String,
    #[serde(default)]
    group_by: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    align: Option<AlignSpec>,
}

#[derive(Deserialize)]
struct CheckReq {
    session: String,
    assertions: Vec<Assertion>,
    #[serde(default = "yes")]
    persist: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct ExportReq {
    session: String,
    out: String,
    #[serde(default)]
    authorized_artifacts: Vec<String>,
    #[serde(default)]
    overwrite: bool,
    #[serde(default)]
    exported_at: String,
}

#[derive(Deserialize)]
struct ResymReq {
    session: String,
    symbols: TableSymbolizer,
    symbol_revision: String,
}

impl Service {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            writers: Mutex::new(HashMap::new()),
            quota: AtomicU64::new(0),
            measured: Mutex::new(None),
            digests: Mutex::new(HashMap::new()),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Answer one request. Never panics on bad input; the reply says what was wrong.
    pub fn handle(&self, command: &str, request: &[u8]) -> Vec<u8> {
        let reply = self.dispatch(command, request);
        let value = match reply {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.insert("ok".into(), true.into());
                }
                v
            }
            Err(f) => json!({"ok": false, "error": {"code": f.code, "message": f.message}}),
        };
        serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"ok\":false}".to_vec())
    }

    fn dispatch(&self, command: &str, request: &[u8]) -> Reply {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(fail("too_large", "request exceeds 16 MiB"));
        }
        if !COMMANDS.contains(&command) {
            return Err(fail(
                "unknown_command",
                format!("unknown command {command}"),
            ));
        }
        crate::cancel::check()?;
        match command {
            "trace_open" => self.open(typed(request)?),
            "trace_append" => self.append(typed(request)?),
            "trace_mark" => self.mark(typed(request)?),
            "trace_query" => self.query(typed(request)?),
            "trace_explain" => self.explain(typed(request)?),
            "trace_diff" => self.diff(typed(request)?),
            "trace_check" => self.check(typed(request)?),
            "trace_export" => self.export(typed(request)?),
            "trace_close" => self.close(typed(request)?),
            "trace_list" => {
                typed::<Value>(request)?; // a body that is not JSON is still refused
                self.list()
            }
            "trace_info" => self.info(typed(request)?),
            "trace_resymbolize" => self.resymbolize(typed(request)?),
            "trace_reprocess" => self.reprocess(typed(request)?),
            "trace_relations" => self.relations(typed(request)?),
            "trace_artifact" => self.artifact(typed(request)?),
            "trace_evict" => self.evict(typed(request)?),
            "trace_bundle" => self.bundle(typed(request)?),
            _ => Err(fail("unknown_command", command)),
        }
    }

    fn writer(&self, session: &str) -> std::result::Result<Arc<Mutex<Session>>, Failure> {
        let map = self
            .writers
            .lock()
            .map_err(|_| fail("internal", "poisoned"))?;
        map.get(session).cloned().ok_or_else(|| {
            fail(
                "not_open",
                format!("session {session} is not open for writing; call trace_open"),
            )
        })
    }

    fn with_writer<T>(
        &self,
        session: &str,
        f: impl FnOnce(&mut Session) -> std::result::Result<T, Failure>,
    ) -> std::result::Result<T, Failure> {
        let writer = self.writer(session)?;
        let mut guard = match writer.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => {
                return Err(fail("busy", "another request is writing this session"));
            }
            Err(TryLockError::Poisoned(_)) => return Err(fail("internal", "poisoned")),
        };
        f(&mut guard)
    }

    fn reader(&self, session: &str) -> std::result::Result<Store, Failure> {
        Ok(session::reader(&self.root, session)?)
    }

    fn open(&self, r: OpenReq) -> Reply {
        if let Some(q) = r.quota_bytes {
            self.quota.store(q, Ordering::Relaxed);
        }
        let mut map = self
            .writers
            .lock()
            .map_err(|_| fail("internal", "poisoned"))?;
        if let Some(w) = map.get(&r.session) {
            let g = w.lock().map_err(|_| fail("internal", "poisoned"))?;
            if let Some(m) = &r.meta {
                g.merge_meta(m)?;
            }
            return Ok(
                json!({"session": r.session, "already_open": true, "revision": g.store().revision()?,
                       "scope": g.scope(), "meta": g.meta()}),
            );
        }
        if let Some(t) = retention::tombstone(&self.root, &r.session) {
            return Err(fail(
                "refused",
                format!(
                    "session {} was evicted ({}); its id is not reused, choose another",
                    r.session,
                    t["reason"].as_str().unwrap_or("?")
                ),
            ));
        }
        if !session::index_path(&self.root.join(&r.session)).exists() {
            self.admit_new_session(&map)?;
        }
        let options = Options {
            symbolizer: r.symbols.map(|t| {
                Arc::new(symbolize::IndexedSymbolizer::from(t)) as Arc<dyn symbolize::Symbolizer>
            }),
            symbol_revision: r.symbol_revision.unwrap_or_default(),
            budget: Budget {
                max_events: r.max_events,
                max_bytes: r.max_bytes,
            },
        };
        std::fs::create_dir_all(&self.root)?;
        let (mut session, recovery) = Session::open(&self.root, &r.session, options)?;
        session.set_preview(crate::corrid::PreviewPolicy {
            allow_preview: r.preview,
        });
        if let Some(sc) = &r.shared_scope {
            session.use_shared_scope(&sc.name, &sc.key)?;
        }
        if let Some(m) = &r.meta {
            session.merge_meta(m)?;
        }
        let revision = session.store().revision()?;
        let (scope, meta) = (session.scope().to_string(), session.meta());
        map.insert(r.session.clone(), Arc::new(Mutex::new(session)));
        Ok(
            json!({"session": r.session, "revision": revision, "recovery": serde_json::to_value(&recovery)?,
                   "scope": scope, "meta": meta}),
        )
    }

    /// Refuse a new session when the store is over its quota: the answer names what could go.
    fn admit_new_session(
        &self,
        open: &HashMap<String, Arc<Mutex<Session>>>,
    ) -> std::result::Result<(), Failure> {
        let quota = self.quota.load(Ordering::Relaxed);
        if quota == 0 {
            return Ok(());
        }
        let used = retention::store_bytes(&self.root);
        if used + NEW_SESSION_BYTES > quota {
            let closable: Vec<String> = retention::by_age(&self.root)
                .into_iter()
                .map(|(_, id)| id)
                .filter(|id| !open.contains_key(id))
                .collect();
            return Err(fail(
                "quota",
                format!(
                    "the trace store holds {used} bytes of a {quota} byte quota and a new session needs {NEW_SESSION_BYTES}; evict a closed session (trace_evict) or raise trace.quotaMB. Closed sessions, oldest first: {closable:?}"
                ),
            ));
        }
        Ok(())
    }

    /// The same check on the append path, throttled: the size of the store is measured at most
    /// every couple of seconds, so a session that grows past the quota is refused with a clear
    /// answer instead of filling the disk.
    fn check_quota(&self) -> std::result::Result<(), Failure> {
        let quota = self.quota.load(Ordering::Relaxed);
        if quota == 0 {
            return Ok(());
        }
        let used = {
            let mut m = self
                .measured
                .lock()
                .map_err(|_| fail("internal", "poisoned"))?;
            match *m {
                Some((at, bytes)) if at.elapsed() < QUOTA_REFRESH => bytes,
                _ => {
                    let bytes = retention::store_bytes(&self.root);
                    *m = Some((Instant::now(), bytes));
                    bytes
                }
            }
        };
        if used > quota {
            return Err(fail(
                "quota",
                format!(
                    "the trace store holds {used} bytes, over its {quota} byte quota: nothing more is recorded; evict closed sessions (trace_evict with to_quota) or raise trace.quotaMB"
                ),
            ));
        }
        Ok(())
    }

    fn append(&self, r: AppendReq) -> Reply {
        self.check_quota()?;
        let reply = self.with_writer(&r.session, |s| Ok(s.append(&r.events)?))?;
        Ok(serde_json::to_value(&reply)?)
    }

    fn mark(&self, r: MarkReq) -> Reply {
        let reply = self.with_writer(&r.session, |s| {
            Ok(s.mark(&r.label, r.phase.as_deref(), r.frame)?)
        })?;
        Ok(serde_json::to_value(&reply)?)
    }

    fn query(&self, r: QueryReq) -> Reply {
        let store = self.reader(&r.session)?;
        let _snapshot = store.read_snapshot()?;
        if let Some(what) = &r.lifetimes {
            let Some(rows) = query::lifetimes(&store, what)? else {
                return Err(fail("refused", format!("no lifetime table {what}")));
            };
            return Ok(
                json!({"revision": store.revision()?, "lifetimes": what, "rows": rows, "gaps": gaps_of(&store)?}),
            );
        }
        if let Some(by) = &r.group_by {
            if query::group_column(by).is_none() {
                return Err(fail("refused", format!("cannot group by {by}")));
            }
            let groups = query::groups(&store, by, &r.kinds)?;
            return Ok(
                json!({"revision": store.revision()?, "group_by": by, "groups": serde_json::to_value(&groups)?,
                             "gaps": gaps_of(&store)?}),
            );
        }
        let page = query::query(
            &store,
            &Filter {
                kinds: r.kinds,
                process_gen: r.process_gen,
                resource_key: r.resource_key,
                state_key: r.state_key,
                corr: r.corr,
                after: r.after,
                up_to: r.up_to,
                limit: r.limit.unwrap_or(100),
            },
        )?;
        let mut out = serde_json::to_value(&page)?;
        if r.with_symbols {
            let interp = match r.interp {
                Some(i) => Some(i),
                None => symbolize::latest_symbolization(&store)?,
            };
            let mut syms = Vec::new();
            for row in &page.rows {
                let (function, reason, stack): (Option<String>, Option<String>, Option<String>) =
                    match interp {
                        Some(i) => store
                            .conn()
                            .query_row(
                                "SELECT function,reason,stack FROM event_symbols WHERE interp=?1 AND seq=?2",
                                rusqlite::params![i, row.seq],
                                |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
                            )
                            .unwrap_or((None, Some("no-symbol".into()), None)),
                        None => (None, None, None),
                    };
                let stack: Value = stack
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(Value::Null);
                syms.push(
                    json!({"seq": row.seq, "function": function, "reason": reason, "stack": stack}),
                );
            }
            out["symbols"] = json!({"interp": interp, "rows": syms});
        }
        if r.decoded {
            let rev = match r.decode_interp {
                Some(i) => Some(i),
                None => interp::revisions(&store)?.last().map(|x| x.0),
            };
            let mut rows = Vec::new();
            for row in &page.rows {
                let fields = match rev {
                    Some(_) => interp::decoded(&store, row.seq, rev)?,
                    None => Vec::new(),
                };
                rows.push(json!({"seq": row.seq, "fields": serde_json::to_value(&fields)?}));
            }
            out["decoded"] = json!({"interp": rev, "rows": rows});
        }
        if r.decoded {
            let rev = match r.decode_interp {
                Some(i) => Some(i),
                None => interp::revisions(&store)?.last().map(|x| x.0),
            };
            let mut rows = Vec::new();
            for row in &page.rows {
                let fields = match rev {
                    Some(_) => interp::decoded(&store, row.seq, rev)?,
                    None => Vec::new(),
                };
                rows.push(json!({"seq": row.seq, "fields": serde_json::to_value(&fields)?}));
            }
            out["decoded"] = json!({"interp": rev, "rows": rows});
        }
        out["gaps"] = gaps_of(&store)?;
        Ok(out)
    }

    fn explain(&self, r: ExplainReq) -> Reply {
        let store = self.reader(&r.session)?;
        let d = ExplainBudget::default();
        let e = explain::explain(
            &store,
            &r.event_id,
            r.direction,
            ExplainBudget {
                max_depth: r.max_depth.unwrap_or(d.max_depth).min(64),
                max_events: r.max_events.unwrap_or(d.max_events).min(5000),
                max_bytes: r.max_bytes.unwrap_or(d.max_bytes).min(4 << 20),
            },
        )?;
        Ok(serde_json::to_value(&e)?)
    }

    fn diff(&self, r: DiffReq) -> Reply {
        let (a, b) = (self.reader(&r.a)?, self.reader(&r.b)?);
        if let Some(mut spec) = r.align {
            if spec.kinds.is_empty() {
                spec.kinds = r.kinds;
            }
            let d = align::diff_aligned_default(&a, &b, &spec)?;
            return Ok(json!({"aligned": serde_json::to_value(&d)?}));
        }
        let by = r.group_by.unwrap_or_else(|| "kind".into());
        if query::group_column(&by).is_none() {
            return Err(fail("refused", format!("cannot group by {by}")));
        }
        let d = query::diff(&a, &b, &by, &r.kinds)?;
        Ok(json!({"diff": serde_json::to_value(&d)?}))
    }

    fn check(&self, r: CheckReq) -> Reply {
        let mut results = Vec::new();
        let mut persisted = false;
        if r.persist
            && let Ok(w) = self.writer(&r.session)
            && let Ok(mut g) = w.try_lock()
        {
            for a in &r.assertions {
                results.push(checks::run(g.store_mut(), a)?);
            }
            persisted = true;
        }
        if !persisted {
            let store = self.reader(&r.session)?;
            for a in &r.assertions {
                results.push(query::check(&store, a)?);
            }
        }
        Ok(json!({"results": serde_json::to_value(&results)?, "persisted": persisted}))
    }

    fn export(&self, r: ExportReq) -> Reply {
        let store = self.reader(&r.session)?;
        let arts = Artifacts::open(artifact::dir_of(&self.root.join(&r.session)))?;
        let report = export::export(
            &store,
            Some(&arts),
            Path::new(&r.out),
            &ExportOptions {
                authorized_artifacts: r.authorized_artifacts,
                overwrite: r.overwrite,
                exported_at: r.exported_at,
            },
        )?;
        Ok(serde_json::to_value(&report)?)
    }

    fn close(&self, r: SessionReq) -> Reply {
        let mut map = self
            .writers
            .lock()
            .map_err(|_| fail("internal", "poisoned"))?;
        let was_open = map.remove(&r.session).is_some();
        Ok(json!({"session": r.session, "was_open": was_open}))
    }

    fn list(&self) -> Reply {
        let mut out = Vec::new();
        for id in session::list(&self.root) {
            let (revision, events) = match self.reader(&id) {
                Ok(s) => (s.revision().unwrap_or(0), s.event_count().unwrap_or(0)),
                Err(_) => (0, 0),
            };
            let open = self
                .writers
                .lock()
                .map(|m| m.contains_key(&id))
                .unwrap_or(false);
            out.push(
                json!({"session": id, "revision": revision, "events": events, "writer_open": open}),
            );
        }
        Ok(
            json!({"sessions": out, "evicted": retention::tombstones(&self.root),
                  "quota_bytes": self.quota.load(Ordering::Relaxed),
                  "store_bytes": retention::store_bytes(&self.root)}),
        )
    }

    fn info(&self, r: SessionReq) -> Reply {
        if !session::index_path(&self.root.join(&r.session)).exists()
            && let Some(t) = retention::tombstone(&self.root, &r.session)
        {
            return Ok(json!({"session": r.session, "evicted": true, "tombstone": t}));
        }
        let store = self.reader(&r.session)?;
        let conn = store.conn();
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |x| x.get(0)).unwrap_or(0) };
        let sources: Vec<Value> = {
            let mut stmt = conn.prepare(
                "SELECT source_id,segment_records,state FROM sources ORDER BY source_id",
            )?;
            stmt.query_map([], |x| {
                Ok(json!({"source_id": x.get::<_, String>(0)?, "records": x.get::<_, i64>(1)?, "state": x.get::<_, String>(2)?}))
            })?
            .collect::<std::result::Result<_, _>>()?
        };
        let counts = symbolize::counts(&store, None)?;
        let rel = relations::current(&store)?;
        let open = self
            .writers
            .lock()
            .map(|m| m.contains_key(&r.session))
            .unwrap_or(false);
        let revision = store.revision()?;
        let session_json = session::read_session_json(&self.root.join(&r.session));
        // The digest reads the whole index: it is computed on request and kept per revision,
        // never as a side effect of asking how a live session is doing.
        let digest = if r.digest {
            let cached = self.digests.lock().ok().and_then(|m| {
                m.get(&r.session)
                    .filter(|(rev, _)| *rev == revision)
                    .cloned()
            });
            let value = match cached {
                Some((_, d)) => d,
                None => {
                    let d = store.digest()?;
                    if let Ok(mut m) = self.digests.lock() {
                        m.insert(r.session.clone(), (revision, d.clone()));
                    }
                    d
                }
            };
            Value::String(value)
        } else {
            Value::Null
        };
        Ok(json!({
            "session": r.session,
            "revision": revision,
            "events": store.event_count()?,
            "sources": sources,
            "gaps": gaps_of(&store)?,
            "rejects": count("SELECT COUNT(*) FROM rejects"),
            "stopped": store.stopped(),
            "budget": {"max_events": store.budget().max_events, "max_bytes": store.budget().max_bytes},
            "processes": count("SELECT COUNT(*) FROM processes"),
            "threads": count("SELECT COUNT(*) FROM threads"),
            "module_instances": count("SELECT COUNT(*) FROM module_instances"),
            "interpretations": count("SELECT COUNT(*) FROM interpretations"),
            "decodings": interp::describe(&store)?,
            "symbolization": serde_json::to_value(&counts)?,
            "relations": {"count": rel.0.len(), "source": rel.1},
            "artifacts": count("SELECT COUNT(*) FROM artifacts"),
            "tombstones": count("SELECT COUNT(*) FROM tombstones"),
            "writer_open": open,
            "scope": session_json.get("scope").cloned().unwrap_or_else(|| json!(format!("session:{}", r.session))),
            "meta": session_json.get("meta").cloned().unwrap_or(Value::Null),
            "digest": digest,
        }))
    }

    fn resymbolize(&self, r: ResymReq) -> Reply {
        let indexed = symbolize::IndexedSymbolizer::from(r.symbols.clone());
        // Through the open writer when there is one, else a short-lived writer connection.
        let rev = if let Ok(w) = self.writer(&r.session) {
            let mut g = w
                .try_lock()
                .map_err(|_| fail("busy", "another request is writing this session"))?;
            symbolize::resymbolize(g.store_mut(), &indexed, &r.symbol_revision)?
        } else {
            if !session::index_path(&self.root.join(&r.session)).exists() {
                return Err(fail("refused", format!("no session {}", r.session)));
            }
            let mut store = Store::open(
                &session::index_path(&self.root.join(&r.session)),
                &r.session,
            )?;
            symbolize::resymbolize(&mut store, &indexed, &r.symbol_revision)?
        };
        let store = self.reader(&r.session)?;
        Ok(
            json!({"interp": rev, "counts": serde_json::to_value(symbolize::counts(&store, Some(rev))?)?,
                  "revision": store.revision()?}),
        )
    }

    /// Run `f` on the session's store through its open writer, else through a short-lived writer
    /// connection (the session is closed but exists).
    fn with_store_mut<T>(
        &self,
        session: &str,
        f: impl FnOnce(&mut Store) -> std::result::Result<T, Failure>,
    ) -> std::result::Result<T, Failure> {
        if let Ok(w) = self.writer(session) {
            let mut g = w
                .try_lock()
                .map_err(|_| fail("busy", "another request is writing this session"))?;
            return f(g.store_mut());
        }
        let index = session::index_path(&self.root.join(session));
        if !index.exists() {
            return Err(fail("refused", format!("no session {session}")));
        }
        let mut store = Store::open(&index, session)?;
        f(&mut store)
    }

    fn reprocess(&self, r: ReprocessReq) -> Reply {
        let dir = self.root.join(&r.session);
        let arts = Artifacts::open(artifact::dir_of(&dir))?;
        let spec = self.with_store_mut(&r.session, |store| {
            let contexts: Vec<Context> = if r.contexts.is_empty() {
                interp::contexts_from_rule(
                    store,
                    &r.codecs,
                    &r.context.clone().unwrap_or_default(),
                )?
            } else {
                let mut out = Vec::new();
                for c in &r.contexts {
                    let codec = r.codecs.get(&c.layout).ok_or_else(|| {
                        fail(
                            "refused",
                            format!("context names layout {} with no codec", c.layout),
                        )
                    })?;
                    out.push(Context {
                        from_seq: c.from_seq,
                        to_seq: c.to_seq,
                        layout: c.layout.clone(),
                        codec: codec.clone(),
                    });
                }
                out
            };
            let up_to: Option<i64> = store
                .conn()
                .query_row("SELECT MAX(seq) FROM events", [], |x| x.get(0))
                .unwrap_or(None);
            let spec = interp::Spec {
                contexts,
                kinds: r.kinds.clone(),
                bytes_field: r.bytes_field.clone(),
                note: r.note.clone(),
                up_to,
            };
            let stats = interp::reprocess(store, &spec, Some(&arts), None)?;
            Ok((spec, stats))
        })?;
        let (spec, stats) = spec;
        interp::journal_append(&dir, stats.revision, &spec)?;
        let store = self.reader(&r.session)?;
        Ok(json!({
            "interp": stats.revision, "stats": serde_json::to_value(&stats)?,
            "decodings": interp::describe(&store)?, "revision": store.revision()?,
        }))
    }

    fn relations(&self, r: RelationsReq) -> Reply {
        match r.op.as_deref().unwrap_or("materialize") {
            "materialize" => {
                let n =
                    self.with_store_mut(&r.session, |store| Ok(relations::materialize(store)?))?;
                let store = self.reader(&r.session)?;
                Ok(json!({"relations": n, "revision": store.revision()?, "source": "materialized"}))
            }
            "status" => {
                let store = self.reader(&r.session)?;
                let rel = relations::current(&store)?;
                Ok(
                    json!({"relations": rel.0.len(), "source": rel.1, "revision": store.revision()?}),
                )
            }
            other => Err(fail(
                "bad_request",
                format!("op must be materialize or status, not {other}"),
            )),
        }
    }

    fn artifact(&self, r: ArtifactReq) -> Reply {
        let bytes = decode_hex(&r.data_hex).ok_or_else(|| {
            fail(
                "bad_request",
                "data_hex must be an even number of hex digits",
            )
        })?;
        let spec = artifact::ArtifactSpec {
            scope: r.scope,
            max_bytes: r.max_bytes,
            retention_secs: r.retention_secs,
            redact: r.redact,
        };
        let id = self.with_writer(&r.session, |s| Ok(s.put_artifact(&bytes, &spec)?))?;
        Ok(json!({"artifact": id, "size": bytes.len()}))
    }

    fn evict(&self, r: EvictReq) -> Reply {
        let reason = r.reason.unwrap_or_else(|| "requested".into());
        let open: Vec<String> = self
            .writers
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut evicted = Vec::new();
        if let Some(id) = &r.session {
            if open.contains(id) {
                return Err(fail(
                    "busy",
                    format!("session {id} is open for writing; close it first"),
                ));
            }
            evicted.push(retention::evict(&self.root, id, &reason)?);
        }
        if r.to_quota {
            let quota = self.quota.load(Ordering::Relaxed);
            if quota == 0 {
                return Err(fail(
                    "refused",
                    "no quota is set: open a session with quota_bytes first",
                ));
            }
            for (_, id) in retention::by_age(&self.root) {
                if retention::store_bytes(&self.root) + NEW_SESSION_BYTES <= quota {
                    break;
                }
                if open.contains(&id) || evicted.iter().any(|t| t["session"] == id.as_str()) {
                    continue;
                }
                evicted.push(retention::evict(&self.root, &id, "quota")?);
            }
        }
        if evicted.is_empty() && r.session.is_none() && !r.to_quota {
            return Err(fail("bad_request", "give session, or to_quota"));
        }
        if let Ok(mut m) = self.measured.lock() {
            *m = None;
        }
        let used = retention::store_bytes(&self.root);
        Ok(json!({"evicted": evicted, "store_bytes": used,
                  "quota_bytes": self.quota.load(Ordering::Relaxed)}))
    }

    fn bundle(&self, r: BundleReq) -> Reply {
        Ok(retention::bundle_status(&self.root, Path::new(&r.path))?)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn gaps_of(store: &Store) -> std::result::Result<Value, Failure> {
    let mut stmt = store.conn().prepare(
        "SELECT source_id,reason,first_missing,last_missing,dropped,observed FROM gaps ORDER BY id LIMIT 100",
    )?;
    let rows: Vec<Value> = stmt
        .query_map([], |x| {
            Ok(json!({"source_id": x.get::<_, String>(0)?, "reason": x.get::<_, String>(1)?,
                      "first_missing": x.get::<_, Option<i64>>(2)?, "last_missing": x.get::<_, Option<i64>>(3)?,
                      "dropped": x.get::<_, Option<i64>>(4)?, "announced": x.get::<_, i64>(5)? == 1}))
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw;
    use crate::synth::{self, Recipe};

    fn svc(name: &str) -> (Service, PathBuf) {
        let d = std::env::temp_dir().join(format!("hydra-service-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        (Service::new(&d), d)
    }

    fn call(s: &Service, cmd: &str, req: Value) -> Value {
        serde_json::from_slice(&s.handle(cmd, &serde_json::to_vec(&req).unwrap())).unwrap()
    }

    fn events(recipe: Recipe, seed: u64, n: usize) -> Vec<Value> {
        let seg = synth::generate(recipe, seed, n).remove(0);
        raw::scan(&seg.bytes, &seg.id)
            .records
            .into_iter()
            .map(|mut r| {
                for k in ["n", "prev", "hash"] {
                    r.remove(k);
                }
                Value::Object(r)
            })
            .collect()
    }

    #[test]
    fn every_command_answers_and_unknown_or_bad_input_is_an_error_reply() {
        let (s, d) = svc("all");
        let o = call(&s, "trace_open", json!({"session": "a"}));
        assert_eq!(o["ok"], true);
        let ap = call(
            &s,
            "trace_append",
            json!({"session": "a", "events": events(Recipe::Interleave, 1, 40)}),
        );
        assert_eq!(ap["accepted"], 42);
        assert_eq!(
            call(
                &s,
                "trace_mark",
                json!({"session": "a", "label": "x", "phase": "p", "frame": 1})
            )["ok"],
            true
        );
        let q = call(
            &s,
            "trace_query",
            json!({"session": "a", "kinds": ["app.request"], "limit": 5}),
        );
        assert_eq!(q["rows"].as_array().unwrap().len(), 5);
        assert!(q["next"].is_number());
        let g = call(
            &s,
            "trace_query",
            json!({"session": "a", "group_by": "kind"}),
        );
        assert!(g["groups"].as_array().unwrap().len() >= 2);
        let first = q["rows"][0]["event_id"].as_str().unwrap().to_string();
        let ex = call(
            &s,
            "trace_explain",
            json!({"session": "a", "event_id": first, "direction": "downstream"}),
        );
        assert!(ex["nodes"].as_array().unwrap().len() >= 2, "{ex}");
        let c = call(
            &s,
            "trace_check",
            json!({"session": "a", "assertions": [
            {"type": "request_completion", "name": "rc", "request": "app.request", "completion": "app.completion"}]}),
        );
        assert_eq!(c["results"][0]["verdict"], "pass");
        assert_eq!(c["persisted"], true);
        call(&s, "trace_open", json!({"session": "b"}));
        call(
            &s,
            "trace_append",
            json!({"session": "b", "events": events(Recipe::Interleave, 2, 20)}),
        );
        let df = call(&s, "trace_diff", json!({"a": "a", "b": "b"}));
        assert!(df["diff"]["entries"].is_array());
        let al = call(
            &s,
            "trace_diff",
            json!({"a": "a", "b": "b", "align": {"keys": ["kind"]}}),
        );
        assert!(al["aligned"]["entries"].is_array());
        let out = d.join("exp");
        let ex = call(
            &s,
            "trace_export",
            json!({"session": "a", "out": out.to_str().unwrap(), "exported_at": "t"}),
        );
        assert_eq!(ex["ok"], true, "{ex}");
        assert!(out.join("manifest.json").is_file());
        let info = call(&s, "trace_info", json!({"session": "a"}));
        assert!(info["events"].as_i64().unwrap() >= 41);
        assert_eq!(info["writer_open"], true);
        let l = call(&s, "trace_list", json!({}));
        assert_eq!(l["sessions"].as_array().unwrap().len(), 2);
        assert_eq!(
            call(&s, "trace_close", json!({"session": "a"}))["was_open"],
            true
        );
        // errors
        assert_eq!(
            call(&s, "trace_append", json!({"session": "a", "events": []}))["error"]["code"],
            "not_open"
        );
        assert_eq!(
            call(&s, "trace_nope", json!({}))["error"]["code"],
            "unknown_command"
        );
        assert_eq!(
            call(&s, "trace_query", json!({"session": "zzz"}))["error"]["code"],
            "refused"
        );
        assert_eq!(
            call(&s, "trace_query", json!({"nonsense": 1}))["error"]["code"],
            "bad_request"
        );
        assert_eq!(s.handle("trace_info", b"{not json")[..], br#"{"error":{"code":"bad_request","message":"key must be a string at line 1 column 2"},"ok":false}"#[..]);
        assert_eq!(
            call(
                &s,
                "trace_query",
                json!({"session": "b", "group_by": "pid; drop"})
            )["error"]["code"],
            "refused"
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn replies_are_byte_identical_across_calls() {
        let (s, d) = svc("det");
        call(&s, "trace_open", json!({"session": "a"}));
        call(
            &s,
            "trace_append",
            json!({"session": "a", "events": events(Recipe::Interleave, 1, 40)}),
        );
        call(&s, "trace_open", json!({"session": "b"}));
        call(
            &s,
            "trace_append",
            json!({"session": "b", "events": events(Recipe::Interleave, 9, 80)}),
        );
        let req = serde_json::to_vec(
            &json!({"a": "a", "b": "b", "align": {"keys": ["kind", "role"], "role_field": "name"}}),
        )
        .unwrap();
        let first = s.handle("trace_diff", &req);
        for _ in 0..3 {
            assert_eq!(first, s.handle("trace_diff", &req));
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn symbolization_and_resymbolize_through_the_service() {
        let (s, d) = svc("sym");
        let symbols = |name: &str| {
            json!({"modules": {"main.exe": {"functions": [
            {"start": 0, "end": 0x2000, "name": name}]}}})
        };
        call(
            &s,
            "trace_open",
            json!({"session": "a", "symbols": symbols("First"), "symbol_revision": "r1"}),
        );
        let mut evs = events(Recipe::Baseline, 1, 5);
        evs.push(json!({"kind": "app.call", "source_id": "src_a", "source_seq": 7, "producer_gen": 1,
            "clock_domain": "qpc-10mhz", "t_mono_ns": 99999, "confidence": "exact", "process_id": 1000,
            "va": 0x40_0100u64, "module": "main.exe"}));
        // The baseline's pid is derived from the seed; use its process_id for the late event.
        let pid = evs[0]["process_id"].clone();
        evs.last_mut().unwrap()["process_id"] = pid;
        let r = call(&s, "trace_append", json!({"session": "a", "events": evs}));
        assert_eq!(r["ok"], true);
        let info = call(&s, "trace_info", json!({"session": "a"}));
        assert_eq!(info["symbolization"]["symbolized"], 1, "{info}");
        let re = call(
            &s,
            "trace_resymbolize",
            json!({"session": "a", "symbols": symbols("Second"), "symbol_revision": "r2"}),
        );
        assert_eq!(re["counts"]["symbolized"], 1);
        let q = call(
            &s,
            "trace_query",
            json!({"session": "a", "kinds": ["app.call"], "with_symbols": true}),
        );
        assert_eq!(q["symbols"]["rows"][0]["function"], "Second");
        let pinned = call(
            &s,
            "trace_query",
            json!({"session": "a", "kinds": ["app.call"], "with_symbols": true, "interp": 1}),
        );
        assert_eq!(pinned["symbols"]["rows"][0]["function"], "First");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn readers_do_not_wait_for_a_busy_writer() {
        let (s, d) = svc("busy");
        call(&s, "trace_open", json!({"session": "a"}));
        call(
            &s,
            "trace_append",
            json!({"session": "a", "events": events(Recipe::Baseline, 1, 20)}),
        );
        let w = s.writer("a").ok().unwrap();
        let held = w.lock().unwrap();
        // A second writer request is answered busy at once; queries are unaffected.
        assert_eq!(
            call(&s, "trace_append", json!({"session": "a", "events": []}))["error"]["code"],
            "busy"
        );
        assert_eq!(
            call(&s, "trace_query", json!({"session": "a", "limit": 3}))["ok"],
            true
        );
        assert_eq!(call(&s, "trace_info", json!({"session": "a"}))["ok"], true);
        drop(held);
        assert_eq!(
            call(&s, "trace_append", json!({"session": "a", "events": []}))["ok"],
            true
        );
        let _ = std::fs::remove_dir_all(d);
    }

    fn msg(seq: u64, kind: &str, payload: Value) -> Value {
        json!({"kind": kind, "source_id": "m", "source_seq": seq, "producer_gen": 1,
            "clock_domain": "c", "t_mono_ns": 100 + seq, "confidence": "exact",
            "process_id": 5, "thread_id": 1, "payload": payload})
    }

    fn layouts_events() -> Vec<Value> {
        // layout 1: u16 type, u16 len, u32 id, u32 amount (12 bytes); layout 2 adds flags + ext.
        vec![
            msg(0, "core.marker", json!({"layout": "v1"})),
            msg(1, "app.msg", json!({"bytes": "01000c0064000000e8030000"})),
            msg(2, "core.marker", json!({"layout": "v2"})),
            msg(
                3,
                "app.msg",
                json!({"bytes": "0200150064000000e803000001e0e1e2"}),
            ),
        ]
    }

    fn codecs(ext: bool) -> Value {
        let f =
            |n: &str, o: u32, l: u32, t: &str| json!({"name": n, "offset": o, "len": l, "type": t});
        let mut v2 = vec![
            f("type", 0, 2, "u16"),
            f("length", 2, 2, "u16"),
            f("id", 4, 4, "u32"),
            f("amount", 8, 4, "u32"),
            f("flags", 12, 1, "u8"),
        ];
        if ext {
            v2.push(f("ext", 13, 3, "hex"));
        }
        json!({"v1": {"name": "m", "fields": [f("type", 0, 2, "u16"), f("length", 2, 2, "u16"), f("id", 4, 4, "u32"), f("amount", 8, 4, "u32")]},
               "v2": {"name": "m", "fields": v2}})
    }

    #[test]
    fn reprocess_makes_explicit_revisions_keeps_evidence_and_shows_unconsumed_bytes() {
        let (s, d) = svc("reproc");
        call(&s, "trace_open", json!({"session": "a"}));
        call(
            &s,
            "trace_append",
            json!({"session": "a", "events": layouts_events()}),
        );
        let first = call(
            &s,
            "trace_reprocess",
            json!({"session": "a", "codecs": codecs(false), "kinds": ["app.msg"], "note": "first guess"}),
        );
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(first["stats"]["unconsumed_events"], 1);
        assert_eq!(first["stats"]["unconsumed_bytes"], 3);
        let second = call(
            &s,
            "trace_reprocess",
            json!({"session": "a", "codecs": codecs(true), "kinds": ["app.msg"], "note": "ext read"}),
        );
        assert_eq!(second["stats"]["unconsumed_events"], 0);
        assert_eq!(
            second["interp"].as_i64().unwrap(),
            first["interp"].as_i64().unwrap() + 1
        );
        let old = call(
            &s,
            "trace_query",
            json!({"session": "a", "kinds": ["app.msg"], "decoded": true, "decode_interp": first["interp"]}),
        );
        let text = old["decoded"]["rows"][1].to_string();
        assert!(
            text.contains("_unconsumed") && text.contains("e0e1e2"),
            "{text}"
        );
        let new = call(
            &s,
            "trace_query",
            json!({"session": "a", "kinds": ["app.msg"], "decoded": true}),
        );
        assert!(new["decoded"]["rows"][1].to_string().contains("\"ext\""));
        assert!(
            !new["decoded"]["rows"][1]
                .to_string()
                .contains("_unconsumed")
        );
        // the observation itself is untouched
        assert!(
            old["rows"][1]["payload"]
                .as_str()
                .unwrap()
                .contains("0200150064000000e803000001e0e1e2")
        );
        let info = call(&s, "trace_info", json!({"session": "a"}));
        assert_eq!(info["decodings"].as_array().unwrap().len(), 2);
        // verify rebuilds the index and replays the journal: the revisions come back identical
        call(&s, "trace_close", json!({"session": "a"}));
        let v = session::verify(&d, "a", &Options::default()).unwrap();
        assert!(v.index_matches_segments);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn meta_scope_and_info_survive_reopen_and_info_has_no_digest_by_default() {
        let (s, d) = svc("meta");
        let key = "ab".repeat(32);
        let o = call(
            &s,
            "trace_open",
            json!({"session": "a", "meta": {"profile": {"id": "p/1", "sha256": "h"}, "scenario": "x"},
            "shared_scope": {"name": "team", "key": key}}),
        );
        assert_eq!(o["scope"], "shared:team", "{o}");
        call(&s, "trace_close", json!({"session": "a"}));
        let s2 = Service::new(&d);
        let info = call(&s2, "trace_info", json!({"session": "a"}));
        assert_eq!(info["meta"]["profile"]["id"], "p/1");
        assert_eq!(info["scope"], "shared:team");
        assert!(info["digest"].is_null());
        let with = call(&s2, "trace_info", json!({"session": "a", "digest": true}));
        assert_eq!(with["digest"].as_str().unwrap().len(), 64);
        let again = call(
            &s2,
            "trace_open",
            json!({"session": "a", "meta": {"scenario": null, "limitations": ["no-stack"]}}),
        );
        assert_eq!(again["meta"]["limitations"][0], "no-stack");
        assert!(again["meta"].get("scenario").is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_shared_scope_correlates_across_sessions_and_the_default_does_not() {
        let (s, d) = svc("scope");
        let key = "cd".repeat(32);
        let ev = |n: u64| {
            vec![msg(
                n,
                "app.x",
                json!({"name": {"$string": "same-secret-value"}}),
            )]
        };
        for (id, shared) in [("a", true), ("b", true), ("c", false), ("e", false)] {
            let mut req = json!({"session": id});
            if shared {
                req["shared_scope"] = json!({"name": "team", "key": key});
            }
            call(&s, "trace_open", req);
            call(&s, "trace_append", json!({"session": id, "events": ev(0)}));
        }
        let corr = |id: &str| {
            let q = call(
                &s,
                "trace_query",
                json!({"session": id, "kinds": ["app.x"]}),
            );
            let p: Value = serde_json::from_str(q["rows"][0]["payload"].as_str().unwrap()).unwrap();
            p["name"]["corr_id"].as_str().unwrap().to_string()
        };
        assert_eq!(corr("a"), corr("b"));
        assert_ne!(corr("c"), corr("e"));
        assert_ne!(corr("a"), corr("c"));
        // a malformed key is refused
        let bad = call(
            &s,
            "trace_open",
            json!({"session": "z", "shared_scope": {"name": "team", "key": "nothex"}}),
        );
        assert_eq!(bad["ok"], false, "{bad}");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn eviction_tombstones_and_quota_refusals() {
        let (s, d) = svc("evict");
        call(&s, "trace_open", json!({"session": "old"}));
        call(&s, "trace_close", json!({"session": "old"}));
        // over quota: a new session is refused with the closed sessions named
        let refused = call(
            &s,
            "trace_open",
            json!({"session": "new", "quota_bytes": 1}),
        );
        assert_eq!(refused["error"]["code"], "quota", "{refused}");
        assert!(
            refused["error"]["message"]
                .as_str()
                .unwrap()
                .contains("old")
        );
        let ev = call(&s, "trace_evict", json!({"to_quota": true}));
        assert_eq!(ev["evicted"][0]["session"], "old", "{ev}");
        assert_eq!(ev["evicted"][0]["reason"], "quota");
        let info = call(&s, "trace_info", json!({"session": "old"}));
        assert_eq!(info["evicted"], true);
        let q = call(&s, "trace_query", json!({"session": "old"}));
        assert!(q["error"]["message"].as_str().unwrap().contains("evicted"));
        // the id is not reused
        assert_eq!(
            call(&s, "trace_open", json!({"session": "old"}))["ok"],
            false
        );
        assert_eq!(
            call(&s, "trace_list", json!({}))["evicted"][0]["session"],
            "old"
        );
        // an open session is not evicted
        call(
            &s,
            "trace_open",
            json!({"session": "live", "quota_bytes": 0}),
        );
        assert_eq!(
            call(&s, "trace_evict", json!({"session": "live"}))["error"]["code"],
            "busy"
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_bundle_of_an_evicted_session_says_it_cannot_be_reproduced() {
        let (s, d) = svc("bundle");
        call(&s, "trace_open", json!({"session": "a"}));
        call(
            &s,
            "trace_append",
            json!({"session": "a", "events": events(Recipe::Baseline, 1, 10)}),
        );
        let out = d.join("exp");
        let ex = call(
            &s,
            "trace_export",
            json!({"session": "a", "out": out.to_str().unwrap(), "exported_at": "t"}),
        );
        assert_eq!(ex["ok"], true, "{ex}");
        let live = call(&s, "trace_bundle", json!({"path": out.to_str().unwrap()}));
        assert_eq!(live["reproducible"], true, "{live}");
        call(&s, "trace_close", json!({"session": "a"}));
        call(&s, "trace_evict", json!({"session": "a", "reason": "test"}));
        let gone = call(&s, "trace_bundle", json!({"path": out.to_str().unwrap()}));
        assert_eq!(gone["reproducible"], false);
        assert_eq!(gone["session_state"], "evicted");
        assert_eq!(gone["reasons"][0]["reason"], "session-evicted");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn relations_materialize_and_cancel_stops_diff_and_query() {
        let (s, d) = svc("rel");
        call(&s, "trace_open", json!({"session": "a"}));
        call(
            &s,
            "trace_append",
            json!({"session": "a", "events": events(Recipe::Interleave, 1, 60)}),
        );
        let m = call(&s, "trace_relations", json!({"session": "a"}));
        assert_eq!(m["ok"], true, "{m}");
        assert_eq!(
            call(&s, "trace_info", json!({"session": "a"}))["relations"]["source"],
            "materialized"
        );
        crate::cancel::set(Some(Box::new(|| true)));
        let cancelled = call(
            &s,
            "trace_diff",
            json!({"a": "a", "b": "a", "align": {"keys": ["kind"]}}),
        );
        let grouped = call(
            &s,
            "trace_query",
            json!({"session": "a", "group_by": "kind"}),
        );
        crate::cancel::set(None);
        assert_eq!(cancelled["error"]["code"], "cancelled", "{cancelled}");
        assert_eq!(grouped["error"]["code"], "cancelled", "{grouped}");
        let _ = std::fs::remove_dir_all(d);
    }
}
