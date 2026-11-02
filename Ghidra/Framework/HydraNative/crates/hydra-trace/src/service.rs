//! The request service behind the C ABI and the CLI: every `trace_*` command takes request bytes
//! (JSON) and returns reply bytes (JSON). Java routes the bytes and nothing more. Replies are
//! deterministic (sorted keys, no floats). Readers open their own read-only connection on the
//! committed index and never wait on a writer; a second request for a writer that is busy is
//! answered `busy`, like the engine's other owner-only operations.

use crate::align::{self, AlignSpec};
use crate::artifact::{self, Artifacts};
use crate::explain::{self, Budget as ExplainBudget, Direction};
use crate::export::{self, ExportOptions};
use crate::query::{self, Assertion, Filter};
use crate::session::{self, Session};
use crate::store::{Budget, Error, Options, Store};
use crate::symbolize::{self, TableSymbolizer};
use crate::{checks, relations};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};

/// The largest request the service reads.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// The commands this service answers.
pub const COMMANDS: [&str; 12] = [
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
];

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
        Error::Sql(e).into()
    }
}

fn parse<T: for<'de> Deserialize<'de>>(req: &Value) -> std::result::Result<T, Failure> {
    Ok(serde_json::from_value(req.clone())?)
}

/// Where the sessions of this service live and which writers are open.
pub struct Service {
    root: PathBuf,
    writers: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
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
}

#[derive(Deserialize)]
struct SessionReq {
    session: String,
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
        let req: Value = if request.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(request)?
        };
        match command {
            "trace_open" => self.open(parse(&req)?),
            "trace_append" => self.append(parse(&req)?),
            "trace_mark" => self.mark(parse(&req)?),
            "trace_query" => self.query(parse(&req)?),
            "trace_explain" => self.explain(parse(&req)?),
            "trace_diff" => self.diff(parse(&req)?),
            "trace_check" => self.check(parse(&req)?),
            "trace_export" => self.export(parse(&req)?),
            "trace_close" => self.close(parse(&req)?),
            "trace_list" => self.list(),
            "trace_info" => self.info(parse(&req)?),
            "trace_resymbolize" => self.resymbolize(parse(&req)?),
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
        let mut map = self
            .writers
            .lock()
            .map_err(|_| fail("internal", "poisoned"))?;
        if let Some(w) = map.get(&r.session) {
            let g = w.lock().map_err(|_| fail("internal", "poisoned"))?;
            return Ok(
                json!({"session": r.session, "already_open": true, "revision": g.store().revision()?}),
            );
        }
        let options = Options {
            symbolizer: r
                .symbols
                .map(|t| Arc::new(t) as Arc<dyn symbolize::Symbolizer>),
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
        let revision = session.store().revision()?;
        map.insert(r.session.clone(), Arc::new(Mutex::new(session)));
        Ok(
            json!({"session": r.session, "revision": revision, "recovery": serde_json::to_value(&recovery)?}),
        )
    }

    fn append(&self, r: AppendReq) -> Reply {
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
                let (function, reason): (Option<String>, Option<String>) = match interp {
                    Some(i) => store
                        .conn()
                        .query_row(
                            "SELECT function,reason FROM event_symbols WHERE interp=?1 AND seq=?2",
                            rusqlite::params![i, row.seq],
                            |x| Ok((x.get(0)?, x.get(1)?)),
                        )
                        .unwrap_or((None, Some("no-symbol".into()))),
                    None => (None, None),
                };
                syms.push(json!({"seq": row.seq, "function": function, "reason": reason}));
            }
            out["symbols"] = json!({"interp": interp, "rows": syms});
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
        Ok(json!({"sessions": out}))
    }

    fn info(&self, r: SessionReq) -> Reply {
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
        Ok(json!({
            "session": r.session,
            "revision": store.revision()?,
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
            "symbolization": serde_json::to_value(&counts)?,
            "relations": {"count": rel.0.len(), "source": rel.1},
            "artifacts": count("SELECT COUNT(*) FROM artifacts"),
            "tombstones": count("SELECT COUNT(*) FROM tombstones"),
            "writer_open": open,
            "digest": store.digest()?,
        }))
    }

    fn resymbolize(&self, r: ResymReq) -> Reply {
        // Through the open writer when there is one, else a short-lived writer connection.
        let rev = if let Ok(w) = self.writer(&r.session) {
            let mut g = w
                .try_lock()
                .map_err(|_| fail("busy", "another request is writing this session"))?;
            symbolize::resymbolize(g.store_mut(), &r.symbols, &r.symbol_revision)?
        } else {
            if !session::index_path(&self.root.join(&r.session)).exists() {
                return Err(fail("refused", format!("no session {}", r.session)));
            }
            let mut store = Store::open(
                &session::index_path(&self.root.join(&r.session)),
                &r.session,
            )?;
            symbolize::resymbolize(&mut store, &r.symbols, &r.symbol_revision)?
        };
        let store = self.reader(&r.session)?;
        Ok(
            json!({"interp": rev, "counts": serde_json::to_value(symbolize::counts(&store, Some(rev))?)?,
                  "revision": store.revision()?}),
        )
    }
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
}
