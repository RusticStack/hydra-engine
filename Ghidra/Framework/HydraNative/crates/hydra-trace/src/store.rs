//! The per-session index: SQLite in WAL mode, derived from the raw segments. One ingester writes
//! it in group commits; any number of readers read committed snapshots. Nothing is dropped
//! silently: a rejected record is stored with its reason, a jump in a producer's sequence is
//! stored as a gap, and reaching the retention budget stops recording with a `core.capture.gap`.
//! `rebuild` replays the batch manifest over the segments and must reproduce the same `digest`.

use crate::lifetime::Lifetimes;
use crate::model::{Event, kind_is_valid};
use crate::raw;
use crate::symbolize::{self, Symbolizer};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

pub const SCHEMA_VERSION: i64 = 2;

/// The synthetic source that carries records written by ingest itself.
pub const INGEST_SOURCE: &str = "hydra-ingest";

const DDL: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL,
  source_id TEXT NOT NULL, source_seq INTEGER NOT NULL, producer_gen INTEGER NOT NULL,
  kind TEXT NOT NULL, clock_domain TEXT NOT NULL, t_mono_ns INTEGER NOT NULL, t_wall_ns INTEGER,
  process_id INTEGER, thread_id INTEGER, process_gen INTEGER, thread_gen INTEGER,
  module TEXT, module_instance INTEGER, va INTEGER, confidence TEXT NOT NULL, acquisition TEXT,
  resource_key TEXT, state_key TEXT, corr TEXT,
  callstack TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, seq);
CREATE INDEX IF NOT EXISTS ev_resource ON events(resource_key, seq) WHERE resource_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_state ON events(state_key, seq) WHERE state_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_corr ON events(corr, seq) WHERE corr IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_process ON events(process_gen, process_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS ev_source ON events(source_id, producer_gen, source_seq);
CREATE TABLE IF NOT EXISTS sources(source_id TEXT PRIMARY KEY, segment_records INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gaps(
  id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, reason TEXT NOT NULL,
  first_missing INTEGER, last_missing INTEGER, dropped INTEGER, t_mono_ns INTEGER, observed INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rejects(id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, n INTEGER NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, first_n INTEGER NOT NULL, count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS processes(
  pid INTEGER NOT NULL, gen INTEGER NOT NULL, start_seq INTEGER, end_seq INTEGER, end_reason TEXT,
  resolved INTEGER NOT NULL, PRIMARY KEY(pid, gen));
CREATE TABLE IF NOT EXISTS threads(
  pgen INTEGER NOT NULL, tid INTEGER NOT NULL, gen INTEGER NOT NULL, start_seq INTEGER, end_seq INTEGER,
  resolved INTEGER NOT NULL, PRIMARY KEY(pgen, tid, gen));
CREATE TABLE IF NOT EXISTS module_instances(
  inst INTEGER PRIMARY KEY, pgen INTEGER NOT NULL, name TEXT NOT NULL, build TEXT, base INTEGER NOT NULL,
  size INTEGER NOT NULL, load_seq INTEGER NOT NULL, unload_seq INTEGER);
CREATE TABLE IF NOT EXISTS objects(
  pgen INTEGER NOT NULL, addr INTEGER NOT NULL, gen INTEGER NOT NULL, type TEXT, create_seq INTEGER,
  destroy_seq INTEGER, resolved INTEGER NOT NULL, PRIMARY KEY(pgen, addr, gen));
CREATE TABLE IF NOT EXISTS clock_domains(
  name TEXT PRIMARY KEY, source_id TEXT NOT NULL, unit TEXT NOT NULL, resolution_ns INTEGER NOT NULL,
  calibrated INTEGER NOT NULL, offset_ns INTEGER, drift_ppm INTEGER, uncertainty_ns INTEGER, to_domain TEXT);
CREATE TABLE IF NOT EXISTS coverage_intervals(
  id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, state TEXT NOT NULL, t_start INTEGER NOT NULL,
  t_end INTEGER NOT NULL, seq_start INTEGER NOT NULL, seq_end INTEGER NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS interpretations(
  rev INTEGER PRIMARY KEY, kind TEXT NOT NULL, parent INTEGER, symbol_revision TEXT, codec_hash TEXT,
  schema_hash TEXT, context_from INTEGER, context_to INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS event_symbols(
  interp INTEGER NOT NULL, seq INTEGER NOT NULL, function TEXT, reason TEXT, stack TEXT, PRIMARY KEY(interp, seq)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS interp_fields(
  interp INTEGER NOT NULL, seq INTEGER NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
  byte_off INTEGER, byte_len INTEGER, PRIMARY KEY(interp, seq, field)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS relations(
  id INTEGER PRIMARY KEY, relation TEXT NOT NULL, from_seq INTEGER NOT NULL, to_seq INTEGER,
  basis TEXT NOT NULL, status TEXT NOT NULL, unresolved TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS rel_from ON relations(from_seq);
CREATE INDEX IF NOT EXISTS rel_to ON relations(to_seq);
CREATE TABLE IF NOT EXISTS artifacts(
  id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, scope TEXT NOT NULL, max_bytes INTEGER NOT NULL,
  retention_secs INTEGER, redaction TEXT NOT NULL, created_unix INTEGER NOT NULL, state TEXT NOT NULL,
  created_rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tombstones(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, reason TEXT NOT NULL, at_rev INTEGER NOT NULL, sha256 TEXT);
CREATE TABLE IF NOT EXISTS assertions(
  name TEXT NOT NULL, rev INTEGER NOT NULL, spec TEXT NOT NULL, PRIMARY KEY(name, rev));
CREATE TABLE IF NOT EXISTS check_results(
  id INTEGER PRIMARY KEY, assertion TEXT NOT NULL, revision INTEGER NOT NULL, verdict TEXT NOT NULL,
  checked INTEGER NOT NULL, counterexamples TEXT NOT NULL, coverage TEXT NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS marks(
  id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, label TEXT NOT NULL, phase TEXT, frame INTEGER);
";

/// Tables the digest covers, with their order.
const DIGEST_TABLES: &[(&str, &str)] = &[
    ("events", "seq"),
    ("gaps", "id"),
    ("rejects", "id"),
    ("sources", "source_id"),
    ("batches", "id"),
    ("processes", "pid,gen"),
    ("threads", "pgen,tid,gen"),
    ("module_instances", "inst"),
    ("objects", "pgen,addr,gen"),
    ("clock_domains", "name"),
    ("coverage_intervals", "id"),
    ("interpretations", "rev"),
    ("event_symbols", "interp,seq"),
    ("interp_fields", "interp,seq,field"),
];

/// An ingest batch: records `first_n .. first_n+count` of one source's segment, committed together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub source_id: String,
    pub first_n: u64,
    pub count: u64,
}

/// What one ingest did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IngestStats {
    pub stored: u64,
    pub rejected: u64,
    pub gaps_found: u64,
    pub revision: u64,
    /// Records not stored because the retention budget was reached (never silent: a
    /// `core.capture.gap` with reason `budget` records them).
    pub dropped_budget: u64,
}

#[derive(Debug)]
pub enum Error {
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    Segment(String),
    Io(std::io::Error),
    Refused(String),
    /// The request was cancelled (see `cancel`); nothing it did is visible.
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sql(e) => write!(f, "sqlite: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Segment(e) => write!(f, "segment: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Refused(e) => write!(f, "refused: {e}"),
            Error::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sql(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Retention budget: a per-session safety bound. Reaching it stops recording with a
/// `core.capture.gap`; it never drops events silently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub max_events: Option<u64>,
    pub max_bytes: Option<u64>,
}

impl Budget {
    /// Derive a budget from the free space above the disk reserve: `share_percent` of it, at an
    /// estimated 512 bytes per indexed event.
    pub fn from_disk(free_bytes: u64, reserve_bytes: u64, share_percent: u64) -> Self {
        let usable = free_bytes.saturating_sub(reserve_bytes) / 100 * share_percent.min(100);
        Self {
            max_events: Some(usable / 512),
            max_bytes: Some(usable),
        }
    }
}

/// Ingest options that are not stored in the segments.
#[derive(Clone, Default)]
pub struct Options {
    pub symbolizer: Option<Arc<dyn Symbolizer>>,
    /// The program revision the symbolizer is pinned to.
    pub symbol_revision: String,
    pub budget: Budget,
}

/// A session index.
pub struct Store {
    conn: Connection,
    session: String,
    life: Lifetimes,
    options: Options,
    sym_interp: Option<i64>,
    checkpoint: Option<crate::checkpoint::Checkpointer>,
    /// The last stored `(producer_gen, source_seq)` per source, so a batch does not rescan the
    /// source's rows to find it. Cleared whenever a batch rolls back.
    last_seen: std::collections::HashMap<String, (u32, u64)>,
}

fn event_cost(event: &Event) -> u64 {
    160 + event.callstack.len() as u64 * 8
        + event
            .payload
            .values()
            .map(|v| v.to_string().len() as u64)
            .sum::<u64>()
}

fn meta_get(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
        r.get(0)
    })
    .ok()
}

impl Store {
    /// Open or create the index at `path` (the writer).
    pub fn open(path: &Path, session: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let mut store = Self::init(conn, session)?;
        store.checkpoint = crate::checkpoint::Checkpointer::start(path);
        Ok(store)
    }

    /// An in-memory index (tests, offline tools).
    pub fn memory(session: &str) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, session)
    }

    /// A read-only handle on an existing index; it sees committed snapshots only.
    pub fn reader(path: &Path, session: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self {
            conn,
            session: session.into(),
            life: Lifetimes::default(),
            options: Options::default(),
            sym_interp: None,
            checkpoint: None,
            last_seen: std::collections::HashMap::new(),
        })
    }

    /// A second read-only handle on the same on-disk index, for a worker thread; `None` for an
    /// in-memory index.
    pub fn reader_clone(&self) -> Option<Store> {
        let path = self.conn.path().filter(|p| !p.is_empty())?;
        Store::reader(Path::new(path), &self.session).ok()
    }

    fn init(conn: Connection, session: &str) -> Result<Self> {
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Indexes on random keys outgrow SQLite's 2 MiB default page cache quickly; a larger cache
        // and fewer checkpoints keep ingest throughput flat as the session grows.
        conn.pragma_update(None, "cache_size", -131_072_i64)?;
        conn.pragma_update(None, "wal_autocheckpoint", 65_536_i64)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(DDL)?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?1),('session',?2),('revision','0'),('ingested_bytes','0')",
            params![SCHEMA_VERSION.to_string(), session],
        )?;
        let life = Lifetimes::load(&conn)?;
        let budget = Budget {
            max_events: meta_get(&conn, "budget_events").and_then(|v| v.parse().ok()),
            max_bytes: meta_get(&conn, "budget_bytes").and_then(|v| v.parse().ok()),
        };
        Ok(Self {
            conn,
            session: session.into(),
            life,
            options: Options {
                budget,
                ..Options::default()
            },
            sym_interp: None,
            checkpoint: None,
            last_seen: std::collections::HashMap::new(),
        })
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    /// Set the ingest options (symbolizer, pinned program revision, budget).
    pub fn set_options(&mut self, options: Options) -> Result<()> {
        self.set_budget(options.budget)?;
        self.options.symbolizer = options.symbolizer;
        self.options.symbol_revision = options.symbol_revision;
        self.sym_interp = None;
        Ok(())
    }

    /// Set the retention budget (stored with the index, so it survives a reopen).
    pub fn set_budget(&mut self, budget: Budget) -> Result<()> {
        self.options.budget = budget;
        for (key, value) in [
            ("budget_events", budget.max_events),
            ("budget_bytes", budget.max_bytes),
        ] {
            match value {
                Some(v) => self.conn.execute(
                    "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2",
                    params![key, v.to_string()],
                )?,
                None => self
                    .conn
                    .execute("DELETE FROM meta WHERE key=?1", params![key])?,
            };
        }
        Ok(())
    }

    pub fn budget(&self) -> Budget {
        self.options.budget
    }

    /// True once the budget stopped recording.
    pub fn stopped(&self) -> bool {
        meta_get(&self.conn, "stopped").is_some()
    }

    /// The committed high-water mark: a reader's revision.
    pub fn revision(&self) -> Result<u64> {
        let v: String =
            self.conn
                .query_row("SELECT value FROM meta WHERE key='revision'", [], |r| {
                    r.get(0)
                })?;
        Ok(v.parse().unwrap_or(0))
    }

    /// Ingest `records` (already chain-verified) of `source_id` as one group commit. `first_n` is
    /// the segment number of the first record, kept in the batch manifest for `rebuild`. A failure
    /// rolls the whole batch back.
    pub fn ingest(
        &mut self,
        source_id: &str,
        first_n: u64,
        records: &[Map<String, Value>],
    ) -> Result<IngestStats> {
        let result = self.ingest_inner(source_id, first_n, records);
        if result.is_err() {
            // The mirror may be ahead of the rolled-back tables: reload it.
            self.life = Lifetimes::load(&self.conn)?;
            self.sym_interp = None;
            self.last_seen.clear();
        }
        result
    }

    fn ingest_inner(
        &mut self,
        source_id: &str,
        first_n: u64,
        records: &[Map<String, Value>],
    ) -> Result<IngestStats> {
        let session = self.session.clone();
        let symbolizer = self.options.symbolizer.clone();
        let budget = self.options.budget;
        let symbol_revision = self.options.symbol_revision.clone();
        let tx = self.conn.transaction()?;
        let mut stats = IngestStats::default();
        let mut next_seq: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq),0)+1 FROM events", [], |r| {
                r.get(0)
            })?;
        let mut bytes: u64 = meta_get_tx(&tx, "ingested_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut stopped = meta_get_tx(&tx, "stopped").is_some();
        // The producer's last sequence in this generation, to detect a jump.
        let mut last: Option<(u32, u64)> = match self.last_seen.get(source_id) {
            Some(v) => Some(*v),
            None => tx
                .query_row(
                    "SELECT producer_gen, source_seq FROM events NOT INDEXED WHERE source_id=?1 ORDER BY seq DESC LIMIT 1",
                    params![source_id],
                    |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u64>(1)?)),
                )
                .ok(),
        };
        let sym_interp = if symbolizer.is_some() {
            Some(sym_interp_in(&tx, &mut self.sym_interp, &symbol_revision)?)
        } else {
            None
        };
        let mut source_state: Option<String> = None;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO events(seq,event_id,source_id,source_seq,producer_gen,kind,clock_domain,t_mono_ns,process_id,
                 thread_id,process_gen,thread_gen,module,module_instance,va,confidence,acquisition,resource_key,state_key,
                 corr,callstack,payload,t_wall_ns) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            )?;
            let mut sym = tx.prepare_cached(
                "INSERT INTO event_symbols(interp,seq,function,reason,stack) VALUES(?1,?2,?3,?4,?5)",
            )?;
            for (offset, record) in records.iter().enumerate() {
                let n = first_n + offset as u64;
                let mut body = record.clone();
                for chain_field in ["n", "prev", "hash"] {
                    body.remove(chain_field);
                }
                let mut event: Event = match serde_json::from_value(Value::Object(body)) {
                    Ok(e) => e,
                    Err(e) => {
                        reject(&tx, source_id, n, &format!("schema: {e}"))?;
                        stats.rejected += 1;
                        continue;
                    }
                };
                if !kind_is_valid(&event.kind) {
                    reject(&tx, source_id, n, &format!("unknown kind {}", event.kind))?;
                    stats.rejected += 1;
                    continue;
                }
                if event.source_id != source_id {
                    reject(&tx, source_id, n, "source_id differs from the segment")?;
                    stats.rejected += 1;
                    continue;
                }
                // Retention budget: stop recording, say so, never drop silently.
                let cost = event_cost(&event);
                let over = budget.max_events.is_some_and(|m| (next_seq as u64) > m)
                    || budget.max_bytes.is_some_and(|m| bytes + cost > m);
                if stopped || over {
                    if !stopped {
                        stopped = true;
                        tx.execute(
                            "INSERT INTO meta(key,value) VALUES('stopped','budget') ON CONFLICT(key) DO UPDATE SET value='budget'",
                            [],
                        )?;
                        tx.execute(
                            "INSERT INTO gaps(source_id,reason,first_missing,last_missing,dropped,t_mono_ns,observed)
                             VALUES(?1,'budget',?2,NULL,0,?3,1)",
                            params![source_id, event.source_seq as i64, event.t_mono_ns as i64],
                        )?;
                        let gap_id = tx.last_insert_rowid().to_string();
                        tx.execute(
                            "INSERT INTO meta(key,value) VALUES('budget_gap',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
                            params![gap_id],
                        )?;
                        let mut gap = Event {
                            kind: "core.capture.gap".into(),
                            source_id: INGEST_SOURCE.into(),
                            source_seq: 0,
                            producer_gen: 0,
                            clock_domain: event.clock_domain.clone(),
                            t_mono_ns: event.t_mono_ns,
                            t_wall_ns: None,
                            process_id: None,
                            thread_id: None,
                            process_gen: None,
                            thread_gen: None,
                            module: None,
                            module_instance: None,
                            confidence: "exact".into(),
                            acquisition: None,
                            va: None,
                            callstack: Vec::new(),
                            payload: Map::new(),
                        };
                        gap.payload.insert("reason".into(), "budget".into());
                        gap.payload
                            .insert("stopped_source".into(), source_id.into());
                        store_event(&mut insert, &session, next_seq, &gap, None)?;
                        next_seq += 1;
                    }
                    stats.dropped_budget += 1;
                    continue;
                }
                match last {
                    Some((generation, seq))
                        if generation == event.producer_gen && event.source_seq > seq + 1 =>
                    {
                        // A jump. A core.capture.gap record from the producer explains it; any
                        // other jump is a lost producer.
                        let explained = event.kind == "core.capture.gap"
                            || gap_explains(&tx, source_id, seq + 1)?;
                        if !explained {
                            tx.execute(
                                "INSERT INTO gaps(source_id,reason,first_missing,last_missing,dropped,t_mono_ns,observed)
                                 VALUES(?1,'producer-lost',?2,?3,NULL,?4,0)",
                                params![source_id, seq + 1, event.source_seq - 1, event.t_mono_ns as i64],
                            )?;
                            stats.gaps_found += 1;
                            self.life.cover_break(
                                &tx,
                                source_id,
                                "gap",
                                "producer-lost",
                                event.t_mono_ns as i64,
                                next_seq,
                            )?;
                        }
                    }
                    Some((generation, seq))
                        if generation == event.producer_gen && event.source_seq <= seq =>
                    {
                        reject(&tx, source_id, n, "source_seq not increasing")?;
                        stats.rejected += 1;
                        continue;
                    }
                    _ => {}
                }
                if event.kind == "core.capture.gap" {
                    let p = &event.payload;
                    let reason = p
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified")
                        .to_string();
                    tx.execute(
                        "INSERT INTO gaps(source_id,reason,first_missing,last_missing,dropped,t_mono_ns,observed)
                         VALUES(?1,?2,?3,?4,?5,?6,1)",
                        params![
                            source_id,
                            reason,
                            p.get("first_missing_source_seq").and_then(Value::as_i64),
                            p.get("last_missing_source_seq").and_then(Value::as_i64),
                            p.get("dropped").and_then(Value::as_i64),
                            event.t_mono_ns as i64
                        ],
                    )?;
                    self.life.cover_break(
                        &tx,
                        source_id,
                        "gap",
                        &reason,
                        event.t_mono_ns as i64,
                        next_seq,
                    )?;
                }
                if event.kind == "core.capture.source" {
                    source_state = event
                        .payload
                        .get("state")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    apply_clock_declaration(&tx, &event)?;
                    if let Some(state) = source_state.as_deref().filter(|s| *s != "observing") {
                        let reason = event
                            .payload
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("declared")
                            .to_string();
                        self.life.cover_break(
                            &tx,
                            source_id,
                            state,
                            &reason,
                            event.t_mono_ns as i64,
                            next_seq,
                        )?;
                    }
                }
                self.life.clock(&tx, &event.clock_domain, source_id)?;
                self.life.observe(&tx, next_seq, &mut event)?;
                if event.kind != "core.capture.gap" && event.kind != "core.capture.source" {
                    self.life
                        .cover_event(&tx, source_id, event.t_mono_ns as i64, next_seq)?;
                }
                let object_gen = event
                    .payload
                    .get("object")
                    .and_then(Value::as_u64)
                    .map(|addr| self.life.object_gen(event.process_gen.unwrap_or(0), addr));
                store_event(&mut insert, &session, next_seq, &event, object_gen)?;
                if let (Some(s), Some(interp)) = (symbolizer.as_deref(), sym_interp) {
                    let site = symbolize::site_of(event.va, &event.callstack);
                    let module = site.and_then(|a| {
                        self.life
                            .find_module(event.process_gen.unwrap_or(0), a, next_seq)
                    });
                    let (function, reason) = symbolize::resolve_site(s, module, site);
                    let stack = symbolize::resolve_stack(
                        s,
                        &self.life,
                        event.process_gen.unwrap_or(0),
                        &event.callstack,
                        next_seq,
                    );
                    sym.execute(params![interp, next_seq, function, reason, stack])?;
                }
                bytes += cost;
                last = Some((event.producer_gen, event.source_seq));
                next_seq += 1;
                stats.stored += 1;
            }
        }
        self.life.end_batch(&tx)?;
        if stats.dropped_budget > 0
            && let Some(id) = meta_get_tx(&tx, "budget_gap")
        {
            tx.execute(
                "UPDATE gaps SET dropped=COALESCE(dropped,0)+?1 WHERE id=?2",
                params![stats.dropped_budget as i64, id],
            )?;
        }
        tx.execute(
            "UPDATE meta SET value=?1 WHERE key='ingested_bytes'",
            params![bytes.to_string()],
        )?;
        let state = source_state.unwrap_or_else(|| "observing".into());
        tx.execute(
            "INSERT INTO sources(source_id,segment_records,state) VALUES(?1,?2,?3)
             ON CONFLICT(source_id) DO UPDATE SET segment_records=segment_records+?2, state=?3",
            params![source_id, records.len() as i64, state],
        )?;
        tx.execute(
            "INSERT INTO batches(source_id,first_n,count) VALUES(?1,?2,?3)",
            params![source_id, first_n as i64, records.len() as i64],
        )?;
        let revision = {
            let current: String =
                tx.query_row("SELECT value FROM meta WHERE key='revision'", [], |r| {
                    r.get(0)
                })?;
            current.parse::<u64>().unwrap_or(0) + 1
        };
        tx.execute(
            "UPDATE meta SET value=?1 WHERE key='revision'",
            params![revision.to_string()],
        )?;
        tx.commit()?;
        if let Some(l) = last {
            self.last_seen.insert(source_id.to_string(), l);
        }
        if let Some(c) = &self.checkpoint {
            c.after_commit();
        }
        stats.revision = revision;
        Ok(stats)
    }

    /// The batch manifest in commit order.
    pub fn batches(&self) -> Result<Vec<Batch>> {
        let mut stmt = self
            .conn
            .prepare("SELECT source_id,first_n,count FROM batches ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Batch {
                source_id: r.get(0)?,
                first_n: r.get::<_, i64>(1)? as u64,
                count: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// The next segment record to ingest for `source_id` (the sum of its committed batches).
    pub fn ingested_records(&self, source_id: &str) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(SUM(count),0) FROM batches WHERE source_id=?1",
            params![source_id],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// A SHA-256 over every stored table in a canonical order: two indexes with the same digest
    /// hold the same evidence.
    pub fn digest(&self) -> Result<String> {
        let mut hasher = Sha256::new();
        for (table, order) in DIGEST_TABLES {
            let mut stmt = self
                .conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
            let columns = stmt.column_count();
            let mut rows = stmt.query([])?;
            hasher.update(table.as_bytes());
            while let Some(row) = rows.next()? {
                for i in 0..columns {
                    let value: rusqlite::types::Value = row.get(i)?;
                    hasher.update(format!("{value:?}|").as_bytes());
                }
                hasher.update(b"\n");
            }
        }
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    pub fn event_count(&self) -> Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

fn meta_get_tx(tx: &rusqlite::Transaction<'_>, key: &str) -> Option<String> {
    tx.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
        r.get(0)
    })
    .ok()
}

fn sym_interp_in(
    tx: &rusqlite::Transaction<'_>,
    cache: &mut Option<i64>,
    symbol_revision: &str,
) -> Result<i64> {
    if let Some(i) = *cache {
        return Ok(i);
    }
    let existing: Option<i64> = tx
        .query_row(
            "SELECT MAX(rev) FROM interpretations WHERE kind='symbolization' AND symbol_revision=?1 AND note='ingest'",
            params![symbol_revision],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let rev = match existing {
        Some(r) => r,
        None => {
            let rev: i64 = tx.query_row(
                "SELECT COALESCE(MAX(rev),0)+1 FROM interpretations",
                [],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO interpretations(rev,kind,parent,symbol_revision,note) VALUES(?1,'symbolization',NULL,?2,'ingest')",
                params![rev, symbol_revision],
            )?;
            rev
        }
    };
    *cache = Some(rev);
    Ok(rev)
}

/// A `core.capture.source` event may declare its clock domain and calibration.
fn apply_clock_declaration(tx: &rusqlite::Transaction<'_>, event: &Event) -> Result<()> {
    let Some(clock) = event.payload.get("clock").and_then(Value::as_object) else {
        return Ok(());
    };
    let unit = clock.get("unit").and_then(Value::as_str).unwrap_or("ns");
    let resolution = clock
        .get("resolution_ns")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let offset = clock.get("offset_ns").and_then(Value::as_i64);
    let drift = clock.get("drift_ppm").and_then(Value::as_i64);
    let uncertainty = clock.get("uncertainty_ns").and_then(Value::as_i64);
    let to = clock.get("to").and_then(Value::as_str);
    let calibrated = i64::from(offset.is_some() && uncertainty.is_some() && to.is_some());
    tx.execute(
        "INSERT INTO clock_domains(name,source_id,unit,resolution_ns,calibrated,offset_ns,drift_ppm,uncertainty_ns,to_domain)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(name) DO UPDATE SET unit=?3,resolution_ns=?4,calibrated=?5,offset_ns=?6,drift_ppm=?7,uncertainty_ns=?8,to_domain=?9",
        params![
            event.clock_domain,
            event.source_id,
            unit,
            resolution,
            calibrated,
            offset,
            drift,
            uncertainty,
            to
        ],
    )?;
    Ok(())
}

fn store_event(
    insert: &mut rusqlite::CachedStatement<'_>,
    session: &str,
    seq: i64,
    event: &Event,
    object_gen: Option<Option<u32>>,
) -> Result<()> {
    let (resource_key, state_key, corr) = keys(event, object_gen);
    insert.execute(params![
        seq,
        format!("ev_{session}_{seq}"),
        event.source_id,
        event.source_seq as i64,
        event.producer_gen,
        event.kind,
        event.clock_domain,
        event.t_mono_ns as i64,
        event.process_id,
        event.thread_id,
        event.process_gen,
        event.thread_gen,
        event.module,
        event.module_instance,
        event.va.map(|v| v as i64),
        event.confidence,
        event.acquisition.map(|a| format!("{a:?}").to_lowercase()),
        resource_key,
        state_key,
        corr,
        serde_json::to_string(&event.callstack)?,
        serde_json::to_string(&Value::Object(event.payload.clone()))?,
        event.t_wall_ns.map(|v| v as i64),
    ])?;
    Ok(())
}

fn reject(tx: &rusqlite::Transaction<'_>, source_id: &str, n: u64, reason: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO rejects(source_id,n,reason) VALUES(?1,?2,?3)",
        params![source_id, n as i64, reason],
    )?;
    Ok(())
}

fn gap_explains(
    tx: &rusqlite::Transaction<'_>,
    source_id: &str,
    missing_from: u64,
) -> Result<bool> {
    let hit: i64 = tx.query_row(
        "SELECT COUNT(*) FROM gaps WHERE source_id=?1 AND first_missing<=?2 AND last_missing>=?2",
        params![source_id, missing_from as i64],
        |r| r.get(0),
    )?;
    Ok(hit > 0)
}

/// Derived lookup keys: the logical resource key, the state key and the correlation id. The
/// state key carries the object's lifetime generation (`#?` when no create was observed), so a
/// reused address is a different state.
fn keys(
    event: &Event,
    object_gen: Option<Option<u32>>,
) -> (Option<String>, Option<String>, Option<String>) {
    let text = |k: &str| {
        event
            .payload
            .get(k)
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
    };
    let resource = event
        .kind
        .starts_with("core.resource.")
        .then(|| text("key"))
        .flatten();
    let state = (event.kind.starts_with("core.state.")).then(|| {
        let object = text("object").unwrap_or_default();
        let key = text("key").or_else(|| text("offset")).unwrap_or_default();
        let lifetime = match object_gen {
            Some(Some(g)) => format!("#{g}"),
            Some(None) => "#?".to_string(),
            None => String::new(),
        };
        format!(
            "{}:{}{}:{}",
            event.process_gen.unwrap_or(0),
            object,
            lifetime,
            key
        )
    });
    (resource, state, text("corr"))
}

/// Rebuild an index from segments and the batch manifest of the original. `segments` maps a
/// source id to its raw bytes. The result has the same `digest` as the original.
pub fn rebuild(session: &str, segments: &[(String, Vec<u8>)], batches: &[Batch]) -> Result<Store> {
    rebuild_with(session, segments, batches, &Options::default())
}

/// [`rebuild`] with the options the original ran under (symbolizer, budget).
pub fn rebuild_with(
    session: &str,
    segments: &[(String, Vec<u8>)],
    batches: &[Batch],
    options: &Options,
) -> Result<Store> {
    let mut store = Store::memory(session)?;
    store.set_options(options.clone())?;
    let scans: Vec<(String, raw::Scan)> = segments
        .iter()
        .map(|(id, bytes)| (id.clone(), raw::scan(bytes, id)))
        .collect();
    for batch in batches {
        let Some((_, scan)) = scans.iter().find(|(id, _)| *id == batch.source_id) else {
            return Err(Error::Segment(format!(
                "missing segment {}",
                batch.source_id
            )));
        };
        let from = batch.first_n as usize;
        let to = from + batch.count as usize;
        if to > scan.records.len() {
            return Err(Error::Segment(format!(
                "segment {} is shorter than the manifest",
                batch.source_id
            )));
        }
        store.ingest(&batch.source_id, batch.first_n, &scan.records[from..to])?;
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{self, Recipe};

    fn load(
        recipe: Recipe,
        seed: u64,
        events: usize,
        batch: usize,
    ) -> (Store, Vec<(String, Vec<u8>)>) {
        let segments = synth::generate(recipe, seed, events);
        let mut store = Store::memory("t1").unwrap();
        let mut raw_segments = Vec::new();
        for s in &segments {
            let scan = raw::scan(&s.bytes, &s.id);
            for (i, chunk) in scan.records.chunks(batch).enumerate() {
                store.ingest(&s.id, (i * batch) as u64, chunk).unwrap();
            }
            raw_segments.push((s.id.clone(), s.bytes.clone()));
        }
        (store, raw_segments)
    }

    #[test]
    fn ingest_assigns_seq_and_revision() {
        let (store, _) = load(Recipe::Baseline, 1, 100, 40);
        assert_eq!(store.event_count().unwrap(), 102);
        assert_eq!(store.revision().unwrap(), 3);
    }

    #[test]
    fn rebuilt_index_equals_the_original() {
        for recipe in [
            Recipe::Baseline,
            Recipe::Interleave,
            Recipe::Reuse,
            Recipe::Delayed,
            Recipe::Gap,
        ] {
            let (store, segments) = load(recipe, 9, 150, 64);
            let rebuilt = rebuild("t1", &segments, &store.batches().unwrap()).unwrap();
            assert_eq!(
                store.digest().unwrap(),
                rebuilt.digest().unwrap(),
                "{}",
                recipe.name()
            );
        }
    }

    #[test]
    fn announced_gap_is_recorded_once_and_a_silent_jump_is_a_lost_producer() {
        let (store, _) = load(Recipe::Gap, 4, 30, 1000);
        let observed: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM gaps WHERE observed=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(observed, 1);
        // Drop records from the middle of a clean segment: the jump is not announced.
        let segment = synth::generate(Recipe::Baseline, 4, 30).remove(0);
        let scan = raw::scan(&segment.bytes, &segment.id);
        let mut kept = scan.records.clone();
        kept.drain(10..14);
        let mut store = Store::memory("t2").unwrap();
        let stats = store.ingest(&segment.id, 0, &kept).unwrap();
        assert_eq!(stats.gaps_found, 1);
        let lost: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM gaps WHERE reason='producer-lost' AND observed=0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lost, 1);
    }

    #[test]
    fn unknown_kinds_are_rejected_visibly() {
        let mut record = Map::new();
        for (k, v) in [
            ("kind", Value::from("core.nonsense")),
            ("source_id", "s".into()),
            ("source_seq", 0.into()),
            ("producer_gen", 1.into()),
            ("clock_domain", "c".into()),
            ("t_mono_ns", 1.into()),
            ("confidence", "exact".into()),
        ] {
            record.insert(k.into(), v);
        }
        let mut store = Store::memory("t3").unwrap();
        let stats = store.ingest("s", 0, &[record]).unwrap();
        assert_eq!((stats.stored, stats.rejected), (0, 1));
    }

    #[test]
    fn a_reader_sees_only_committed_batches() {
        let dir = std::env::temp_dir().join(format!("hydra-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t4.db");
        let _ = std::fs::remove_file(&path);
        let mut writer = Store::open(&path, "t4").unwrap();
        let segment = synth::generate(Recipe::Baseline, 2, 60).remove(0);
        let scan = raw::scan(&segment.bytes, &segment.id);
        writer.ingest(&segment.id, 0, &scan.records[..20]).unwrap();
        let reader = Store::reader(&path, "t4").unwrap();
        assert_eq!(
            (reader.revision().unwrap(), reader.event_count().unwrap()),
            (1, 20)
        );
        writer.ingest(&segment.id, 20, &scan.records[20..]).unwrap();
        let after = (reader.revision().unwrap(), reader.event_count().unwrap());
        assert_eq!(after.1, scan.records.len() as u64);
        assert_eq!(after.0, 2);
        drop((reader, writer));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
