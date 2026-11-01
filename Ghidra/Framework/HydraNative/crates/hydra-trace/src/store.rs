//! The per-session index: SQLite in WAL mode, derived from the raw segments. One ingester writes
//! it in group commits; any number of readers read committed snapshots. Nothing is dropped
//! silently: a rejected record is stored with its reason, a jump in a producer's sequence is
//! stored as a gap. `rebuild` replays the batch manifest over the segments and must reproduce the
//! same `digest`.

use crate::model::{Event, kind_is_valid};
use crate::raw;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 1;

const DDL: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL,
  source_id TEXT NOT NULL, source_seq INTEGER NOT NULL, producer_gen INTEGER NOT NULL,
  kind TEXT NOT NULL, clock_domain TEXT NOT NULL, t_mono_ns INTEGER NOT NULL,
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
";

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
}

#[derive(Debug)]
pub enum Error {
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    Segment(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sql(e) => write!(f, "sqlite: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Segment(e) => write!(f, "segment: {e}"),
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

pub type Result<T> = std::result::Result<T, Error>;

/// A session index.
pub struct Store {
    conn: Connection,
    session: String,
}

impl Store {
    /// Open or create the index at `path` (the writer).
    pub fn open(path: &Path, session: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn, session)
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
        })
    }

    fn init(conn: Connection, session: &str) -> Result<Self> {
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(DDL)?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?1),('session',?2),('revision','0')",
            params![SCHEMA_VERSION.to_string(), session],
        )?;
        Ok(Self {
            conn,
            session: session.into(),
        })
    }

    pub fn session(&self) -> &str {
        &self.session
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
    /// the segment number of the first record, kept in the batch manifest for `rebuild`.
    pub fn ingest(
        &mut self,
        source_id: &str,
        first_n: u64,
        records: &[Map<String, Value>],
    ) -> Result<IngestStats> {
        let tx = self.conn.transaction()?;
        let mut stats = IngestStats::default();
        let mut next_seq: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq),0)+1 FROM events", [], |r| {
                r.get(0)
            })?;
        // The producer's last sequence in this generation, to detect a jump.
        let mut last: Option<(u32, u64)> = tx
            .query_row(
                "SELECT producer_gen, source_seq FROM events WHERE source_id=?1 ORDER BY seq DESC LIMIT 1",
                params![source_id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u64>(1)?)),
            )
            .ok();
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO events(seq,event_id,source_id,source_seq,producer_gen,kind,clock_domain,t_mono_ns,process_id,
                 thread_id,process_gen,thread_gen,module,module_instance,va,confidence,acquisition,resource_key,state_key,
                 corr,callstack,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            )?;
            for (offset, record) in records.iter().enumerate() {
                let n = first_n + offset as u64;
                let mut body = record.clone();
                for chain_field in ["n", "prev", "hash"] {
                    body.remove(chain_field);
                }
                let event: Event = match serde_json::from_value(Value::Object(body)) {
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
                    tx.execute(
                        "INSERT INTO gaps(source_id,reason,first_missing,last_missing,dropped,t_mono_ns,observed)
                         VALUES(?1,?2,?3,?4,?5,?6,1)",
                        params![
                            source_id,
                            p.get("reason").and_then(Value::as_str).unwrap_or("unspecified"),
                            p.get("first_missing_source_seq").and_then(Value::as_i64),
                            p.get("last_missing_source_seq").and_then(Value::as_i64),
                            p.get("dropped").and_then(Value::as_i64),
                            event.t_mono_ns as i64
                        ],
                    )?;
                }
                let (resource_key, state_key, corr) = keys(&event);
                insert.execute(params![
                    next_seq,
                    format!("ev_{}_{}", self.session, next_seq),
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
                ])?;
                last = Some((event.producer_gen, event.source_seq));
                next_seq += 1;
                stats.stored += 1;
            }
        }
        tx.execute(
            "INSERT INTO sources(source_id,segment_records,state) VALUES(?1,?2,'observing')
             ON CONFLICT(source_id) DO UPDATE SET segment_records=segment_records+?2",
            params![source_id, records.len() as i64],
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

    /// A SHA-256 over every stored table in a canonical order: two indexes with the same digest
    /// hold the same evidence.
    pub fn digest(&self) -> Result<String> {
        let mut hasher = Sha256::new();
        for (table, order) in [
            ("events", "seq"),
            ("gaps", "id"),
            ("rejects", "id"),
            ("sources", "source_id"),
            ("batches", "id"),
        ] {
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

/// Derived lookup keys: the logical resource key, the state key and the correlation id.
fn keys(event: &Event) -> (Option<String>, Option<String>, Option<String>) {
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
        format!("{}:{}:{}", event.process_gen.unwrap_or(0), object, key)
    });
    (resource, state, text("corr"))
}

/// Rebuild an index from segments and the batch manifest of the original. `segments` maps a
/// source id to its raw bytes. The result has the same `digest` as the original.
pub fn rebuild(session: &str, segments: &[(String, Vec<u8>)], batches: &[Batch]) -> Result<Store> {
    let mut store = Store::memory(session)?;
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
