//! A session on disk: raw segments (the truth), a batch manifest, the derived index, keys and
//! artifacts. Layout under `<root>/<id>/`:
//!
//! ```text
//! session.json     id, creation time, budget
//! segments/<source>.trace   one append-only segment per source
//! manifest.jsonl   one line per ingest batch (source, first_n, count)
//! index.db         the derived SQLite index
//! keys/  artifacts/
//! ```
//!
//! Write order for every append is: segment bytes synced, manifest line synced, index commit. A
//! crash anywhere in that sequence is repaired by [`Session::open`], which replays whatever the
//! index is missing from the manifest and the segments, so a rebuilt index equals the original.

use crate::artifact::{self, Artifacts};
use crate::corrid::{self, KeyRing, PreviewPolicy};
use crate::model::Event;
use crate::raw::{self, Chain, Damage};
use crate::store::{Batch, Budget, Error, INGEST_SOURCE, Options, Result, Store, rebuild_with};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Fields a producer must not set (ingest assigns them).
const RESERVED: [&str; 4] = ["seq", "event_id", "static", "revision"];

/// The closed envelope (everything else is rejected at append).
const ENVELOPE: [&str; 20] = [
    "kind",
    "source_id",
    "source_seq",
    "producer_gen",
    "clock_domain",
    "t_mono_ns",
    "t_wall_ns",
    "process_id",
    "thread_id",
    "process_gen",
    "thread_gen",
    "module",
    "module_instance",
    "confidence",
    "acquisition",
    "va",
    "callstack",
    "payload",
    "n",
    "prev",
];

pub const MAX_EVENTS_PER_APPEND: usize = 10_000;

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        && !name.starts_with('.')
}

struct SegWriter {
    file: File,
    chain: Chain,
    /// Set when the segment is damaged in the middle: no further appends.
    damaged: Option<String>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Rejected {
    pub index: usize,
    pub reason: String,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct AppendReply {
    pub accepted: u64,
    pub rejected: Vec<Rejected>,
    pub revision: u64,
    pub dropped_budget: u64,
    pub strings_keyed: u64,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Recovery {
    pub sources: Vec<RecoveredSource>,
    pub replayed_batches: u64,
    pub tail_batches: u64,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct RecoveredSource {
    pub source: String,
    pub records: u64,
    pub torn_bytes_removed: u64,
    pub damage: Option<String>,
}

/// An open session (the writer).
pub struct Session {
    dir: PathBuf,
    id: String,
    store: Store,
    writers: HashMap<String, SegWriter>,
    manifest: File,
    ring: KeyRing,
    artifacts: Artifacts,
    preview: PreviewPolicy,
    started: Instant,
    mark_seq: u64,
}

fn segment_dir(dir: &Path) -> PathBuf {
    dir.join("segments")
}

pub fn index_path(dir: &Path) -> PathBuf {
    dir.join("index.db")
}

fn damage_text(d: &Damage) -> String {
    match d {
        Damage::TornTail { offset, bytes } => format!("torn tail: {bytes} bytes at {offset}"),
        Damage::Corrupt { offset, line } => format!("corrupt line {line} at offset {offset}"),
        Damage::ChainBreak { offset, n, reason } => {
            format!("chain break ({reason}) at record {n}, offset {offset}")
        }
    }
}

/// Read the manifest; a torn last line is ignored.
fn read_manifest(dir: &Path) -> Vec<Batch> {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.jsonl")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        let Ok(v) = serde_json::from_str::<Value>(line.trim_end()) else {
            break;
        };
        let (Some(s), Some(f), Some(c)) = (
            v.get("source").and_then(Value::as_str),
            v.get("first_n").and_then(Value::as_u64),
            v.get("count").and_then(Value::as_u64),
        ) else {
            break;
        };
        out.push(Batch {
            source_id: s.to_string(),
            first_n: f,
            count: c,
        });
    }
    out
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Session {
    /// Create the session if it does not exist, open it, and repair whatever an earlier crash
    /// left behind.
    pub fn open(root: &Path, id: &str, options: Options) -> Result<(Self, Recovery)> {
        if !valid_name(id) {
            return Err(Error::Refused(format!("invalid session id {id:?}")));
        }
        let dir = root.join(id);
        std::fs::create_dir_all(segment_dir(&dir))?;
        let meta_path = dir.join("session.json");
        if !meta_path.exists() {
            std::fs::write(
                &meta_path,
                serde_json::to_vec(&json!({
                    "id": id,
                    "created_unix": now_unix(),
                    "budget_events": options.budget.max_events,
                    "budget_bytes": options.budget.max_bytes,
                }))?,
            )?;
        }
        // The budget on disk wins over the caller's after the first open.
        let meta: Value = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
        let budget = Budget {
            max_events: meta.get("budget_events").and_then(Value::as_u64),
            max_bytes: meta.get("budget_bytes").and_then(Value::as_u64),
        };
        let mut store = Store::open(&index_path(&dir), id)?;
        store.set_options(Options { budget, ..options })?;
        let manifest = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("manifest.jsonl"))?;
        let mut session = Self {
            ring: KeyRing::open(dir.join("keys"))?,
            artifacts: Artifacts::open(artifact::dir_of(&dir))?,
            dir,
            id: id.to_string(),
            store,
            writers: HashMap::new(),
            manifest,
            preview: PreviewPolicy::default(),
            started: Instant::now(),
            mark_seq: 0,
        };
        let recovery = session.recover()?;
        Ok((session, recovery))
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    pub fn set_preview(&mut self, policy: PreviewPolicy) {
        self.preview = policy;
    }

    fn segment_path(&self, source: &str) -> PathBuf {
        segment_dir(&self.dir).join(format!("{source}.trace"))
    }

    fn write_manifest(&mut self, source: &str, first_n: u64, count: u64) -> Result<()> {
        writeln!(
            self.manifest,
            "{}",
            json!({"source": source, "first_n": first_n, "count": count})
        )?;
        self.manifest.sync_data()?;
        Ok(())
    }

    /// Bring the index and the on-disk truth into agreement after a crash.
    fn recover(&mut self) -> Result<Recovery> {
        let mut report = Recovery::default();
        let mut sources: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(segment_dir(&self.dir))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("trace")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                sources.push(stem.to_string());
            }
        }
        sources.sort();
        let mut scans: HashMap<String, raw::Scan> = HashMap::new();
        for source in &sources {
            let path = self.segment_path(source);
            let scan = crate::rawio::scan_file(&path, source)?;
            let mut rec = RecoveredSource {
                source: source.clone(),
                records: scan.records.len() as u64,
                ..RecoveredSource::default()
            };
            let mut damaged = None;
            match &scan.damage {
                Some(Damage::TornTail { bytes, .. }) => {
                    // A write that never finished: it was never acknowledged. Remove it so the
                    // chain can continue.
                    let f = OpenOptions::new().write(true).open(&path)?;
                    f.set_len(scan.valid_end as u64)?;
                    f.sync_all()?;
                    rec.torn_bytes_removed = *bytes as u64;
                }
                Some(other) => {
                    let text = damage_text(other);
                    rec.damage = Some(text.clone());
                    damaged = Some(text);
                }
                None => {}
            }
            let file = OpenOptions::new().append(true).create(true).open(&path)?;
            self.writers.insert(
                source.clone(),
                SegWriter {
                    file,
                    chain: Chain::resume(scan.head.clone(), scan.records.len() as u64),
                    damaged,
                },
            );
            report.sources.push(rec);
            scans.insert(source.clone(), scan);
        }
        // 1. Manifest batches the index never committed, exactly as they were planned.
        let manifest = read_manifest(&self.dir);
        let committed = self.store.batches()?.len();
        for batch in manifest.iter().skip(committed) {
            let Some(scan) = scans.get(&batch.source_id) else {
                return Err(Error::Segment(format!(
                    "manifest names missing segment {}",
                    batch.source_id
                )));
            };
            let (from, to) = (
                batch.first_n as usize,
                (batch.first_n + batch.count) as usize,
            );
            if to > scan.records.len() {
                return Err(Error::Segment(format!(
                    "segment {} is shorter than its manifest",
                    batch.source_id
                )));
            }
            self.store
                .ingest(&batch.source_id, batch.first_n, &scan.records[from..to])?;
            report.replayed_batches += 1;
        }
        // 2. Segment records no batch covers (the crash came before the manifest line).
        for source in &sources {
            let scan = &scans[source];
            let done = self.store.ingested_records(source)? as usize;
            if done < scan.records.len() {
                let first = done as u64;
                let count = (scan.records.len() - done) as u64;
                self.write_manifest(source, first, count)?;
                self.store.ingest(source, first, &scan.records[done..])?;
                report.tail_batches += 1;
            }
        }
        Ok(report)
    }

    /// Append events from producers. Each is validated against the closed envelope, scrubbed of
    /// plain strings, written to its source's segment (synced), and only then committed to the
    /// index. Rejections are returned with their position and reason, never dropped.
    pub fn append(&mut self, events: &[Value]) -> Result<AppendReply> {
        if events.len() > MAX_EVENTS_PER_APPEND {
            return Err(Error::Refused(format!(
                "at most {MAX_EVENTS_PER_APPEND} events per append"
            )));
        }
        let mut reply = AppendReply::default();
        let mut by_source: Vec<(String, Vec<Map<String, Value>>)> = Vec::new();
        for (index, value) in events.iter().enumerate() {
            match self.prepare(value) {
                Ok((source, record, keyed)) => {
                    reply.strings_keyed += keyed as u64;
                    match by_source.iter_mut().find(|(s, _)| *s == source) {
                        Some((_, list)) => list.push(record),
                        None => by_source.push((source, vec![record])),
                    }
                }
                Err(reason) => reply.rejected.push(Rejected { index, reason }),
            }
        }
        for (source, records) in by_source {
            let stats = self.commit(&source, records)?;
            reply.accepted += stats.stored;
            reply.dropped_budget += stats.dropped_budget;
            for _ in 0..stats.rejected {
                reply.rejected.push(Rejected {
                    index: usize::MAX,
                    reason: "rejected at ingest; see the index rejects table".into(),
                });
            }
        }
        reply.revision = self.store.revision()?;
        Ok(reply)
    }

    fn prepare(&mut self, value: &Value) -> std::result::Result<(String, Map<String, Value>, usize), String> {
        let Some(obj) = value.as_object() else {
            return Err("event is not an object".into());
        };
        for key in obj.keys() {
            if RESERVED.contains(&key.as_str()) {
                return Err(format!("{key} is assigned by ingest and must not be set"));
            }
            if !ENVELOPE.contains(&key.as_str()) {
                return Err(format!("unknown envelope field {key}"));
            }
        }
        let mut record = obj.clone();
        record.remove("n");
        record.remove("prev");
        let mut keyed = 0;
        if let Some(Value::Object(payload)) = record.get_mut("payload") {
            let scope = format!("session:{}", self.id);
            keyed = corrid::scrub(payload, &mut self.ring, &scope, self.preview)
                .map_err(|e| e.to_string())?;
        }
        let event: Event = serde_json::from_value(Value::Object(record.clone()))
            .map_err(|e| format!("schema: {e}"))?;
        if !crate::model::kind_is_valid(&event.kind) {
            return Err(format!("unknown kind {}", event.kind));
        }
        if !valid_name(&event.source_id) || event.source_id == INGEST_SOURCE {
            return Err(format!("invalid source_id {:?}", event.source_id));
        }
        artifact::require_present_refs(&self.store, &event.payload).map_err(|e| e.to_string())?;
        // Re-serialize through the model so the segment holds exactly the envelope.
        Ok((event.source_id.clone(), event.to_record(), keyed))
    }

    fn commit(
        &mut self,
        source: &str,
        records: Vec<Map<String, Value>>,
    ) -> Result<crate::store::IngestStats> {
        if !self.writers.contains_key(source) {
            let path = self.segment_path(source);
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.writers.insert(
                source.to_string(),
                SegWriter {
                    file,
                    chain: Chain::new(source),
                    damaged: None,
                },
            );
        }
        let writer = self
            .writers
            .get_mut(source)
            .ok_or_else(|| Error::Segment("writer missing".into()))?;
        if let Some(why) = &writer.damaged {
            return Err(Error::Refused(format!("segment {source} is damaged: {why}")));
        }
        let first_n = writer.chain.count();
        let mut bytes = Vec::with_capacity(records.len() * 256);
        for record in &records {
            let line = writer
                .chain
                .push(record.clone())
                .map_err(|e| Error::Refused(e.to_string()))?;
            bytes.extend_from_slice(&line);
        }
        // 1. the segment, durable; 2. the manifest line, durable; 3. the index commit.
        writer.file.write_all(&bytes)?;
        writer.file.sync_data()?;
        let count = records.len() as u64;
        self.write_manifest(source, first_n, count)?;
        self.store.ingest(source, first_n, &records)
    }

    /// Record a named point: an event of kind `core.marker` from the session's own source.
    pub fn mark(&mut self, label: &str, phase: Option<&str>, frame: Option<i64>) -> Result<AppendReply> {
        let mut payload = Map::new();
        payload.insert("label".into(), label.into());
        if let Some(p) = phase {
            payload.insert("phase".into(), p.into());
        }
        if let Some(f) = frame {
            payload.insert("frame".into(), f.into());
        }
        let seq = self.mark_seq;
        self.mark_seq += 1;
        // Continue the marks source after a reopen.
        let base = self
            .writers
            .get("marks")
            .map_or(0, |w| w.chain.count());
        let event = json!({
            "kind": "core.marker",
            "source_id": "marks",
            "source_seq": base.max(seq),
            "producer_gen": 1,
            "clock_domain": "session-mono",
            "t_mono_ns": self.started.elapsed().as_nanos() as u64,
            "t_wall_ns": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64),
            "confidence": "exact",
            "payload": payload,
        });
        let reply = self.append(&[event])?;
        let seq: Option<i64> = self.store.conn().query_row(
            "SELECT MAX(seq) FROM events WHERE source_id='marks'",
            [],
            |r| r.get(0),
        )?;
        if let Some(seq) = seq {
            self.store.conn().execute(
                "INSERT INTO marks(seq,label,phase,frame) VALUES(?1,?2,?3,?4)",
                rusqlite::params![seq, label, phase, frame],
            )?;
        }
        Ok(reply)
    }
}

/// A read-only handle on a session's index.
pub fn reader(root: &Path, id: &str) -> Result<Store> {
    if !valid_name(id) {
        return Err(Error::Refused(format!("invalid session id {id:?}")));
    }
    let path = index_path(&root.join(id));
    if !path.exists() {
        return Err(Error::Refused(format!("no session {id}")));
    }
    Store::reader(&path, id)
}

/// Session ids under `root`, sorted.
pub fn list(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("index.db").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    out.sort();
    out
}

#[derive(Debug, Serialize)]
pub struct Verification {
    pub session: String,
    pub segments: Vec<SegmentCheck>,
    pub index_digest: String,
    pub rebuilt_digest: String,
    pub index_matches_segments: bool,
    pub revision: u64,
}

#[derive(Debug, Serialize)]
pub struct SegmentCheck {
    pub source: String,
    pub records: u64,
    pub clean: bool,
    pub damage: Option<String>,
}

fn load_segments(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(segment_dir(dir))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("trace")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            out.push((stem.to_string(), std::fs::read(&path)?));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn options_of(dir: &Path, base: &Options) -> Options {
    let meta: Value = std::fs::read(dir.join("session.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    Options {
        budget: Budget {
            max_events: meta.get("budget_events").and_then(Value::as_u64),
            max_bytes: meta.get("budget_bytes").and_then(Value::as_u64),
        },
        ..base.clone()
    }
}

/// Verify a session offline (no daemon): every segment's chain, and that the index equals one
/// rebuilt from the segments and the manifest. `options` carries the symbolizer the index was
/// built with, if any.
pub fn verify(root: &Path, id: &str, options: &Options) -> Result<Verification> {
    let dir = root.join(id);
    let segments = load_segments(&dir)?;
    let mut checks = Vec::new();
    for (source, bytes) in &segments {
        let scan = raw::scan(bytes, source);
        checks.push(SegmentCheck {
            source: source.clone(),
            records: scan.records.len() as u64,
            clean: scan.is_clean(),
            damage: scan.damage.as_ref().map(damage_text),
        });
    }
    let index = Store::reader(&index_path(&dir), id)?;
    let manifest = read_manifest(&dir);
    let rebuilt = rebuild_with(id, &segments, &manifest, &options_of(&dir, options))?;
    let (a, b) = (index.digest()?, rebuilt.digest()?);
    Ok(Verification {
        session: id.into(),
        segments: checks,
        index_matches_segments: a == b,
        index_digest: a,
        rebuilt_digest: b,
        revision: index.revision()?,
    })
}

/// Rebuild `index.db` from the segments and the manifest (the index may be lost or damaged).
/// The old index is kept as `index.db.old` until the new one is complete.
pub fn rebuild(root: &Path, id: &str, options: &Options) -> Result<String> {
    let dir = root.join(id);
    let segments = load_segments(&dir)?;
    let manifest = read_manifest(&dir);
    // Write the new index next to the old and swap.
    let fresh = dir.join("index.db.new");
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", fresh.display()));
    }
    let mut store = Store::open(&fresh, id)?;
    store.set_options(options_of(&dir, options))?;
    for batch in &manifest {
        let seg = segments
            .iter()
            .find(|(s, _)| *s == batch.source_id)
            .ok_or_else(|| Error::Segment(format!("missing segment {}", batch.source_id)))?;
        let scan = raw::scan(&seg.1, &seg.0);
        let (from, to) = (
            batch.first_n as usize,
            (batch.first_n + batch.count) as usize,
        );
        store.ingest(&batch.source_id, batch.first_n, &scan.records[from..to])?;
    }
    let digest = store.digest()?;
    drop(store);
    let live = index_path(&dir);
    for ext in ["", "-wal", "-shm"] {
        let from = format!("{}{ext}", live.display());
        if Path::new(&from).exists() {
            let _ = std::fs::remove_file(format!("{from}.old"));
            std::fs::rename(&from, format!("{from}.old"))?;
        }
    }
    for ext in ["", "-wal", "-shm"] {
        let from = format!("{}{ext}", fresh.display());
        if Path::new(&from).exists() {
            std::fs::rename(&from, format!("{}{ext}", live.display()))?;
        }
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{self, Recipe};

    fn root(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hydra-session-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The synthetic baseline as append payloads.
    fn events(seed: u64, n: usize) -> Vec<Value> {
        let seg = synth::generate(Recipe::Baseline, seed, n).remove(0);
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
    fn append_writes_segment_manifest_and_index() {
        let r = root("a");
        let (mut s, rec) = Session::open(&r, "s1", Options::default()).unwrap();
        assert_eq!(rec.replayed_batches + rec.tail_batches, 0);
        let reply = s.append(&events(1, 50)).unwrap();
        assert_eq!(reply.accepted, 52);
        assert!(reply.rejected.is_empty());
        assert_eq!(s.store().event_count().unwrap(), 52);
        assert!(r.join("s1/segments/src_a.trace").is_file());
        assert_eq!(read_manifest(&r.join("s1")).len(), 1);
        let v = verify(&r, "s1", &Options::default()).unwrap();
        assert!(v.index_matches_segments);
        assert!(v.segments.iter().all(|c| c.clean));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn producers_cannot_set_reserved_fields_or_unknown_ones() {
        let r = root("b");
        let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
        let mut ev = events(1, 3);
        ev[0]["seq"] = json!(5);
        ev[1]["bogus"] = json!(1);
        ev[2]["kind"] = json!("core.nonsense");
        let reply = s.append(&ev).unwrap();
        assert_eq!(reply.accepted, 2);
        assert_eq!(reply.rejected.len(), 3);
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn strings_never_reach_the_segment() {
        let r = root("c");
        let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
        let ev = json!({
            "kind": "app.login", "source_id": "p", "source_seq": 0, "producer_gen": 1,
            "clock_domain": "c", "t_mono_ns": 1, "confidence": "exact",
            "payload": {"user": {"$string": "alice-secret-name"}}
        });
        let reply = s.append(&[ev]).unwrap();
        assert_eq!((reply.accepted, reply.strings_keyed), (1, 1));
        let seg = std::fs::read_to_string(r.join("s1/segments/p.trace")).unwrap();
        assert!(!seg.contains("alice-secret-name"));
        assert!(seg.contains("corr_id"));
        let payload: String = s
            .store()
            .conn()
            .query_row("SELECT payload FROM events", [], |r| r.get(0))
            .unwrap();
        assert!(payload.contains("session:s1") && !payload.contains("alice"));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn a_dangling_artifact_reference_is_rejected_until_the_artifact_exists() {
        let r = root("d");
        let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
        let mk = |id: &str| {
            json!({"kind": "app.packet", "source_id": "p", "source_seq": 0, "producer_gen": 1,
                "clock_domain": "c", "t_mono_ns": 1, "confidence": "exact", "payload": {"artifact": id}})
        };
        assert_eq!(s.append(&[mk("art_nope")]).unwrap().rejected.len(), 1);
        let spec = artifact::ArtifactSpec {
            scope: "packet".into(),
            max_bytes: 64,
            retention_secs: None,
            redact: vec![],
        };
        let arts = Artifacts::open(artifact::dir_of(s.dir())).unwrap();
        let id = arts.put(s.store_mut(), b"bytes", &spec, 0).unwrap();
        assert_eq!(s.append(&[mk(&id)]).unwrap().accepted, 1);
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn marks_become_marker_events_and_rows() {
        let r = root("e");
        let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
        s.mark("level 1", Some("load"), Some(0)).unwrap();
        s.mark("level 2", Some("play"), Some(10)).unwrap();
        let n: i64 = s.store().conn().query_row("SELECT COUNT(*) FROM events WHERE kind='core.marker'", [], |r| r.get(0)).unwrap();
        let m: i64 = s.store().conn().query_row("SELECT COUNT(*) FROM marks", [], |r| r.get(0)).unwrap();
        assert_eq!((n, m), (2, 2));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn reopening_resumes_the_chain_and_a_crash_after_the_segment_is_repaired() {
        let r = root("f");
        let want_digest;
        {
            let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
            s.append(&events(1, 30)).unwrap();
            want_digest = s.store().digest().unwrap();
        }
        // Simulate a crash after the segment and manifest were written but before the commit:
        // append a valid extra batch to the files by hand, leaving the index behind.
        {
            let seg_path = r.join("s1/segments/src_a.trace");
            let scan = raw::scan(&std::fs::read(&seg_path).unwrap(), "src_a");
            let mut chain = Chain::resume(scan.head.clone(), scan.records.len() as u64);
            let next = scan.records.len() as u64;
            let ev = json!({"kind": "app.late", "source_id": "src_a", "source_seq": next, "producer_gen": 1,
                "clock_domain": "qpc-10mhz", "t_mono_ns": 99999, "confidence": "exact"});
            let line = chain.push(ev.as_object().unwrap().clone()).unwrap();
            let mut f = OpenOptions::new().append(true).open(&seg_path).unwrap();
            f.write_all(&line).unwrap();
            f.write_all(b"deadbeef {\"torn\"").unwrap(); // and a torn tail after it
            let mut m = OpenOptions::new().append(true).open(r.join("s1/manifest.jsonl")).unwrap();
            writeln!(m, "{}", json!({"source": "src_a", "first_n": next, "count": 1})).unwrap();
        }
        let (mut s, rec) = Session::open(&r, "s1", Options::default()).unwrap();
        assert_eq!(rec.replayed_batches, 1);
        assert_eq!(rec.sources[0].torn_bytes_removed, 16);
        assert_eq!(s.store().event_count().unwrap(), 33);
        assert_ne!(s.store().digest().unwrap(), want_digest);
        // The chain continues after the repair and the index equals a rebuild.
        s.append(&[json!({"kind": "app.more", "source_id": "src_a", "source_seq": 100, "producer_gen": 1,
            "clock_domain": "qpc-10mhz", "t_mono_ns": 123456, "confidence": "exact"})])
            .unwrap();
        let v = verify(&r, "s1", &Options::default()).unwrap();
        assert!(v.index_matches_segments, "{v:?}");
        assert!(v.segments.iter().all(|c| c.clean));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn a_crash_between_segment_and_manifest_is_a_tail_batch() {
        let r = root("g");
        {
            let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
            s.append(&events(1, 10)).unwrap();
        }
        let seg_path = r.join("s1/segments/src_a.trace");
        let scan = raw::scan(&std::fs::read(&seg_path).unwrap(), "src_a");
        let mut chain = Chain::resume(scan.head.clone(), scan.records.len() as u64);
        let ev = json!({"kind": "app.late", "source_id": "src_a", "source_seq": 5000, "producer_gen": 1,
            "clock_domain": "qpc-10mhz", "t_mono_ns": 99999, "confidence": "exact"});
        let line = chain.push(ev.as_object().unwrap().clone()).unwrap();
        OpenOptions::new().append(true).open(&seg_path).unwrap().write_all(&line).unwrap();
        let (s, rec) = Session::open(&r, "s1", Options::default()).unwrap();
        assert_eq!(rec.tail_batches, 1);
        assert_eq!(s.store().event_count().unwrap(), 13);
        drop(s);
        assert!(verify(&r, "s1", &Options::default()).unwrap().index_matches_segments);
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn a_lost_index_is_rebuilt_to_the_same_digest() {
        let r = root("h");
        let digest;
        {
            let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
            s.append(&events(1, 40)).unwrap();
            s.append(&events(2, 20).into_iter().map(|mut e| { e["source_id"] = json!("src_b"); e }).collect::<Vec<_>>()).unwrap();
            s.append(&[]).unwrap();
            digest = s.store().digest().unwrap();
        }
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", index_path(&r.join("s1")).display()));
        }
        let rebuilt = rebuild(&r, "s1", &Options::default()).unwrap();
        assert_eq!(rebuilt, digest);
        let (s, rec) = Session::open(&r, "s1", Options::default()).unwrap();
        assert_eq!(rec.replayed_batches + rec.tail_batches, 0);
        assert_eq!(s.store().digest().unwrap(), digest);
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn damage_in_the_middle_of_a_segment_is_reported_and_blocks_appends() {
        let r = root("i");
        {
            let (mut s, _) = Session::open(&r, "s1", Options::default()).unwrap();
            s.append(&events(1, 30)).unwrap();
        }
        let p = r.join("s1/segments/src_a.trace");
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[200] ^= 1;
        std::fs::write(&p, bytes).unwrap();
        let (mut s, rec) = Session::open(&r, "s1", Options::default()).unwrap();
        assert!(rec.sources[0].damage.as_deref().unwrap().contains("corrupt"));
        let err = s.append(&events(1, 3)).unwrap_err();
        assert!(err.to_string().contains("damaged"));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn names_and_listing() {
        assert!(valid_name("a-b_c.1"));
        assert!(!valid_name("../x") && !valid_name("") && !valid_name(".hidden") && !valid_name("a/b"));
        let r = root("j");
        let (_s, _) = Session::open(&r, "one", Options::default()).unwrap();
        let (_t, _) = Session::open(&r, "two", Options::default()).unwrap();
        assert_eq!(list(&r), vec!["one", "two"]);
        assert!(reader(&r, "nope").is_err());
        assert!(Session::open(&r, "../evil", Options::default()).is_err());
        let _ = std::fs::remove_dir_all(r);
    }
}
