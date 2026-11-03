//! Transaction, undo, redo and rollback differential test. `oracle/OracleTx.java` runs a script
//! on the repository's `DBHandle` and prints what it observes (transaction results, undo / redo
//! outcomes, counters, expected errors) and, at every `snap`, the buffer geometry, per-buffer
//! SHA-256 and master rows of the database written with `saveAs`. The same script is replayed with
//! `Database<CheckpointStore>`, and the whole transcript must be identical.
//!
//! `snap` mirrors `DBHandle.saveAs`: a hidden transaction flushes the master rows, the state is
//! captured, and the extra checkpoint is undone when it was added.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use common::sha256_hex;
use ghidra_fmt_db::{Database, DbError};
use ghidra_fmt_field::{Field, FieldType, JString, Record, Schema};
use ghidra_fmt_gbf::{BufferFile, BufferStore, CheckpointStore};

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/tx")
}

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn key_type(k: &str) -> FieldType {
    match k {
        "long" => FieldType::Long,
        "int" => FieldType::Int,
        "short" => FieldType::Short,
        "string" => FieldType::String,
        other => panic!("key type {other}"),
    }
}

fn key(k: &str, v: &str) -> Field {
    match k {
        "long" => Field::Long(v.parse().unwrap()),
        "int" => Field::Int(v.parse().unwrap()),
        "short" => Field::Short(v.parse().unwrap()),
        "string" => Field::string(v),
        other => panic!("key type {other}"),
    }
}

fn schema(key: &str, layout: &str) -> Schema {
    let fields = match layout {
        "fixed" => vec![FieldType::Long, FieldType::Int, FieldType::Short],
        "var" => vec![FieldType::Int, FieldType::Binary, FieldType::String],
        other => panic!("layout {other}"),
    };
    Schema::new(
        1,
        key_type(key),
        "Key",
        fields,
        ["A", "B", "C"].map(str::to_owned).to_vec(),
        &[],
    )
    .unwrap()
}

/// The Java exception class `err` corresponds to.
fn java_name(err: &DbError) -> &'static str {
    match err {
        DbError::NoTransaction => "NoTransactionException",
        DbError::TerminatedTransaction => "TerminatedTransactionException",
        DbError::IllegalState(_) => "IllegalStateException",
        DbError::DuplicateName(_) => "DuplicateNameException",
        DbError::TableExists(_) => "IOException",
        other => panic!("unexpected error {other}"),
    }
}

#[derive(Clone)]
struct Meta {
    fixed: bool,
    key: String,
}

/// What `snap` does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Snaps {
    /// `saveAs` into a file and read the file back (the conformance tests).
    File,
    /// The same image kept in memory: no file written or read (the timing runs).
    Memory,
    /// Nothing: the transactions alone.
    Skip,
}

struct Replay {
    name: String,
    dbid: i64,
    snaps: usize,
    db: Option<Database<CheckpointStore>>,
    tx: i64,
    meta: BTreeMap<String, Meta>,
    out: Vec<String>,
    sha: ShaMemo,
    snaps_mode: Snaps,
    /// Time spent in the phases of `snap`: `saveAs`, reading the buffers, opening the database
    /// and listing its tables, reading every record.
    t_snap: [std::time::Duration; 4],
}

/// SHA-256 of buffer contents already hashed in this replay, keyed by the full contents (an exact
/// key, so a hit is never a collision). Consecutive snapshots share most of their buffers.
type ShaMemo = HashMap<Vec<u8>, String>;

fn sha_memo(memo: &mut ShaMemo, data: &[u8]) -> String {
    if let Some(h) = memo.get(data) {
        return h.clone();
    }
    let h = sha256_hex(data);
    memo.insert(data.to_vec(), h.clone());
    h
}

fn buffer_lines<S: BufferStore>(
    store: &S,
    free: &[i32],
    memo: &mut ShaMemo,
    out: &mut Vec<String>,
) {
    let mut free = free.to_vec();
    free.sort_unstable();
    let list: Vec<String> = free.iter().map(i32::to_string).collect();
    out.push(format!(
        "bufferSize={} indexCount={} free=[{}]",
        store.buffer_size(),
        store.index_count(),
        list.join(", ")
    ));
    for i in 0..store.index_count() {
        let b = store.get_buffer(i).unwrap();
        match &b.data {
            Some(d) => out.push(format!(
                "buf {i} id={i} empty=false sha256={}",
                sha_memo(memo, d)
            )),
            None => out.push(format!("buf {i} id=-1 empty=true sha256=-")),
        }
    }
}

impl Replay {
    fn db(&mut self) -> &mut Database<CheckpointStore> {
        self.db.as_mut().unwrap()
    }

    fn run(&mut self, t: &[&str]) -> Result<(), DbError> {
        match t[0] {
            "buffer" => {
                let mut store = CheckpointStore::new(t[1].parse().unwrap());
                if let Some(cache) = t.get(2) {
                    store.set_cache_bytes(cache.parse().unwrap());
                }
                self.db = Some(Database::create(store, self.dbid).unwrap());
                self.out.push(format!("dbid={}", self.dbid));
            }
            "cachedump" => {
                let dump = self.db().store().cache_dump();
                self.out.push(dump);
            }
            "begin" => self.tx = self.db().start_transaction()?,
            "end" => {
                let tx = self.tx;
                let added = self.db().end_transaction(tx, t[1] == "commit")?;
                self.out.push(format!("end added={added}"));
            }
            "terminate" => {
                let tx = self.tx;
                self.db().terminate_transaction(tx, t[1] == "commit")?;
            }
            "commit" => {
                let tx = self.tx;
                self.db().end_transaction(tx, true)?;
                self.tx = self.db().start_transaction()?;
            }
            "undo" => {
                let ok = self.db().undo()?;
                self.out.push(format!("undo ok={ok}"));
            }
            "redo" => {
                let ok = self.db().redo()?;
                self.out.push(format!("redo ok={ok}"));
            }
            "maxundos" => self.db().set_max_undos(t[1].parse().unwrap()),
            "rename" => {
                let ok = self.db().set_table_name(t[1], t[2])?;
                if ok {
                    let m = self.meta[t[1]].clone();
                    self.meta.insert(t[2].to_owned(), m);
                }
                self.out.push(format!("rename ok={ok}"));
            }
            "deltable" => self.db().delete_table(t[1])?,
            "status" => {
                let d = self.db();
                let line = format!(
                    "status undo={} redo={} canUndo={} canRedo={} uncommitted={} changed={} tx={} stack={:?}",
                    d.available_undo_count(),
                    d.available_redo_count(),
                    d.can_undo(),
                    d.can_redo(),
                    d.has_uncommitted_changes(),
                    d.is_changed(),
                    d.is_transaction_active(),
                    d.store().free_ids()
                );
                self.out.push(line);
            }
            "snap" if self.snaps_mode == Snaps::Skip => {}
            "snap" if self.snaps_mode == Snaps::Memory => self.snap_memory(t[1])?,
            "snap" => self.snap(t[1])?,
            "try" => match self.run(&t[1..]) {
                Ok(()) => self.out.push("try ok".into()),
                Err(e) => self.out.push(format!("try err {}", java_name(&e))),
            },
            "table" => {
                let fixed = t[3] == "fixed";
                let cols: Vec<usize> = if t[4] == "-" {
                    vec![]
                } else {
                    t[4].split(',').map(|c| c.parse().unwrap()).collect()
                };
                self.db()
                    .create_indexed_table(t[1], schema(t[2], t[3]), &cols)?;
                self.meta.insert(
                    t[1].to_owned(),
                    Meta {
                        fixed,
                        key: t[2].to_owned(),
                    },
                );
            }
            "put" => {
                if self.db().table(t[1]).is_err() {
                    self.out.push("skip put".into());
                    return Ok(());
                }
                let m = self.meta[t[1]].clone();
                let values = if m.fixed {
                    vec![
                        Some(Field::Long(t[3].parse().unwrap())),
                        Some(Field::Int(t[4].parse().unwrap())),
                        Some(Field::Short(t[5].parse().unwrap())),
                    ]
                } else {
                    let text = if t[5] == "-" { "" } else { t[5] };
                    vec![
                        Some(Field::Int(t[3].parse().unwrap())),
                        Some(Field::Binary(Some(hex(t[4])))),
                        Some(Field::String(Some(JString::new(text)))),
                    ]
                };
                let rec = Record {
                    key: key(&m.key, t[2]),
                    values,
                };
                self.db().put_record(t[1], &rec)?;
            }
            "del" => {
                if self.db().table(t[1]).is_err() {
                    self.out.push("skip del".into());
                    return Ok(());
                }
                let k = key(&self.meta[t[1]].key, t[2]);
                self.db().delete_record_field(t[1], &k)?;
            }
            other => panic!("bad script line {other}"),
        }
        Ok(())
    }

    /// `DBHandle.saveAs` into a scratch file, then `Oracle` / `OracleDb` on it: the transcript
    /// is built from the file Rust wrote, read back with the Rust readers.
    fn snap(&mut self, tag: &str) -> Result<(), DbError> {
        // `HYDRA_SNAP_DIR` moves the scratch files (the benchmark compares disks)
        let dir = std::env::var_os("HYDRA_SNAP_DIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")), PathBuf::from);
        let path = dir.join(format!("{}-snap-{}.gbf", self.name, self.snaps));
        self.snaps += 1;
        let _ = std::fs::remove_file(&path);
        let t0 = std::time::Instant::now();
        self.db().save_as(&path)?;
        self.t_snap[0] += t0.elapsed();
        self.out.push(format!("== {tag}"));
        let bf = BufferFile::open(&path, true).unwrap();
        let free = bf.free_indexes().to_vec();
        self.report(bf, &free);
        if let Some(keep) = std::env::var_os("HYDRA_FMT_KEEP_DIR") {
            let dest =
                PathBuf::from(keep).join(format!("{}-rust-snap{}.gbf", self.name, self.snaps - 1));
            std::fs::copy(&path, dest).unwrap();
            std::fs::remove_file(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
        Ok(())
    }

    /// The part of a snapshot that is read back from the image `store` (its buffers, then the
    /// database opened on it): the lines of the transcript.
    fn report<S: BufferStore>(&mut self, store: S, free: &[i32]) {
        let t0 = std::time::Instant::now();
        let mut lines = Vec::new();
        buffer_lines(&store, free, &mut self.sha, &mut lines);
        self.t_snap[1] += t0.elapsed();
        let t0 = std::time::Instant::now();
        let db = Database::open(store).unwrap();
        let mut tables: Vec<(String, i32, i64)> = db
            .tables()
            .map(|t| (t.name().to_owned(), t.record_count(), t.max_key()))
            .collect();
        tables.sort();
        lines.extend(
            tables
                .iter()
                .map(|(n, c, m)| format!("table {n} count={c} max={m}")),
        );
        lines.extend(db.all_tables().map(|t| {
            let r = t.table_record();
            format!(
                "tr num={} name={} idx={} root={} keytype={} version={} max={} count={}",
                r.table_num,
                r.name,
                r.indexed_column,
                r.root_buffer_id,
                t.schema().encoded_key_field_type(),
                t.schema().version(),
                r.max_key,
                r.record_count
            )
        }));
        self.t_snap[2] += t0.elapsed();
        let t0 = std::time::Instant::now();
        // OracleDb reads every record of every table; Java stops at the first one it cannot read
        // (a chained buffer that is not in the file)
        let unreadable = db
            .all_tables()
            .any(|t| t.records().map_or(true, |mut it| it.any(|r| r.is_err())));
        if unreadable {
            lines.push("oracledb err IOException".to_owned());
        }
        self.t_snap[3] += t0.elapsed();
        self.out.append(&mut lines);
    }

    /// `snap` without a file: the image `save_as` would write, read from memory.
    fn snap_memory(&mut self, tag: &str) -> Result<(), DbError> {
        let t0 = std::time::Instant::now();
        let image = self.db().save_to_memory()?;
        self.t_snap[0] += t0.elapsed();
        self.out.push(format!("== {tag}"));
        let free = image.free_indexes().to_vec();
        self.report(image, &free);
        Ok(())
    }
}

/// The lines of the Java transcript the Rust replay reproduces.
fn wanted(expected: &str) -> Vec<String> {
    let mut seen_dbid = false;
    let mut out = Vec::new();
    for l in expected.lines() {
        if l.starts_with("dbid=") {
            if seen_dbid {
                continue;
            }
            seen_dbid = true;
        }
        let keep = [
            "dbid=",
            "bufferSize=",
            "buf ",
            "table ",
            "oracledb ",
            "cache ",
            "fatal",
            "end ",
            "undo ",
            "redo ",
            "rename ",
            "status ",
            "try ",
            "skip ",
            "== ",
        ]
        .iter()
        .any(|p| l.starts_with(p));
        if l.starts_with("tr ") {
            let cut = l.find(" variable=").unwrap();
            out.push(l[..cut].to_owned());
        } else if keep {
            out.push(l.to_owned());
        }
    }
    out
}

fn check(name: &str) {
    check_in(&data_dir(), name);
}

/// Runs the script `name` of `dir` against the port; `snaps_mode` says what a `snap` does.
fn replay(dir: &Path, name: &str, snaps_mode: Snaps) -> Replay {
    let script = std::fs::read_to_string(dir.join(format!("{name}.script"))).unwrap();
    let expected = std::fs::read_to_string(dir.join(format!("{name}.expected"))).unwrap();
    // the first line of the transcript is the database id Java drew
    let dbid: i64 = expected
        .lines()
        .next()
        .unwrap()
        .strip_prefix("dbid=")
        .unwrap()
        .parse()
        .unwrap();
    let mut r = Replay {
        name: name.to_owned(),
        dbid,
        snaps: 0,
        db: None,
        tx: 0,
        meta: BTreeMap::new(),
        out: Vec::new(),
        sha: ShaMemo::new(),
        snaps_mode,
        t_snap: [std::time::Duration::ZERO; 4],
    };
    for line in script.lines().filter(|l| !l.is_empty()) {
        let t: Vec<&str> = line.split(' ').collect();
        if let Err(e) = r.run(&t) {
            // Java stops at an operation that fails outside `try` and prints `fatal`
            assert!(
                matches!(
                    e,
                    DbError::Corrupt(_) | DbError::Chain(_) | DbError::Btree(_) | DbError::Gbf(_)
                ),
                "{name}: `{line}` failed: {e}"
            );
            r.out.push("fatal".to_owned());
            break;
        }
    }
    r
}

fn check_in(dir: &Path, name: &str) {
    check_in_mode(dir, name, Snaps::File);
}

fn check_in_mode(dir: &Path, name: &str, snaps: Snaps) {
    let expected = std::fs::read_to_string(dir.join(format!("{name}.expected"))).unwrap();
    let r = replay(dir, name, snaps);
    let want = wanted(&expected);
    if let Some(keep) = std::env::var_os("HYDRA_FMT_KEEP_DIR").map(PathBuf::from) {
        std::fs::write(
            keep.join(format!("{name}.rust.txt")),
            r.out.join(
                "
",
            ),
        )
        .unwrap();
        std::fs::write(
            keep.join(format!("{name}.java.txt")),
            want.join(
                "
",
            ),
        )
        .unwrap();
    }
    assert_eq!(r.out.len(), want.len(), "{name}: transcript length");
    let bad: Vec<usize> = r
        .out
        .iter()
        .zip(&want)
        .enumerate()
        .filter(|(_, (g, w))| g != w)
        .map(|(i, _)| i)
        .collect();
    assert!(
        bad.is_empty(),
        "{name}: {} of {} lines differ, first at {:?}: rust {:?} java {:?} (context before: {:?})",
        bad.len(),
        want.len(),
        &bad[..bad.len().min(10)],
        bad.first().map(|&i| &r.out[i]),
        bad.first().map(|&i| &want[i]),
        bad.first().map(|&i| &want[i.saturating_sub(6)..i]),
    );
}

#[test]
fn basic_commit_rollback_undo_redo_and_errors() {
    check("tx-basic");
}

#[test]
fn more_commits_than_the_undo_depth() {
    check("tx-many-commits");
}

#[test]
fn delete_tables_with_chained_records_and_undo_it() {
    check("tx-delete-heavy");
}

#[test]
fn random_sequence_507_byte_buffers() {
    check("tx-rand-1");
}

#[test]
fn random_sequence_max_undos_3() {
    check("tx-rand-2");
}

#[test]
fn random_sequence_no_undo() {
    check("tx-rand-3");
}

#[test]
fn random_sequence_16379_byte_buffers() {
    check("tx-rand-4");
}

#[test]
fn random_sequence_long_with_30_undos() {
    check("tx-rand-5");
}

#[test]
fn random_sequence_2k_buffers_one_undo() {
    check("tx-rand-6");
}

/// A limit of one checkpoint (`maxundos 0`): rollback cannot undo, the renamed tables keep their
/// old names in the file, and a table created in the rolled back transaction is the one the name
/// finds afterwards (`DBHandle.reloadTables`).
#[test]
fn limit_one_checkpoint_rollback_keeps_the_work_and_the_table_names() {
    check("tx-sweep-00");
}

/// After a rollback that cannot undo, a chained buffer is gone while its record is not: Java
/// fails at `deleteTable` ("Invalid Buffer") and so does the port, at the same operation.
#[test]
fn limit_one_checkpoint_corruption_fails_at_the_same_operation() {
    check("tx-sweep-03");
}

#[test]
fn limit_one_checkpoint_second_sequence() {
    check("tx-sweep-15");
}

/// A node created after a rollback holds the stale bytes of a freed buffer in the unused part
/// of the page (with `-Dhydra.db.sharedPages=false`; see the db notes).
#[test]
fn stale_bytes_of_a_recreated_node() {
    check("tx-sweep-18");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: default undo depth.
#[test]
fn cache_exhausted_1() {
    check("tx-cache-1");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: three undos.
#[test]
fn cache_exhausted_2() {
    check("tx-cache-2");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: one checkpoint, 1019 byte buffers.
#[test]
fn cache_exhausted_3() {
    check("tx-cache-3");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: one undo.
#[test]
fn cache_exhausted_4() {
    check("tx-cache-4");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: 30 undos, 2043 byte buffers.
#[test]
fn cache_exhausted_5() {
    check("tx-cache-5");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: 2043 byte buffers, default undo depth.
#[test]
fn cache_exhausted_6() {
    check("tx-cache-6");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: 4091 byte buffers (16 in the cache), three undos.
#[test]
fn cache_exhausted_7() {
    check("tx-cache-7");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: 1019 byte buffers, two undos.
#[test]
fn cache_exhausted_8() {
    check("tx-cache-8");
}

/// The memory cache (64 KiB) is exhausted, so Java recycles buffers: 2043 byte buffers, five undos.
#[test]
fn cache_exhausted_9() {
    check("tx-cache-9");
}

/// Replays every `*.script` of the directory in `HYDRA_TX_SWEEP_DIR` (written by
/// `oracle/gen_tx_scripts.py <dir> sweep`, with `.expected` files from `oracle/run_tx.sh`) and
/// reports how many match Java instead of stopping at the first difference.
#[test]
#[ignore = "needs HYDRA_TX_SWEEP_DIR"]
fn sweep() {
    let dir = PathBuf::from(std::env::var_os("HYDRA_TX_SWEEP_DIR").expect("HYDRA_TX_SWEEP_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".script").map(str::to_owned)
        })
        .collect();
    names.sort();
    let mut failed = Vec::new();
    for n in &names {
        if std::panic::catch_unwind(|| check_in(&dir, n)).is_err() {
            failed.push(n.clone());
        }
    }
    println!(
        "sweep: {} of {} scripts differ: {failed:?}",
        failed.len(),
        names.len()
    );
    assert!(failed.is_empty());
}

/// The snapshots kept in memory ([`Snaps::Memory`], what the timing runs use) give the same
/// transcript as the files, so the timed path compares exactly what the file path compares.
#[test]
fn memory_images_give_the_transcript_of_the_files() {
    for name in [
        "tx-basic",
        "tx-delete-heavy",
        "tx-rand-3",
        "tx-rand-4",
        "tx-rand-5",
        "tx-many-commits",
        "tx-cache-5",
        "tx-cache-7",
        "tx-sweep-00",
        "tx-sweep-03",
        "tx-sweep-18",
    ] {
        check_in_mode(&data_dir(), name, Snaps::Memory);
    }
}

/// Timing of the replay: `HYDRA_BENCH=<script name>[,..] HYDRA_BENCH_REPS=n cargo test --release
/// -p ghidra-fmt-db --test tx_diff bench -- --ignored --nocapture --exact`. Prints, per script and
/// mode (`files` = the snapshots written to disk and read back, `memory` = the same images kept
/// in memory, `nosnap` = the transactions alone), the
/// first run (cold) and the fastest of `n` runs in microseconds, and the share of `save_as`.
/// `oracle/OracleTx.java` has the same two modes (`ORACLETX_REPS`, `ORACLETX_NOSNAP`).
#[test]
#[ignore = "benchmark"]
fn bench() {
    let Ok(names) = std::env::var("HYDRA_BENCH") else {
        return;
    };
    let reps: usize = std::env::var("HYDRA_BENCH_REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    let only = std::env::var("HYDRA_BENCH_MODE").ok();
    let dir = data_dir();
    for name in names.split(',') {
        for (mode, snaps) in [
            ("files", Snaps::File),
            ("memory", Snaps::Memory),
            ("nosnap", Snaps::Skip),
        ] {
            if only.as_deref().is_some_and(|m| m != mode) {
                continue;
            }
            let mut times = Vec::new();
            let mut phases = [std::time::Duration::ZERO; 4];
            for _ in 0..reps {
                let t0 = std::time::Instant::now();
                let r = replay(&dir, name, snaps);
                times.push(t0.elapsed());
                phases = r.t_snap;
            }
            let cold = times[0].as_secs_f64() * 1e3;
            let min = times.iter().min().unwrap().as_secs_f64() * 1e3;
            let ms = |i: usize| phases[i].as_secs_f64() * 1e3;
            println!(
                "{name} {mode} rust cold={cold:.1}ms warm-min={min:.2}ms (last run: save_as {:.2}                  read-buffers {:.2} open {:.2} records {:.2})",
                ms(0),
                ms(1),
                ms(2),
                ms(3)
            );
        }
    }
}
