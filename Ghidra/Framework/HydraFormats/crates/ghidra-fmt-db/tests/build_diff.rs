//! Write path differential test. `oracle/OracleBuild.java` builds a database from a script with
//! the repository's DB classes and saves it; the same script is replayed here with
//! `Database::create`, `put_record`, `delete_record` and `commit`, and every buffer of the result
//! must have the SHA-256 Java reports (so the master table, the table trees, chained buffers
//! and the free list are identical, byte for byte). The database id is taken from the Java run,
//! as Java draws it at random.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::sha256_hex;
use ghidra_fmt_db::Database;
use ghidra_fmt_field::{Field, FieldType, Record, Schema};
use ghidra_fmt_gbf::{BufferFile, BufferStore, MemoryBufferStore};

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/build")
}

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn schema(fixed: bool) -> Schema {
    if fixed {
        Schema::new(
            1,
            FieldType::Long,
            "Key",
            vec![FieldType::Long, FieldType::Int, FieldType::Short],
            ["A", "B", "C"].map(str::to_owned).to_vec(),
            &[],
        )
        .unwrap()
    } else {
        Schema::new(
            1,
            FieldType::Long,
            "Key",
            vec![FieldType::Int, FieldType::Binary],
            ["A", "B"].map(str::to_owned).to_vec(),
            &[],
        )
        .unwrap()
    }
}

/// Replays a script; returns the database and the model of every table (key to record).
fn replay(
    script: &str,
    dbid: i64,
) -> (
    Database<MemoryBufferStore>,
    BTreeMap<String, BTreeMap<i64, Record>>,
) {
    let mut db: Option<Database<MemoryBufferStore>> = None;
    let mut fixed: BTreeMap<String, bool> = BTreeMap::new();
    let mut model: BTreeMap<String, BTreeMap<i64, Record>> = BTreeMap::new();
    for line in script.lines() {
        let t: Vec<&str> = line.split(' ').collect();
        match t[0] {
            "buffer" => {
                let store = MemoryBufferStore::new(t[1].parse().unwrap());
                db = Some(Database::create(store, dbid).unwrap());
            }
            "table" => {
                let fx = t[2] == "fixed";
                db.as_mut().unwrap().create_table(t[1], schema(fx)).unwrap();
                fixed.insert(t[1].to_owned(), fx);
                model.insert(t[1].to_owned(), BTreeMap::new());
            }
            "put" => {
                let key: i64 = t[2].parse().unwrap();
                let values = if fixed[t[1]] {
                    vec![
                        Some(Field::Long(t[3].parse().unwrap())),
                        Some(Field::Int(t[4].parse().unwrap())),
                        Some(Field::Short(t[5].parse().unwrap())),
                    ]
                } else {
                    vec![
                        Some(Field::Int(t[3].parse().unwrap())),
                        Some(Field::Binary(Some(hex(t[4])))),
                    ]
                };
                let rec = Record {
                    key: Field::Long(key),
                    values,
                };
                db.as_mut().unwrap().put_record(t[1], &rec).unwrap();
                model.get_mut(t[1]).unwrap().insert(key, rec);
            }
            "del" => {
                let key: i64 = t[2].parse().unwrap();
                let existed = db.as_mut().unwrap().delete_record(t[1], key).unwrap();
                assert_eq!(existed, model.get_mut(t[1]).unwrap().remove(&key).is_some());
            }
            "commit" => db.as_mut().unwrap().commit().unwrap(),
            other => panic!("bad script line {other}"),
        }
    }
    let mut db = db.unwrap();
    db.commit().unwrap();
    (db, model)
}

fn buffer_lines(store: &MemoryBufferStore) -> Vec<String> {
    let mut out = Vec::new();
    let mut free = store.free_ids().to_vec();
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
                sha256_hex(d)
            )),
            None => out.push(format!("buf {i} id=-1 empty=true sha256=-")),
        }
    }
    out
}

fn check(name: &str) {
    let dir = data_dir();
    let script = std::fs::read_to_string(dir.join(format!("{name}.script"))).unwrap();
    let expected = std::fs::read_to_string(dir.join(format!("{name}.expected"))).unwrap();
    let dbid: i64 = expected
        .lines()
        .next()
        .unwrap()
        .strip_prefix("dbid=")
        .unwrap()
        .parse()
        .unwrap();
    let (db, model) = replay(&script, dbid);

    let want: Vec<&str> = expected
        .lines()
        .filter(|l| l.starts_with("bufferSize=") || l.starts_with("buf "))
        .collect();
    let got = buffer_lines(db.store());
    assert_eq!(got.len(), want.len(), "{name}: buffer count");
    let bad: Vec<usize> = got
        .iter()
        .zip(&want)
        .enumerate()
        .filter(|(_, (g, w))| g != w)
        .map(|(i, _)| i)
        .collect();
    assert!(
        bad.is_empty(),
        "{name}: {} of {} buffer lines differ, first at {:?}: rust {:?} java {:?}",
        bad.len(),
        got.len(),
        &bad[..bad.len().min(20)],
        bad.first().map(|&i| &got[i]),
        bad.first().map(|&i| want[i])
    );

    // table summary lines of the Java run
    let mut tables: Vec<(String, i32, i64)> = db
        .tables()
        .map(|t| (t.name().to_owned(), t.record_count(), t.max_key()))
        .collect();
    tables.sort();
    let want_tables: Vec<String> = expected
        .lines()
        .filter(|l| l.starts_with("table "))
        .map(str::to_owned)
        .collect();
    let got_tables: Vec<String> = tables
        .iter()
        .map(|(n, c, m)| format!("table {n} count={c} max={m}"))
        .collect();
    assert_eq!(got_tables, want_tables, "{name}: tables");
    assert_eq!(db.database_id().unwrap(), dbid);

    // the result reads back as the model says, from memory and from a saved file
    // HYDRA_FMT_KEEP_DIR keeps the files so the Java oracle can read them (see oracle/README.md)
    let keep = std::env::var_os("HYDRA_FMT_KEEP_DIR").map(PathBuf::from);
    let dir = keep
        .clone()
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    let path = dir.join(format!("rust-built-{name}.gbf"));
    let _ = std::fs::remove_file(&path);
    db.store().save_to_file(&path, 1).unwrap();
    let reopened = Database::open(BufferFile::open(&path, true).unwrap()).unwrap();
    for (tname, rows) in &model {
        let t = reopened.table(tname).unwrap();
        let got: Vec<Record> = t.records().unwrap().map(|r| r.unwrap()).collect();
        let want: Vec<Record> = rows.values().cloned().collect();
        assert_eq!(got, want, "{name}: table {tname}");
        assert_eq!(t.record_count() as usize, rows.len());
    }
    assert_eq!(reopened.database_id().unwrap(), dbid);
    drop(reopened);
    if keep.is_none() {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn sequential_inserts() {
    check("seq");
}

#[test]
fn reverse_inserts() {
    check("reverse");
}

#[test]
fn random_puts_updates_and_deletes() {
    check("rand");
}

#[test]
fn delete_everything_then_refill() {
    check("drain");
}

#[test]
fn fixed_length_records() {
    check("fixed");
}

#[test]
fn several_tables_with_commits() {
    check("multi");
}

#[test]
fn default_buffer_size() {
    check("default16k");
}
