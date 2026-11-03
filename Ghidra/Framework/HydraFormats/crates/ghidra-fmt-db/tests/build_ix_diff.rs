//! Write path differential test for field-key tables and index tables: `oracle/OracleBuildIx.java`
//! builds a database from a script with the repository's DB classes; the same script is replayed
//! with `Database::create_indexed_table`, `put_record`, `delete_record_field` and `commit`, and
//! every buffer must have the SHA-256 Java reports. This covers the fixed-key node family (key
//! types int/short/long with index tables) and the index maintenance order of `Table`.

mod common;

use std::path::{Path, PathBuf};

use common::sha256_hex;
use ghidra_fmt_db::Database;
use ghidra_fmt_field::{Field, FieldType, JString, Record, Schema};
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

fn schema(key: &str, fixed: bool) -> Schema {
    let (fields, names) = if fixed {
        (
            vec![FieldType::Long, FieldType::Int, FieldType::Short],
            ["A", "B", "C"],
        )
    } else {
        (
            vec![FieldType::Int, FieldType::Binary, FieldType::String],
            ["A", "B", "C"],
        )
    };
    Schema::new(
        1,
        key_type(key),
        "Key",
        fields,
        names.map(str::to_owned).to_vec(),
        &[],
    )
    .unwrap()
}

struct Meta {
    fixed: bool,
    key: String,
}

fn replay(script: &str, dbid: i64) -> Database<MemoryBufferStore> {
    let mut db: Option<Database<MemoryBufferStore>> = None;
    let mut meta: std::collections::BTreeMap<String, Meta> = Default::default();
    for line in script.lines() {
        let t: Vec<&str> = line.split(' ').collect();
        match t[0] {
            "buffer" => {
                let store = MemoryBufferStore::new(t[1].parse().unwrap());
                db = Some(Database::create(store, dbid).unwrap());
            }
            "table" => {
                let fixed = t[3] == "fixed";
                let cols: Vec<usize> = if t[4] == "-" {
                    vec![]
                } else {
                    t[4].split(',').map(|c| c.parse().unwrap()).collect()
                };
                db.as_mut()
                    .unwrap()
                    .create_indexed_table(t[1], schema(t[2], fixed), &cols)
                    .unwrap();
                meta.insert(
                    t[1].to_owned(),
                    Meta {
                        fixed,
                        key: t[2].to_owned(),
                    },
                );
            }
            "put" => {
                let m = &meta[t[1]];
                let values = if m.fixed {
                    vec![
                        Some(Field::Long(t[3].parse().unwrap())),
                        Some(Field::Int(t[4].parse().unwrap())),
                        Some(Field::Short(t[5].parse().unwrap())),
                    ]
                } else {
                    vec![
                        Some(Field::Int(t[3].parse().unwrap())),
                        Some(Field::Binary(Some(hex(t[4])))),
                        Some(Field::String(Some(JString::new(if t[5] == "-" {
                            ""
                        } else {
                            t[5]
                        })))),
                    ]
                };
                let rec = Record {
                    key: key(&m.key, t[2]),
                    values,
                };
                db.as_mut().unwrap().put_record(t[1], &rec).unwrap();
            }
            "del" => {
                let m = &meta[t[1]];
                db.as_mut()
                    .unwrap()
                    .delete_record_field(t[1], &key(&m.key, t[2]))
                    .unwrap();
            }
            "commit" => db.as_mut().unwrap().commit().unwrap(),
            other => panic!("bad script line {other}"),
        }
    }
    let mut db = db.unwrap();
    db.commit().unwrap();
    db
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
    let db = replay(&script, dbid);

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

    // master rows (root, key type, count, node family) must match too
    let want_tr: Vec<String> = expected
        .lines()
        .filter(|l| l.starts_with("tr "))
        .map(|l| {
            // keep num, name, idx, root, keytype, version, max, count
            let cut = l.find(" variable=").unwrap();
            l[..cut].to_owned()
        })
        .collect();
    let got_tr: Vec<String> = db
        .all_tables()
        .map(|t| {
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
        })
        .collect();
    assert_eq!(got_tr, want_tr, "{name}: master rows");

    // the saved file reads back, with every index table equal to what its primary table implies
    let keep = std::env::var_os("HYDRA_FMT_KEEP_DIR").map(PathBuf::from);
    let out = keep
        .clone()
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    let path = out.join(format!("rust-built-{name}.gbf"));
    let _ = std::fs::remove_file(&path);
    db.store().save_to_file(&path, 1).unwrap();
    let reopened = Database::open(BufferFile::open(&path, true).unwrap()).unwrap();
    for t in reopened.tables() {
        let rows: Vec<Record> = t.records().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), t.record_count() as usize);
        for idx in reopened.index_tables(t.name()) {
            let col = idx.indexed_column() as usize;
            let entries = idx.index_entries().unwrap();
            assert_eq!(entries.len(), rows.len(), "{name}: index {col} size");
            let mut want: Vec<(Field, Field)> = rows
                .iter()
                .map(|r| (r.values[col].clone().unwrap(), r.key.clone()))
                .collect();
            want.sort_by(|a, b| {
                a.0.compare(&b.0)
                    .unwrap()
                    .then_with(|| a.1.compare(&b.1).unwrap())
            });
            let got: Vec<(Field, Field)> = entries
                .iter()
                .map(|e| (e.indexed.clone(), e.primary.clone()))
                .collect();
            assert_eq!(got, want, "{name}: index {col} content");
        }
    }
    drop(reopened);
    if keep.is_none() {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn fixed_key_fixed_records() {
    check("fk-int-fixed");
}

#[test]
fn fixed_key_variable_records() {
    check("fk-short-var");
}

#[test]
fn long_table_with_one_index() {
    check("ix-long-fixed-1");
}

#[test]
fn long_table_with_two_indexes_created_out_of_order() {
    check("ix-long-fixed-2-0");
}

#[test]
fn variable_records_with_int_index() {
    check("ix-int-var-0");
}

#[test]
fn several_indexed_tables() {
    check("ix-multi");
}

#[test]
fn string_keys_fixed_records() {
    check("vk-string-fixed");
}

#[test]
fn string_keys_variable_records() {
    check("vk-string-var");
}

#[test]
fn index_on_a_string_column() {
    check("ix-string-column");
}

#[test]
fn index_on_every_column() {
    check("ix-all-columns");
}

#[test]
fn string_keys_stress() {
    check("vk-string-stress");
    check("vk-string-var-stress");
}
