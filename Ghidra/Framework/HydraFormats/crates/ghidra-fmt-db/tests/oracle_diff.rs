//! Differential check of the table-level read path against `oracle/OracleDb.java` (built from
//! this repository's DB sources) on the two checked-in legacy fixtures.
//!
//! For every master table row the expected file lists name, index column, root buffer, key type,
//! version, max key, record count and which node family the Java schema selects; for every table
//! (index tables included) it lists the record count and a SHA-256 over the stored bytes of each
//! key and record in iteration order. The Rust side decodes every record and re-encodes it, so
//! the hash also proves the Field/Schema encoders reproduce the file bytes.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use common::sha256_hex;
use ghidra_fmt_db::Database;
use ghidra_fmt_field::{Field, FieldType};
use ghidra_fmt_gbf::BufferFile;

fn fixture(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(dir)
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

fn expected(dir: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(format!("oracledb-{dir}.txt"));
    std::fs::read_to_string(p).unwrap()
}

/// `key=value` pairs of one oracle line (names may contain spaces, so `name=` is cut at the
/// next known key).
fn pairs(line: &str, keys: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut marks: Vec<(usize, &str)> = Vec::new();
    for k in keys {
        let pat = format!(" {k}=");
        let at = line.find(&pat).expect(k);
        marks.push((at, k));
    }
    marks.sort();
    for (i, (at, k)) in marks.iter().enumerate() {
        let start = at + k.len() + 2;
        let end = marks.get(i + 1).map_or(line.len(), |m| m.0);
        out.insert((*k).to_owned(), line[start..end].to_owned());
    }
    out
}

const TR_KEYS: [&str; 12] = [
    "num",
    "name",
    "idx",
    "root",
    "keytype",
    "version",
    "max",
    "count",
    "variable",
    "long",
    "varnodes",
    "fixednodes",
];

fn check(dir: &str) {
    let text = expected(dir);
    let bf = BufferFile::open(fixture(dir), true).unwrap();
    let db = Database::open(bf).unwrap();

    let mut lines = text.lines();
    let first = lines.next().unwrap();
    let dbid: i64 = first.strip_prefix("dbid=").unwrap().parse().unwrap();
    assert_eq!(db.database_id().unwrap(), dbid);

    // master table rows
    let mut trs = Vec::new();
    let mut tbls = Vec::new();
    let mut consistent = Vec::new();
    for l in lines {
        if let Some(rest) = l.strip_prefix("tr ") {
            trs.push(pairs(&format!(" {rest}"), &TR_KEYS));
        } else if let Some(rest) = l.strip_prefix("tbl ") {
            tbls.push(pairs(
                &format!(" {rest}"),
                &["num", "name", "idx", "n", "sha256"],
            ));
        } else if let Some(rest) = l.strip_prefix("consistent name=") {
            let (name, ok) = rest.rsplit_once(' ').unwrap();
            consistent.push((name.to_owned(), ok == "true"));
        }
    }
    assert!(
        consistent.iter().all(|(_, ok)| *ok),
        "oracle says inconsistent"
    );
    let recs = db.table_records();
    assert_eq!(recs.len(), trs.len());
    assert_eq!(tbls.len(), trs.len());
    let mut families = [0usize; 3];
    for (r, e) in recs.iter().zip(&trs) {
        let ctx = format!("{dir}: table {}", e["num"]);
        assert_eq!(r.table_num.to_string(), e["num"], "{ctx}");
        assert_eq!(r.name, e["name"], "{ctx}");
        assert_eq!(r.indexed_column.to_string(), e["idx"], "{ctx}");
        assert_eq!(r.root_buffer_id.to_string(), e["root"], "{ctx}");
        assert_eq!(
            r.schema.encoded_key_field_type().to_string(),
            e["keytype"],
            "{ctx}"
        );
        assert_eq!(r.schema.version().to_string(), e["version"], "{ctx}");
        assert_eq!(r.max_key.to_string(), e["max"], "{ctx}");
        assert_eq!(r.record_count.to_string(), e["count"], "{ctx}");
        assert_eq!(
            r.schema.is_variable_length().to_string(),
            e["variable"],
            "{ctx}"
        );
        assert_eq!(
            r.schema.use_long_key_nodes().to_string(),
            e["long"],
            "{ctx}"
        );
        assert_eq!(
            r.schema.use_variable_key_nodes().to_string(),
            e["varnodes"],
            "{ctx}"
        );
        assert_eq!(
            r.schema.use_fixed_key_nodes().to_string(),
            e["fixednodes"],
            "{ctx}"
        );
        families[usize::from(!r.schema.use_long_key_nodes())
            + usize::from(r.schema.use_fixed_key_nodes())] += 1;
    }
    assert!(families.iter().all(|&n| n > 0), "families {families:?}");

    // record streams, decoded and re-encoded
    for (t, e) in db.all_tables().zip(&tbls) {
        let ctx = format!("{dir}: {} (idx {})", t.name(), t.indexed_column());
        assert_eq!(t.name(), e["name"], "{ctx}");
        let mut bytes = Vec::new();
        let mut n = 0u64;
        for r in t.records().unwrap() {
            let r = r.unwrap();
            r.key.write(&mut bytes);
            t.schema().write_record(&r, &mut bytes).unwrap();
            n += 1;
        }
        assert_eq!(n.to_string(), e["n"], "{ctx} count");
        assert_eq!(sha256_hex(&bytes), e["sha256"], "{ctx} sha256");
        // master count agrees with the walk
        assert_eq!(i64::from(t.record_count()), n as i64, "{ctx} master count");
    }

    // indexed lookups and index table consistency
    let mut checked_indexes = 0;
    for t in db.tables() {
        let indexes = db.index_tables(t.name());
        for idx in &indexes {
            let col = idx.indexed_column() as usize;
            let legacy = matches!(idx.schema().key_type(), FieldType::LegacyIndex { .. });
            let mut want: Vec<Field> = Vec::new();
            let mut by_value: HashMap<Vec<u8>, Vec<Field>> = HashMap::new();
            for r in t.records().unwrap() {
                let r = r.unwrap();
                let Some(v) = r.values[col].clone() else {
                    continue;
                };
                if t.schema().is_sparse_column(col) && v.is_null() {
                    continue;
                }
                by_value
                    .entry(v.to_bytes())
                    .or_default()
                    .push(r.key.clone());
                want.push(Field::new_index(v, r.key, legacy).unwrap());
            }
            let got: Vec<Field> = idx.records().unwrap().map(|r| r.unwrap().key).collect();
            let mut want_sorted = want.clone();
            want_sorted.sort_by(|a, b| a.compare(b).unwrap());
            assert_eq!(got.len(), want.len(), "{dir}: {} col {col}", t.name());
            assert_eq!(got, want_sorted, "{dir}: {} col {col}", t.name());
            // find_primary_keys agrees with a scan of the primary table
            for r in t.records().unwrap().take(50) {
                let r = r.unwrap();
                let Some(v) = r.values[col].clone() else {
                    continue;
                };
                if v.is_null() {
                    continue;
                }
                let mut found = t.find_primary_keys(col, &v).unwrap().unwrap();
                found.sort_by(|a, b| a.compare(b).unwrap());
                let mut expect = by_value[&v.to_bytes()].clone();
                expect.sort_by(|a, b| a.compare(b).unwrap());
                assert_eq!(found, expect, "{dir}: {} col {col}", t.name());
            }
            checked_indexes += 1;
        }
    }
    assert!(checked_indexes > 0, "no index tables checked");
}

#[test]
fn legacy_fixture_matches_java_oracle() {
    check("legacy-12.1.4");
}

#[test]
fn analysed_fixture_matches_java_oracle() {
    check("legacy-12.1.4-analysed");
}
