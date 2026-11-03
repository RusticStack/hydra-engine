//! Differential check against output of the Java oracle (`HydraFormats/oracle/Oracle.java`,
//! built from this repository's DB sources) on the checked-in legacy fixtures.
//!
//! The expected files in `testdata/` were produced by `java db.buffers.Oracle <copy of db.1.gbf>`
//! and record, per fixture: block file geometry, free list, every buffer's id/empty flag and
//! SHA-256, every table's name/record count/max key as `DBHandle` reports them, and the
//! database id. The Rust side recomputes all of it from the raw file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ghidra_fmt_btree::longkey::{LongKeyTree, Record};
use ghidra_fmt_bytes::BeCursor;
use ghidra_fmt_chain::DbParms;
use ghidra_fmt_gbf::{BufferFile, BufferStore};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(dir: &str) -> PathBuf {
    root()
        .join("../../Features/HeadlessSession/examples/fixtures")
        .join(dir)
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

// Minimal SHA-256 (FIPS 180-4) so the test needs no dependency.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[test]
fn sha256_known_answers() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Master-table row fields the oracle reports.
fn table_rows(bf: &BufferFile) -> BTreeMap<String, (i32, i64)> {
    let root = DbParms::read(bf).unwrap().master_table_root().unwrap();
    let mut out = BTreeMap::new();
    for r in LongKeyTree::new(bf, root, None).records().unwrap() {
        let Record { data, .. } = r.unwrap();
        let mut c = BeCursor::new(&data);
        let n = c.read_i32().unwrap() as usize;
        let name = String::from_utf8(c.read_bytes(n).unwrap().to_vec()).unwrap();
        c.read_i32().unwrap(); // version
        c.read_i32().unwrap(); // buffer id
        c.read_u8().unwrap(); // key type
        let n = c.read_i32().unwrap() as usize;
        c.read_bytes(n).unwrap(); // field types
        let n = c.read_i32().unwrap() as usize;
        c.read_bytes(n).unwrap(); // field names
        let indexed = c.read_i32().unwrap(); // -1 = primary table; index tables reuse the name
        let max_key = c.read_i64().unwrap();
        let count = c.read_i32().unwrap();
        if indexed == -1 {
            out.insert(name, (count, max_key));
        }
    }
    out
}

fn check(fixture_dir: &str, expected_file: &str) {
    let expected = std::fs::read_to_string(root().join("testdata").join(expected_file)).unwrap();
    let bf = BufferFile::open(fixture(fixture_dir), true).unwrap();

    let mut lines = expected.lines();
    let first = lines.next().unwrap();
    assert_eq!(
        first,
        format!(
            "bufferSize={} indexCount={} free={:?}",
            bf.buffer_size(),
            bf.index_count(),
            bf.free_indexes()
        )
    );

    let tables = table_rows(&bf);
    let mut seen_tables = 0;
    let mut seen_buffers = 0;
    for line in lines {
        if let Some(rest) = line.strip_prefix("buf ") {
            // "<index> id=<id> empty=<bool> sha256=<hex|->"
            let f: Vec<&str> = rest.split(' ').collect();
            let index: i32 = f[0].parse().unwrap();
            let b = bf.get_buffer(index).unwrap();
            assert_eq!(f[1], format!("id={}", b.id), "buffer {index} id");
            assert_eq!(f[2], format!("empty={}", b.empty), "buffer {index} empty");
            let hash = b.data.as_deref().map_or("-".to_owned(), sha256_hex);
            assert_eq!(f[3], format!("sha256={hash}"), "buffer {index} data");
            seen_buffers += 1;
        } else if let Some(rest) = line.strip_prefix("table ") {
            // "<name> count=<n> max=<k>" (name may contain spaces)
            let (name_and_count, max) = rest.rsplit_once(" max=").unwrap();
            let (name, count) = name_and_count.rsplit_once(" count=").unwrap();
            let (c, m) = tables
                .get(name)
                .unwrap_or_else(|| panic!("table {name} missing"));
            assert_eq!(count.parse::<i32>().unwrap(), *c, "{name} count");
            assert_eq!(max.parse::<i64>().unwrap(), *m, "{name} max key");
            seen_tables += 1;
        } else if let Some(id) = line.strip_prefix("dbid=") {
            assert_eq!(
                id.parse::<i64>().unwrap(),
                DbParms::read(&bf).unwrap().database_id().unwrap()
            );
        } else {
            panic!("unrecognized oracle line: {line}");
        }
    }
    assert_eq!(seen_buffers, bf.index_count());
    assert_eq!(seen_tables, tables.len(), "table sets differ");
}

#[test]
fn legacy_fixture_matches_java_oracle() {
    check("legacy-12.1.4", "oracle-legacy-12.1.4.txt");
}

#[test]
fn analysed_fixture_matches_java_oracle() {
    check(
        "legacy-12.1.4-analysed",
        "oracle-legacy-12.1.4-analysed.txt",
    );
}
