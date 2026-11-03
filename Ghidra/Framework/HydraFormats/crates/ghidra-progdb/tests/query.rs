//! The `query` facade answers what the Java oracle printed (`testdata/oracleprog-*.txt`).

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ghidra_progdb::query::Program;
use ghidra_progdb::{AddressSpaces, SpaceDef};

fn fixture(dir: &str) -> PathBuf {
    if dir == "synth-33" {
        return Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/synth/progdb-synth-33.gbf");
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(dir)
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

fn oracle(dir: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(format!("oracleprog-{dir}.txt")),
    )
    .unwrap()
}

/// `key=value` from an oracle line; bracketed values may hold spaces.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!(" {key}=");
    let start = line.find(&pat).map(|i| i + pat.len()).unwrap();
    let rest = &line[start..];
    if rest.starts_with('[') {
        &rest[1..rest.find(']').unwrap()]
    } else {
        rest.split(' ').next().unwrap()
    }
}

fn open(dir: &str, text: &str) -> Program<ghidra_fmt_gbf::BufferFile> {
    let mut defs = Vec::new();
    let mut default = String::new();
    for l in text.lines() {
        if let Some(d) = l.strip_prefix("default_space=") {
            default = d.to_owned();
        }
        if l.starts_with("space ") {
            let l = format!(" {l}");
            defs.push(SpaceDef {
                name: field(&l, "name").to_owned(),
                id: field(&l, "id").parse().unwrap(),
                bits: field(&l, "bits").parse().unwrap(),
            });
        }
    }
    Program::open_file(fixture(dir), AddressSpaces::new(defs, &default)).unwrap()
}

fn check(dir: &str) {
    let text = oracle(dir);
    let p = open(dir, &text);
    let lines: Vec<String> = text.lines().map(|l| format!(" {l}")).collect();

    // functions: ids, entries, bodies
    let want_count: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("functions="))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(p.functions().len(), want_count);
    for l in lines.iter().filter(|l| l.starts_with(" func ")) {
        let id: i64 = field(l, "id").parse().unwrap();
        let entry = p.parse_address(field(l, "entry")).unwrap();
        let f = p.function_by_id(id).unwrap();
        assert_eq!(f.entry, entry);
        assert_eq!(p.function_at(&entry).unwrap().function.id, id);
    }
    for l in lines.iter().filter(|l| l.starts_with(" fnbody ")) {
        let id: i64 = field(l, "id").parse().unwrap();
        let ranges = field(l, "ranges");
        let f = p.function_by_id(id).unwrap();
        let got: String = f.body.iter().map(|r| format!("{r};")).collect();
        assert_eq!(got, ranges);
        for r in &f.body {
            let start = p
                .parse_address(&format!("{}:{:x}", r.space, r.min))
                .unwrap();
            let end = p
                .parse_address(&format!("{}:{:x}", r.space, r.max))
                .unwrap();
            assert_eq!(p.function_containing(&start).unwrap().function.id, id);
            assert_eq!(p.function_containing(&end).unwrap().function.id, id);
        }
    }

    // references
    let mut want_from: BTreeMap<String, usize> = BTreeMap::new();
    let mut want_to: BTreeMap<String, usize> = BTreeMap::new();
    for l in &lines {
        if l.starts_with(" ref ") {
            *want_from.entry(field(l, "from").to_owned()).or_default() += 1;
        } else if l.starts_with(" toref ") {
            *want_to.entry(field(l, "to").to_owned()).or_default() += 1;
        }
    }
    for (addr, n) in &want_from {
        if addr == "EXT_FROM" {
            continue;
        }
        let a = p.parse_address(addr).unwrap();
        assert_eq!(p.xrefs_from(&a).len(), *n, "xrefs_from {addr}");
    }
    for (addr, n) in &want_to {
        let a = p.parse_address(addr).unwrap();
        assert_eq!(p.xrefs_to(&a).len(), *n, "xrefs_to {addr}");
    }

    // symbols by name and at an address
    for l in lines.iter().filter(|l| l.starts_with(" symbyname ")) {
        let ids: Vec<String> = p
            .symbols_by_name(field(l, "name"))
            .iter()
            .map(|s| s.id.to_string())
            .collect();
        assert_eq!(ids.join(","), field(l, "ids"));
    }
    for l in lines
        .iter()
        .filter(|l| l.starts_with(" symat ") && !field(l, "addr").starts_with("NO_ADDRESS"))
    {
        let a = p.parse_address(field(l, "addr")).unwrap();
        let ids: Vec<String> = p.symbols_at(&a).iter().map(|s| s.id.to_string()).collect();
        assert_eq!(ids.join(","), field(l, "ids"));
    }

    // data types: id -> name / path / size, and defined data resolved to its type
    for l in lines.iter().filter(|l| l.starts_with(" dt id=")) {
        let id: i64 = field(l, "id").parse().unwrap();
        let t = p.data_type(id).unwrap().unwrap();
        // names such as `char[2]` hold the closing bracket, so compare the whole span
        let want = format!(
            " name=[{}] path=[{}] len={}",
            t.name,
            t.path,
            t.size.unwrap()
        );
        assert!(l.contains(&want), "{l} vs {want}");
        assert_eq!(p.data_type_by_path(&t.path).unwrap().unwrap().path, t.path);
    }
    let mut resolved = 0;
    for l in lines.iter().filter(|l| l.starts_with(" data addr=")) {
        let a = p.parse_address(field(l, "addr")).unwrap();
        let t = p.data_type_at(&a).unwrap().unwrap();
        assert!(l.ends_with(&format!(" dt=[{}]", t.path)), "{l}");
        resolved += 1;
    }
    assert!(resolved > 0);
    assert!(p.data_type(-12345).unwrap().is_none());

    annotations_and_more(&p, &text, &lines);

    // bytes
    for l in lines.iter().filter(|l| l.starts_with(" memread ")) {
        let a = p.parse_address(field(l, "addr")).unwrap();
        let len: usize = field(l, "len").parse().unwrap();
        match p.read_bytes(&a, len) {
            Ok(b) => {
                assert_eq!(b.len().to_string(), field(l, "n"));
                assert_eq!(common::sha256_hex(&b), field(l, "sha256"));
            }
            Err(_) => assert!(l.ends_with(" error"), "{l}"),
        }
    }
}

fn count(text: &str, key: &str) -> usize {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap()
        .parse()
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Equates, bookmarks, relocations, register values, options, property maps, externals and
/// namespaces through the facade, against the oracle lines.
fn annotations_and_more(p: &Program<ghidra_fmt_gbf::BufferFile>, text: &str, lines: &[String]) {
    // equates: name, value, reference count, and the equates at each reference address
    let mut equate_lines = 0;
    for l in lines.iter().filter(|l| l.starts_with(" equate name=")) {
        let e = p.equate_by_name(field(l, "name")).unwrap().unwrap();
        assert_eq!(e.value.to_string(), field(l, "value"));
        assert_eq!(e.references.len().to_string(), field(l, "refs"));
        for r in &e.references {
            assert!(
                p.equates_at(&r.address)
                    .unwrap()
                    .iter()
                    .any(|(x, op)| x.id == e.id && *op == r.op_index)
            );
        }
        equate_lines += 1;
    }
    assert_eq!(p.equates().unwrap().len(), equate_lines);

    // bookmarks
    assert_eq!(p.bookmarks().unwrap().len(), count(text, "bookmarks="));
    for l in lines.iter().filter(|l| l.starts_with(" bookmark id=")) {
        let id: i64 = field(l, "id").parse().unwrap();
        let a = p.parse_address(field(l, "addr")).unwrap();
        assert!(p.bookmarks_at(&a).unwrap().iter().any(|b| b.id == id));
    }

    // relocations: count and the original bytes of every relocation
    assert_eq!(p.relocations().unwrap().len(), count(text, "relocations="));
    let reloc_lines: Vec<&String> = lines
        .iter()
        .filter(|l| l.starts_with(" reloc addr="))
        .collect();
    for (r, l) in p.relocations().unwrap().iter().zip(reloc_lines) {
        assert_eq!(r.address.to_string(), field(l, "addr"));
        assert_eq!(r.status.name(), field(l, "status"));
        let want = field(l, "bytes");
        match p.relocation_bytes(r).unwrap() {
            Some(b) => assert_eq!(hex(&b), want),
            None => assert_eq!(want, "null"),
        }
        assert!(p.relocations_at(&r.address).unwrap().contains(&r));
    }

    // register values
    assert_eq!(
        p.register_values().unwrap().len(),
        count(text, "register_values=")
    );
    for l in lines.iter().filter(|l| l.starts_with(" regvalue reg=")) {
        let a = p.parse_address(field(l, "min")).unwrap();
        let found = p.register_values_at(field(l, "reg"), &a).unwrap();
        assert!(
            found.iter().any(|v| hex(&v.bytes) == field(l, "bytes")),
            "{l}"
        );
    }

    // options and property maps
    assert_eq!(p.options().unwrap().len(), count(text, "options="));
    for l in lines.iter().filter(|l| l.starts_with(" option key=")) {
        let o = p.option(field(l, "key")).unwrap().unwrap();
        assert_eq!(o.type_id.to_string(), field(l, "type"));
    }
    for l in lines.iter().filter(|l| l.starts_with(" propmap name=")) {
        let m = p.property_map(field(l, "name")).unwrap().unwrap();
        assert_eq!(m.kind.name(), field(l, "kind"));
        assert_eq!(m.entries.len().to_string(), field(l, "size"));
    }

    // externals and namespaces
    let mut locations = 0;
    for lib in p.external_libraries().unwrap() {
        locations += p.external_locations(&lib.name).unwrap().len();
    }
    let want_locs = lines
        .iter()
        .filter(|l| l.starts_with(" extloc id="))
        .count();
    assert_eq!(locations, want_locs);
    for l in lines.iter().filter(|l| l.starts_with(" sympath id=")) {
        let id: i64 = field(l, "id").parse().unwrap();
        assert_eq!(p.symbol_path(id).unwrap(), field(l, "path"));
    }
    for l in lines.iter().filter(|l| l.starts_with(" namespace id=")) {
        let id: i64 = field(l, "id").parse().unwrap();
        let n = p.namespaces().unwrap().iter().find(|n| n.id == id).unwrap();
        assert_eq!(n.path, field(l, "path"));
        assert_eq!(n.parent_id.to_string(), field(l, "parent"));
    }
}

#[test]
fn synthetic_v33_fixture() {
    check("synth-33");
}

#[test]
fn legacy_fixture() {
    check("legacy-12.1.4");
}

#[test]
fn analysed_fixture() {
    check("legacy-12.1.4-analysed");
}

#[test]
fn addresses_parse_with_and_without_a_space() {
    let text = oracle("legacy-12.1.4");
    let p = open("legacy-12.1.4", &text);
    let a = p.parse_address("ram:140001000").unwrap();
    assert_eq!(p.parse_address("0x140001000").unwrap(), a);
    assert_eq!(p.parse_address("140001000").unwrap(), a);
    assert!(p.parse_address("nope:10").is_err());
    assert!(p.parse_address("ram:zz").is_err());
}

#[test]
fn program_over_memory_store_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Program<ghidra_fmt_gbf::MemoryBufferStore>>();
}
