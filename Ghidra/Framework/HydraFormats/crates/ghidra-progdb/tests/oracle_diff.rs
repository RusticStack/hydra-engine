//! Differential check against `oracle/OracleProgram.java`, which opens the same fixtures through
//! the stock `ProgramDB` (read-only) and prints the language, address spaces, memory blocks and
//! symbols. The Rust reader must reproduce every line.

use std::path::{Path, PathBuf};

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::{AddressSpaces, ProgramDb, SpaceDef};

fn fixture(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(dir)
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

fn expected(dir: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(format!("oracleprog-{dir}.txt"));
    std::fs::read_to_string(p).unwrap()
}

/// Value of `key=` in an oracle line (up to the next space; bracketed values may hold spaces).
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!(" {key}=");
    let start = line.find(&pat).map(|i| i + pat.len()).unwrap();
    let rest = &line[start..];
    if rest.starts_with('[') {
        let end = rest.find(']').unwrap();
        &rest[1..end]
    } else {
        rest.split(' ').next().unwrap()
    }
}

fn spaces_of(text: &str) -> AddressSpaces {
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
    AddressSpaces::new(defs, &default)
}

fn check(dir: &str) {
    let text = expected(dir);
    let db = ProgramDb::open(
        BufferFile::open(fixture(dir), true).unwrap(),
        spaces_of(&text),
    )
    .unwrap();

    let mut got = Vec::new();
    got.push(format!("stored_version={}", db.stored_version()));
    got.push(format!("language={}", db.language_id().unwrap()));
    got.push(format!("compiler={}", db.compiler_spec_id().unwrap()));
    let base = ghidra_progdb::Address::Space {
        space: db.address_map().spaces().default_space.clone(),
        offset: db.image_base_offset() as u64,
    };
    got.push(format!("image_base={base}"));

    let blocks = db.memory_blocks().unwrap();
    got.push(format!("blocks={}", blocks.len()));
    for b in &blocks {
        let end = match &b.start {
            ghidra_progdb::Address::Space { space, offset } => ghidra_progdb::Address::Space {
                space: space.clone(),
                offset: offset + b.length as u64 - 1,
            },
            other => other.clone(),
        };
        got.push(format!(
            "block name={} start={} end={} size={} r={} w={} x={} vol={} art={} init={} overlay=false mapped={} comment=[{}] source=[{}] subs={}",
            b.name,
            b.start,
            end,
            b.length,
            b.is_read(),
            b.is_write(),
            b.is_execute(),
            b.is_volatile(),
            b.is_artificial(),
            b.is_initialized(),
            b.is_mapped(),
            b.comment.as_deref().unwrap_or("null"),
            b.source_name.as_deref().unwrap_or("null"),
            b.sub_blocks.len()
        ));
        for s in &b.sub_blocks {
            // zero filled parts of a file-backed block are plain buffers in Java too
            got.push(format!(
                "  sub kind={} len={} off={}",
                s.kind.oracle_name(),
                s.length,
                s.start_offset
            ));
        }
    }

    let symbols = db.symbols().unwrap();
    for s in &symbols {
        let name = if s.source == ghidra_progdb::SourceType::Default {
            ""
        } else {
            &s.name
        };
        got.push(format!(
            "sym id={} name=[{}] addr={} parent={} type={} source={} primary={} pinned={}",
            s.id,
            name,
            s.address,
            s.parent_id,
            s.symbol_type,
            s.source.name(),
            s.is_primary(),
            s.is_pinned()
        ));
    }
    let want_count: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("symbols="))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(symbols.len(), want_count);
    let want: Vec<&str> = text
        .lines()
        .filter(|l| {
            !l.starts_with("space ")
                && !l.starts_with("symbols=")
                && !l.starts_with("default_space=")
        })
        .collect();
    let got_refs: Vec<&str> = got.iter().map(String::as_str).collect();
    assert_eq!(got_refs.len(), want.len());
    for (g, w) in got_refs.iter().zip(&want) {
        assert_eq!(g, w);
    }
}

#[test]
fn legacy_fixture_matches_java() {
    check("legacy-12.1.4");
}

#[test]
fn analysed_fixture_matches_java() {
    check("legacy-12.1.4-analysed");
}
