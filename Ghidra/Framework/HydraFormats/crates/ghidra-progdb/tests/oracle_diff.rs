//! Differential check against `oracle/OracleProgram.java`, which opens the same fixtures through
//! the stock `ProgramDB` (read-only) and prints the language, address spaces, memory blocks and
//! symbols. The Rust reader must reproduce every line.

use std::path::{Path, PathBuf};

mod common;

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::{Address, AddressSpaces, ProgramDb, RefKind, SpaceDef};

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
    got.extend(listing_lines(&db));
    got.extend(memory_lines(&db));
    let got_refs: Vec<&str> = got.iter().map(String::as_str).collect();
    for (i, (g, w)) in got_refs.iter().zip(&want).enumerate() {
        assert_eq!(g, w, "line {i}");
    }
    assert_eq!(got_refs.len(), want.len());
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn ref_line(tag: &str, r: &ghidra_progdb::Reference) -> String {
    let extra = match r.kind {
        RefKind::Offset(o) => format!(" offset={o}"),
        RefKind::Shifted(s) => format!(" shift={s}"),
        _ => String::new(),
    };
    format!(
        "{tag} from={} to={} type={} op={} src={} primary={} sym={} kind={}{extra}",
        r.from,
        r.to,
        r.ref_type_name(),
        r.op_index,
        r.source.name(),
        r.primary,
        r.symbol_id.unwrap_or(-1),
        r.kind.class_name()
    )
}

/// Sort by key (stable) and append the lines, like the oracle's `emit`.
fn emit(out: &mut Vec<String>, mut rows: Vec<(String, String)>) {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    out.extend(rows.into_iter().map(|r| r.1));
}

fn listing_lines(db: &ProgramDb<BufferFile>) -> Vec<String> {
    let mut out = Vec::new();
    let mut fns = db.functions().unwrap();
    fns.sort_by_key(|f| f.id);
    out.push(format!("functions={}", fns.len()));
    for f in &fns {
        let entry = f
            .entry
            .as_ref()
            .map_or("null".to_owned(), |a| a.to_string());
        if let Some(t) = f.thunk_target {
            out.push(format!("func id={} entry={entry} thunk={t}", f.id));
        } else {
            out.push(format!(
                "func id={} entry={entry} thunk=-1 vararg={} inline={} noreturn={} custom={} cc={} purge={} sigsrc={}",
                f.id,
                f.has_var_args(),
                f.is_inline(),
                f.has_no_return(),
                f.has_custom_storage(),
                f.calling_convention,
                f.stack_purge,
                f.signature_source().unwrap().name()
            ));
        }
    }

    let mut rows = Vec::new();
    for (owner, refs) in db.references_from().unwrap() {
        for r in &refs {
            rows.push((owner.to_string(), ref_line("ref", r)));
        }
    }
    out.push(format!("ref_sources={}", rows.len()));
    emit(&mut out, rows);

    let spaces = db.address_map().spaces();
    let mut rows = Vec::new();
    for (owner, refs) in db.references_to().unwrap() {
        // getReferencesTo is not supported for stack and register addresses
        if let ghidra_progdb::Address::Space { space, .. } = &owner
            && (*space == spaces.stack_space || *space == spaces.register_space)
        {
            continue;
        }
        for r in &refs {
            rows.push((owner.to_string(), ref_line("toref", r)));
        }
    }
    out.push(format!("ref_destinations={}", rows.len()));
    emit(&mut out, rows);

    let rows: Vec<(String, String)> = db
        .instructions()
        .unwrap()
        .iter()
        .map(|i| (i.address.to_string(), format!("inst addr={}", i.address)))
        .collect();
    out.push(format!("instructions={}", rows.len()));
    emit(&mut out, rows);

    let rows: Vec<(String, String)> = db
        .data()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d.address.to_string(),
                format!("data addr={} type={}", d.address, d.datatype_id),
            )
        })
        .collect();
    out.push(format!("data={}", rows.len()));
    emit(&mut out, rows);

    let mut rows = Vec::new();
    for (addr, c) in db.comments().unwrap() {
        let kinds = [
            ("EOL", &c.eol),
            ("PRE", &c.pre),
            ("POST", &c.post),
            ("PLATE", &c.plate),
            ("REPEATABLE", &c.repeatable),
        ];
        for (ordinal, (name, text)) in kinds.iter().enumerate() {
            if let Some(t) = text {
                rows.push((
                    format!("{addr} {ordinal}"),
                    format!("comment addr={addr} kind={name} text=[{}]", esc(t)),
                ));
            }
        }
    }
    out.push(format!("comments={}", rows.len()));
    emit(&mut out, rows);
    out
}

fn mem_read_line(
    mem: &ghidra_progdb::Memory<'_, BufferFile>,
    addr: &Address,
    len: usize,
) -> String {
    match mem.read(addr, len) {
        Ok(b) => format!(
            "memread addr={addr} len={len} n={} sha256={}",
            b.len(),
            common::sha256_hex(&b)
        ),
        Err(_) => format!("memread addr={addr} len={len} error"),
    }
}

fn shift(addr: &Address, delta: i64) -> Address {
    match addr {
        Address::Space { space, offset } => Address::Space {
            space: space.clone(),
            offset: offset.wrapping_add_signed(delta),
        },
        other => other.clone(),
    }
}

fn memory_lines(db: &ProgramDb<BufferFile>) -> Vec<String> {
    let mem = db.memory().unwrap();
    let mut out = Vec::new();
    for b in mem.blocks() {
        match mem.read(&b.start, b.length as usize) {
            Ok(bytes) => out.push(format!(
                "memblock name={} n={} sha256={}",
                b.name,
                bytes.len(),
                common::sha256_hex(&bytes)
            )),
            Err(_) => out.push(format!("memblock name={} error", b.name)),
        }
        let end = shift(&b.start, b.length - 1);
        out.push(mem_read_line(&mem, &b.start, 16));
        out.push(mem_read_line(&mem, &shift(&end, -7), 32));
        out.push(mem_read_line(&mem, &shift(&end, -3), 4096));
        out.push(mem_read_line(&mem, &shift(&b.start, b.length / 2), 4096));
        out.push(mem_read_line(&mem, &shift(&b.start, -1), 8));
    }
    out
}

#[test]
fn legacy_fixture_matches_java() {
    check("legacy-12.1.4");
}

#[test]
fn analysed_fixture_matches_java() {
    check("legacy-12.1.4-analysed");
}
