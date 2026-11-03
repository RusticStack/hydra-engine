//! Differential check against `oracle/OracleProgram.java`, which opens the same fixtures through
//! the stock `ProgramDB` (read-only) and prints the language, address spaces, memory blocks and
//! symbols. The Rust reader must reproduce every line.

use std::path::{Path, PathBuf};

mod common;

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::{Address, AddressSpaces, ProgramDb, RefKind, SpaceDef};

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
    got.extend(symbol_query_lines(&db));
    got.extend(datatype_lines(&db));
    got.extend(extras_lines(&db));
    let got_refs: Vec<&str> = got.iter().map(String::as_str).collect();
    for (i, (g, w)) in got_refs.iter().zip(&want).enumerate() {
        assert_eq!(g, w, "line {i}");
    }
    assert_eq!(got_refs.len(), want.len());
}

fn esc_opt(s: Option<&str>) -> String {
    s.map_or("null".to_owned(), esc)
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

    // bodies, stack frame return offset and stored variables
    let bodies = db.function_bodies().unwrap();
    let variables = db.variables().unwrap();
    let mut var_rows = Vec::new();
    for f in &fns {
        let body: String = bodies[&f.id]
            .iter()
            .map(|r| format!("{r};"))
            .collect::<Vec<_>>()
            .concat();
        out.push(format!("fnbody id={} ranges=[{body}]", f.id));
        if f.is_thunk() {
            continue;
        }
        out.push(format!(
            "fnframe id={} retoff={}",
            f.id, f.stack_return_offset
        ));
        for v in variables.iter().filter(|v| v.function_id == f.id) {
            let kind = if v.is_parameter { "param" } else { "local" };
            let name = if v.source == ghidra_progdb::SourceType::Default {
                ""
            } else {
                &v.name
            };
            let ord = v.ordinal.map_or("-".to_owned(), |o| o.to_string());
            let first = v.first_use_offset.map_or("-".to_owned(), |o| o.to_string());
            let storage = if v.is_parameter && !f.has_custom_storage() {
                "-"
            } else {
                v.storage.as_deref().unwrap_or("")
            };
            var_rows.push((
                format!("{:020} {kind} {:020}", f.id, v.symbol_id),
                format!(
                    "fnvar fn={} sym={} kind={kind} name=[{name}] src={} ord={ord} first={first} dt={} storage=[{storage}]",
                    f.id,
                    v.symbol_id,
                    v.source.name(),
                    v.datatype_id.unwrap_or(-1)
                ),
            ));
        }
    }
    out.push(format!("fnvars={}", var_rows.len()));
    emit(&mut out, var_rows);

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

    let dts = db.data_types().unwrap();
    let rows: Vec<(String, String)> = db
        .data()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d.address.to_string(),
                format!(
                    "data addr={} type={} dt=[{}]",
                    d.address,
                    d.datatype_id,
                    dts.get(d.datatype_id).map_or("?", |t| t.path.as_str())
                ),
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

fn ids_of(list: &[&ghidra_progdb::Symbol]) -> String {
    list.iter()
        .map(|s| s.id.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn symbol_query_lines(db: &ProgramDb<BufferFile>) -> Vec<String> {
    use ghidra_progdb::SourceType;
    use std::collections::BTreeSet;
    let st = db.symbol_table().unwrap();
    let spaces = db.address_map().spaces();
    let mut out = Vec::new();
    let is_default_fn_or_param = |s: &ghidra_progdb::Symbol| {
        s.source == SourceType::Default && (s.symbol_type == 5 || s.symbol_type == 6)
    };

    let rows: Vec<(String, String)> = st
        .all()
        .iter()
        .filter(|s| is_default_fn_or_param(s))
        .map(|s| {
            (
                format!("{:020}", s.id),
                format!("symname id={} name=[{}]", s.id, esc(&st.name(s).unwrap())),
            )
        })
        .collect();
    out.push(format!("symnames={}", rows.len()));
    emit(&mut out, rows);

    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for s in st.all() {
        if let Address::Space { space, .. } = &s.address
            && (*space == spaces.stack_space
                || *space == spaces.register_space
                || space == "VARIABLE")
        {
            continue;
        }
        let key = s.address.to_string();
        if !seen.insert(key.clone()) {
            continue;
        }
        let primary = st.primary_at(&s.address).map_or(-1, |p| p.id);
        rows.push((
            key.clone(),
            format!(
                "symat addr={key} ids=[{}] primary={primary}",
                ids_of(&st.at(&s.address))
            ),
        ));
    }
    out.push(format!("symat={}", rows.len()));
    emit(&mut out, rows);

    let mut names = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for s in st.all() {
        if s.source != SourceType::Default {
            names.insert(s.name.clone());
            pairs.insert((s.name.clone(), s.parent_id));
        }
    }
    for s in st.all() {
        if is_default_fn_or_param(s) {
            let n = st.name(s).unwrap();
            names.insert(n.clone());
            pairs.insert((n, st.parent_namespace_id(s)));
        }
    }
    let rows: Vec<(String, String)> = names
        .iter()
        .map(|n| {
            (
                n.clone(),
                format!(
                    "symbyname name=[{}] ids=[{}]",
                    esc(n),
                    ids_of(&st.by_name(n))
                ),
            )
        })
        .collect();
    out.push(format!("symbynames={}", rows.len()));
    emit(&mut out, rows);

    let is_namespace = |id: i64| {
        id == 0
            || st
                .get(id)
                .is_some_and(|s| matches!(s.symbol_type, 1 | 3 | 4 | 5))
    };
    let rows: Vec<(String, String)> = pairs
        .iter()
        .filter(|(_, ns)| is_namespace(*ns))
        .map(|(n, ns)| {
            (
                format!("{ns:020}{n}"),
                format!(
                    "symbyns name=[{}] ns={ns} ids=[{}]",
                    esc(n),
                    ids_of(&st.by_name_in_namespace(n, *ns))
                ),
            )
        })
        .collect();
    out.push(format!("symbyns={}", rows.len()));
    emit(&mut out, rows);

    let mut ns_ids = BTreeSet::new();
    ns_ids.insert(0i64);
    for s in st.all() {
        ns_ids.insert(s.parent_id);
    }
    let rows: Vec<(String, String)> = ns_ids
        .iter()
        .filter(|id| is_namespace(**id))
        .map(|id| {
            (
                format!("{id:020}"),
                format!("symchildren ns={id} ids=[{}]", ids_of(&st.children(*id))),
            )
        })
        .collect();
    out.push(format!("symchildren={}", rows.len()));
    emit(&mut out, rows);
    out
}

fn datatype_lines(db: &ProgramDb<BufferFile>) -> Vec<String> {
    use ghidra_progdb::DataTypeKind;
    let dts = db.data_types().unwrap();
    let mut out = Vec::new();
    let mut rows = Vec::new();
    for (id, path) in dts.categories() {
        rows.push((
            format!("{id:020}"),
            format!("category id={id} path=[{}]", esc(&path)),
        ));
    }
    out.push(format!("categories={}", rows.len()));
    emit(&mut out, rows);

    let mut rows = Vec::new();
    let mut sub = Vec::new();
    for t in dts.all().filter(|t| t.kind != DataTypeKind::Default) {
        let key = format!("{:020}", t.id);
        let id = t.id;
        let base = match t.kind {
            DataTypeKind::TypeDef | DataTypeKind::Pointer => {
                format!(" base={}", t.base.unwrap_or(-1))
            }
            DataTypeKind::Array => format!(
                " base={} n={}",
                t.base.unwrap_or(-1),
                t.elements.unwrap_or(0)
            ),
            _ => String::new(),
        };
        let class = match (&t.kind, &t.class_name) {
            (DataTypeKind::BuiltIn, Some(c)) => format!(" class={c}"),
            _ => String::new(),
        };
        let len = t.size.map_or("?".to_owned(), |n| n.to_string());
        rows.push((
            key.clone(),
            format!(
                "dt id={id} kind={} name=[{}] path=[{}] len={len}{base}{class}",
                t.kind.name(),
                esc(&t.name),
                esc(&t.path)
            ),
        ));
        match t.kind {
            DataTypeKind::Structure | DataTypeKind::Union => {
                sub.push((
                    format!("{key}000000"),
                    format!("dtcomment id={id} text=[{}]", esc_opt(t.comment.as_deref())),
                ));
                for c in dts.components(id) {
                    sub.push((
                        format!("{key}{:06}", c.ordinal + 1),
                        format!(
                            "comp parent={id} ord={} off={} type={} name=[{}] comment=[{}] len={}",
                            c.ordinal,
                            c.offset,
                            c.datatype_id,
                            esc_opt(c.name.as_deref()),
                            esc_opt(c.comment.as_deref()),
                            c.length
                        ),
                    ));
                }
            }
            DataTypeKind::Enum => {
                sub.push((
                    format!("{key}000000"),
                    format!("dtcomment id={id} text=[{}]", esc_opt(t.comment.as_deref())),
                ));
                for (i, v) in dts.enum_values(id).iter().enumerate() {
                    sub.push((
                        format!("{key}{:06}", i + 1),
                        format!(
                            "enumv parent={id} idx={} name=[{}] value={} comment=[{}]",
                            i + 1,
                            esc(&v.name),
                            v.value,
                            esc_opt(v.comment.as_deref())
                        ),
                    ));
                }
            }
            DataTypeKind::FunctionDefinition => {
                sub.push((
                    format!("{key}000000"),
                    format!("dtcomment id={id} text=[{}]", esc_opt(t.comment.as_deref())),
                ));
                let f = dts.function_def(id).unwrap();
                sub.push((
                    format!("{key}000001"),
                    format!(
                        "funcdef id={id} ret={} varargs={} noreturn={} cc=[{}] params={}",
                        f.return_type,
                        f.var_args,
                        f.no_return,
                        esc(&f.calling_convention),
                        f.parameters.len()
                    ),
                ));
                for p in &f.parameters {
                    sub.push((
                        format!("{key}{:06}", p.ordinal + 2),
                        format!(
                            "fparam parent={id} ord={} type={} name=[{}] comment=[{}]",
                            p.ordinal,
                            p.datatype_id,
                            esc_opt(p.name.as_deref()),
                            esc_opt(p.comment.as_deref())
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    out.push(format!("datatypes={}", rows.len()));
    emit(&mut out, rows);
    out.push(format!("datatype_details={}", sub.len()));
    emit(&mut out, sub);
    out.push("dt_default name=[undefined] len=1".to_owned());
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn extras_lines(db: &ProgramDb<BufferFile>) -> Vec<String> {
    use ghidra_progdb::{PropertyKind, PropertyValue};
    let mut out = Vec::new();

    let mut rows = Vec::new();
    for e in db.equates().unwrap() {
        rows.push((
            e.name.clone(),
            format!(
                "equate name=[{}] value={} refs={}",
                esc(&e.name),
                e.value,
                e.references.len()
            ),
        ));
        for r in &e.references {
            let tail = format!(
                "{} {} {:08} {:020}",
                e.name, r.address, r.op_index, r.dynamic_hash
            );
            rows.push((
                format!("{}\u{1}{tail}", e.name),
                format!(
                    "equateref name=[{}] addr={} op={} hash={}",
                    esc(&e.name),
                    r.address,
                    r.op_index,
                    r.dynamic_hash
                ),
            ));
        }
    }
    out.push(format!("equates={}", rows.len()));
    emit(&mut out, rows);

    let rows: Vec<_> = db
        .bookmark_types()
        .unwrap()
        .into_iter()
        .map(|n| (n.clone(), format!("booktype name=[{}]", esc(&n))))
        .collect();
    out.push(format!("bookmark_types={}", rows.len()));
    emit(&mut out, rows);
    let rows: Vec<_> = db
        .bookmarks()
        .unwrap()
        .into_iter()
        .map(|b| {
            (
                format!("{:020}", b.id),
                format!(
                    "bookmark id={} addr={} type=[{}] cat=[{}] comment=[{}]",
                    b.id,
                    b.address,
                    esc(&b.type_name),
                    esc(&b.category),
                    esc(&b.comment)
                ),
            )
        })
        .collect();
    out.push(format!("bookmarks={}", rows.len()));
    emit(&mut out, rows);

    let relocs = db.relocations().unwrap();
    let memory = db.memory().unwrap();
    out.push(format!("relocations={}", relocs.len()));
    let spaces = db.address_map().spaces();
    let pointer = spaces.find(&spaces.default_space).unwrap().bits as i32 / 8;
    for r in &relocs {
        let values = r.values.as_ref().map_or(String::new(), |v| {
            v.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
        });
        let bytes = r
            .bytes(&memory, pointer)
            .unwrap()
            .map_or("null".to_owned(), |b| hex(&b));
        out.push(format!(
            "reloc addr={} status={} type={} values=[{values}]{} bytes={bytes} symbol=[{}]",
            r.address,
            r.status.name(),
            r.kind,
            if r.values.is_none() {
                " valuesnull"
            } else {
                ""
            },
            esc_opt(r.symbol_name.as_deref())
        ));
    }

    let mut rows = Vec::new();
    let mut last = String::new();
    let mut i = 0;
    for v in db.register_values().unwrap() {
        if v.register != last {
            last = v.register.clone();
            i = 0;
        }
        rows.push((
            format!("{} {:08}", v.register, i),
            format!(
                "regvalue reg={} min={}:{:x} max={}:{:x} bytes={}",
                v.register,
                v.range.space,
                v.range.min,
                v.range.space,
                v.range.max,
                hex(&v.bytes)
            ),
        ));
        i += 1;
    }
    out.push(format!("register_values={}", rows.len()));
    emit(&mut out, rows);

    let mut rows = Vec::new();
    for m in db.property_maps().unwrap() {
        assert!(m.kind != PropertyKind::Object);
        rows.push((
            m.name.clone(),
            format!(
                "propmap name=[{}] kind={} size={}",
                esc(&m.name),
                m.kind.name(),
                m.entries.len()
            ),
        ));
        for (a, v) in &m.entries {
            let text = match v {
                PropertyValue::Int(n) => n.to_string(),
                PropertyValue::Long(n) => n.to_string(),
                PropertyValue::String(s) => esc(s),
                _ => String::new(),
            };
            rows.push((
                format!("{}\u{1}{a}", m.name),
                format!("propval map=[{}] addr={a} value=[{text}]", esc(&m.name)),
            ));
        }
    }
    out.push(format!("property_maps={}", rows.len()));
    emit(&mut out, rows);

    let rows: Vec<_> = db
        .options()
        .unwrap()
        .into_iter()
        .map(|o| {
            (
                o.key.clone(),
                format!(
                    "option key=[{}] type={} value=[{}]",
                    esc(&o.key),
                    o.type_id,
                    esc(&o.value)
                ),
            )
        })
        .collect();
    out.push(format!("options={}", rows.len()));
    emit(&mut out, rows);

    let mut rows = Vec::new();
    for lib in db.external_libraries().unwrap() {
        rows.push((
            lib.name.clone(),
            format!(
                "extlib name=[{}] path=[{}]",
                esc(&lib.name),
                esc_opt(lib.path.as_deref())
            ),
        ));
        for x in db.external_locations(&lib.name).unwrap() {
            rows.push((
                format!("{}\u{1}{:020}", lib.name, x.symbol_id),
                format!(
                    "extloc id={} lib=[{}] label=[{}] orig=[{}] addr={} extaddr={} src={} func={} ns=[{}]",
                    x.symbol_id,
                    esc(&x.library),
                    esc(&x.label),
                    esc_opt(x.original_imported_name.as_deref()),
                    x.program_address
                        .as_ref()
                        .map_or("null".to_owned(), |a| a.to_string()),
                    x.external_address,
                    x.source.name(),
                    x.is_function,
                    esc(&x.namespace_path)
                ),
            ));
        }
    }
    out.push(format!("externals={}", rows.len()));
    emit(&mut out, rows);

    let table = db.symbol_table().unwrap();
    let mut rows = Vec::new();
    for n in db.namespaces().unwrap() {
        rows.push((
            format!("{:020}", n.id),
            format!(
                "namespace id={} kind={} path=[{}] parent={} class={}",
                n.id,
                n.kind.name(),
                esc(&n.path),
                n.parent_id,
                n.kind == ghidra_progdb::NamespaceKind::Class
            ),
        ));
    }
    for s in db.symbols().unwrap() {
        if matches!(s.symbol_type, 0 | 5) && s.parent_id != 0 {
            rows.push((
                format!("{:020}", s.id),
                format!("sympath id={} path=[{}]", s.id, esc(&table.path(&s))),
            ));
        }
    }
    out.push(format!("namespaces={}", rows.len()));
    emit(&mut out, rows);
    out
}

#[test]
fn legacy_fixture_matches_java() {
    check("legacy-12.1.4");
}

#[test]
fn synthetic_v33_fixture_matches_java() {
    check("synth-33");
}

#[test]
fn analysed_fixture_matches_java() {
    check("legacy-12.1.4-analysed");
}
