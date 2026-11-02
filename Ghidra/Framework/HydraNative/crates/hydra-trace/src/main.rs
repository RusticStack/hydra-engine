//! `hydra-trace`: offline tool for TRACE-1 sessions.
//!
//! ```text
//! hydra-trace gen <recipe> <seed> <events> <outdir>
//! hydra-trace verify <segment-file> <segment-id>      verify one segment's chain
//! hydra-trace verify <root> <session>                 segments + index against a rebuild
//! hydra-trace import <root> <session> <file>          JSONL events, or a minidump (*.dmp)
//! hydra-trace rebuild <root> <session>                rebuild index.db from the segments
//! hydra-trace export <root> <session> <outdir> [--overwrite]
//! hydra-trace resymbolize <root> <session> <symbols.json> <symbol-revision>
//!                                                     symbolize every event as a new interpretation revision
//! hydra-trace dump <file.dmp> [--symbols <symbols.json>] [--source <id>] [--wait <fn>]... [--fault-handler <fn>]...
//!                                                     read a minidump: modules, symbolized stacks, the spec 15.9 patterns
//!                                                     with citations, and the events `import` would append
//! ```

use hydra_trace::export::{self, ExportOptions};
use hydra_trace::session::{self, Session};
use hydra_trace::store::{Options, Store};
use hydra_trace::symbolize;
use hydra_trace::{minidump, synth};
use serde_json::Value;
use std::path::Path;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: hydra-trace gen <recipe> <seed> <events> <outdir>\n       \
         hydra-trace verify <segment-file> <segment-id>\n       \
         hydra-trace verify <root> <session>\n       \
         hydra-trace import <root> <session> <file.jsonl|file.dmp>\n       \
         hydra-trace rebuild <root> <session>\n       \
         hydra-trace export <root> <session> <outdir> [--overwrite]\n       \
         hydra-trace resymbolize <root> <session> <symbols.json> <symbol-revision>\n       \
         hydra-trace dump <file.dmp> [--symbols <symbols.json>] [--source <id>] [--wait <fn>]... [--fault-handler <fn>]..."
    );
    ExitCode::from(2)
}

fn fail(what: impl std::fmt::Display) -> ExitCode {
    eprintln!("{what}");
    ExitCode::from(1)
}

fn gen_cmd(args: &[String]) -> ExitCode {
    let (Some(recipe), Ok(seed), Ok(events)) = (
        synth::Recipe::parse(&args[1]),
        args[2].parse(),
        args[3].parse(),
    ) else {
        return usage();
    };
    let dir = Path::new(&args[4]);
    if std::fs::create_dir_all(dir).is_err() {
        return fail(format!("cannot create {}", dir.display()));
    }
    for segment in synth::generate(recipe, seed, events) {
        let path = dir.join(format!("{}.trace", segment.id));
        if let Err(err) = std::fs::write(&path, &segment.bytes) {
            return fail(format!("{}: {err}", path.display()));
        }
        println!("{}", path.display());
    }
    ExitCode::SUCCESS
}

fn verify_segment(file: &str, id: &str) -> ExitCode {
    match hydra_trace::rawio::scan_file(Path::new(file), id) {
        Ok(scan) => {
            println!(
                "records={} valid_bytes={} size={} damage={:?}",
                scan.records.len(),
                scan.valid_end,
                scan.size,
                scan.damage
            );
            if scan.is_clean() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => fail(format!("{file}: {err}")),
    }
}

fn verify_session(root: &str, id: &str) -> ExitCode {
    match session::verify(Path::new(root), id, &Options::default()) {
        Ok(v) => {
            println!("{}", serde_json::to_string(&v).unwrap_or_default());
            if v.index_matches_segments && v.segments.iter().all(|s| s.clean) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => fail(err),
    }
}

#[cfg(windows)]
fn peak_working_set() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: a zeroed counters struct with cb set is the documented input; the pseudo handle of
    // the current process is always valid.
    unsafe {
        let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            c.PeakWorkingSetSize as u64
        } else {
            0
        }
    }
}

#[cfg(not(windows))]
fn peak_working_set() -> u64 {
    0
}

/// Tallies of one import.
#[derive(Default)]
struct Tally {
    accepted: u64,
    rejected: usize,
    dropped: u64,
}

fn append_chunk(s: &mut Session, chunk: &[Value], t: &mut Tally) -> Result<(), String> {
    let r = s.append(chunk).map_err(|e| e.to_string())?;
    t.accepted += r.accepted;
    t.rejected += r.rejected.len();
    t.dropped += r.dropped_budget;
    for rej in r.rejected.iter().take(5) {
        eprintln!("rejected #{}: {}", rej.index, rej.reason);
    }
    Ok(())
}

/// Import a JSONL file (or a minidump) into a session. A JSONL file is streamed line by line in
/// chunks, so memory stays flat however large it is. The outcome is reported, never guessed:
/// `clean`, `empty`, `torn_tail` (the last line has no newline and is not valid) or `corrupt` (a
/// bad line with more after it). The valid prefix is kept in every case; the exit code is 0 for
/// clean, 1 for rejected events, 3 for a torn tail or corruption, 4 for an empty file.
fn import(root: &str, id: &str, file: &str) -> ExitCode {
    let (mut s, recovery) = match Session::open(Path::new(root), id, Options::default()) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    let mut tally = Tally::default();
    let (mut lines, mut outcome, mut damage_line, mut reason) =
        (0u64, "clean", None::<u64>, String::new());
    if file.ends_with(".dmp") {
        let bytes = match std::fs::read(file) {
            Ok(b) => b,
            Err(e) => return fail(format!("{file}: {e}")),
        };
        let events = match minidump::parse(&bytes) {
            Ok(d) => minidump::to_events(&d, "minidump"),
            Err(e) => return fail(e),
        };
        lines = events.len() as u64;
        for chunk in events.chunks(session::MAX_EVENTS_PER_APPEND) {
            if let Err(e) = append_chunk(&mut s, chunk, &mut tally) {
                return fail(e);
            }
        }
    } else {
        use std::io::BufRead;
        let f = match std::fs::File::open(file) {
            Ok(f) => f,
            Err(e) => return fail(format!("{file}: {e}")),
        };
        let mut reader = std::io::BufReader::with_capacity(1 << 20, f);
        let mut chunk: Vec<Value> = Vec::with_capacity(session::MAX_EVENTS_PER_APPEND);
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(n) => n,
                Err(e) => return fail(format!("{file}: {e}")),
            };
            if n == 0 {
                break;
            }
            let ends_clean = buf.ends_with('\n');
            let text = buf.trim();
            if text.is_empty() {
                continue;
            }
            lines += 1;
            match serde_json::from_str::<Value>(text) {
                Ok(v) => chunk.push(v),
                Err(e) => {
                    outcome = if ends_clean { "corrupt" } else { "torn_tail" };
                    damage_line = Some(lines);
                    reason = e.to_string();
                    break;
                }
            }
            if chunk.len() == session::MAX_EVENTS_PER_APPEND {
                if let Err(e) = append_chunk(&mut s, &chunk, &mut tally) {
                    return fail(e);
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty()
            && let Err(e) = append_chunk(&mut s, &chunk, &mut tally)
        {
            return fail(e);
        }
        if lines == 0 {
            outcome = "empty";
        }
    }
    println!(
        "{}",
        serde_json::json!({"accepted": tally.accepted, "rejected": tally.rejected,
            "dropped_budget": tally.dropped, "lines": lines, "outcome": outcome,
            "damage_line": damage_line, "reason": reason,
            "peak_working_set": peak_working_set(),
            "recovered_batches": recovery.replayed_batches + recovery.tail_batches})
    );
    match outcome {
        "empty" => ExitCode::from(4),
        "torn_tail" | "corrupt" => ExitCode::from(3),
        _ if tally.rejected > 0 => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}

/// Symbolize a session's events against a table (`{"modules": {name: {"code": [[start, end]], "functions":
/// [{"start", "end", "name"}]}}}`, RVAs) as a new interpretation revision and print the counts.
fn resymbolize_cmd(root: &str, id: &str, symbols: &str, revision: &str) -> ExitCode {
    let table: symbolize::TableSymbolizer = match std::fs::read_to_string(symbols)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
    {
        Ok(t) => t,
        Err(e) => return fail(format!("{symbols}: {e}")),
    };
    let index = session::index_path(&Path::new(root).join(id));
    if !index.exists() {
        return fail(format!("no session {id} under {root}"));
    }
    let mut store = match Store::open(&index, id) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    match symbolize::resymbolize(&mut store, &table, revision) {
        Ok(rev) => match symbolize::counts(&store, Some(rev)) {
            Ok(counts) => {
                println!("{}", serde_json::json!({"interp": rev, "counts": counts}));
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Err(e) => fail(e),
    }
}

/// Read a minidump and print what the importer knows: no session is touched.
fn dump_cmd(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        return usage();
    };
    let mut symbols: Option<symbolize::TableSymbolizer> = None;
    let mut source = "minidump".to_string();
    let mut cfg = minidump::PatternConfig::windows();
    let mut i = 1;
    while i < args.len() {
        let Some(value) = args.get(i + 1) else {
            return usage();
        };
        match args[i].as_str() {
            "--symbols" => {
                symbols = match std::fs::read_to_string(value)
                    .map_err(|e| e.to_string())
                    .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
                {
                    Ok(t) => Some(t),
                    Err(e) => return fail(format!("{value}: {e}")),
                }
            }
            "--source" => source = value.clone(),
            "--wait" => cfg.wait_functions.push(value.clone()),
            "--fault-handler" => cfg.fault_handler_functions.push(value.clone()),
            _ => return usage(),
        }
        i += 2;
    }
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return fail(format!("{file}: {e}")),
    };
    let dump = match minidump::parse(&bytes) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let symbolizer: Option<&dyn symbolize::Symbolizer> =
        symbols.as_ref().map(|t| t as &dyn symbolize::Symbolizer);
    let frames: Vec<Value> = dump
        .threads
        .iter()
        .map(|th| {
            let list: Vec<Value> = th
                .frames
                .iter()
                .map(|&addr| {
                    let module = dump.modules.iter().find(|m| {
                        m.base <= addr && addr < m.base.saturating_add(u64::from(m.size))
                    });
                    let function = symbolizer.and_then(|s| minidump::resolve(&dump, s, addr));
                    serde_json::json!({"address": addr, "module": module.map(|m| m.name.clone()),
                        "rva": module.map(|m| addr - m.base), "function": function})
                })
                .collect();
            serde_json::json!({"thread_id": th.thread_id, "suspend_count": th.suspend_count,
                               "rip": th.rip, "rsp": th.rsp, "frames": list,
                               "basis": "return-address candidates found on the stack (inferred)"})
        })
        .collect();
    let patterns = minidump::patterns(&dump, symbolizer, &cfg);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "dump": dump, "stacks": frames, "patterns": patterns,
            "events": minidump::to_events(&dump, &source),
            "symbolized": symbolizer.is_some(),
        }))
        .unwrap_or_default()
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") if args.len() == 5 => gen_cmd(&args),
        Some("verify") if args.len() == 3 => {
            if Path::new(&args[1]).is_dir() {
                verify_session(&args[1], &args[2])
            } else {
                verify_segment(&args[1], &args[2])
            }
        }
        Some("resymbolize") if args.len() == 5 => {
            resymbolize_cmd(&args[1], &args[2], &args[3], &args[4])
        }
        Some("import") if args.len() == 4 => import(&args[1], &args[2], &args[3]),
        Some("dump") if args.len() >= 2 => dump_cmd(&args[1..]),
        Some("rebuild") if args.len() == 3 => {
            match session::rebuild(Path::new(&args[1]), &args[2], &Options::default()) {
                Ok(digest) => {
                    println!("{digest}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
        Some("export") if args.len() >= 4 => {
            let store = match session::reader(Path::new(&args[1]), &args[2]) {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            let arts = hydra_trace::artifact::Artifacts::open(hydra_trace::artifact::dir_of(
                &Path::new(&args[1]).join(&args[2]),
            ))
            .ok();
            let opts = ExportOptions {
                overwrite: args.iter().any(|a| a == "--overwrite"),
                ..ExportOptions::default()
            };
            match export::export(&store, arts.as_ref(), Path::new(&args[3]), &opts) {
                Ok(r) => {
                    println!("{}", serde_json::to_string(&r).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
        _ => usage(),
    }
}
