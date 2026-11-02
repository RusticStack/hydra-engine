//! `hydra-trace`: offline tool for TRACE-1 sessions.
//!
//! ```text
//! hydra-trace gen <recipe> <seed> <events> <outdir>
//! hydra-trace verify <segment-file> <segment-id>      verify one segment's chain
//! hydra-trace verify <root> <session>                 segments + index against a rebuild
//! hydra-trace import <root> <session> <file>          JSONL events, or a minidump (*.dmp)
//! hydra-trace rebuild <root> <session>                rebuild index.db from the segments
//! hydra-trace export <root> <session> <outdir> [--overwrite]
//! ```

use hydra_trace::export::{self, ExportOptions};
use hydra_trace::session::{self, Session};
use hydra_trace::store::Options;
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
         hydra-trace export <root> <session> <outdir> [--overwrite]"
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

fn import(root: &str, id: &str, file: &str) -> ExitCode {
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return fail(format!("{file}: {e}")),
    };
    let events: Vec<Value> = if file.ends_with(".dmp") {
        match minidump::parse(&bytes) {
            Ok(d) => minidump::to_events(&d, "minidump"),
            Err(e) => return fail(e),
        }
    } else {
        let mut out = Vec::new();
        for (i, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(v) => out.push(v),
                Err(e) => return fail(format!("{file}:{}: {e}", i + 1)),
            }
        }
        out
    };
    let (mut s, recovery) = match Session::open(Path::new(root), id, Options::default()) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    let (mut accepted, mut rejected, mut dropped) = (0u64, 0usize, 0u64);
    for chunk in events.chunks(session::MAX_EVENTS_PER_APPEND) {
        match s.append(chunk) {
            Ok(r) => {
                accepted += r.accepted;
                rejected += r.rejected.len();
                dropped += r.dropped_budget;
                for rej in r.rejected.iter().take(5) {
                    eprintln!("rejected #{}: {}", rej.index, rej.reason);
                }
            }
            Err(e) => return fail(e),
        }
    }
    println!(
        "{}",
        serde_json::json!({"accepted": accepted, "rejected": rejected, "dropped_budget": dropped,
                           "recovered_batches": recovery.replayed_batches + recovery.tail_batches})
    );
    if rejected == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
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
        Some("import") if args.len() == 4 => import(&args[1], &args[2], &args[3]),
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
