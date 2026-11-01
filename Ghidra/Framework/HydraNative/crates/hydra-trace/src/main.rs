//! `hydra-trace`: offline tool for TRACE-1 segments (gen, verify). Import, rebuild and export are
//! added with the store.

use hydra_trace::{raw, synth};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: hydra-trace gen <recipe> <seed> <events> <outdir>\n       hydra-trace verify <segment-file> <segment-id>");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") if args.len() == 5 => {
            let (Some(recipe), Ok(seed), Ok(events)) = (synth::Recipe::parse(&args[1]), args[2].parse(), args[3].parse())
            else {
                return usage();
            };
            let dir = std::path::Path::new(&args[4]);
            if std::fs::create_dir_all(dir).is_err() {
                eprintln!("cannot create {}", dir.display());
                return ExitCode::from(1);
            }
            for segment in synth::generate(recipe, seed, events) {
                let path = dir.join(format!("{}.trace", segment.id));
                if let Err(err) = std::fs::write(&path, &segment.bytes) {
                    eprintln!("{}: {err}", path.display());
                    return ExitCode::from(1);
                }
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Some("verify") if args.len() == 3 => match std::fs::read(&args[1]) {
            Ok(data) => {
                let scan = raw::scan(&data, &args[2]);
                println!(
                    "records={} valid_bytes={} size={} damage={:?}",
                    scan.records.len(),
                    scan.valid_end,
                    scan.size,
                    scan.damage
                );
                if scan.is_clean() { ExitCode::SUCCESS } else { ExitCode::from(1) }
            }
            Err(err) => {
                eprintln!("{}: {err}", args[1]);
                ExitCode::from(1)
            }
        },
        _ => usage(),
    }
}
