//! Open-cost benchmark: opens a Program database through the `query` facade and prints the time
//! of each step. Peak memory is read from outside (PowerShell `PeakWorkingSet64`), so the
//! program can sleep for `--hold-ms` before it exits.
//!
//! ```text
//! open_bench <db.1.gbf> <oracleprog-*.txt> [--lazy] [--bytes] [--queries] [--hold-ms N]
//! ```
//!
//! The oracle text supplies the address spaces (`space name= id= bits=` lines).

use std::time::{Duration, Instant};

use ghidra_progdb::query::Program;
use ghidra_progdb::{AddressSpaces, SpaceDef};

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!(" {key}=");
    let start = line.find(&pat).map(|i| i + pat.len()).unwrap();
    line[start..].split(' ').next().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[2]).unwrap();
    let queries = args.iter().any(|a| a == "--queries");
    let lazy = args.iter().any(|a| a == "--lazy");
    let bytes_only = args.iter().any(|a| a == "--bytes");
    let hold: u64 = args
        .iter()
        .position(|a| a == "--hold-ms")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
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
    let spaces = AddressSpaces::new(defs, &default);
    let t = Instant::now();
    let program = if lazy {
        Program::open_file_lazy(&args[1], spaces).unwrap()
    } else {
        Program::open_file(&args[1], spaces).unwrap()
    };
    let open = t.elapsed();
    println!("open_ms={:.2}", open.as_secs_f64() * 1000.0);
    if bytes_only {
        // memory content needs no index
        let start = program.db().memory_blocks().unwrap()[0].start.clone();
        let t = Instant::now();
        let n = program.read_bytes(&start, 64).map(|b| b.len()).unwrap_or(0);
        println!(
            "read_bytes={n} read_ms={:.2}",
            t.elapsed().as_secs_f64() * 1000.0
        );
    }
    if queries {
        let t = Instant::now();
        let n = program.functions().len();
        println!(
            "functions={n} functions_ms={:.2}",
            t.elapsed().as_secs_f64() * 1000.0
        );
        let entry = program.functions().first().map(|f| f.entry.clone());
        if let Some(entry) = entry {
            let t = Instant::now();
            let from = program.xrefs_from(&entry).len();
            let to = program.xrefs_to(&entry).len();
            println!(
                "xrefs_from={from} xrefs_to={to} xrefs_ms={:.2}",
                t.elapsed().as_secs_f64() * 1000.0
            );
            let t = Instant::now();
            let bytes = program.read_bytes(&entry, 16).map(|b| b.len()).unwrap_or(0);
            println!(
                "read_bytes={bytes} read_ms={:.2}",
                t.elapsed().as_secs_f64() * 1000.0
            );
            let t = Instant::now();
            let sym = program.symbols_at(&entry).len();
            println!(
                "symbols_at={sym} symbols_ms={:.2}",
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
    if hold > 0 {
        std::thread::sleep(Duration::from_millis(hold));
    }
}
