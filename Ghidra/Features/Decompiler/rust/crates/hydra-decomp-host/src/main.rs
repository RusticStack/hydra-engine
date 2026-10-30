//! hydra-decomp-host: run decompiler console scripts over DecompileDebug dumps on N threads.
//!
//!   hydra-decomp-host convert <datatests-dir> <out-dir>
//!   hydra-decomp-host run --root <ghidra-install> [--threads N] [--repeat K] [--out <dir>] <scripts-dir>
//!   hydra-decomp-host stock --exe <decomp.exe> --root <ghidra-install> [--out <dir>] <scripts-dir>
//!
//! `run` writes <out>/<stem>.txt (stdout of each script, as the console prints it) and prints one
//! JSON line: {"mode","threads","jobs","failures","wall_ms","sum_job_ms"}. `--threads 0` (default)
//! uses the CPUs the OS grants this process. `stock` runs the stock console executable once per
//! script, sequentially (`decomp -i script`, stdin empty, SLEIGHHOME=root), for comparison.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use hydra_decomp_host as host;

fn usage() -> ! {
    eprintln!(
        "usage:\n  hydra-decomp-host convert <datatests-dir> <out-dir>\n  hydra-decomp-host run --root <dir> [--threads N] [--repeat K] [--out <dir>] <scripts-dir>\n  hydra-decomp-host stock --exe <decomp.exe> --root <dir> [--out <dir>] <scripts-dir>"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let mut root = None;
    let mut exe = None;
    let mut out = None;
    let mut threads = 0usize;
    let mut repeat = 1usize;
    let mut pos = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        let mut val = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| usage())
        };
        match a.as_str() {
            "--root" => root = Some(PathBuf::from(val())),
            "--exe" => exe = Some(PathBuf::from(val())),
            "--out" => out = Some(PathBuf::from(val())),
            "--threads" => threads = val().parse().unwrap_or_else(|_| usage()),
            "--repeat" => repeat = val().parse().unwrap_or_else(|_| usage()),
            _ => pos.push(PathBuf::from(a)),
        }
        i += 1;
    }
    match cmd.as_str() {
        "convert" => {
            if pos.len() != 2 {
                usage()
            }
            match host::convert_all(&pos[0], &pos[1]) {
                Ok((s, f)) => println!("{{\"scripts\":{},\"functions\":{}}}", s.len(), f),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        "run" => {
            let (Some(root), Some(dir)) = (root, pos.first()) else {
                usage()
            };
            if let Err(e) = host::init(&root) {
                eprintln!("{e}");
                std::process::exit(1)
            }
            let one = host::scripts_in(dir);
            let mut scripts = Vec::with_capacity(one.len() * repeat);
            for _ in 0..repeat {
                scripts.extend(one.iter().cloned());
            }
            let n = if threads == 0 {
                host::granted_cpus()
            } else {
                threads
            };
            let t = Instant::now();
            let res = host::run_batch(&scripts, n).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1)
            });
            let wall = t.elapsed();
            let failures = res.iter().filter(|r| r.code == 3).count();
            let sum: f64 = res.iter().map(|r| r.elapsed.as_secs_f64() * 1e3).sum();
            if let Some(o) = &out {
                std::fs::create_dir_all(o).unwrap();
                for r in res.iter().take(one.len()) {
                    let stem = r.script.file_stem().unwrap().to_string_lossy().to_string();
                    std::fs::write(o.join(format!("{stem}.txt")), &r.stdout).unwrap();
                }
            }
            println!(
                "{{\"mode\":\"host\",\"threads\":{n},\"jobs\":{},\"failures\":{failures},\"wall_ms\":{:.1},\"sum_job_ms\":{sum:.1}}}",
                res.len(),
                wall.as_secs_f64() * 1e3
            );
        }
        "stock" => {
            let (Some(root), Some(exe), Some(dir)) = (root, exe, pos.first()) else {
                usage()
            };
            let scripts = host::scripts_in(dir);
            if let Some(o) = &out {
                std::fs::create_dir_all(o).unwrap();
            }
            let t = Instant::now();
            let mut failures = 0;
            for s in &scripts {
                let r = Command::new(&exe)
                    .arg("-i")
                    .arg(s)
                    .env("SLEIGHHOME", &root)
                    .stdin(Stdio::null())
                    .output()
                    .expect("spawn stock decompiler");
                if r.status.code().is_none_or(|c| c > 2) {
                    failures += 1;
                }
                if let Some(o) = &out {
                    let stem = s.file_stem().unwrap().to_string_lossy().to_string();
                    std::fs::write(o.join(format!("{stem}.txt")), &r.stdout).unwrap();
                }
            }
            println!(
                "{{\"mode\":\"stock\",\"threads\":1,\"jobs\":{},\"failures\":{failures},\"wall_ms\":{:.1}}}",
                scripts.len(),
                t.elapsed().as_secs_f64() * 1e3
            );
        }
        _ => usage(),
    }
}
