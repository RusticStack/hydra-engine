//! Identity test for the concurrent host.
//!
//! Converts every decompiler datatest (src/decompile/datatests, ~89 files with several functions
//! each) into a DecompileDebug-style dump plus console script, runs them all with 1 worker and with
//! N workers (N = max(4, granted CPUs)), and requires byte-identical console output per script. With
//! HYDRA_DECOMP_STOCK_EXE set (see scripts/build_stock_console.ps1) it also runs the stock console
//! executable once per script and requires the host output to equal it.
//!
//! Needs compiled .sla files: HYDRA_DECOMP_TEST_ROOT = an engine install (Ghidra/Processors/...).
//! Without the thread_local fixes in the C++ sources this test crashes or mismatches at N > 1
//! (shared bison parser globals and a shared Sleigh translator cache).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use hydra_decomp_host as host;

fn datatests() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../src/decompile/datatests")
}

#[test]
#[ignore = "needs HYDRA_DECOMP_TEST_ROOT (an engine install with compiled .sla files)"]
fn n_workers_match_one_worker_and_stock() {
    let root =
        PathBuf::from(std::env::var("HYDRA_DECOMP_TEST_ROOT").expect("set HYDRA_DECOMP_TEST_ROOT"));
    let work = std::env::var("HYDRA_DECOMP_TEST_WORK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("hydra-decomp-host-it-{}", std::process::id()))
        });
    let (scripts, funcs) = host::convert_all(&datatests(), &work).unwrap();
    assert!(scripts.len() >= 50, "only {} datatests", scripts.len());
    assert!(funcs >= 50, "only {funcs} functions");
    host::init(&root).unwrap();

    let one = host::run_batch(&scripts, 1).unwrap();
    let n = host::granted_cpus().max(4);
    // Twice the work so every worker sees several dumps and reuses its thread_local Sleigh.
    let mut twice = scripts.clone();
    twice.extend(scripts.iter().cloned());
    let many = host::run_batch(&twice, n).unwrap();

    let mut mismatches = Vec::new();
    let mut decompiled = 0usize;
    for (i, a) in one.iter().enumerate() {
        assert_ne!(
            a.code,
            3,
            "{}: uncaught exception: {}",
            a.script.display(),
            String::from_utf8_lossy(&a.stderr)
        );
        decompiled += String::from_utf8_lossy(&a.stdout)
            .matches("Decompilation complete")
            .count();
        for b in [&many[i], &many[i + scripts.len()]] {
            if a.stdout != b.stdout || a.code != b.code {
                mismatches.push(a.script.display().to_string());
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "1 vs {n} workers differ for: {mismatches:?}"
    );
    assert!(decompiled >= 50, "only {decompiled} functions decompiled");
    eprintln!(
        "scripts={} lo_fu={funcs} decompiled={decompiled} threads={n}: identical",
        scripts.len()
    );

    if let Ok(exe) = std::env::var("HYDRA_DECOMP_STOCK_EXE") {
        let mut diff = Vec::new();
        for a in &one {
            let r = Command::new(&exe)
                .arg("-i")
                .arg(&a.script)
                .env("SLEIGHHOME", &root)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            // The stock exe writes stdout in CRT text mode (\n -> \r\n on Windows); undo only that.
            let stock = String::from_utf8_lossy(&r.stdout).replace("\r\n", "\n");
            if stock.as_bytes() != a.stdout.as_slice() || r.status.code() != Some(a.code) {
                diff.push(a.script.display().to_string());
            }
        }
        assert!(diff.is_empty(), "host differs from stock for: {diff:?}");
        eprintln!("stock comparison: {} scripts identical", one.len());
    }
}
