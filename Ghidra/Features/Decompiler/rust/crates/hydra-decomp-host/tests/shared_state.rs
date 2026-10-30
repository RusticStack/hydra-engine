//! Non-ignored checks that need no compiled .sla files (each integration test file is its own
//! process, so `init` and the affinity change here do not leak into other tests).

use std::path::{Path, PathBuf};

use hydra_decomp_host as host;

/// A Ghidra root holding only the x86 .ldefs: enough for `init` (it parses language descriptions,
/// it does not load .sla files).
fn fake_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("hydra-decomp-host-ss-{}", std::process::id()));
    let langs = root.join("Ghidra/Processors/x86/data/languages");
    std::fs::create_dir_all(&langs).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../../Processors/x86/data/languages/x86.ldefs");
    std::fs::copy(src, langs.join("x86.ldefs")).unwrap();
    root
}

/// `addpath` mutates the process-global spec search path that every worker reads; the host must
/// refuse it rather than race on it.
#[test]
fn addpath_is_refused_on_every_worker() {
    let root = fake_root();
    host::init(&root).unwrap();
    let script = root.join("addpath.script");
    std::fs::write(&script, format!("addpath {}\nquit\n", root.display())).unwrap();
    let many: Vec<PathBuf> = std::iter::repeat_n(script.clone(), 32).collect();
    let rs = host::run_batch(&many, 8).unwrap();
    for r in &rs {
        let out = String::from_utf8_lossy(&r.stdout);
        // The console reports an unregistered command as "ERROR: Invalid command" and carries on
        // (exit code 0, as stock does for any unknown command); a registered addpath prints nothing.
        assert!(
            out.contains("addpath") && out.contains("ERROR: Invalid command"),
            "addpath accepted? stdout={out:?} stderr={:?}",
            String::from_utf8_lossy(&r.stderr)
        );
    }
    // A control command still runs, so the refusal is specific to addpath.
    let ok = root.join("ok.script");
    std::fs::write(&ok, "echo hello\nquit\n").unwrap();
    let r = host::run_script(&ok);
    assert_eq!(r.code, 0, "{:?}", String::from_utf8_lossy(&r.stdout));
    std::fs::remove_dir_all(&root).ok();
}

/// The pool is sized from the CPUs the OS grants the process, affinity mask included.
#[cfg(windows)]
#[test]
fn granted_cpus_honours_process_affinity() {
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessAffinityMask(p: isize, pm: *mut usize, sm: *mut usize) -> i32;
        fn SetProcessAffinityMask(p: isize, m: usize) -> i32;
    }
    let (mut pm, mut sm) = (0usize, 0usize);
    // SAFETY: pseudo-handle and valid out-pointers.
    assert_ne!(
        unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut pm, &mut sm) },
        0
    );
    if pm.count_ones() < 2 {
        eprintln!("only {} CPU granted; nothing to narrow", pm.count_ones());
        return;
    }
    // Keep the two lowest granted CPUs.
    let low = pm.isolate_lowest_one();
    let rest = pm & !low;
    let two = low | rest.isolate_lowest_one();
    // SAFETY: as above; `two` is a subset of the granted mask.
    assert_ne!(
        unsafe { SetProcessAffinityMask(GetCurrentProcess(), two) },
        0
    );
    let n = host::granted_cpus();
    // SAFETY: restore the original mask.
    unsafe { SetProcessAffinityMask(GetCurrentProcess(), pm) };
    assert_eq!(n, 2);
}
