//! Prototype decompiler host (Hydra Rust plan rank 12, finding D10).
//!
//! Links the C++ decompiler core as a static library and runs N decompile jobs concurrently on
//! rayon worker threads. A job is a console script over a DecompileDebug / `xml_savefile` dump
//! (`restore dump.xml`, `lo fu name`, `decompile`, `print C`), so no Java callbacks are involved.
//! Each job builds its own `IfaceStatus` and `Architecture`; the Sleigh translator cache and the
//! parser globals are `thread_local` in the C++ sources, so each worker owns one Sleigh per language.
//!
//! This is not wired into the engine: nothing uses it unless the `hydra-decomp-host` binary is run.

use std::ffi::{CString, c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rayon::prelude::*;

mod parser_check;
pub use parser_check::missing_thread_local;

pub mod snapshot;

mod ffi {
    use std::ffi::{c_char, c_int};
    unsafe extern "C" {
        pub fn hydra_decomp_init(
            root: *const c_char,
            err: *mut *mut c_char,
            errlen: *mut usize,
        ) -> c_int;
        pub fn hydra_decomp_run_script(
            script: *const c_char,
            out: *mut *mut c_char,
            outlen: *mut usize,
            err: *mut *mut c_char,
            errlen: *mut usize,
        ) -> c_int;
        pub fn hydra_decomp_free(p: *mut c_char);
    }
}

/// Takes ownership of a buffer returned by the shim.
fn take(p: *mut c_char, len: usize) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: the shim returned `p` from malloc with `len` initialised bytes; we copy and free it once.
    unsafe {
        let v = std::slice::from_raw_parts(p as *const u8, len).to_vec();
        ffi::hydra_decomp_free(p);
        v
    }
}

static INIT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Starts the decompiler library for `ghidra_root` (an engine install, or a directory holding
/// `Ghidra/Processors/*/data/languages`). Runs once per process; later calls must pass the same root.
pub fn init(ghidra_root: &Path) -> Result<(), String> {
    let r = INIT.get_or_init(|| {
        let c =
            CString::new(ghidra_root.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        let mut err = std::ptr::null_mut();
        let mut errlen = 0usize;
        // SAFETY: valid C string and out-pointers; called once, before any worker runs.
        let rc = unsafe { ffi::hydra_decomp_init(c.as_ptr(), &mut err, &mut errlen) };
        let msg = take(err, errlen);
        if rc == 0 {
            Ok(ghidra_root.to_path_buf())
        } else {
            Err(format!(
                "hydra_decomp_init rc={rc}: {}",
                String::from_utf8_lossy(&msg)
            ))
        }
    });
    match r {
        Ok(p) if p == ghidra_root => Ok(()),
        Ok(p) => Err(format!(
            "decompiler library already started for {}",
            p.display()
        )),
        Err(e) => Err(e.clone()),
    }
}

/// Result of one script.
#[derive(Debug, Clone)]
pub struct JobResult {
    pub script: PathBuf,
    /// Console exit code: 0 ok, 1 a command failed, 2 interface error, 3 uncaught exception.
    pub code: i32,
    /// Exactly what `decomp -i script` writes to stdout.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

/// Exit code of a job refused before it reached the decompiler (library not started, bad path).
pub const CODE_NOT_RUN: i32 = -1;

fn initialised() -> bool {
    matches!(INIT.get(), Some(Ok(_)))
}

fn refused(script: &Path, why: &str) -> JobResult {
    JobResult {
        script: script.to_path_buf(),
        code: CODE_NOT_RUN,
        stdout: Vec::new(),
        stderr: why.as_bytes().to_vec(),
        elapsed: Duration::ZERO,
    }
}

/// Runs one console script on the calling thread. Refused (code [`CODE_NOT_RUN`]) unless `init`
/// has succeeded: without it the capabilities are not registered and workers would race on the
/// lazily filled language list.
pub fn run_script(script: &Path) -> JobResult {
    if !initialised() {
        return refused(script, "decompiler library not started: call init() first");
    }
    let t = Instant::now();
    let Ok(c) = CString::new(script.to_string_lossy().as_bytes()) else {
        return refused(script, "script path contains a NUL byte");
    };
    let (mut out, mut outlen, mut err, mut errlen) =
        (std::ptr::null_mut(), 0usize, std::ptr::null_mut(), 0usize);
    // SAFETY: valid C string and out-pointers; the shim keeps all decompiler state per call or thread_local.
    let code: c_int = unsafe {
        ffi::hydra_decomp_run_script(c.as_ptr(), &mut out, &mut outlen, &mut err, &mut errlen)
    };
    JobResult {
        script: script.to_path_buf(),
        code,
        stdout: take(out, outlen),
        stderr: take(err, errlen),
        elapsed: t.elapsed(),
    }
}

/// Logical CPUs the OS grants this process. On Windows `available_parallelism` reports the CPUs
/// of the processor group and ignores the process affinity mask, so the result is also capped by
/// the number of CPUs in the affinity mask (which job-object affinity limits narrow too).
pub fn granted_cpus() -> usize {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    match affinity_cpus() {
        Some(a) if a > 0 => n.min(a),
        _ => n,
    }
}

#[cfg(windows)]
fn affinity_cpus() -> Option<usize> {
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessAffinityMask(
            process: isize,
            proc_mask: *mut usize,
            sys_mask: *mut usize,
        ) -> i32;
    }
    let (mut p, mut s) = (0usize, 0usize);
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing; both out-pointers are valid.
    let ok = unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut p, &mut s) };
    // A process spanning several processor groups reports a zero mask; fall back to the group count.
    (ok != 0 && p != 0).then(|| p.count_ones() as usize)
}

#[cfg(not(windows))]
fn affinity_cpus() -> Option<usize> {
    // available_parallelism already honours sched_getaffinity and cgroup quotas on Linux.
    None
}

/// Runs `scripts` on a dedicated rayon pool of `threads` workers (0 = granted CPUs). Results come
/// back in input order whatever the thread count, so output is deterministic.
pub fn run_batch(scripts: &[PathBuf], threads: usize) -> Result<Vec<JobResult>, String> {
    let n = if threads == 0 {
        granted_cpus()
    } else {
        threads
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .thread_name(|i| format!("decomp-host-{i}"))
        // Deep recursion in the C++ passes; give workers more than the default 2 MB.
        .stack_size(16 << 20)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(pool.install(|| {
        scripts
            .par_iter()
            .with_max_len(1)
            .map(|s| run_script(s))
            .collect()
    }))
}

/// Converts one `decompilertest` file (src/decompile/datatests) into a DecompileDebug-style dump
/// (`<xml_savefile>` with the same children as the test minus `<script>`/`<stringmatch>`) and a
/// console script (`restore <dump>` followed by the test's `<com>` commands). Returns
/// (dump path, script path, number of `lo fu` commands).
pub fn convert_datatest(test: &Path, out_dir: &Path) -> Result<(PathBuf, PathBuf, usize), String> {
    let text = std::fs::read_to_string(test).map_err(|e| format!("{}: {e}", test.display()))?;
    let stem = test.file_stem().unwrap().to_string_lossy().to_string();
    let open =
        text.find("<decompilertest>").ok_or("no <decompilertest>")? + "<decompilertest>".len();
    let s0 = text.find("<script>").ok_or("no <script>")?;
    let s1 = text.find("</script>").ok_or("no </script>")?;
    let body = &text[open..s0];
    let tail = &text[s1 + "</script>".len()..];
    // Only <stringmatch> elements and the closing tag may follow the script.
    let mut rest = tail.trim_start();
    while rest.starts_with("<stringmatch") {
        let e = rest
            .find("</stringmatch>")
            .ok_or("unterminated stringmatch")?;
        rest = &rest[e + "</stringmatch>".len()..];
        // Stray character data between elements (forloop1.xml has "match>") is ignored, as the
        // test harness's XML reader does.
        rest = &rest[rest.find('<').unwrap_or(rest.len())..];
    }
    if rest.trim() != "</decompilertest>" {
        return Err(format!(
            "{}: unexpected content after </script>",
            test.display()
        ));
    }
    let dump = out_dir.join(format!("{stem}.xml"));
    let script = out_dir.join(format!("{stem}.script"));
    let path = dump.to_string_lossy().replace('\\', "/");
    let body = body.trim();
    // The datatests hold a lone <binaryimage> (with loader <symbol>s): the test harness builds an
    // XmlArchitecture from it and reads the loader symbols, which is exactly the console's
    // `load file <binaryimage.xml>`. Anything more (a full DecompileDebug dump) becomes an
    // <xml_savefile> read by `restore`.
    let first = if body.starts_with("<binaryimage")
        && body.ends_with("</binaryimage>")
        && body.matches("<binaryimage").count() == 1
    {
        std::fs::write(&dump, format!("{body}\n")).map_err(|e| e.to_string())?;
        format!("load file {path}")
    } else {
        let name = xml_escape(&stem);
        std::fs::write(
            &dump,
            format!("<xml_savefile name=\"{name}\" target=\"default\" adjustvma=\"0\">\n{body}\n</xml_savefile>\n"),
        )
        .map_err(|e| e.to_string())?;
        format!("restore {path}")
    };
    let mut lines = vec![first];
    let mut funcs = 0;
    let mut cur = &text[s0..s1];
    while let Some(a) = cur.find("<com>") {
        let b = cur[a..].find("</com>").ok_or("unterminated com")? + a;
        let cmd = xml_unescape(&cur[a + 5..b]);
        let t = cmd.trim_start();
        if t.starts_with("lo fu") || t.starts_with("load function") {
            funcs += 1;
        }
        lines.push(cmd);
        cur = &cur[b + 6..];
    }
    if !lines.last().is_some_and(|l| l.trim() == "quit") {
        lines.push("quit".into());
    }
    std::fs::write(&script, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
    Ok((dump, script, funcs))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Lists `*.script` files in `dir`, sorted by name.
pub fn scripts_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| {
            r.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "script"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Converts every `*.xml` in `datatests` into `out_dir`; returns (scripts, total `lo fu` count).
pub fn convert_all(datatests: &Path, out_dir: &Path) -> Result<(Vec<PathBuf>, usize), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mut tests: Vec<PathBuf> = std::fs::read_dir(datatests)
        .map_err(|e| format!("{}: {e}", datatests.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    tests.sort();
    let mut scripts = Vec::new();
    let mut funcs = 0;
    for t in &tests {
        let (_, s, f) = convert_datatest(t, out_dir)?;
        scripts.push(s);
        funcs += f;
    }
    Ok((scripts, funcs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_script_refuses_before_init() {
        // No unit test calls init(), so the library is not started in this process.
        let r = run_script(Path::new("does-not-matter.script"));
        assert_eq!(r.code, CODE_NOT_RUN);
        assert!(String::from_utf8_lossy(&r.stderr).contains("init()"));
        let b = run_batch(&[PathBuf::from("a.script"), PathBuf::from("b.script")], 2).unwrap();
        assert!(b.iter().all(|r| r.code == CODE_NOT_RUN));
    }

    /// The bison-generated parsers are maintained in source control and regenerated by hand
    /// (Makefile / build.gradle `yaccDecompiler`). Regeneration drops the thread_local edits and
    /// brings back the multi-worker crash; build.rs refuses to build then, and this test says why.
    #[test]
    fn generated_parsers_keep_thread_local_state() {
        let cpp = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/decompile/cpp");
        for (f, pfx) in [
            ("grammar.cc", "grammar"),
            ("xml.cc", "xml"),
            ("pcodeparse.cc", "pcode"),
        ] {
            let s = std::fs::read_to_string(cpp.join(f)).unwrap();
            assert!(
                missing_thread_local(&s, pfx).is_empty(),
                "{f}: {:?}",
                missing_thread_local(&s, pfx)
            );
        }
        // And the check does catch a regenerated (unmodified) parser.
        assert_eq!(
            missing_thread_local(
                "int yychar;
YYSTYPE yylval;
int yynerrs;
extern XMLSTYPE xmllval;
",
                "xml"
            ),
            vec!["yychar", "yylval", "yynerrs", "extern xmllval"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn converts_a_decompilertest() {
        let dir = std::env::temp_dir().join(format!("hydra-decomp-host-ut-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = dir.join("sample.xml");
        std::fs::write(
            &t,
            concat!(
                "<decompilertest>\n<binaryimage arch=\"x86:LE:64:default:gcc\">\n",
                "<bytechunk space=\"ram\" offset=\"0x10\">90c3</bytechunk>\n</binaryimage>\n<script>\n",
                "  <com>parse line extern int4 f(char *a&amp;b);</com>\n  <com>lo fu f</com>\n",
                "  <com>decompile</com>\n  <com>print C</com>\n  <com>quit</com>\n</script>\n",
                "<stringmatch name=\"x\" min=\"1\" max=\"1\">a &lt; b</stringmatch>match>\n</decompilertest>\n"
            ),
        )
        .unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let (dump, script, funcs) = convert_datatest(&t, &out).unwrap();
        assert_eq!(funcs, 1);
        let d = std::fs::read_to_string(dump).unwrap();
        assert!(d.starts_with("<binaryimage arch=\"x86:LE:64:default:gcc\">"));
        assert!(!d.contains("<script>") && !d.contains("stringmatch"));
        let s = std::fs::read_to_string(script).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[0].starts_with("load file ") && lines[0].ends_with("/sample.xml"));
        assert_eq!(
            &lines[1..],
            &[
                "parse line extern int4 f(char *a&b);",
                "lo fu f",
                "decompile",
                "print C",
                "quit"
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
