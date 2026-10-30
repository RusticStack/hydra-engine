//! Builds the C++ decompiler core as a static library with the MSVC flags of
//! `Ghidra/Features/Decompiler/buildNatives.gradle` (/EHsc /O2 /Oy, _SECURE_SCL=0,
//! _HAS_ITERATOR_DEBUGGING=0, WINDOWS/WIN32/WIN64 defines; zlib with NO_GZIP).
//! /GL + /LTCG is optional: set HYDRA_DECOMP_LTCG=1.
//! HYDRA_DECOMP_CPP_DIR points the build at another copy of `src/decompile` (for example the
//! unmodified main sources, to show that the concurrency test fails without the thread_local fixes).

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let decompile = match std::env::var("HYDRA_DECOMP_CPP_DIR") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => manifest.join("../../../src/decompile"),
    };
    let cpp = decompile.join("cpp");
    let zlib = decompile.join("zlib");
    println!("cargo:rerun-if-env-changed=HYDRA_DECOMP_CPP_DIR");
    println!("cargo:rerun-if-env-changed=HYDRA_DECOMP_LTCG");
    println!("cargo:rerun-if-changed=cpp-sources.txt");
    println!("cargo:rerun-if-changed=cpp/host_shim.cc");

    let list = std::fs::read_to_string(manifest.join("cpp-sources.txt")).unwrap();
    let names: Vec<&str> = list
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.split_whitespace())
        .collect();
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    let ltcg = std::env::var("HYDRA_DECOMP_LTCG").as_deref() == Ok("1");

    let mut b = cc::Build::new();
    b.cpp(true)
        .include(&cpp)
        .warnings(false)
        .define("LOCAL_ZLIB", None);
    if msvc {
        for f in ["/EHsc", "/O2", "/Oy"] {
            b.flag(f);
        }
        if ltcg {
            b.flag("/GL");
        }
        for d in ["_SECURE_SCL=0", "_HAS_ITERATOR_DEBUGGING=0"] {
            let (k, v) = d.split_once('=').unwrap();
            b.define(k, Some(v));
        }
        for d in ["WINDOWS", "_WINDOWS", "WIN32", "_WIN32", "WIN64", "_WIN64"] {
            b.define(d, None);
        }
    } else {
        b.flag("-std=c++11").flag("-O2").flag("-Wno-sign-compare");
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            b.define("LINUX", None).define("_LINUX", None);
        }
    }
    for n in &names {
        let p = cpp.join(format!("{n}.cc"));
        println!("cargo:rerun-if-changed={}", p.display());
        b.file(p);
    }
    // The shim includes consolemain.cc (main renamed) so the console commands (restore, load file,
    // save, addpath) are the stock ones.
    b.file(manifest.join("cpp/host_shim.cc"));
    // Capabilities (XmlArchitectureCapability, PrintCCapability, IfaceDecompCapability...) register
    // through static constructors in objects nothing references; link the whole archive or the
    // linker drops them.
    b.link_lib_modifier("+whole-archive");
    b.compile("hydradecomp");

    let mut z = cc::Build::new();
    z.include(&zlib).warnings(false).define("NO_GZIP", None);
    if msvc {
        for f in ["/O2", "/Oy"] {
            z.flag(f);
        }
        for d in [
            "_CRT_SECURE_NO_DEPRECATE",
            "_CRT_NONSTDC_NO_DEPRECATE",
            "ZLIB_WINAPI",
        ] {
            z.define(d, None);
        }
    }
    for e in std::fs::read_dir(&zlib).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "c") {
            z.file(p);
        }
    }
    z.compile("hydrazlib");
}
