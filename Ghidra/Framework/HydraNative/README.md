# HydraNative

The Rust core of Hydra Engine: a Cargo workspace whose library, `hydra_native` (a `cdylib` with a C
ABI), Java calls through the foreign function API (`java.lang.foreign`, normal downcalls only; no JNI,
no `Linker.Option.critical`). See `hydra-rust-plan.md` in the workspace for where this is going.

The first part answers what the process may use and what it runs on:

* **Granted CPUs**: the logical CPUs the process may run on (Windows: process affinity, all its
  processor groups, default CPU sets; Linux: `sched_getaffinity`), lowered to a CPU quota rounded up
  (Windows: a job object hard CPU rate cap; Linux: cgroup v2 `cpu.max`, or v1 `cpu.cfs_quota_us`).
  Never `std::thread::available_parallelism`, which can overcount under affinity or job limits.
* **Memory limit**: the lower of a job object process/job memory limit (Linux: cgroup `memory.max`)
  and physical memory.
* **CPU identification**: CPUID vendor, family, model, stepping, the hybrid flag and the SIMD level
  (SSE4.2, AVX2, AVX-512, each only when the OS saves the register state).
* **Topology**: Windows `GetSystemCpuSetInformation` (cores, `EfficiencyClass`, last-level cache) and
  `GetLogicalProcessorInformationEx` (L2 groups); Linux sysfs (`cpu_core`/`cpu_atom`, caches).
* **Tuning profiles**: `generic` (the default) and `raptorlake-hybrid`, chosen from the CPU or forced
  with `HYDRA_CPU_PROFILE`. A profile sets performance knobs only. See [PROFILES.md](PROFILES.md).

Java reads it through `ghidra.util.HydraCpu` (module Utility), which falls back to
`Runtime.availableProcessors()` and the `generic` profile when the library is missing. Nothing sizes
its pools from it yet; that is a later, measured change.

## Layout

| path | what |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | the workspace and its pinned dependencies |
| `rust-toolchain.toml` | the pinned Rust toolchain |
| `.cargo/config.toml` | Cargo output goes to `build/cargo` |
| `crates/hydra-native` | the library: `cpuid`, `topology`, `limits`, `os` (Windows, Linux), `profile`, and the C ABI in `lib.rs` |
| `include/hydra_native.h` | the C ABI, for C and C++ callers and as the reference for `HydraCpu` |

The workspace is a module of its own under `Ghidra/Framework`, as Ghidra keeps each module's natives
with that module (`build/os/<platform>` in the tree, `os/<platform>` in an install): `Framework` puts
it below every feature that will call it, and its own `Module.manifest` records the licences of the
crates linked into the library. The Java side is in Utility because `SystemUtilities`, which sizes the
default pools, is there, and Utility (on the launcher's class path) cannot depend on another module.

## Build and test

Gradle builds it with every install: `buildNatives` (or `cargoBuild`) runs
`cargo build --release --locked` and copies the library to `build/os/<platform>`, which the install
ships as `Ghidra/Framework/HydraNative/os/<platform>`. Cargo comes from the `PATH` (or `CARGO`) and
installs the toolchain of `rust-toolchain.toml` on first use; the dependencies are fetched once into
the Cargo home.

```bash
cargo test                                  # unit tests, including profile selection from made-up CPUs
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run --example cpu                     # what is detected for this process
gradle :Utility:test --tests ghidra.util.HydraCpuTest   # Java through FFM, and the fallback
```

The C ABI version is `hydra_native_abi_version()`; `HydraCpu` uses the library only when it matches
its own (and `hydra_cpu_info_size()` matches the struct it reads), so a stale library falls back
instead of being misread. A change to a function or to `HydraCpuInfo` raises the version in
`lib.rs`, the header and `HydraCpu.java` together.
