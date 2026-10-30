# hydra-decomp-host: design note (plan rank 12, D10)

Status: prototype behind a flag (a separate binary; nothing in the engine calls it). This note
covers what the prototype does, the shared C++ state it isolates, and how to wire it in as the
daemon decompile backend over the sealed snapshot.

## What the prototype does

- `build.rs` compiles the C++ decompiler core (CORE + DECCORE + SLEIGH + console EXTRA, list in
  `cpp-sources.txt`; bfd_arch, loadimage_bfd, analyzesigs and codedata need libbfd and are left out) into a static library with the MSVC flags of
  `buildNatives.gradle` (`/EHsc /O2 /Oy`, `_SECURE_SCL=0`, `_HAS_ITERATOR_DEBUGGING=0`, WIN64
  defines; zlib with `NO_GZIP`). `/GL` + LTCG is opt-in (`HYDRA_DECOMP_LTCG=1`).
- `cpp/host_shim.cc` includes `consolemain.cc` (with `main` renamed) and exposes a C ABI:
  `hydra_decomp_init(root)` runs `startDecompilerLibrary` and collects the `.ldefs` list once,
  single-threaded; `hydra_decomp_run_script(script)` is `decomp -i script </dev/null` in-process:
  a fresh `IfaceTerm` over an in-memory stream, the stock command set, `mainloop`.
- Rust (`src/lib.rs`): `run_batch(scripts, threads)` runs jobs on a dedicated rayon pool
  (`threads = 0` means the CPUs the OS grants: `available_parallelism`, capped on Windows by the
  number of CPUs in the process affinity mask, which `available_parallelism` ignores there),
  results in input order. `run_script`/`run_batch` refuse jobs (code -1) until `init` succeeded.
- `addpath` is not registered in the host: it appends to the process-global
  `SleighArchitecture::specpaths` that every worker reads. Search paths are fixed by `init`.
- No C++ exception crosses the C ABI: the shim functions are `noexcept` and catch everything,
  including allocation failures while copying the output out.
- Inputs are DecompileDebug dumps (`<xml_savefile>`, read by `XmlArchitecture` through `restore`),
  so no Java callbacks are needed. The test converts the repo's 89 decompiler datatests into
  a `<binaryimage>` dump (the datatests hold only that) loaded with `load file` (XmlArchitecture
  init + loader symbols, the same steps as the datatest harness) plus a console script; a dump with
  more than a binaryimage becomes an `<xml_savefile>` read with `restore`.

## Measured (2026-10-30; available_parallelism = 24, before the affinity cap was added, so the
"24 workers" runs were sized from the group's CPUs, not the granted mask; machine shared with other agents and builds)

- 89 dumps, 190 `lo fu` commands, 159 `Decompilation complete` (the rest are the datatests' own
  `parse line`/language errors, identical in stock).
- Host 1 worker vs N = 4, 8, 24 workers: all 89 outputs byte-identical. Host 1 worker vs the stock
  console exe built from unmodified main sources (same flags and source list), run per script
  in its own process: all 89 identical (after undoing the stock exe's CRT `\n` -> `\r\n` translation).
- Without the thread_local fixes (host built from unmodified main sources, `HYDRA_DECOMP_CPP_DIR`):
  1 worker runs fine, 16 workers segfault in 3 of 3 runs.
- Wall time, 890 jobs (89 dumps x 10): 1 worker 21.6 s, 2 workers 13.4 s, 4 workers 6.9 s,
  8 workers 2.9 s, 16 workers 2.1 s (10.5x). One pass of 89 dumps: stock, one process per script
  sequentially 142.8 s; host 1 worker 1.44 s, 24 workers 1.13 s (start-up and .sla load dominate one pass).

## Shared state found and isolated (single-thread behaviour unchanged)

Every change is `static` -> `static thread_local` (or a global -> `thread_local`). On one thread the
sequence of values is the same as before, so `decompile.exe` (one thread) behaves identically.

| State | File | Why it matters |
|---|---|---|
| `TokenSplit::countbase` | prettyprint.hh/.cc | begin/end id counter, `++` from every print |
| `global_scan`, `handler`, `xmlchar/xmllval/xmlnerrs` | xml.y / xml.cc | XML parser (every `restore`, every spec) |
| `parse`, `grammarchar/lval/nerrs` | grammar.y / grammar.cc | C type parser (`parse line`) |
| `pcode`, `pcodechar/lval/nerrs` | pcodeparse.y / pcodeparse.cc | p-code snippet parser (inject payloads) |
| `SleighArchitecture::translators` | sleigh_arch.hh/.cc | Sleigh cache keyed by language: a shared Sleigh across Architectures. Now one Sleigh per thread (D10, sleigh.hh:168-172) |
| `savefile` | consolemain.cc | `restore` file name |
| `jumpstack`, `dcp_callback`, `status_callback` | ifacedecomp.cc | console jump-table/override callbacks |

Read-only after start-up (left as is, initialised before workers run): capability lists
(`CapabilityPoint`, `ArchitectureCapability`, `IfaceCapability`, `PrintLanguageCapability`),
`AttributeId`/`ElementId` tables, `SleighArchitecture::description` (filled by
`hydra_decomp_init`; `collectSpecFiles` returns early once filled) and `specpaths` (only written
by `addpath`, which the host does not register; test `addpath_is_refused_on_every_worker`),
`Symbol::ID_BASE`, the `PrintC` operator tokens, `FileManage::separator`.

Thread affinity: `buildTranslator` returns a pointer into the calling thread's `translators` map,
so an Architecture is thread-affine: it must be used and destroyed only on the worker that built
it. A worker keeps one Sleigh per language it has seen for the thread's lifetime, so Sleigh memory
is N workers x languages used, independent of any Architecture cache. Between jobs the Sleigh's
`loader` points at the previous (destroyed) LoadImage until the next `reset`; nothing reads it then.

`TokenSplit::countbase` (one counter per thread now) numbers the markup `open`/`close` ids that
`EmitMarkup` writes. In stock `decompile.exe` it already accumulates over every function a process
has printed, so ids depend on history there too; with N workers they depend on which jobs ran
earlier on the same thread. The console `print C` text (what the prototype compares) does not
contain them. The daemon gate (step 5) therefore compares markup with the syntax `open`/`close`
ids renumbered in order of appearance; everything else must be byte-identical.

Not in the host build: `ghidra_process.cc` `archlist` / `GhidraCapability::commandmap` (the
Java-pipe process). They are per-process and only touched by the single command thread there; the
daemon backend below does not use the pipe protocol, so they stay as they are.

Bison note: `yychar`/`yylval`/`yynerrs` (and the `extern yylval` declaration) are emitted by the
bison skeleton. The checked-in `.cc` files carry `thread_local`; the `.y` files say so.
Regenerating them (Makefile rules or the Gradle `yaccDecompiler` task; the native build itself uses
the checked-in files) drops the edit. `build.rs` then refuses to build the host (checked by
`src/parser_check.rs`, unit test `generated_parsers_keep_thread_local_state`) until the edit is
re-applied; `HYDRA_DECOMP_ALLOW_SHARED_PARSERS=1` bypasses it only for the negative control on
unmodified sources (together with `HYDRA_DECOMP_CPP_DIR`). A move to `%define api.pure full` would
remove the hand edit but is a larger change.

Build note: the user-level cargo config routes cc-rs through the kache wrapper
(`CC_KNOWN_WRAPPER_CUSTOM=kache`), which fails on `cl.exe`. `build.rs` drops `RUSTC_WRAPPER` and
`CC_KNOWN_WRAPPER_CUSTOM` from its own environment before compiling the C++, so `cargo test` works
without overrides (rustc itself still goes through kache). `HYDRA_DECOMP_CC_WRAPPER=1` keeps them.

## Wiring it as the daemon decompile backend over the sealed snapshot

1. Provider: replace `XmlArchitecture` (dump-backed) with a `SnapshotArchitecture` whose LoadImage,
   Scope/symbols, comments, context and string data read the sealed generation file (the
   `rust/p2-snapshot` package: memmap reader + C++ `LoadImage` from snapshot). One
   `SnapshotArchitecture` per worker per program generation; Sleigh stays thread_local per
   language, so a worker that moves between programs of the same language only resets it.
2. Host: the daemon owns one `hydra-decomp-host` pool per JVM (FFM downcall into a Rust cdylib, or
   a child process speaking the decomp protocol from `rust/p2-decomp-protocol`). Pool size comes
   from the OS-granted CPUs and the daemon's decompile budget (DecompilerGate permits, S10), not a
   fixed count; the rayon pool replaces N `decompile.exe` processes and their pipes (D1-D4, D9).
3. Request: (program id, generation, function entry, options). The worker looks up or builds the
   Architecture for (program, generation), runs `decompile` + the markup printer, and returns the
   same XML/packed result `ghidra_process` returns today, so `DecompileResults` decoding is unchanged.
   Each Architecture is pinned to the worker that built it (thread affinity above).
4. Remaining callbacks: inject payloads and cpool answer from the snapshot when exported; anything
   else falls back to the existing process path (behind the same flag).
5. Flag and rollout: `hydra.decomp.backend=host` (default `process`). Gate: the golden diff (9.1)
   must be identical with the flag on, and the offline replay (500 DecompileDebug dumps, N workers vs
   `decompile.exe`) must be byte-identical after renumbering the markup `open`/`close` ids in order
   of appearance (see `countbase` above), as this prototype's test does for the datatests' C text.
   A markup-output (EmitMarkup) identity test is part of that backend work; it is not in the prototype.
6. Memory: one Architecture per worker per open generation; cap with an LRU per worker and size
   the pool so N x (Architecture + languages x Sleigh) fits the decompile budget (today 200 MB per
   permit). When the LRU drops a worker's last Architecture for a language, clear that language's
   entry in the worker's thread_local `translators` map (an eviction hook to add with the backend).
7. Failure isolation: a C++ crash in-process takes the daemon down, unlike a `decompile.exe`
   crash. Keep the process backend as the fallback; run the host in a child process (one process,
   N threads) until the crash rate on the full KotOR set is measured at zero.
