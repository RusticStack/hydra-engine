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

## Step 5 status (rust/p5-decomp-backend, 2026-10-30)

In place: the daemon seam. `HeadlessSession` `QueryCommands.decompile` offers every request to
`HostDecompileBackend.tryDecompile` first (`-Dhydra.decomp.backend=host`, default `process`);
`null` takes the existing `DecompInterface` path. `unsupportedReason` names the first missing
piece; the first fallback is logged once (`decompile backend host: falling back ...`), and
`hostedCount`/`fallbackCount` count both paths.

Not in place: the provider. The snapshot (format v1) holds bytes only, nothing exports the
symbol scope, data types, prototypes, comments, context, cpool or inject payloads per generation,
the host has no `SnapshotArchitecture` and no C ABI the JVM calls (no FFM binding or child
process). So every request falls back today and the flag changes no reply.

Gate run (fixture projects copied from `_golden/projects/fixtures`, all 8 programs, every
non-external function, 3959 decompiles, reply JSON hashed per function): flag on vs off identical
with 1 client and with 4 concurrent clients; 4 clients vs 1 client identical. Wall, sum over the 8
programs (on and off ran at the same time on a shared machine): 1 client off 40.3 s / on 40.0 s;
4 clients off 12.7 s / on 12.5 s. The numbers measure the process path both times.

## Step 6 status (rust/p6-snapshot-arch, 2026-10-30): the callback-free backend

In place. With `-Dhydra.decomp.backend=host` a session decompile runs in this library's worker
pool, in-process, with no call into Java while the decompiler runs.

- **C++ `SnapshotArchitecture`** (`cpp/snapshot_arch.hh/.cc`, the xml_arch/sleigh_arch pattern):
  the stock `ArchitectureGhidra` (ScopeGhidra, TypeFactoryGhidra, GhidraTranslate, ContextGhidra,
  CommentDatabaseGhidra, PcodeInjectLibraryGhidra, ConstantPoolGhidra, GhidraStringManager,
  LoadImageGhidra) over in-memory streams (`SnapshotChannel`). A query the decompiler writes is cut
  from its output and answered from a `SnapshotStore` (key: the packed query payload, value: the
  exact response bytes `DecompileProcess` writes). Registration is registerProgram (`init`), the
  byte snapshot (`setSnapshot`, format v1, as in p2) and `setOptions`; each decompile is
  `DecompileAt::rawAction` inside `GhidraCommand::doit`'s error handling, then `flushNative`, as
  `DecompInterface.decompileFunction` does. Same components, same answers, so the same result.
- **Snapshot v2 = the answer table**, exported by `DecompileSnapshot.java` (a copy of every
  `DecompileProcess` query handler into a byte buffer, exception responses included), once per
  program generation (modification number + encoded options; `HostDecompiler` keeps one store
  per generation, retired when the program changes or closes). Classification: GLOBAL; SCOPED to
  the decompiled function (its own symbol and external reference, code labels in a function
  namespace); UNSTORABLE (p-code by pseudo-disassembly, injection at an address with no
  instruction, any answer that handed out a temporary data-type id: the function falls back).
- **Export**: per generation the registration answers (user-op names) and every register; per
  function, before its first decompile, its symbol, tracked registers, comments (filter learned
  from the first miss), the p-code of every instruction of its body, call-fixup injections of its
  call sites, and symbol / code label / external reference of every reference target. A query the
  store does not hold is a *miss*: optional answers (symbol: the one-byte hole the client gives;
  external reference, comments, data type, string, register name: none; label: empty; name in
  use: no) are fed a neutral answer and the run goes on, any other miss ends the run with an
  exception. The host returns the misses and the answers it fed: if each fed answer is the real
  one byte for byte, the run is used as is; otherwise the answers are exported and the decompile
  runs again (at most 12 runs, `hydra.decomp.host.rounds`). A p-code miss inside another function
  exports that function's p-code at once.
- **Rust host** (`src/snapshot.rs`, cdylib `hydra_decomp_host.dll` shipped in
  `Decompiler/os/<platform>` by the Gradle task `buildDecompHost_<platform>`): C ABI v2, a rayon
  pool (16 MB stacks; size = granted CPUs or `hydra.decomp.host.threads`), per-worker
  Architectures (LRU, `HYDRA_SNAPSHOT_ARCHS`, default 4), an SEH guard per job (a hardware
  exception drops that worker's Architectures and the request falls back).
- **Java**: `HostDecompiler` binds the library with FFM downcalls only, makes them from platform
  threads (no virtual-thread pinning) with the request timeout, decodes the response with
  `DecompileResults` as the process path does, and returns a result only when the decompile
  completed. `HostDecompileBackend.tryDecompile` offers ProgramEntry decompiles; everything else,
  and every host failure, takes the process path. `status.decompileBackend` reports hostedCount,
  fallbackCount, the fallback reasons and the host's counters.

Falls back (process path, reply unchanged): backend off; no library; not a ProgramEntry
decompiler / non-default set-up; external, undefined or overlay function; a body with
stack-depth overrides (CallDepthChangeInfo: callee answers would depend on the caller); an
unstorable answer; misses left after 12 runs; a run that failed, crashed, did not complete or
passed the timeout; any Java-side error.

Measured (gate `_logs/rust-integration/gate/gate_p6.py`, copies of the 8 fixture projects, 3959
functions, and the first 200 KotOR functions; replies hashed per function; each run under
heavy.py with 16 cores on a shared machine):

| set | clients | process wall | host wall | replies differ | hosted / fallback |
|---|---|---|---|---|---|
| fixtures, engine defaults | 1 | 20.17 s | 21.83 s | 0 | 3944 / 15 |
| fixtures | 4 | 6.68 s | 7.38 s | 0 | 3945 / 14 |
| fixtures | 8 | 5.72 s | 6.30 s | 0 | 3948 / 11 |
| KotOR 200 | 1 | 1.96 s | 2.12 s | 0 | 197 / 3 |
| KotOR 200 | 4 | 0.88 s | 1.61 s | 0 | 199 / 1 |
| KotOR 200 | 8 | 0.74 s | 1.22 s | 0 | 199 / 1 |
| fixtures, cache off, pass 2 (warm) | 1 | 19.34 s | 13.50 s | 0 | |
| fixtures, cache off, pass 2 | 8 | 4.70 s | 3.09 s | 0 | |
| KotOR 200, cache off, pass 2 | 4 | 0.71 s | 0.38 s | 0 | |
| KotOR 200, cache off, pass 2 | 8 | 0.49 s | 0.27 s | 0 | |

Identical replies everywhere. A function's first decompile in a generation is slower on the host
(the export plus about 1.45 native runs per function, more contention at 4-8 clients); once the
generation's answers are exported the host is 30-45 % faster than the process path. The backend
stays off by default for that reason. Next: export the remaining per-function answers in bulk
when a generation is made (data types, strings), and look at the cold-path contention at 4-8 clients.

## rust/t-host status (2026-10-30): async submission, store affinity, measured as the default

- **Async submission (C ABI 3).** `hydra_dhost_submit(store, addr, ticket)` queues a run and
  returns at once (bounded: 8 runs per worker, `hydra_dhost_queue_capacity`; over the bound it
  returns `BUSY`); finished runs go to one completion queue that a single JVM platform thread
  drains with the blocking downcall `hydra_dhost_completions` (plain downcalls only, no upcall).
  `HostDecompiler` runs the export and the round loop on the caller's thread and waits on a
  `CompletableFuture` (a virtual thread unmounts), so no platform thread is held per request; the
  generation stays open until the run's completion is taken, also after a timeout.
  `-Dhydra.decomp.host.async=false` keeps the step 6 path (one platform thread per request,
  blocking downcall); `status.decompileBackend.host.submission` says which is in use.
- **Store affinity (`src/workers.rs`, replaces the rayon pool for snapshot jobs).** A job for a
  store goes to an idle worker that already holds its Architecture, else to the idle worker that
  holds the fewest stores, else behind the least loaded warm worker. A store decompiled one
  request at a time keeps one Architecture instead of one per worker (unit test
  `sequential_jobs_of_one_store_stay_on_one_worker`); concurrent requests still spread to idle
  workers. The pool mirrors the C++ per-worker LRU (`HYDRA_SNAPSHOT_ARCHS`) and forgets a store
  when it is closed.
- **Identity.** KotOR, all 8,616 non-external functions through the daemon `decompile` command
  (decompile cache off, 4 clients), with the host as the default: 8,616 identical to the hydra.4
  reference (`gate/dc/h4-plain.json`, aggregate `c954f77a1b13d6f2`), 0 errors, 8,600 hosted,
  16 fallbacks (11 pseudo-disassembly p-code, 4 misses after 12 runs, 1 over the 120 s timeout).
  Same result before and after the affinity pool. Multi-agent benchmark: every reply equal to h4.
- **Why it stays opt-in.** On the shared multi-agent benchmark (`_logs/rust-targets/bench`,
  16 agents, interleaved with hydra.4, integration-next and this build with the host off) the host
  as default cut `decompile.exe` CPU (8.5 s to 3.4 s) but added more JVM CPU (export of about
  120 answers per function and 1.14 native runs per function), so total CPU was flat to +2 %;
  `decompile_fresh` p50 rose from about 8 ms to about 63 ms and `decompile_hot` from about 10 ms to
  about 96 ms (the hot set's first decompile and every waiter of its flight pay the cold host
  path); peak committed memory rose by about 150 MB (Architectures in the JVM process; the
  process path's `decompile.exe` processes are small for this workload). The native run itself
  took 32 ms per run with one client against about 7 ms CPU per function in `decompile.exe` for the
  same functions, so the next step is a native profile of `SnapshotArchitecture` runs (samply with
  the PDB build), not more wiring.
- **Shared spec data: not done.** Every Architecture parses the registerProgram pspec/cspec/tspec
  and builds its own TypeFactory/Scope caches, and those are mutated while decompiling, so they
  cannot be shared read-only as they are. Sharing needs an immutable spec/type core split out of
  `ArchitectureGhidra` (C++ change in the decompiler core); store affinity is the cheaper half:
  it keeps the number of Architectures at the real concurrency.