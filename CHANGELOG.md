# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

A version is the Ghidra version a release is built on, then `-hydra.` and a counter (for
example `12.3-hydra.1`); its tag is `v` and the version. Releases are on
[GitHub](https://github.com/RusticStack/hydra-engine/releases).

## Unreleased

### `decompile`: response cap per query and non-contiguous functions (issues 6 and 7)

- `decompile` takes `maxResultMb` (alias `max_result_mb`, 1 to 1024): a hard ceiling. Absent, the budget is adaptive (was a fixed 50): a quarter of the free physical memory above a 4096 MB floor and an eighth of the free heap, divided by the decompiles in flight, 8 to 1024 MB; the buffer fills page by page and the request `timeout` still bounds a runaway decompile. An overflow reply carries `budget` with those numbers. `offset` pages the text (`next_offset`). Not done: spilling the response to disk, re-checking the budget while reading, a background lane for huge decompiles: the cap on the native decompiler's response buffer. It is not `maxChars`, which only cuts the text of an answer that already fit. A response over the cap now answers `completed:false, truncated:true, bytes_emitted, reason:"response_buffer"` instead of failing with `Response buffer size exceeded`; a timeout is labelled `reason:"timeout"`. Raise the cap for the whole text; the front of the text is returned as `partial` (below).
- A function with a non-contiguous (pdata) body that the decompiler cannot flow over (it ran into a pointer table between pieces: `Bad instruction count exceeded`) now decompiles piece by piece: `completed:true, partial:true` with a `fragments` list of `{start, end, class: code|data|unknown, decompiled}`; data pieces are skipped. Whole-body decompiles that succeed are unchanged. Tests: `examples/cc_issues_eng.py`. Details: `PROTOCOL-3.md` 8.21.
- An overflowed response now also carries the C text it began with (issue 6, second step): additive fields `partial:true`, `c` (cut to `maxChars`), `chars`, `signature` and `cut` (`kind`, `c_recovered`, `c_chars`, `c_lines`, `what` is missing). The text is read token by token from the front of the packed answer (`PartialMarkup`), so it is exactly the first part of the complete text (long comments are not rewrapped, names are not transformed); `completed` stays false and `reason` stays `response_buffer`. A cap that ends before the C markup begins gives `cut.c_recovered:false` and no `c`. Java API: `DecompInterface.setSalvageOverflow` / `takeSalvaged`. Test: `cap_partial` in `examples/cc_issues_eng.py`.
- `DecompInterface.setMaxResultBytes` and `DecompileProcess.setMaxResultBytes` (Java API): a per-use cap in bytes that wins over the options' payload limit.

### Semantic trace: non-functional measurements (draft)

- Privacy tests for the trace (`hydra-trace` `tests/privacy.rs`): secrets absent from replies, index, WAL, segments, exports and CLI output; keyed ids stable per scope and unlinkable across sessions and installs; payload artifacts excluded from export unless authorized; evicted artifacts leave a tombstone; the retention budget accounts for every event.
- Benchmarks: `multiagent_bench.py` and `multiproj_bench.py` take `--trace-readers`, `--cpu-profile`; `multiagent_bench.py` also `--affinity`; `trace_bench_rounds.py` runs and reports interleaved rounds; `trace_constrained.py` runs the disk and event-budget refusals.
- Measured: with 4 trace readers and a live capture the 16-agent run shows 0 waits and unchanged core replies; tree CPU rises by about 9 s (+45 %) in the 5 s workload, and `trace_info` on a live session costs O(session size). Details and what was not run: `docs/release-notes-12.3-hydra.6.md`.
- README: "System requirements" (minimum, reference, recommended, optional capabilities, support matrix, constrained behaviour); module README: a row for the trace store in "Why each part lives where it does".

## 12.3-hydra.5

Released 2026-11-01. Based on upstream Ghidra `master` (12.3 DEV) at
commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, the same upstream commit as 12.3-hydra.3 and
12.3-hydra.4. This release carries the round-4 work: the Rust protocol client, the PE import's
dependency-DLL skip, one decompiler Architecture per worker per program, overlay generation
inheritance, direct prefetch answers, one Sleigh parse per process, and the edit, close, analysis,
I/O and script-worker start-up changes. Every gate with its run, the measured numbers and what was
not met are in [`docs/release-notes-12.3-hydra.5.md`](docs/release-notes-12.3-hydra.5.md). Every
result is for a process tree on Windows x64 with JDK 25 on NTFS.

### Performance at 16 agents

Same fixed workload, three interleaved rounds, hydra.5 against 12.3-hydra.4
(`_logs/rust-round4/perop/REPORT.md`):

- Workload wall **5.70 s against 13.39 s**; tree CPU **27.95 s against 53.96 s** (-48 %); peak
  committed memory **1144.5 MB against 1725.3 MB** (-34 %); mean **795.1 MB against 1257.9 MB**
  (-37 %).
- Faster at p50 on every operation except `info` (0.52 against 0.49 ms, sub-millisecond parity) and
  `decompile_fresh` (8.18 against 7.51 ms, +9 %; see "Not met"). `connect` 6.10 against 33.80 ms,
  `list_functions` 15.36 against 1937.96, `read_script` 5.67
  against 291.06, `decompile_hot` 0.54 against 10.12, `decompile_overlay` 56.35 against 283.84,
  `fork` 351.32 against 612.25, `fork_close` 5.23 against 14.93, `save` 49.00 against 55.59,
  `edit` 7.44 against 9.93, `hy_edit` 364.10 against 421.06, `hy_publish` 1034.56 against
  2570.99.
- Import plus auto-analysis of KotOR: **71.4 s wall / 196.4 s CPU / 2.44 GB peak**, against
  hydra.4's 99.7 / 197.0 / 2.65 and stock Ghidra 12.2's 142.4 / 245.9 / 4.93.

### What changed

- **Rust protocol client and agent** (`Ghidra/Features/HeadlessSession/rust/`): the protocol 2/3
  core (framing, ids, deadlines and cancel, reconnect, events, raw lines), the read path and a
  benchmark agent; 434 KiB binary, no unsafe, one dependency. 34 of 34 replies are value- and
  byte-identical to the Python client and 376 of 376 reply keys hash to one digest over six
  interleaved rounds. With 16 agents the agent process peaks at 2.71 MB private against 13.90,
  uses 0.037 against 0.144 s of CPU, and lowers the tree peak by 166.6 MB. The Python client
  remains the default (`_logs/rust-round4/rustclient/REPORT.md`,
  `_logs/rust-round4/rustclient2/REPORT.md`).
- **PE import loads a dependency DLL only when its export table can change the program**: a
  library is skipped unless the program imports from it by ordinal, and a 32-bit program keeps
  the old every-table behaviour for the stack purge and "no return". `import_exe` 21.11 -> 9.53
  CPU s and 4.83 -> 1.73 s wall; `import_dll` 6.14 -> 0.28 and 3.65 -> 0.14 s; imported symbols,
  functions, purge, calling convention, libraries, memory blocks and source hash identical
  (`_logs/rust-round4/create/REPORT.md`).
- **Decompiler host**: one `Architecture` per worker per program, rebound for each generation
  instead of rebuilt; an annotation-only overlay generation inherits data-type and register-name
  answers from its base generation; a fresh decompile's prefetched answers are used directly
  (no query encode and re-decode). The overlay first decompile fell from 1133 to 243 ms and its
  p99 from 892 to 559 ms (`_logs/rust-round4/hostmem/REPORT.md`,
  `_logs/rust-round4/latency/REPORT.md`).
- **One Sleigh parse per process**: workers adopt the parsed tables; 48 parses (7.03 s) became 2
  (0.05 s), and a digest of every decompiler header is a build input so an incremental native
  build cannot link mixed layouts (`hydra-rust-round3.md`, 5c).
- **Edit**: a writable open warms the write-side tables a first change touches, the C signature
  parser is parsed once per daemon, and a re-applied signature skips the parameter resolve loop.
  `edit` p50 6.40 against 11.09 ms in the dedicated 48-edit harness
  (`_logs/rust-round4/edit2/REPORT.md`).
- **Close**: a disposable fork's close no longer rewrites the two storage indexes, and the channel
  locker deletes its marker without re-reading it. `fork_close` 5.23 against 14.93 ms at 16
  agents, 2.75 against 11.25 ms paired (`_logs/rust-round4/close/REPORT.md`,
  `_logs/rust-round4/perop/REPORT.md`).
- **Analysis**: the switch analyzer runs its defined and undefined phases through one decompiler
  pool and queues each phase's functions largest first. KotOR analysis 72.7 -> 69.4 s and 71 ->
  66.2 s; the switch pass 31.1 -> 27.6 s; the listing digest is identical on KotOR, KotOR II,
  Empire at War and `choice.exe` (`_logs/rust-round4/analysis/REPORT.md`).
- **I/O**: one volume query per fork cost (6.8 -> 1.8 ms), the Windows directory sync returns at
  once instead of throwing, publish verification uses the engine's `decompile` command (0.39
  against 6.08 ms per call) in a window of 8, and a publish forces only the files the save wrote
  (14 -> 5 fsyncs). Publish build 922 -> 690 ms; `hy_publish` 1274 -> 1105 ms
  (`_logs/rust-round4/io/REPORT.md`).
- **Script worker start-up**: the worker receives the daemon's class cache, AOT cache,
  configuration and script build store, and the deferred initialization runs before the script.
  Start CPU 11.6 -> 7.1 s and wall 4.2 -> 2.8 s per worker; the suite's own run fell from 549.8
  to 443.9 s, part of that difference being a 37 s machine stall in the base run
  (`_logs/rust-round4/suite/REPORT.md`).
- **CPU profiles**: `HYDRA_CPU_PROFILE=generic|auto|<name>`, `auto` by default, sizes the pools
  from the CPUs the OS grants and places threads by core class (each `GThreadPool` uses its own
  occupancy counter). Total CPU 57.62 -> 53.76 s (-6.7 %), setup CPU -19.3 %, output identical
  (`_logs/rust-round4/profiles/REPORT.md`).
- **JIT C1 pins**: the one-shot Xerces XML parser and log4j configuration parser stay on C1;
  95 C2 compiles, 0.70 s of C2 thread time and 0.33 MB of code are removed per daemon
  (`_logs/rust-round4/cds/REPORT.md`).
- **Hydralysis 0.7.0** (released with this engine) publishes the subjects a generation actually
  applied instead of a wildcard, so a publish does not conflict the agent's own next edit; a dead
  publish worker or leader answers `failed`/`unled` in 10 s instead of waiting to a deadline, and
  the next publish moves an unappended sealed generation aside and rebuilds it. The final series had
  104 edits and 104 publishes with 0 failures, and the earlier fixed series adds another 104 edits
  and 104 publishes — 208 edits in all. The Hydralysis suite had 1640 results and 0 failed
  (`_logs/rust-round4/hyedit/REPORT.md`).

### Reliability and scale

- A real multi-project run: 16 agents on Cyberpunk 2077, KotOR and KotOR II while Empire at War
  imported and auto-analysed behind them, in one daemon and in one daemon per project. Every clean
  run served 818 of 818 operations with 0 errors, 0 requests waiting on another request, 0 queued
  lanes, 0 daemon restarts and 0 inconsistent reply hashes; every fork edit was present after save
  and re-open and every project tree was byte-identical
  (`_logs/rust-round4/multiproj/REPORT.md`).
- Game corpus (KotOR II, StarWarsG, Empire at War, KotOR, Cyberpunk 2077): identical to
  hydra.4 on function and symbol counts, external libraries and every sampled decompile; against
  stock Ghidra 12.2 only version differences (`_logs/rust-round4/games-e/REPORT.md`,
  `_logs/rust-round4/games-cp/REPORT.md`).
- In the 16-agent benchmark all six runs had 412 of 412 reply keys and one canonical digest
  (`285b55a2…a77df`), identical to hydra.4 (`_logs/rust-round4/perop/REPORT.md`, section 1.1).

### Not met

- Peak memory is **-33 to -40 %**, not -50 %: 1144.5 against 1725.3 MB at 16 agents, mean -37 %.
  The measured floor and the rejected levers are in `_logs/rust-round4/memory/REPORT.md`.
- `decompile_fresh` is bound by the stock decompiler's own analysis (84 % of the host decompile)
  and is not 2x faster: its paired CPU is +17 % (+2.95 ms) and its 16-agent p50 is 9 % slower
  (8.18 against 7.51 ms), while its paired wall median is faster (4.08 against 4.99 ms). The
  cause is host dispatch plus per-generation Architecture setup on a cold function
  (`_logs/rust-round4/fresh/REPORT.md`, perop section 7).
- `hy_publish` is 1.1-1.5 s median, not below 1 s: 1105 ms against 1274 ms, with 3 of 6 runs at
  845-994 ms. The rest is eight concurrent publishes over about 1.5 builds plus the harness'
  250 ms poll (`_logs/rust-round4/io/REPORT.md`).
- The daemon suite is **255 of 255 on the release install** (`o4-h5-release`, stamped
  `12.3-hydra.5`; `_logs/rust-round4/release/suite2.out.log`). An earlier run on the integration7
  build was 254/255: `e2a_kill_fork` is a pre-existing chaos flake, 1 failure in 6 standalone runs
  on hydra.4 and 1 in 6 on each of the two preceding integration builds; it passed 2 of 3 standalone
  reruns after that failure
  (`_logs/rust-round4/integration/e2a-h4.log`, `e2a-int5.log`, `e2a-int6.log`, `e2a-int7.log`).
- The 16-agent `fork` p50 moved from 214 to 351 ms between sessions while the isolated fork stayed
  at 81 ms; the ratio is window-dependent and no fork speed-up is stated from that row (perop
  section 9).

### Other changes in this release

- Python 3.13 or later is required (3.10 reaches end of life in October 2026). `ghidra_session.py`
  exits with status 2 and "Hydra Engine's launcher needs Python 3.13 or later; this is X.Y" on an
  older Python. CI and the upstream sync run on 3.13.
- CI skips daemon_tests and contract_tests, as the release workflow does, when
  `.github/local-test-record.json` names a locally tested commit and only documents or `.github/`
  files changed since; the build, the smoke test and the client packaging always run.
- `-Dcpu.core.uncapped=true` (off by default) sizes the default CPU-bound thread pools (the
  shared "Analysis" pool, `GThreadPool` defaults) from the processors the OS grants the process
  (`Runtime.availableProcessors() + 1`) without Ghidra's fixed cap of 10. The cap stays the
  default: it bounds every default-sized pool, including the decompiler pools
  (`ParallelDecompiler`, `DecompilerConcurrentQ`) whose threads each keep a native decompiler
  process, and no end-to-end speed-up from a bigger pool was measured. `-Dcpu.core.override`
  (exact size) and `-Dcpu.core.limit` (upper bound) still apply.
- `-Dhydra.decompiler.pipeline=true` (off by default) runs the batch decompile methods
  (`ParallelDecompiler.decompileFunctions`) as a pipeline (`generic.concurrent.BoundedPipeline`):
  the caller enumerates the functions a bounded window ahead of the workers instead of queueing
  all of them first under the queue lock, and consumes results while the workers keep
  decompiling; a consumer is called on the calling thread, one result at a time; the methods
  that return a list return it in the iterator's order instead of completion order. Every
  decompile result is the same (8 fixtures and 2000 KotOR functions, all methods compared).
  Workers: `-Dhydra.decompiler.pipeline.workers=pool|granted|<n>` (default `pool`, today's size
  from the granted CPUs with the cap of 10; `granted` is every CPU `HydraCpu` reports, uncapped);
  window per worker: `-Dhydra.decompiler.pipeline.window` (4, or 128 when ordered). New
  `ParallelDecompiler.decompileFunctionsInOrder` streams results in iterator order with bounded
  memory, whatever the flag. Errors and cancel behave as on the queue path (a consumer exception
  is logged and stops the work, not thrown; a stop cancels the decompiles still running; a
  cancelled monitor returns the finished results); `decompileFunctionsInOrder` throws a consumer
  exception.
- A constant propagation Max Threads value above the analysis pool size runs with the whole
  pool (`AbstractAnalyzer.clampThreadCount`) instead of silently dropping to one thread
  (`ConstantPropagationAnalyzer.runAddressAnalysis`), and the Max Threads option is no longer
  rewritten to 1. This is an accepted semantic change for users who set Max Threads above the
  pool size; with the default (2) nothing changes. The default Max Threads (2) of the
  constant reference and stack analyzers is unchanged: on six x86/x64 binaries (four test
  fixtures, `zipfldr.dll`, `msvcp_win.dll`) every reference and stack variable was identical at
  1, 2, 4 and 24 threads, but neither analyzer got faster above 2-4 threads (the stack analyzer
  was slower at 24), so a CPU-derived default would add contention for no gain.

### Compatibility

- One port serves protocol 2 and protocol 3; `minClient` stays `1.0.0`, so no existing client is
  rejected. Hydralysis 0.6.0 refuses this engine by its own pin; **Hydralysis 0.7.0 pins this
  release**. Clients of hydra.2, hydra.3 and hydra.4 keep working at protocol 2.
- Headless only: there is no GUI, and projects this engine writes cannot be opened by Ghidra 12.2
  or 12.1.4.
- The upgrade and backup policy, the limits of protocol 3 and the database formats are unchanged
  from 12.3-hydra.4 (`docs/release-notes-12.3-hydra.4.md`, sections 1 and 5).

## 12.3-hydra.4

Released 2026-10-30. Based on upstream Ghidra `master` (12.3 DEV) at
commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, the same upstream commit as 12.3-hydra.3. This
release adds protocol 3 beside protocol 2, the storage-integrity changes, the resource governor
and the script worker. Every release gate with its run, the guarantees with the test that decides
each, and what was not met are in
[`docs/release-notes-12.3-hydra.4.md`](docs/release-notes-12.3-hydra.4.md). Every result is for a
process crash on Windows x64 with JDK 25 on NTFS.

### Compatibility

- One port serves protocol 2 and protocol 3. The endpoint file and the `ready` event carry
  `protocolMin` (2) and `protocolMax` (3). `minClient` stays `1.0.0`, so no existing client is
  rejected. `ghidra_session.py` 1.1.0 asks for protocol 3 and falls back to 2.
- Hydralysis 0.4.x refuses this engine by its own pin; clients of hydra.2 and hydra.3 keep working
  at protocol 2. Hydralysis 0.6.0 pins this release. Restart the MCP harness once after updating
  Hydralysis (catalog epoch).
- Headless only: there is no GUI, and projects this engine writes cannot be opened by Ghidra 12.2
  or 12.1.4.

### Changes a protocol 2 client can see

Everything else a protocol 2 client does is unchanged and checked against the vendored 1.0.0
client (`examples/stock/`, `examples/client_compat_tests.py`, 52 of 52). The declared exceptions:

- V1, the upgrade gate: `open_program` with `writable` and `upgrade` on a canonical project in an
  older format is refused with `conflict` (`details.reason` `backup_required`) unless the request
  carries a valid `backup`; a fork is allowed.
- V2, the import wait: an import without `wait` no longer fails `busy` ten seconds after it reaches
  the front; an import with a numeric `wait` spends one budget across the gate, the slot and the
  project lock.
- V3, bounded release of a dead client: its slots and locks are released after `cleanupGraceS` and
  `abandonWaitS` (15 s and 5 s by default); the 600 s waits of `disconnect` and `leaveProject` for
  owners and writers use the same bounds.
- V4: a request for a program held by an abandoned request answers `busy` at once.
- V5: `cancel`, and a `timeout` deadline, end a request-bound lock wait (a program, a project, or an
  overlay's request lock site). The overlay lifecycle waits (open, rebuild, drop and promote of an
  overlay) are untimed and are not ended by `cancel`, a `timeout` or the release of a dead client.
- V6: `protocolMin` and `protocolMax` in the endpoint file and the `ready` event.
- V7: the sidecar of every `fork_project` gains `purpose` and `disposable`.
- V8: a project this engine sealed refuses every writable path with `conflict` (`details.reason`
  `sealed`). A project it did not seal behaves as before.
- V9: a per-connection cap on running requests applies while another connection waits; the long
  lane defaults to `max(8, CPUs)` slots.
- V10: a client that is neither owner, writer nor overlay holder leaves a program without taking its
  exclusive lock.
- V11: concurrent `fork_project` calls to one destination give one success and `conflict`
  (`fork_in_progress` or `exists`) to the others.
- V12: a request that fails because another process holds a file or folder of the project answers
  `busy` with `details.path` and `suggest:"retry"` (protocol 3 also gets `details.reason`
  `file_held` and `retryAfterMs`), where it used to answer `bad_request` ("Unknown-File"),
  `not_found` or a bare `failed`. Once the hold ends, the same request succeeds without a reopen.

### Protocol 3

Only for a client that asks for protocol 3: the `expect` check on `signature` and `data_type`, the
`rk` idempotency key, `error.next`, the identity block of `hello` (`paths`, `platform`,
`analysisIdentity`), the capability, limit and policy blocks, the maintenance lane for `save`,
`fork_project`, `refresh`, `reopen` and `promote_overlay`, the `queue` key of slot waits,
validation before a wait, `seal_project`, backups with a manifest, the `isolation` and `lane`
fields of `script`, the `health` command, and the daemon settings passed as `-set key=value` (the
`engine` object of `config.json`).

### Resources and scripts

- Resource governor: a view, fork or import that does not fit the heap, `maxViews` (32) or the
  per-client cap `maxViewsPerClient` (4) answers `busy` with `reason` `capacity`. Tested with
  `-Xmx256m` (24 views asked, 6 opened, 18 `busy`, no out-of-memory) and `-Xmx512m` (24 of 24).
- A native decompiler crash, hang or timeout fails that one request (`decompiler_failed`,
  retryable). The daemon puts its decompilers in its own Job Object, so a killed daemon leaves no
  decompiler behind (tested with suspended decompilers and a no-job control). Both in gate 9.14.
- Script worker (`isolation:"worker"`): a script that ignores cancel is ended at its timeout and its
  slot released (gate 9.14). A script that runs inside the daemon is still bounded and quarantined,
  not stopped.

### Storage integrity

- A new version file's header is written and synced before the rename to its final name, and the
  newest version is checked when a database is opened. Gate 9.15: 563 counted kills during a save
  on NTFS, 0 unopenable and 0 unrepaired (below 0.75% at 95%, on NTFS alone).
- Fork publish is staged and published `.gpr` last; a sidecar records its state. A killed publish
  can leave a `.rep` without its `.gpr`, which the sweep removes at the next daemon start,
  `open_project` or `fork_project` of that directory. Gate 9.15: 330 counted `fork_project` kills
  and 211 `promote_overlay` kills, 0 failures.

### Fixed during the release gates

- A file or folder held by another process (an antivirus, an indexer) answers `busy` (V12) instead
  of `bad_request`, `not_found` or a bare `failed`, and the project no longer keeps a broken entry
  after the hold.
- A save whose folder listing was held for a moment no longer leaves the program unsaveable until a
  daemon restart; the next save works without a reopen.
- Script loads during an analysis's own script load wait for the shared lock instead of failing with
  `OverlappingFileLockException`.
- Leftovers of a killed fork or promote (a `.rep` without its `.gpr`, a sidecar's temporary file,
  Ghidra's empty time probe) are swept at daemon start and at `open_project`, not only at the next
  `fork_project`.
- The client launcher writes its shared launch files under per-writer temporary names: two clients
  starting against one state directory no longer fail the rename (WinError 32).
- `lockWaiters` appears in a program status on protocol 3 only; protocol 2 status replies are
  byte-identical to 12.3-hydra.3 again.

### Not met

- Reader throughput under four concurrent view writers is about 0.76 of the no-writer baseline,
  below the 0.9 of gate 9.13 (`s11`). Not a requirement for this release (owner decision
  2026-10-30); nothing is claimed about it.
- A concurrent `fork_project` takes a median 1226 ms against 313 ms on 12.3-hydra.3 (time to the
  first decompile +28%). Recorded, not fixed.
- The soak for this release is the PR lane (passed) and one nightly run of 16 agents on 4 projects
  for 1 h 47 min, stopped early by the owner. That run failed: four Hydralysis view findings (fixed
  in Hydralysis 0.6.0, not re-run), and two fault classes below their minimum (handle holder 8 of
  10, backup lane 3 of 4). Scale is stated as tested with up to 4 clients.

### Limits

Every limit of `PROTOCOL-3.md` 6.2 is listed in the module README, "Limits of 12.3-hydra.4 and
protocol 3". In short: a script that ignores cancel is ended only in the script worker; the overlay
lifecycle waits are not cancel-aware; the leave of an owner or writer of an open program still
queues the exclusive lock (bounded); `lane:"quick"` is a trusted hint; Windows x64 and JDK 25 only,
no Linux or macOS claim; no power-cut test; nothing about ReFS is tested for this release (no ReFS
volume on the release machine, owner decision 2026-10-30; NTFS is the release file system); the
upgrade gate and the backup check guard against accidents and are not a security boundary.

### Documentation and internals

- Wording corrected to what the tests show (claims audit, `PROTOCOL-3.md` 8.3): writes are
  serialized and no corruption was seen in the tests listed; collisions are detected only when you
  pass `expect`; native commands stay in the quick lane; several clients (tested with up to 4
  clients); a native decompile takes about 1 to 45 ms by function size.
- `NOTICE-HYDRA` lists every modified Ghidra file, including those of this release.
- `Session.java` is split into command classes by area (no reply changed, field order included;
  `ARCHITECTURE.md`), and `examples/characterization_tests.py` records the exact replies of every
  command.

## 12.3-hydra.3

Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-27,
commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, merged into the Hydra Engine branch with a
plain merge commit (no rebase): 0 conflicts. The previous base was `057a646233`; the merge brings in
35 upstream commits (17 that are not merges) and touches 29 files, none of which Hydra Engine
changed. `git merge-tree` predicted the merged tree `069259b499` and the merge produced the same
tree.

### Upstream changes picked up

- Decompiler (C++, so the native `decompile.exe` is rebuilt): GP-7212 (`RuleRangeMeld` extra
  pull back for offcut matches, `ruleaction.cc`), GP-7414 (`truncatePointer` checks for a
  constant varnode), GP-7423 (`findCbranch` in `checkCommonCbranch`, `coreaction.cc`,
  `jumptable.cc`).
- GP-1 `ghidra.util.datastruct.Range` is `long` based instead of `int` based.
- GP-7418 Ghidra URL encode and decode fixes (`GhidraURL`); GP-7416 loader options built with
  constructors deprecated in 12.2 no longer lose headless `-loader-*` arguments (`Option`).
- Bounds-checking fix in `StaticValueByteProvider`, symbol path parsing (`SymbolPathParser`),
  Objective-C message analyzer, Windows RTTI script, and dialog and marker fixes in code the
  headless install does not contain.

### Database format gate

Nothing in the database or language layers changed: the merge touches no file in
`Ghidra/Framework/DB`, `Ghidra/Framework/SoftwareModeling`'s `program/database` packages or any
processor (`Ghidra/Processors`); `ProgramDB.DB_VERSION` is still 33,
`DataTypeManagerDB.DB_VERSION` 3, `DataTypeArchiveDB.DB_VERSION` 5, `ProgramUserDataDB.DB_VERSION`
1, `SlaFormat.FORMAT_VERSION` 4, `LocalBufferFile.HEADER_FORMAT_VERSION` 1. Projects of
12.3-hydra.2 open unchanged. `LocalBufferFile` still has both GP-7261's size checks and Hydra's
truncate-before-close for temporary buffer files (`3229f6e79f`).

### Decompiler gate

The decompiler output of this build was compared with 12.3-hydra.2 (`golden.py`, one program
function at a time, C text hashed):

- KotOR (an x86 game executable, 8616 functions): 8616/8616 identical to 12.3-hydra.2 on all three
  decompile paths (explicit, explicit-program and production), and identical between two runs of
  12.3-hydra.3.
- x86 fixtures: identical. x64 fixtures: exactly one function per program differs, the same CRT
  `strncmp` (125 bytes) in all four; the change is GP-7212's. The 100% fixtures profile therefore
  fails by one function per x64 program until those baselines are re-recorded.
- GP-7423 and GP-7414 changed no output in this corpus (no regression seen; not a verified
  improvement). KotOR is x86 only.
- Timing: no regression above the run-to-run noise of a machine shared with other Java processes
  (interleaved A/B medians: 3.40 ms for 12.3-hydra.2 against 3.37 ms for 12.3-hydra.3); one raw pair
  of back-to-back runs showed +14 to +16%, which the interleaved runs did not reproduce.
- A project saved by 12.3-hydra.3 opens in 12.3-hydra.2 and back. This is expected: both builds
  use the same database format, so it is not independent evidence about the format.

### Build and tests

`gradle buildHeadless` (JDK 25, Gradle 9.8.2, Visual Studio Build Tools) built the headless install
for Windows x64, native decompiler included: `decompile.exe` and `sleigh.exe` were compiled from the
merged sources, not copied. On that install (NTFS volume): `session_smoke.py` passed (34 checks),
`contract_tests.py` 5/5, `daemon_tests.py` 31/31 (including `import_queue`, `import_isolation`,
`parallel_imports`, `import_speed`, `upgrade_cache` and `fork`); `legacy_overlay` and the
older-format half of `upgrade_cache` need a project saved by Ghidra 12.1.4 and were skipped. Not
exercised: the ReFS-only behaviour (block-clone fork, slow close of a temporary buffer file). A
stock `analyzeHeadless` import with `-loader-*` arguments applied them; upstream's tests for
`GhidraURL`, the protocol connector and `SymbolPathParser` pass (55 tests).

### Documentation and licensing (no change in behaviour)

- **README**: Hydra Engine is described as a fork of Ghidra 12.3 DEV that depends on it (the
  project format, decompiler, analyzers and scripts are Ghidra's), not as an independent project.
- **Speed**: the warm decompile time is qualified as size-dependent. The 6.7-7.1 ms of the benchmark function
  is one function whose size was not recorded; measured by the owner on a KotOR
  executable on 2026-10-27, a warm decompile took 0.7-2.1 ms for a one-byte function and 35-45 ms
  for a 6.7 KB function of 29 basic blocks.
- **Writes**: they are serialized, and no corruption was seen in the tests listed in the module
  README; they are not collision-checked by default: shared writes are last-writer-wins per value, and `expect` is opt-in per call. The
  wording "write without stepping on each other" is replaced accordingly (README and module
  README).
- **Platform and limits** section: releases are Windows x64 only, JDK 25 is required, one daemon
  per state directory, `fork_project` is a block clone only on ReFS (a full copy elsewhere),
  changes are kept only by `save`, and the project upgrade from 12.1.4 is one-way.
- **Hydralysis** (renamed from RusticRE): a status note says its repository, command and
  `HYDRALYSIS_ROOT` are not published yet; the links stay.
- **NOTICE-HYDRA** rewritten as the Apache-2.0 section 4(b) notice of modifications: it lists
  every modified upstream file with what changed, and each of the three modified Java files
  (`LocalBufferFile`, `LocalDatabaseItem`, `SleighLanguageFile`) has a one-line comment saying so
  (no code change).
- **Release archives** now ship `NOTICE` and `NOTICE-HYDRA` next to `LICENSE`: in the headless
  install's root (`gradle/hydra/headless.gradle`) and in the client zip
  (`.github/scripts/package-client.sh`); the release workflow checks the unzipped engine for all
  three.
- **CONTRIBUTING**: the upstream sync policy (merge never rebase, one `sync/upstream-YYYY-MM-DD`
  branch cut from `origin/main`, the golden decompile diff gate, the upstream commit recorded in
  the changelog, the database format constants check, `legacy-12.1.4` frozen and end of life) and
  a complete list of the upstream files that can conflict.

## 12.3-hydra.2

Released 2026-10-26. Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-26,
commit `057a646233edfb21768a42a0aabc1d1a7709da19`: the same upstream commit as 12.3-hydra.1
(upstream had no newer commit when this release was cut).

### What's new for integrators

Several agents can now change things at the same time, each in the way that fits its work:

- **A working copy of a project** (`fork_project`) while every other client keeps reading the
  master: a block clone on ReFS (about 0.2 s and 3-5 MB for a 1.5 GB project), a full copy
  elsewhere (8.5 s for the same project to NTFS), with the source
  and base revision recorded next to the fork.
- **A private overlay** of a program others read (`open_program` with `overlay`,
  `apply_overlay`): renames, labels, comments, signatures and data types only that client sees,
  never saved unless promoted into a working copy (`promote_overlay`).
- **Several writers**: several clients write one project (different programs in parallel), or
  one program in shared mode (`"share": true`), with every change journalled with its author,
  `expect` to detect lost updates, an atomic `edit` command and `discard_edits`.
- **Revisions and `refresh`**: answers say when another process saved a project a read-only
  view serves (`stale`); `refresh` reopens it for all its clients at once.
- **Who holds it, and what to do**: `busy`, `conflict` and `not_owner` name the holder
  (`holderInfo`) and suggest the action (`retry`, `fork_project` with a ready request, an
  overlay, `share`, `reread`, `open_read_only`).
- **Imports in parallel** (`maxImports`), with a visible, cancellable queue in `status.imports`.
- **Per-request `client`/`harness` labels**, so one MCP server serving several agents can tell
  them apart in holders, `status`, the import queue and `cancel`.
- **A versioned integration contract**: `hello` and `status` carry `protocol`, `minClient`,
  `hydraVersion`, `ghidraVersion` and `installId`; the client ships as its own release asset,
  `hydra-client-12.3-hydra.2.zip`, and refuses an engine it cannot drive. The export contract
  of long scripts (artifact path, progress, cancel, partial files) is documented and tested.

### Compatibility

- **Protocol 2, unchanged.** Everything above is new commands and new fields; nothing was
  renamed or removed, except that the `busy` details of a program lock carry the program's key
  in `program` (its project path moved to `path`). The engine answers `minClient: "1.0.0"`.
- **Client 1.0.0** (`ghidra_session.py`, `CLIENT_VERSION`) is the first versioned client;
  pin it together with the engine. The unversioned client of 12.3-hydra.1 still speaks protocol
  2 but does not check the engine.
- **Projects**: a project saved by this build cannot be opened by Ghidra 12.2 or 12.1.4
  (upstream `master` writes data type databases at version 3). Projects analysed with 12.1.4
  open read-only without being written, upgraded in memory and then served from the upgrade
  cache; `fork_project` makes a writable copy that leaves the original as it was. The
  `legacy-12.1.4` branch remains for projects that must stay on 12.1.4.
- **Platforms**: built and tested on Windows 11 x64 only (locally and in the release
  workflow). Linux and macOS are not released or tested routinely.

### Downloads

- `hydra-engine-12.3-hydra.2-win_x86_64.zip`: the headless install for Windows x64 (`gradle
  zipHeadless`); the release workflow ran the three test suites on it after unzipping it.
- `hydra-client-12.3-hydra.2.zip`: `ghidra_session.py` (standard library only) stamped with
  this release, `LICENSE` and a short `README.txt`.
- `SHA256SUMS` for both.

You need a JDK 25 and Python 3.10 or later; the install has no JDK.

### Known limits

- The data type database version 3 limit above, and a development snapshot as the base
  (upstream `master` is Ghidra's next version under work, not a Ghidra release).
- Overlays change only through their five operations (rename, label, comment, signature, data
  type) and show the program as stored when they opened, not other writers' unsaved changes.
- A fork is a block clone only on ReFS (Windows 11 24H2 and later); on NTFS it is a full copy,
  which `auto` mode refuses above `forkCopyLimitMb` (default 2048).
- The author journal lives in the daemon's memory while the program is open and keeps the last
  200,000 entries; `discard_edits` reverts renames, labels and comments only.
- There is no GUI: headless only, with no help, javadoc or Python type stubs.

### Added

- **Holder information in `busy`, `conflict` and `not_owner`** (HeadlessSession). The error
  details name who holds the project, program or lock: `holderInfo` (`client`, `name`,
  `harness`, `label`, `command`, `heldMs`; for another process, the user, host and time from
  Ghidra's project lock file and whether that process is alive), the project or program identity
  (`project`, `gpr`, `program` key, `path`, `sha256`), and `suggest`: `retry`,
  `fork_project` (with a ready `suggestion` request) where a working copy is the answer,
  `share` (join a shared program), `reread` (a value changed since it was read), or
  `open_read_only`. `holder` stays a string as before; everything else is new fields.

- **`fork_project`** (HeadlessSession): copies a project into a working copy for the caller
  while the source and its read-only views stay open and in use. A block clone on ReFS (Windows
  11 24H2 and later), else a full copy; `mode` `auto` (clone, or a full copy up to
  `forkCopyLimitMb`, default 2048), `copy-on-write` (clone or refuse) or `full`. The answer has
  the new project id, the paths, the source's identity and base revision, `method`, `cloned`
  (measured), `bytes`, `files` and times. The fork records its source, base revision and lineage
  in `<name>.fork.json` next to its `.gpr`, shown as `fork` by `project`. A source another
  client or process writes is refused, naming it. New launcher setting `forkCopyLimitMb`
  (`GHIDRA_SESSION_FORK_COPY_LIMIT_MB`), daemon option `-forkCopyLimitMb`.

- **Revisions and `refresh`** (HeadlessSession): every project and program has a `revision`
  (a fingerprint of the saved files), shown by `open_project`, `project`, `projects`,
  `open_program`, `info`, `save` and `status` with `diskRevision`, `stale` and `generation`.
  Answers carry `stale` (a read-only view whose project another process saved) and, once,
  `refreshed` (another client refreshed it). New command `refresh` (alias `reopen`) reopens a
  read-only view for all its clients at once, under the same keys. The Python client gains
  `call_raw` and `last_response`.
- **Integration contract** (`Ghidra/Features/HeadlessSession`, `support/ghidra_session.py`):
  `hello`, `status` and the endpoint file now carry `protocol`, `minClient`, `hydraVersion`,
  `ghidraVersion`, `installId` and `startedAt`; the Python client has a `CLIENT_VERSION`
  (`1.0.0`) and refuses, with `IncompatibleError` (exit code 4 on the command line), an engine of
  another protocol or one whose `minClient` is newer than itself; `status` and `stop` still work
  on such an engine. `ghidra_session.py version` prints the client's version. README: "Pinning
  and upgrading", and a compatibility statement for projects analysed with Ghidra 12.1.4.
- **Client release artifact**: the release workflow also publishes `hydra-client-<version>.zip`
  (the standard-library-only `ghidra_session.py` stamped with the release, `LICENSE`, a short
  `README.txt`), listed in `SHA256SUMS`. `.github/scripts/package-client.sh` builds it and
  checks the packaged file; CI runs it as a dry run.
- **Status shows requests**: each client in `status` lists its unanswered requests (`id`, `cmd`,
  `artifact`, `ms`, `message`, `progress`, `maximum`) and its `clientVersion`.
- **Script exports**: `script` takes an optional `artifact` (a path the script writes), echoed in
  `status` and in the result; `examples/scripts/ExportJsonl.java` is a sample export with
  progress and an inspectable partial file; README "Scripts" states the export contract
  (output outside the project, not capped by `maxChars`, partial files after cancel and shutdown).
- **Concurrency documentation**: README "Who can do what at the same time": readers, writers,
  projects, imports, and what `conflict`, `busy` and `not_owner` mean.
- **Tests**: `examples/contract_tests.py` (identity fields, client compatibility, a 600,000-line
  export with progress, cancel and shutdown), run by CI and the release workflow.
- **The import queue is visible and cancellable.** Imports that cannot run yet (one at a time
  when this was added; up to `maxImports` since "Imports run in parallel" below) queue
  first-come, first-served without holding a scheduler slot. `status.imports` shows the
  holder (client label, project, file, running time), the queue with each entry's position and an
  estimated wait (from the durations of earlier imports), and the history. A queued `import`
  sends `progress` events "waiting behind ..." and its answer reports `queue` (`waitedMs`,
  `positionAtEntry`, `behind`). Cancelling a queued import removes it without touching the
  running one; cancelling the running one starts the next. A numeric `wait` now limits the queue
  wait; without one a queued import waits in the queue without limit, and at the front it still
  needs a long slot and fails `busy` after `wait` (10 s default).
- **Per-request `client` and `harness` labels.** Any request may carry them; they replace the
  connection's name for that request in `busy`/`conflict` holders (`holder` and `holderInfo`), `status` (requests, scheduler
  lanes, owner of a writable program, `youAre`), the import queue and the log, and they scope
  `cancel` (`all` reaches only that label's requests; `target` refuses another label's request).
  Ownership is unchanged (still per connection). One MCP server serving several agents can now
  tell which agent holds a program or an import. `ghidra_session.py`: labels on any `call`, and
  `labelled(client=, harness=)` views with `cancel_all()`.
- `daemon_tests.py`: `import_queue`, `import_isolation`, `caller_labels`; `--raw-mb`.

- **Shared writing** (HeadlessSession): `open_program` with `"writable": true, "share": true`
  lets several clients write one program at once. Each change is its own transaction,
  committed one at a time under the program's exclusive lock and visible to all; last writer
  wins, and `expect` on renames, labels and comments (also as `edit` operations) turns a lost update into
  `conflict` (`reason: "changed"`) naming the last editor. Every change to a writable program
  is journalled with its author (`journal`; `journalSeq`, `unsavedEdits`, `savedSeq`); new
  commands `edit` (operations, all or none) and `discard_edits` (revert one author's unsaved
  renames, labels, comments). A writer that dies loses only its uncommitted change; when it was
  the last writer, the unsaved work is kept (program and project stay open) until a client
  joins and saves or discards it. Owner and shared mode do not mix on one program. Tested with
  4 clients x 2 threads, 3,200 edits and 64 saves: none lost, journal complete, reopen clean.
- **Several writers in one project** (HeadlessSession): `open_project` writable while other
  clients use the read-only view now reopens it writable in place (same id and keys, their
  programs reopened, overlays rebuilt, `refreshed` once) instead of `conflict`; refused only
  when another process holds the project lock. A second writable open joins; writers of
  different programs of one project work in parallel (tested with concurrent renames,
  comments, analysis and saves). `not_owner` adds `alternatives: ["overlay", "fork_project"]`
  and an `overlaySuggestion`.
- **Overlays** (HeadlessSession): a client's private annotation view of a shared program.
  `open_program` with `overlay` opens one: its own program object over the stored file
  (changeable, never saved), measured at 116 ms and +54 MB heap for a 243,855-function program.
  `apply_overlay` applies `rename`, `label`, `comment`, `signature` and `data_type` operations
  atomically and logs them; `info`, `functions`, `decompile`, `script` (contained), `rename` and
  `comment` take `overlay`; `drop_overlay`, `overlays`; `promote_overlay` replays the log into a
  writable copy (a project the client opened writable, or a new fork) and saves it. Each overlay
  shows `overlayVersion`, the program's SHA-256 and revisions, in its answers, `info` and
  `status.overlays`. A refresh rebuilds overlays from their logs; a client's disconnect drops
  its overlays.

### Changed

- **Imports run in parallel** (HeadlessSession). Up to `maxImports` imports (new launcher
  setting and daemon option `-maxImports`; default one per four CPUs, 1 to 4) run at once, into
  different projects or into one; more queue as before. Imports no longer set the process-wide
  active project: nothing on Ghidra's load path reads it (the README's "Parallel imports" lists
  what the load path shares and why parallel loads work): four 12-25 MB PEs imported at once took 64 s
  against 165 s one after the other, with identical programs. The gate covers the load and the
  save; `analyze: true` analyses afterwards in the import's long slot, as before. The same file sent twice at
  once into one project is imported once: the second waits and answers `existing`, with
  `sameFileImport`. `status.imports` gains `maxImports`, `running` and `history.peakRunning`
  (`holder` is the oldest running import); an import's `queue` gains `runningAtStart`. Opening an
  upgrade cache copy no longer goes through the import gate.
- `daemon_tests.py`: `parallel_imports`, `import_kill`, `import_readers`, `import_speed`
  (`--big`, `--big-analyze`); `import_queue` runs with `maxImports` 1.
- The project files the upgrade cache keys and copies leave out Ghidra's transient files in a
  `.rep` (`tmp<n>.ps` pre-save copies of programs open for update, `tmp<n>.tmp`), so that a
  project another process has open for update keeps its identity until it is saved. Cache
  entries made before this are rebuilt once.
- The `busy` details of a program lock carry `program` as the program's key
  (`p1:/path`), like every other error, instead of its project path (now in `path`).
- A `script` result's `changed` now says whether the script changed the program (always false
  for a contained script, whose changes are rolled back); the new `unsaved` says whether the
  program has unsaved changes, which is what `changed` used to report.

### Fixed

- **A writer's read-only script was journalled as a change** (HeadlessSession). A script run by
  an owner or shared writer of a program with unsaved changes (from anyone) answered
  `changed: true` and added a `script` entry to the author journal, although it changed
  nothing; on a shared program every query script did so. The session now compares the
  program's modification number before and after the script. Found by `daemon_tests.py edit`.
- **A program killed while being written into a project was listed but could not be opened**
  (Ghidra, `Framework/FileSystem` `LocalDatabaseItem.create`). Ghidra wrote the new item's
  property file, with its file type, before streaming the database in, so a process killed
  mid-write (an import's save, or a *Save As*) left an item that every later open listed as a
  program and failed to open ("Unrecognized file format"). The file type is now written once
  version 1 of the database is complete; an item killed earlier is removed by Ghidra's existing
  repair the next time its folder is listed. Found by `daemon_tests.py import_write_kill`.
- **`kill` returned before the daemon's process was gone** (`ghidra_session.py`). It waited for
  the instance lock only; a daemon killed during a large write on ReFS kept its project lock
  for seconds more (closing a file with many dirty pages waits for them), so a daemon started
  right after got `conflict` ("locked by another process", `live: true`). `kill` now also waits
  for the process to exit (within its 30 s). Found by `daemon_tests.py import_write_kill`.
- **A daemon started after a crash could take minutes to become ready** (HeadlessSession).
  Ghidra's `DBInitializer` deletes the buffer cache files dead processes left in the user temp
  folder before start-up goes on; with `tmpdir` on ReFS, deleting the large cache file of a JVM
  killed while it held a big program waits until ReFS has written its dirty pages back
  (measured: 43 s, 61 s and once 222 s, beyond the launcher's 180 s wait). On a class cache hit
  the session now does this cleanup itself on a background thread, and on Windows renames each
  file first (which fails while any live process has it open), truncates it to 0 bytes (which
  drops its unwritten pages) and deletes it: the next daemon was ready in 0.35 s. Found by
  `daemon_tests.py import_write_kill`.

### Tests

- `daemon_tests.py`: `edit` (the `edit` command, all or none, `expect` naming the author;
  `discard_edits` deleting newly created labels), `overlay_owned` (an overlay of a program
  another client owns writable, with the owner saving while it is open), `refresh_force`,
  `legacy_overlay` (overlays of a 12.1.4-format program, during and after its upgrade cache
  build), `orphan_shutdown` (orphaned shared-write work discarded and logged at shutdown),
  `import_write_kill` (the daemon killed during an import's final write: the program absent or
  complete, never half).
- `parallel_imports` cancels its import during the load: on a fast CI runner its fixed 1 s
  delay let the cancel arrive during the final write, which is not cancellable (README,
  "Parallel imports", now says so).

## 12.3-hydra.1

Released 2026-10-26. The first release. Based on upstream Ghidra `master` (12.3 DEV) as of
2026-10-26, commit `057a646233edfb21768a42a0aabc1d1a7709da19`.

### Downloads

One zip, `hydra-engine-12.3-hydra.1-win_x86_64.zip`: the headless install for Windows x64
(`gradle zipHeadless`), on which the release workflow ran both test suites after unzipping it.
You need a JDK 25 and Python 3.10 or later; the install has no JDK.

### Known limits

- **Projects saved by this build cannot be opened by Ghidra 12.2 or 12.1.4.** Upstream `master`
  writes data type databases at version 3; 12.2 and 12.1.4 read version 2. A project opened
  read-only is not written; open older projects writable only from a copy. The
  `legacy-12.1.4` branch serves projects that must stay on 12.1.4.
- **Based on a development snapshot.** Upstream `master` is Ghidra's next version under work
  (12.3 DEV), not a Ghidra release.
- **Windows only.** CI and releases build and test on Windows. The module and launcher have no
  Windows-only path, but no Linux or macOS claim is made: neither is released or tested.
- **There is no GUI.** Headless only: no help, javadoc or Python type stubs; `gradle buildGhidra`
  still builds the whole source tree, from source.

### Added

- **HeadlessSession module** (`Ghidra/Features/HeadlessSession`): a shared headless session
  daemon, one per state directory and instance. One JVM serves several projects and clients over JSON lines on an
  authenticated loopback socket (or stdio), with protocol version 2.
  - Projects opened in place: read-only without a lock, or writable with one.
  - Programs opened and switched without importing; imports with any Ghidra loader,
    deduplicated by SHA-256.
  - Analysis, decompiling, renames, comments, saves, and GhidraScripts (Java or Python) with
    arguments; scripts on programs a client does not own run contained and are rolled back.
  - Two scheduling lanes (quick and long, round-robin by connection), one writer and several
    readers per program, per-client cancel, a disconnected client's requests cancelled and its
    uncommitted changes rolled back when its running request ends, idle shutdown, warm programs
    kept open for the next client.
- **`ghidra_session.py`**: a standard-library-only Python launcher, daemon manager and client
  (`connect()`), with no `.bat` or `.sh` launcher. Fast start with a class search cache and,
  on JDK 25+, an AOT cache.
- **Tests**: `examples/session_smoke.py` and `examples/daemon_tests.py`.
- **Headless build** (`gradle buildHeadless`, `gradle/hydra/headless.gradle`): an install
  without the modules only an interactive tool uses, the help, javadoc and Python stubs, and with
  a check that no module of the install depends on one it leaves out. `gradle buildGhidra` still
  builds the whole source tree.
- **Repository**: this README (Ghidra's original is `README-GHIDRA.md`), `NOTICE-HYDRA`, a
  security policy and contributor guide in `.github/`, issue and pull request templates, and CI
  (`.github/workflows/ci.yml`) that builds the headless install and runs both test suites.
- **Releases** (`.github/workflows/release.yml`): a tag `v<version>` builds the headless zip on
  Windows, runs both test suites on the unzipped install, and publishes the zip, `SHA256SUMS`
  and this file's section as a GitHub Release.
### Branches

- `main`: the above, on upstream `master`.
- `legacy-12.1.4`: the same module on Ghidra 12.1.4, kept for projects analysed with 12.1.4.
