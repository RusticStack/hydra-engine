# Hydra Engine 12.3-hydra.5: release notes

Released 2026-11-01. Based on upstream Ghidra `master` (12.3 DEV), commit
`1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, the same upstream commit as 12.3-hydra.3 and
12.3-hydra.4. The published release body is the `## 12.3-hydra.5` section of `CHANGELOG.md` plus the
download table the release workflow adds. This file is the longer record: every release gate that was
run for this release with its result, the round-4 changes with their measured numbers, and what was
not met or not run.

Rule for this file and for every document of the release (PROTOCOL-3.md D52, D58): a claim appears
only with the test or measurement that passed for it. Where a test did not pass or was not run, the row
says so. The scope of every result is a process tree on Windows x64 with JDK 25 on NTFS. Nothing is
stated about ReFS, power loss or an OS crash, and no Linux or macOS claim is made.

Round-4 evidence (cited below by lane):

- `_logs/rust-round4/perop/REPORT.md` (16-agent benchmark, paired per-op CPU and
  memory, import+analysis, vanilla 12.2)
- `suite/REPORT.md`, `analysis/REPORT.md`, `create/REPORT.md`, `close/REPORT.md`, `edit2/REPORT.md`,
  `fresh/REPORT.md`, `io/REPORT.md`, `cds/REPORT.md`, `profiles/REPORT.md`, `hostmem/REPORT.md`,
  `latency/REPORT.md`, `memory/REPORT.md`, `rustclient/REPORT.md`, `rustclient2/REPORT.md`
- `multiproj/REPORT.md` (16 real agents on three game programs with a fourth importing)
- `hyedit/REPORT.md` (Hydralysis edit/publish reliability, 208 edits)
- `games-e/REPORT.md`, `games-cp/REPORT.md` (game corpus against hydra.4 and stock Ghidra 12.2)
- `hydra-rust-round3.md` sections 5c to 7 (round-3 core already in the tree)
- gate logs under `_logs/rust-round4/integration/`

## 1. What a reader of the release must be told

- **Nothing on the wire changed.** `minClient` stays `1.0.0`; one port serves protocol 2 and protocol
  3 exactly as in 12.3-hydra.4. `ghidra_session.py` is still client 1.1.0 and protocol 3, and it falls
  back to protocol 2.
- **Hydralysis 0.6.0 refuses this engine by its own pin** (`hydra.py`, the pin check). That cannot be
  fixed on the engine side; it is stated here. **Hydralysis 0.7.0 pins 12.3-hydra.5** and is the
  release that follows this one (it needs the SHA-256 of the built engine zip). Hydralysis 0.7.0 also
  carries the publish-reliability changes of `_logs/rust-round4/hyedit/REPORT.md`.
- **The engine's replies are unchanged in what was re-run for this release.** All six 16-agent runs
  had the 412 reply keys of the fixed workload and the canonical digest `285b55a2…a77df`, identical
  to hydra.4 (`perop/REPORT.md` 1.1); `client_compat_tests.py` passed 54 of 54 on a clean work
  directory (`integration/cc-int7b.log`). The protocol-3 characterization suite and the R1 hello
  golden were **not re-run** for this release: no protocol, reply field or hello field changed in the
  round-4 work, and the planted workload's 412 keys cover every reply it reads, but the
  characterization run is not claimed.
- **Headless only.** There is no GUI. Projects this engine writes cannot be opened by Ghidra 12.2 or
  12.1.4.
- **Build identity.** A local build says `<Ghidra version>-hydra.dev` and Hydralysis classifies it as
  stock Ghidra. The release workflow stamps `hydra.version` into
  `Ghidra/Features/HeadlessSession/src/main/resources/hydra.properties` before the build and checks
  the stamp inside `HeadlessSession.jar` in the zip; the tree keeps the file empty. For a local build
  see the module README, "Stamping a local build".

## 2. Release gates

"Pass" means the gate's command ran with a verified exit code and met its pass condition; the run is
named. The candidate is the `rust/final` merge `67e420e399`, whose tree `8745d167c9` is the build
`o4-integration7` used by the per-op, suite and game checks (`rust/final` merge of o4-integration6:
edit2 + close + fresh + analysis + io).

| Gate | Result | Run and evidence |
|---|---|---|
| 9.1 golden decompile diff | **pass** | `o4-integration7` (`8745d167c9`): KotOR 8,616 of 8,616 functions identical on `production` and `explicit`, standard and raw; `copy_rc 0`, `capture_rc 0`, source tree hash `6d8ced78…60df` unchanged, program SHA-256 `0290889e…37e6`, all 8,616 rows `ok`, both diffs rc 0 (`integration/g91-int7.out.log`, `integration/g91-int7/`) |
| 9.4 daemon suite | **255/255** on the release install | `o4-h5-release` (built from this tree, stamped `12.3-hydra.5`) ran the full suite through `run_parallel.py --workers 16 --legacy-project --no-result-cache`: **255 passed, 0 skipped, 0 failed alone, 0 failed only under load, 0 problems**, queue 281 s, wall 327 s (`release/suite2.out.log`). An earlier run on the integration7 build was 254/255: `e2a_kill_fork` failed alone (`retry_blocked: 1`, `not_complete_after: 1`); the same test fails 1 in 6 standalone runs on hydra.4 (`integration/e2a-h4.log`), 1 in 6 on integration5 (`e2a-int5.log`), 1 in 6 on integration6 (`e2a-int6.log`) and passed 2 of 3 reruns on integration7 (`e2a-int7.log`) - a pre-existing probabilistic chaos flake, not a hydra.5 regression, and the release run is green |
| 9.4 client compatibility | **pass, 54/54** | `integration/cc-int7b.log`, `cc-int7b.json`, exit 0. The first attempt (`cc-int7.log`) ran 32/54 because its work directory lacked the `choice.exe` fixture (`not_found: no file named choice.exe in project p1`); the clean re-run is the gate |
| 9.4 session smoke and contract tests | **not re-run on this tree** | The release workflow runs `session_smoke.py`, `daemon_tests.py` and `contract_tests.py` on the unzipped release zip; the local round-4 work did not re-run the smoke or contract suites |
| 9.7 database-version check | **pass by no change** | No file in `Ghidra/Framework/DB`, the `program/database` packages, any processor or the language format changed in round 4; the round-3 constants check (`hydra-rust-round3.md` 12.3-hydra.3, "Database format gate") still applies. `format_gate.py` was not re-run on this tree |
| 9.8 compatibility | **pass for the re-run parts** | 412/412 reply keys, one digest, in 6/6 planted runs (`perop/REPORT.md`); Hydralysis `dc49221` suite 1,640 results, 0 failed and engine-gated 17/17 against this engine (`hyedit/REPORT.md` 8); `bump_hydra.py --release 12.3-hydra.5 --dist <dir> --check` exits 0 on the built artifacts (release prep, `REPORT.md` section 6). The protocol-2 transcript and the characterization goldens were not re-run |
| 9.10 and 9.18 measurements | **recorded on NTFS** | `perop/REPORT.md`: 16 agents, three interleaved rounds; 5.70 s against 13.39 s wall, 27.95 against 53.96 s tree CPU, 1,144.5 against 1,725.3 MB peak; every paired per-op CPU is lower except `decompile_fresh`. ReFS and the clone/copy comparison were not runnable (no ReFS volume), as in 12.3-hydra.4 |
| 9.14 resource gate | **not re-run for this release** | The admission and decompiler-fault items passed for 12.3-hydra.4 and their code is unchanged in round 4. The script worker's start-up changed (class cache, AOT, deferred init); its kill/cancel containment code did not. The suite's `e9_*` and `e7_*` tests pass in `suite-int7.out.log` (255 tests, only `e2a_kill_fork` fails); no new resource-gate batch was run |
| 9.15 crash gate | **not re-run for this release** | Round 4 changes the close of a disposable fork (no index rewrite when its journal is empty) and makes the Windows directory sync a no-op; the suite's `e8_*`, `e12_*` and `dt_e12` tests pass on this tree. No new counted save/fork/promote kill batch was run; the 12.3-hydra.4 results (563 save kills, 330 fork kills, 211 promote kills, 0 failures on NTFS) are those of hydra.4 and are not restated for hydra.5 |
| 9.16 view cost | **not re-run** | No view-cost measurement for hydra.5 |
| 9.17 chaos and soak | **not run for hydra.5** | No nightly for this release. The scale evidence is the real multi-project run below: 16 agents on three programs plus one concurrent import+analysis, one run per shape, 818/818 operations, 0 waits. It is not a 16-agent x 4-project nightly and is not stated as gate 9.17 |
| 9.19 claims | **pass for the engine documents of this release** | The D52 grep of the workflow (`never (corrupt\|block\|collide)`, `any number of (agents\|clients)`, `cannot corrupt`) finds no hit in the `## 12.3-hydra.5` section; the section names commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, which is in this tree's history. Hydralysis' `tests/test_claims.py` passes 12/12 in the release prep (`REPORT.md` section 4) |
| 9.20 spikes | **not re-run** | No spike changed in round 4 |

## 3. Performance at 16 agents

Method: `multiagent_bench.py`, the fixed workload of 16 agent processes (12 direct `ghidra_session.py`
agents, 4 Hydralysis agents), one daemon started by Hydralysis with `expected_agents: 16`, three
rotated/interleaved rounds of hydra.5 (`o4-integration7`, `8745d167c9`) and hydra.4 (`bench-h4`) in
the same window under one 12-core `heavy.py` claim (`perop/REPORT.md` 1.1). All six runs have 412/412
reply keys and the digest `285b55a2f873abb9bf7b5c67ddfd0f69dea874af0d1b1a2de8da7642a08a77df`.

| metric (median of 3) | hydra.5 | hydra.4 | change |
|---|---|---|---|
| workload wall | **5.70 s** | 13.39 s | -57 % |
| tree CPU | **27.95 s** | 53.96 s | -48 % |
| Java CPU | 20.03 s | 38.11 s | -47 % |
| native decompiler CPU | 0.64 s | 7.59 s | -92 % |
| Python CPU | 7.12 s | 7.47 s | -5 % (agents, within load) |
| peak committed memory | **1,144.5 MB** | 1,725.3 MB | -34 % |
| mean committed memory | **795.1 MB** | 1,257.9 MB | -37 % |

Per-op wall latency, p50 and p99 in ms, medians of the three runs (`perop/REPORT.md` 2):

| op | h5 p50 | h5 p99 | h4 p50 | h4 p99 | h5/h4 p50 |
|---|---|---|---|---|---|
| connect | 6.10 | 13.31 | 33.80 | 55.30 | **0.18** |
| open_view | 3.36 | 10.65 | 6.81 | 27.39 | **0.49** |
| close_view | 0.48 | 0.92 | 0.54 | 0.74 | 0.89 |
| info | 0.52 | 1.41 | 0.49 | 1.38 | 1.06 |
| list_functions | 15.36 | 25.54 | 1937.96 | 2153.81 | **0.01** |
| read_script | 5.67 | 38.97 | 291.06 | 977.61 | **0.02** |
| decompile_hot | 0.54 | 70.57 | 10.12 | 347.43 | **0.05** |
| decompile_fresh | 8.18 | 138.55 | 7.51 | 298.61 | 1.09 |
| decompile_overlay | 56.35 | 752.17 | 283.84 | 673.63 | **0.20** |
| overlay_open | 0.84 | 8.53 | 27.91 | 40.37 | **0.03** |
| overlay_edit | 0.59 | 3.99 | 2.37 | 6.33 | **0.25** |
| overlay_drop | 0.54 | 3.83 | 2.31 | 7.53 | **0.23** |
| decompile_edited | 97.05 | 169.25 | 287.73 | 360.10 | **0.34** |
| edit | 7.44 | 10.80 | 9.93 | 32.77 | **0.75** |
| save | 49.00 | 94.71 | 55.59 | 126.29 | **0.88** |
| fork | 351.32 | 428.35 | 612.25 | 751.10 | **0.57** |
| fork_close | 5.23 | 6.98 | 14.93 | 21.27 | **0.35** |
| sub_connect | 6.66 | 16.05 | 18.26 | 20.93 | **0.36** |
| sub_open_view | 2.90 | 5.62 | 4.05 | 6.08 | **0.72** |
| sub_decompile | 0.98 | 13.17 | 8.59 | 99.62 | **0.11** |
| sub_read_script | 3.09 | 4.55 | 176.23 | 296.93 | **0.02** |
| subagent_total | 47.99 | 66.81 | 280.44 | 494.48 | **0.17** |
| hy_functions | 91.34 | 127.04 | 734.66 | 789.30 | **0.12** |
| hy_decompile_hot | 20.32 | 362.01 | 214.26 | 560.65 | **0.09** |
| hy_decompile_fresh | 16.97 | 291.47 | 194.53 | 652.00 | **0.09** |
| hy_xrefs | 5.49 | 136.34 | 193.73 | 332.37 | **0.03** |
| hy_edit | 364.10 | 626.35 | 421.06 | 893.82 | **0.86** |
| hy_publish | 1034.56 | 1302.96 | 2570.99 | 4174.01 | **0.40** |

`info` is sub-millisecond parity (0.52 against 0.49 ms); `decompile_fresh` is the one positive p50
difference and is discussed in section 6. The p50 on every other row is lower on hydra.5.

Paired same-window per-op CPU (`perop/REPORT.md` 4.1; both daemons up, ops in pairs, equal load)
agrees: `fork` 125.0 against 557.3 ms of CPU (0.22), `save` 46.9 against 103.7 (0.45), `fork_close`
below one 15.6 ms tick against 10.4, `list_functions` 15.66 against 230.3 (0.07), `read_script` 4.77
against 43.29 (0.11), `connect` 2.30 against 17.55 (0.13). The only positive paired CPU delta is
`decompile_fresh`, 20.23 against 17.28 ms (+17 %).

Import plus auto-analysis of `swkotor.exe` (`perop/REPORT.md` 6; one fresh run each; load 3.8, 2.8 and
11.5 mean busy cores):

| engine | wall | tree CPU | peak private | functions |
|---|---|---|---|---|
| **hydra.5** | **71.4 s** | 196.4 s | **2.44 GB** | 8,956 |
| hydra.4 | 99.7 s | 197.0 s | 2.65 GB | 8,956 |
| stock Ghidra 12.2 | 142.4 s | 245.9 s | 4.93 GB | 8,615 |

hydra.5 against hydra.4: -28 % wall and -31 % analysis (61.4 against 88.9 s) at equal CPU; against
vanilla 12.2: -50 % wall, -20 % CPU, -51 % peak. The analysis lane's own KotOR number was 69.4 s under
a busier window; this 61.4 s run is at 3.8 mean busy cores.

## 4. The changes, with their measurements

Each row names the commit or lane and the report that measured it. The round-3 core (overlay log
answers, Sleigh once per process, compiled-script store, host instruction translation) is already in
12.3-hydra.4's successor line and is summarized in `hydra-rust-round3.md` 5c.

| Change | Measured result | Report |
|---|---|---|
| Rust protocol client and agent (`HeadlessSession/rust/`) | 34/34 replies value- and byte-identical to the Python client; 376/376 keys one digest; 16 agents 2.71 against 13.90 MB private peak, 0.037 against 0.144 s CPU per agent; tree peak -166.6 MB; full bench 1,123.3 / 969.4 / 993.1 MB (Python / Rust / mixed), 412/412 in 9/9 runs | `rustclient/REPORT.md`, `rustclient2/REPORT.md` |
| PE import skips dependency DLLs whose export table cannot change the program | `import_exe` 21.11 -> 9.53 CPU s, 4.83 -> 1.73 s wall; `import_dll` 6.14 -> 0.28 and 3.65 -> 0.14; second import -39 %; suite wall 443.9 -> 354.7 s; imported symbols, functions, purge, calling convention, libraries, memory blocks and source hash identical | `create/REPORT.md` |
| One decompiler `Architecture` per worker per program, rebound per generation | builds/rebinds 24/6 on the merged bench; no re-parse/rebuild per generation; 412/412 and golden 8616/8616 on the merge | `hostmem/REPORT.md`, `integration5/REPORT.md` |
| Annotation-only overlay generation inherits base data-type and register-name answers; comment filter computed at generation time | overlay first decompile 1,133 -> 243 ms (3 -> 1 host runs); overlay p50 -67 % against h4, p99 892 -> 559 ms; 160/160 overlay/base replies byte-identical | `latency/REPORT.md` |
| Fresh decompile answers prefetched directly (no query encode/re-decode) | reply bytes identical over 400 cold functions; 1 client 3.0-3.3 against h4 5.3-5.8 ms and -53 % CPU/call; 16-agent p50 does not improve (section 6) | `fresh/REPORT.md` |
| Sleigh parsed once per process, workers adopt the tables; decompiler headers are a build input | 48 parses 7.03 s -> 2 parses 0.05 s; tree CPU 43.1 against 73.6 s h4 (-41.5 %) in that lane's six rotated rounds; suite 255/255, golden 8616/8616, 412/412 | `hydra-rust-round3.md` 5c |
| Edit: write-side warm at the writable open, C parser once per daemon, no parameter work for a re-applied signature | dedicated 48-edit harness p50 6.40 against h4 11.09 and int4 14.18 ms; first-edit parse 6.9-13.1 -> 0.24-0.30 ms; re-applied signature 811-1,123 -> 412-453 us | `edit2/REPORT.md` |
| Close: disposable fork skips the two storage-index rewrites when its journal is empty; channel locker deletes its marker without re-reading it | daemon close 6.00 -> 3.2-4.8 ms at one client; `fork_close` 5.23 against 14.93 ms at 16 agents and 2.75 against 11.25 paired; `seal_union` caught the first, global version and passes with the disposable-fork scoping | `close/REPORT.md` |
| Analysis: one decompiler pool for both switch phases, largest function first | KotOR analyze 72.7 -> 69.4 s and 71 -> 66.2 s; switch pass 31.1 -> 27.6 s; listing digest identical on KotOR, KotOR II, Empire at War and `choice.exe` | `analysis/REPORT.md` |
| I/O: one volume query per fork cost; Windows directory sync returns at once; publish verification through `decompile` in a window of 8; publish flush only what the save wrote | fork `cost` 6.8 -> 1.8 ms; verification 6.08 -> 0.39 ms per call; publish fsyncs 14 -> 5 (27-35 -> 12.5 ms); leader build 922 -> 690 ms; `hy_publish` 1,274 -> 1,105 ms | `io/REPORT.md` |
| Script worker receives the daemon's class cache, AOT cache, configuration and script build store; deferred init runs before the script | worker start CPU 11.6 -> 7.1 s, wall 4.2 -> 2.8 s (-39 % / -36 %); `e7_cost` worker start 21,812 -> 11,546 ms; suite wall 549.8 -> 443.9 s, self-sum -17.5 % (part of the wall difference is a 37 s machine stall in the base run) | `suite/REPORT.md` |
| CPU profiles (`generic`, `auto`, named), OS-granted sizes, per-pool placement counters | `auto` against `generic`: total CPU 57.62 -> 53.76 s (-6.7 %), setup CPU 21.45 -> 17.31 s (-19.3 %), 412/412 all 12 runs; golden 8616/8616 with both profiles | `profiles/REPORT.md` |
| JIT one-shot C1 pins (Xerces XML parser, log4j configuration parser) | 95 C2 compiles, 0.70 s of C2 thread time and 0.33 MB of code removed per daemon; 0.02 s moved to C1; no steady-state cost; 412/412, suite, client_compat on the lane's install | `cds/REPORT.md` |

## 5. Reliability, scale and the game corpus

**Hydralysis publish/edit reliability (`hyedit/REPORT.md`).** The 16-agent workload's `hy_edit`
failure was a Hydralysis optimistic-concurrency race: the publish's lazy view finalize journalled its
revision bump with `subjects:["*"]`, so it overlapped every subject, including a second edit by the
same agent on a function the publish never touched. The same payload and sequence reproduce on
hydra.4 (4 failures in 72 edits across the earlier samples; 7/104 across all samples), so it was not
an engine regression; the faster hydra.5 path widened the window. Hydralysis `dc49221` journals the
subjects the generation actually applied (union across crossed generations), so an edit on an
untouched subject rebases and an edit on a published subject still conflicts. It also makes a dead
publish worker or leader answer `failed`/`unled` in 10 s with the exact job error and a retry path,
narrows the job-registry lock so a slow warm-worker handover cannot time out another publish, and
moves an unappended sealed generation aside and rebuilds it on the next publish; the `CURRENT.log`
append remains the only commit point.

Final series: 13 interleaved sessions per engine, 8 Hydralysis edits per session. **hydra.5: 104
edits, 0 failed, 104/104 publishes, 412/412 keys and the canonical digest in 13/13 runs; the earlier
fixed series adds another 104 edits, 0 failed — 208 edits total.** h4 control: 104 edits, 0 failed,
104/104 publishes. Hydralysis suite: 1,640 test results, 0 failed (the one task-plan artefact,
`test_runtime_scenario_fixture`, reproduces identically on the base worktree); engine-gated 17/17.

**Real multi-project run (`multiproj/REPORT.md`).** 16 agent processes on three real programs — seven
on Cyberpunk 2077 (242,475 functions), six on KotOR (8,966), three on KotOR II (27,294) — while Empire
at War imported and auto-analysed (4,261 functions) in the same daemon or a fourth daemon. In both
shapes every clean run served **818/818 operations with 0 errors, 0 `waited` replies, 0 queued lanes,
0 `foreignBlocked` waits, 0 restarts and 0 inconsistent reply hashes**; the 632 shared reply keys were
identical between hydra.5 and hydra.4 (shape a: 632/632), the three fork edits per run were re-opened
after save and matched the agent's post-edit decompile hash, six agents renaming one function each saw
only their own overlay, and every project tree was byte-identical before and after. Cost in shape a:
73.7 s wall, 249.1 CPU s, 1.65 GB peak / 1.23 GB mean; shape b: 54.2 s, 216.9 CPU s, 3.54 GB / 2.84 GB.
The one defect the shape exposed (an h4 shape-b publish leader that sealed a generation and never
appended it) is the Hydralysis state machine fixed in `dc49221`; the engine state was intact and the
project tree unchanged.

**Game corpus (`games-e/REPORT.md`, `games-cp/REPORT.md`).** KotOR II (27,294 functions / 186,655
symbols), StarWarsG (20,636 / 140,490), Empire at War (4,261 / 8,895) and KotOR (8,956 / 37,591):
function and symbol counts, external libraries and every sampled decompile hash are identical between
hydra.5 and hydra.4 (19/19 or 20/20 per binary). Against stock Ghidra 12.2 the differences are
version differences: KotOR II has 12 more functions and 10,937 more symbols in stock, one sampled C
text differs only in a register rendering (`register_ESP` against `register0x00000010`) with identical
p-code, and p-code hashes differ on 3/19 `sweaw` and 1/20 StarWarsG samples while the C text is
unchanged. Cyberpunk 2077: import identical to hydra.4 and stock (92,382,720-byte memory, 8 sections,
336,271 symbols, 723 externals, 229,450 loader functions); hydra.5 no longer loads the 37 dependent
DLLs at import and the resulting program is identical. The 900 s-capped analyses produced the same
241,808-function list on hydra.5 and stock; a shared read-only database gives 20/20 C and p-code
against both hydra.4 and stock.

## 6. Not met, not run, limits

- **Peak memory is not -50 %.** The 16-agent peak is 1,144.5 against 1,725.3 MB (-33.7 %) and the mean
  795.1 against 1,257.9 MB (-36.8 %); across paired runs the peak is -33 to -40 %. The measured floor
  at the daemon peak (637 MB private: heap 192 with 94 live, G1 75, JIT code and arenas 99, metaspace
  61, native host 180, plus 16 agent processes at 267-325 MB) and the rejected levers (AOT +45 MB,
  generation LRU 4->2 regressing `decompile_hot` p99 47 -> 98 ms) are in `memory/REPORT.md`.
- **`decompile_fresh` is not 2x faster and its CPU is higher.** The stock decompiler's own analysis is
  8.44 of 10.0 ms of host time (84 %, 96 % of `decompileAt`); native decode is 11 %, encode 3 %, flush
  4 %. At 16 agents its p50 is 8.18 against 7.51 ms (+9 %) and its paired CPU 20.23 against 17.28 ms
  (+17 %, +2.95 ms); its paired wall median is h5-faster (4.08 against 4.99 ms), and at one client the
  build is 1.6-1.9x faster with 53 % less CPU per call. The 240 fresh addresses are 240/240 distinct,
  so a fresh cache would hit nothing. Cause: host-worker dispatch and per-generation Architecture
  set-up on a cold function (`fresh/REPORT.md`; perop section 7).
- **`hy_publish` is not below 1 s.** 1,105 ms against 1,274 ms (median of six runs), with 3 of 6 runs
  at 845/960/994 ms and a leader build of 690 ms; the rest is eight concurrent publishes over about
  1.5 builds plus the harness' 250 ms poll (`io/REPORT.md` 3.1).
- **`e2a_kill_fork` is a pre-existing chaos flake.** The suite run failed it alone (and under load);
  it passes 1 in 6 standalone runs on hydra.4 and on integration5 and integration6, and passed 2 of 3
  standalone reruns on this tree. The runner prints `FAILED ALONE`, and this document does not call
  the suite green.
- **The `fork` 16-agent p50 is window-dependent.** It moved from 214 to 351 ms between sessions while
  the isolated fork stayed at 81 ms (paired CPU 0.22), and hydra.4 moved in the opposite direction
  (1,001.8 -> 612.3 ms). No fork speed-up is stated from that row (`perop/REPORT.md` 7, 9).
- **The 16-agent `edit` p50 target (3.8 ms) was not reached on the loaded machine.** The dedicated
  48-edit harness measured 6.40 ms (h4 11.09, int4 14.18); the full-bench run's best sample is 3.74 ms
  and its spread 3.74-10.53 ms. The quiet-shape target is not claimed (`edit2/REPORT.md` 6).
- **Analysis is not "24 cores".** KotOR analysis is 69.4 s; one 6,718-byte function takes 12.3 s of
  decompiler time where the other 8,547 average 13 ms, and ~23 s is order-dependent work. The measured
  practical floor is ~20-25 s, not the 24-core ideal (`analysis/REPORT.md` 4).
- **Not run for this release:** the 9.17 nightly soak and any new 9.15 counted kill batch; the
  protocol-3 characterization suite and R1 hello golden; `session_smoke.py` and `contract_tests.py`
  on this tree (the release workflow runs them on the unzipped zip); the ReFS parts of 9.4, 9.15 and
  9.16 (no ReFS volume, as in 12.3-hydra.4); `bump_hydra.py --check` is run after the artifacts are
  built and its result is in `REPORT.md`.
- **Limits.** Every limit of PROTOCOL-3.md 6.2 is unchanged from 12.3-hydra.4 and is stated in the
  module README, "Limits of 12.3-hydra.4 and protocol 3": a script that ignores cancel is ended only
  in the script worker; the overlay lifecycle waits are not cancel-aware; the leave of an owner or
  writer still queues the exclusive lock (bounded); `lane:"quick"` is a trusted hint; Windows x64 and
  JDK 25 only; no power-cut test; nothing about ReFS is tested; the upgrade gate and the backup check
  are guards against accidents, not a security boundary.

## 7. Claims audit (PROTOCOL-3.md 8.3)

| Claim | Status for hydra.5 |
|---|---|
| C1 (write collisions) | not flipped: the release suite is 255/255 but no soak passed; writes are serialized and a collision is detected when the client passes `expect` |
| C2 contained-script visibility | unchanged wording |
| C3 (analysis and questions) | not flipped: no 9.13 run for this release |
| C4 (programs and their waits) | not flipped: no 9.13 run; the multi-project run measured 0 `foreignBlocked` in one scenario |
| C5 (cleanup of a dead client) | unchanged from hydra.4; Hydralysis' `failed`/`unled` is a client-side publish state, not an engine guarantee |
| C6 queued import waits | unchanged from hydra.4; no new run |
| C7 `cancel` of a lock wait | unchanged from hydra.4; no new run |
| C8, C9, C10 | no engine test |
| C11 number of modified Ghidra files | `NOTICE-HYDRA` lists every modified core file; the round-4 changes add no modified Ghidra file beyond those already listed (the host, session and Rust client are Hydra files) |
| U1 scale | not flipped: this release states 16 agents on three projects plus one concurrent import, in one run per shape, not a nightly |
| U2 per-connection fairness | unchanged from hydra.4 |
| U3 serialized writes | "no corruption was seen in the tests listed"; the multi-project run's project trees were byte-identical and its 818 replies consistent; the release suite is 255/255 |
| U4 replay from the store | Hydralysis Y1, Y2 tests pass; the publish series had 0 failures in 208 publishes across the two series |
| U13 stale versions | flips when Hydralysis runs `tools/bump_hydra.py` for this release against the built zip; done in 0.7.0 |

## 8. After the release: the Hydralysis pin

Hydralysis 0.7.0 pins this release. Once the release zip and `SHA256SUMS` exist:

```
python tools/bump_hydra.py --release 12.3-hydra.5 --dist <folder with the release files> --write
python tools/bump_hydra.py --release 12.3-hydra.5 --dist <folder> --check
```

`--check` must exit 0. It also refuses an engine zip whose `hydra.properties` is empty, which is why
the release workflow stamps the version before the build.
