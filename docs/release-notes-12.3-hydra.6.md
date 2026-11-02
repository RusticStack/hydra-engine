# Hydra Engine 12.3-hydra.6: release notes

Prepared 2026-11-02. **Not tagged, not pushed, not published.** Based on the same upstream Ghidra `master` (12.3 DEV)
commit as 12.3-hydra.5. This release adds the semantic trace and the `decompile` response cap and fragment-wise decompile of
issues 6 and 7 (see `CHANGELOG.md`). This file records every gate that was run for the release with its result, the lane
measurements of the non-functional workstream (sections 1 to 6), and what was not met or not run.

Rule (as in the hydra.5 notes): a claim appears only with the run that produced it. Scope of every result: a process tree on
Windows x64 with JDK 25 on NTFS, on one shared machine (system requirements in `README.md`; other lanes were running on it, which
is why wall times in the soak differ between runs). Nothing is stated about ReFS, power loss, Linux or macOS.

Evidence: `E:/Projects/Hydra/_logs/trace-final/F/` (gates of section 0), `_logs/trace-final/` (the first gate pass on the
pre-merge install, same results), `_logs/trace-lnfr/` (sections 1 to 6).

## 0. Release gates of the candidate

Candidate: branch `trace/final-eng` = `trace/integration` (including `trace/issues-eng` 241439c72d) plus the snapshot fix of 0.1.
The install under test is `C:/dev-overflow/hydra-engines/trace-final/ghidra_12.3_DEV` on NTFS, stamped
`hydra.version=12.3-hydra.6` (the hello and the golden capture header say `12.3-hydra.6`), made by `_logs/trace-final/build.sh`: a
copy of the published 12.3-hydra.5 install with the `HeadlessSession.jar` classes recompiled from the tree (javac, JDK 25.0.4),
`DecompInterface` and `DecompileProcess` in `Decompiler.jar`, `HydraCpu` in `Utility.jar` (ABI 2), the release `hydra_native.dll`
(with the trace), `hydra-trace.exe`, and `hydra-agent.exe` and `hydra-etw.exe` from `build-install.py`. It is **not** a Gradle or CI
build of the release zip; the zip and its SHA-256 do not exist yet.

| Gate | Result | Run (under `F/`) |
|---|---|---|
| Golden 9.1 (KotOR, 8,616 functions, `production` and `explicit`, standard and raw) | **pass**: 8,616 of 8,616, all rows `ok`, both diffs rc 0, source tree hash `6d8ced78...60df` unchanged, program SHA-256 `0290889e...37e6` | `g91b.out.log`, `g91b-result/` (a first attempt `g91.out.log` reported FAIL only because its copy directory already existed, `copy_rc 1`; rerun on a clean work directory) |
| `daemon_tests.py`, 268 tests (the 255 of hydra.5 plus 13 trace cases), `run_parallel.py --workers 16 --no-result-cache` | **263 passed, 0 skipped, 3 failed alone, 2 failed only under load, 0 problems**. The 3 are environmental (0.2) and pass (3/3) when the fixture is opened as its owner. The 2 under-load failures (`refcount_leak`, `yield_slots_stress`) passed alone | `daemon.log`, `legacy.log` |
| Named flaky cases run alone | `cpu_profile_identical`, `e2a_kill_fork`, `e9_decompiler_faults`, `e9_guarded_threads`, `trace_agent_workload`, `trace_client_identity`: **6/6 passed** | `flaky.log` |
| `client_compat_tests.py` (54 of hydra.5, 2 trace, 2 issues 6/7) | **58/58** | `cc.log` |
| `contract_tests.py` | **7/7** | `contract.log` |
| `session_smoke.py` | all smoke checks passed | `smoke.log` |
| Python and Rust client identity including trace | **pass**: `trace_client_identity` (16 trace requests, reply lines byte-identical between `hydra-agent` and `ghidra_session.py`) and `trace_agent_workload` | `flaky.log` |
| 16-agent bench, 825 operations, h5 against the candidate, 3 rotated rounds, 6 configurations | **pass**: 412 of 412 reply keys, digest `285b55a2f873abb9` in all 18 runs, `foreignBlocked` 0 and `contended` 0 in all 18 (0 requests waiting), trace digest `c12316d79475b820` in all 6 trace runs, 0 trace errors, 10,000 to 10,200 live events accepted per run | `bench-report.md` (0.4) |
| Multi-project soak (16 agents, three game programs, Empire at War importing; live capture and 2 trace readers) | **pass**: 818 of 818 operations, 0 errors, 632-key digest `9071602cf75b` in all 3 runs, 0 waited replies, 0 `foreignBlocked`, project trees byte-identical, 3 fork edits re-opened and matching | `mp-report.md` (0.5) |
| Hydralysis unit suite `tools/run_tests.py -j 4 --strict` | **pass**: 1,996 of 1,996, 0 failed alone, 0 failed under load, 0 task problems | `hy-unit.log` |
| Hydralysis engine-gated suite (`--integration`, against this install) | **pass**: 1,996 of 1,996, 0 failed alone, 1 failed only under load (`M3Pairing` delay test, passed alone), 0 task problems; includes `M3Concurrency` and `M4Bypass` | `hy-engine.log` |
| `M3Concurrency` repeated alone | 3 of 3 OK (173 to 195 s each) | `m3-rep*.log` |
| `cargo test -p hydra-trace`, `clippy -D warnings`, `fmt` | 112 lib tests plus 11 integration tests pass; clippy and fmt clean | `../cargo-test-trace.log`, `../clippy.log` |

### 0.1 Defect found and fixed by the gates: a trace reply could mix two revisions

The M3 concurrency agent (`tests/trace_agent_proc.py`) had reported once, with no cause found, `revision 5 read twice with different
content`. The cause is real and in the engine: `query::query` read the revision, then `MAX(seq)` for the pin, then the rows as three
statements on a reader connection, and in WAL mode each statement sees the newest commit. A batch committed between the first two
gave a reply labelled revision r whose pin and rows belong to r+1. Rows of a given `seq` never change; the revision label was wrong.
Fix (commit `73b3a8380a`): `Store::read_snapshot` wraps the revision, the pin and the rows (and the lifetimes, groups, symbols and
decoded branches of `trace_query`) in one deferred read transaction. Regression test
`query::tests::a_reply_at_revision_r_holds_exactly_the_events_of_r` (a writer committing two-event batches while a reader queries):
37 of 381 replies mismatched before the fix, 0 after (3 of 3 runs). Other trace commands read `revision` once or take a digest per
revision; they were not changed.

### 0.2 The three legacy cases are environmental, not regressions

`upgrade_cache`, `legacy_overlay` and `fork_upgrade_from_cache` fail on the published hydra.5 install too. The checked-in fixture
`examples/fixtures/legacy-12.1.4/legacy.gpr` was saved by a user named `test` (`project.prp` `OWNER=test`), and Ghidra refuses to open a
project owned by another user (`NotOwnerException: Project is owned by test`) when it builds the upgrade-cache copy. All three pass
(3 of 3, `legacy.log`) with `GHIDRA_SESSION_VMARGS=-Duser.name=test` for those tests, and with a 12.1.4 project saved by the current user.
Setting `user.name=test` for the whole suite is not an option (15 other tests then fail because their projects are owned by the real
user). So on a machine whose user is not `test` the suite is 263 of 268 plus these 3 run separately; the fixture would have to be replaced
by one saved by the user that runs it, which is a test-data change not made here.

### 0.3 Load-sensitive tests: what was found

All of these pass alone; none failed alone in any run. Only the first has a root cause that is fixed.

- `M3Concurrency` "revision read twice": **root-caused and fixed** (0.1).
- `e2a_kill_fork` (kill -9 of the fork writer 24 times, then retry): failed under load once; the retry of one killed fork failed with a
  `fork failed` error whose full text the test truncates at 120 characters, so the cause is **not found**. It passed in 4 of 5 loaded runs
  and 3 of 3 alone.
- `e9_guarded_threads` ("timed out waiting for the reaper and the governor to beat"): a heartbeat-timing test that fails when 16 daemons
  start at once on a loaded machine; **not root-caused**.
- `trace_agent_workload`: failed under load once with `foreignBlocked` 1 (`shared`, `singleFlightOpen` 2, `contended` 3, lock wait
  p99 294 ms) while the 4 agents and the writer started together; passed alone 3 of 3 and in the 18-run bench with 0 waiting. **Not
  root-caused**: whether it is the agents' simultaneous first open of the same program (a legitimate single-flight wait) or a trace
  request that waited was not established. This is the one item that bears on the "0 requests waiting" claim; the bench and soak
  numbers above are the evidence for it.
- `cpu_profile_identical`: passed in every run (suite and alone); no failure was seen in this release's runs.
- `M3Pairing` delay test (engine-gated, `-j 4`): failed once under load, passed alone; not root-caused.
- `test_trace_gates4.M4Bypass`: in one first engine-gated run (`-j 4`, before the merge of the issues branches) its `vcall_fixture.exe`
  child kept running for 30 minutes and held the task's pipes, so the run never completed (I stopped the runner after the other 363 task
  logs were `OK`). It passed alone (3 of 3 and twice more), and in the final engine-gated run on the merged install. Cause not found;
  another lane started a daemon suite on the machine during the hang. `mv_memory` was not part of any run listed here.

### 0.4 16-agent bench (medians of 3 rotated rounds)

| | h5 generic | h5 auto | cand generic | cand auto | candtr generic | candtr auto |
|---|---|---|---|---|---|---|
| workload wall s | 5.36 | 5.35 | 5.35 | 5.35 | 5.39 | 5.50 |
| tree CPU s | 19.64 | 20.57 | 20.15 | 20.13 | 28.59 | 27.91 |
| peak committed MB | 1091 | 1072 | 991 | 1029 | 1025 | 1147 |

`candtr` is the candidate with 4 trace readers (about 250 trace operations per second) and one live capture (about 2,000 events per
second). Without trace use the candidate equals h5 within noise. Trace use costs about +7.5 to +8.5 tree CPU seconds (+37 % to +42 %) in a
workload that lasts 5 s.

### 0.5 Multi-project soak (one run without trace, two with 2 trace readers and a live capture)

| | cand | candtr run 1 | candtr run 2 |
|---|---|---|---|
| workload wall s | 73.9 | 80.4 | 58.4 |
| tree CPU s | 193.6 | 299.2 | 269.7 |
| trace operations | 0 | 6,488 | 6,612 |

The wall times are higher than in the lane's earlier soak (48 to 53 s) because other jobs shared the machine; the run-to-run spread
means wall time is not a result of this release. Correctness columns are in the gate table.

### 0.6 Not met, not run

- **Overhead on a bare-loop microbenchmark is not met.** Hydralysis `docs/trace-overhead.md`: 0.1 % (16 ms frames) and 1.7 % (200 us
  frames) are inside the 5 % target; a loop of about 4 us per frame costs 113 % of mean frame time with 678k of 990k hits shed (counted and
  cited). The 2 % target for sampled mode is not established by any run listed here.
- **Live `trace_info` is O(session size)**: it is the main trace cost in the soak (section 4). Not fixed.
- **Daemon CPU cost of trace use is not free** (0.4, 0.5).
- **The trace reply digest differs from the lane runs** (`91606cf1e287...` in sections 3 and 4, `c12316d79475...` here); it is identical
  across all 6 bench runs and both soak runs here, so the stability gate holds. Which merged lane changed the reply bytes was not bisected.
- `test_runtime_scenario_fixture` ("ran 23 tests, N planned") did not reproduce: 1,996 of 1,996 with 0 task problems.
- Not run for this release: a Gradle or CI build of the release zip, the hosted-runner CI, the protocol-3 characterization suite and the R1
  hello golden, a memory-limited (`-Xmx`) run, real Frida or ETW capture through the daemon at the benchmark's rate, other hardware, ReFS.
- Hydralysis `tools/bump_hydra.py --release 12.3-hydra.6` was **not run**: it reads the release zips (`hydra-engine-12.3-hydra.6-win_x86_64.zip`,
  `hydra-client-12.3-hydra.6.zip`) and pins their SHA-256 and size. Those zips exist only after the release workflow builds them, and
  pinning a locally assembled zip would pin an artifact that is not the published one. The script itself is local and does not push.

## 1. What a reader must be told

- The trace's closed-session replies are byte-stable across engine builds, CPU profiles and installs **only when the
  session holds no `$string` values**: string ids are keyed per install by design (unlinkable across installs), so a
  session with strings has a different digest per install. The stability gate uses reference sessions without strings.
- `trace_info` on a live session costs O(session size) (it digests every table on each call): 151 to 192 ms p50 and
  436 to 541 ms p99 at 100,000 events. It is the dominant trace cost in the multi-project run (section 4). Not fixed here.
- The protocol has no shared-scope option: key scope is always `session:<id>`. Shared scope exists at the key-ring level and
  is tested there only.
- There is no session-level eviction, only artifact eviction with a tombstone; an exported bundle cannot be recalled.

## 2. Gates measured by this lane

| Gate | Result | Run |
|---|---|---|
| Privacy: secrets absent from replies, index, WAL, segments, exports, CLI output | met (7/7) | privacy.rs |
| Keyed ids stable per scope, unlinkable across sessions and installs | met | privacy.rs |
| Payload artifacts excluded from export unless authorized; eviction tombstones | met | privacy.rs |
| Retention budget accounts for every event | met | privacy.rs, trace_constrained.py |
| Disk shortage refused with busy/capacity/disk, no file left, reads served | met | trace_constrained.py, daemon_tests trace_disk_reserve |
| Trace tests against a real daemon | 11/11 passed | daemon_tests.py (trace_*) |
| Core replies unchanged with the trace code present | met: 412 keys, digest `285b55a2f873abb9...` in all 18 runs | section 3 |
| Trace reply digest stable across profiles and runs | met: `91606cf1e287...` in all 12 trace runs of section 3 and all 6 trace runs of the section 4 rounds | sections 3, 4 |
| 0 waits, 0 `foreignBlocked`, 0 trace errors under 16 agents plus capture plus readers | met | sections 3, 4 |
| Project trees byte-identical after the soak | met (12 of 12 rounds-series runs) | section 4 |
| Daemon CPU cost of live trace use | **not met as free**: +9 tree CPU s (+45 %) in the 5 s workload; about +100 java CPU s in the soak, 60 of them from `trace_info` on the live session | sections 3, 4 |

## 3. Daemon impact, 16 agents, fixed 825-operation workload

Three rotated rounds, a fresh daemon per run, medians (min-max in the report). h5 is 12.3-hydra.5 as published; cand is
this tree; candtr is cand with 4 trace readers (about 250 operations per second) and one live capture (2,000 events per second).

| | h5 generic | h5 auto | cand generic | cand auto | candtr generic | candtr auto |
|---|---|---|---|---|---|---|
| workload wall s | 5.30 | 5.30 | 5.29 | 5.28 | 5.50 | 5.50 |
| tree CPU s | 20.79 | 19.63 | 20.20 | 21.36 | 29.44 | 29.91 |
| peak committed MB | 1183 | 1102 | 1083 | 1109 | 1165 | 1138 |
| mean committed MB | 787 | 769 | 770 | 776 | 872 | 846 |

Without trace use, cand equals h5 within run-to-run noise (per-operation p50 within noise; p99 noisy). Per-operation latency
of the trace under this load (candtr, ms p50 / p99): trace_query 6.4 / 31.7, trace_groups 5.6 / 58.9, trace_check 5.6 / 32.8,
trace_info 13.9 / 45.3, trace_explain 5.1 / 40.2, trace_diff 12.6 / 53.4, trace_append of 200 events 9.3 / 78.4, live_info 32.4 / 84.
The live capture accepted 9,400 to 10,200 events per run with none rejected or dropped. Caveat: the workload lasts only about 5 s.

## 4. Multi-project soak

16 agents on three game programs with the Empire at War import running, plus the live capture and 2 trace readers, `auto`
profile, three rotated rounds (medians):

| | h5 | cand (no trace) | candtr | candtr without live `trace_info` |
|---|---|---|---|---|
| workload wall s | 57.4 | 49.8 | 53.9 | 53.2 |
| tree CPU s | 187.1 | 165.7 | 267.0 | 206.7 |
| java CPU s | 174.6 | 154.1 | 252.6 | 192.5 |
| peak committed MB | 1671 | 1870 | 1871 | 1872 |

Every run: 818 of 818 core operations, 0 errors, 632 reply keys with one digest (`9071602cf75b...`) across all four
configurations, 0 waited replies, `foreignBlocked` 0, no queued lanes, 3 fork edits re-opened and matching, project trees
byte-identical before and after, trace digest identical. About 105,000 events were accepted per run with none rejected.
Skipping the live `trace_info` removes about 60 of the 100 extra CPU seconds. Earlier single runs (generic profile, shape b with the
Cyberpunk daemon) also ended with 0 errors. The wall time of h5 here is higher than cand without trace; the machine was
shared and three runs per configuration do not separate that from noise.

## 5. Scale and constrained runs

- 1,000,000 events (`scale.rs`): ingest 18,981 events/s, indexed query p50 0.02 ms and p95 0.40 ms, 800,000 relations
  computed on demand in 1.96 s, aligned diff 0.60 s, peak working set 1,229 MiB at the end (191 MiB during ingest).
- 4 logical CPUs (affinity of the whole run), 16 agents, trace readers and capture (`aff4-report.md`): all 825 operations
  correct, same digests, 0 waits; wall 7.3 s generic and 7.9 s auto against 6.5 s for h5 without trace; tree CPU 27.2 and
  28.3 s against 20.5 s. Whether the daemon sized its pools from 4 CPUs was not read back.
- Disk and budget behaviour: see "System requirements" in the README.

## 6. Not met, not run, limits

- A memory-limited run (`-Xmx`) was not run.
- No real Frida or ETW capture was driven through the daemon in these benchmarks: the live capture is the `trace_append`
  protocol at about 2,000 events per second. Overhead on a real target is in Hydralysis `docs/trace-overhead.md`, not measured here.
- No hardware other than the reference machine; no ReFS; the machine was shared with other work.
- h5 and the candidate used the same Hydralysis (0.7.0-era source) in the benchmarks.
- Gate status of the store, protocol, capture, relations, checks, imports and concurrency workstreams is not claimed by this lane.
- Not done by this lane: version bump, tag, push, publish.
