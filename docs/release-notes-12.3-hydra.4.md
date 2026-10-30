# Hydra Engine 12.3-hydra.4: release notes

Released 2026-10-30. Based on upstream Ghidra `master` (12.3 DEV), commit
`1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, the same upstream commit as 12.3-hydra.3. The published release body is
the `## 12.3-hydra.4` section of `CHANGELOG.md` plus the download table the release workflow adds. This file is the
longer record: what a reader of the release must be told, every release gate of `PROTOCOL-3.md` section 9 with its run,
the guarantees of 6.1 with the test that decides each, and what was not met or not run.

Rule for this file and for every document of the release (PROTOCOL-3.md D52, D58): a claim appears only with the test
that passed for it. Where a test did not pass or was not run, the row says so. The scope of every result is a process
crash (`TerminateProcess`, a client kill) on Windows x64 with JDK 25 on NTFS. Nothing is stated about ReFS, power loss
or an OS crash, and no Linux or macOS claim is made.

Gate reports (the evidence for every result below): `D:/Projects/Hydra/_logs/gates/gates-1.md` (9.1-9.4, 9.6, 9.7,
9.11), `gates-2.md` (9.14, 9.15), `gates-3.md` (9.17), `gates-4.md` (9.8, 9.9, 9.19), `gates-5.md` (9.10, 9.12, 9.13,
9.14 throughput, 9.16, 9.18, 9.20); the gate-run amendments are `PROTOCOL-3.md` 8.12 to 8.17 (A42 to A65).

## 1. What a reader of the release must be told

- **`minClient` stays `1.0.0`** (D4). No existing client is rejected by a hydra.4 engine. It serves protocol 2
  and protocol 3 on one port. The one bump is reserved for the release that drops protocol 2.
- **Hydralysis 0.4.x refuses a hydra.4 engine by its own pin** (`hydra.py`, the pin check). That cannot be fixed
  on the engine side; it is stated here. Clients of hydra.2 and hydra.3 keep working at protocol 2. Hydralysis 0.6.0
  is the release that pins hydra.4; it follows this release (it needs the SHA-256 of the published engine zip).
- **Changes a protocol 2 client can see, by name (V1 to V12).** Every other behaviour is gated on protocol 3
  (G1 to G8 of PROTOCOL-3.md 5.1).

  | # | Change | Test that decides it | Result |
  |---|---|---|---|
  | V1 | the upgrade gate refuses a writable upgrade of a canonical older-format project without a valid `backup` | `cc_e2` on the legacy fixture (`--legacy-project`) | pass (a) |
  | V2 | import wait fix: no ten-second `busy` after the front of the queue; one budget for an explicit `wait` | `cc_e3a` `import_wait`, `import_wait_explicit` | pass (a) |
  | V3 | bounded release of a dead client (`cleanupGraceS`, `abandonWaitS`) | `cc_e3b` `dead_client_lock_wait`, `owner_leave_bounded` | pass (a); the 9.13 timing items `dead_client_released` and `owner_leave_bounded` pass (b) |
  | V4 | a request for a program held by an abandoned request answers `busy` at once | `cc_e3b` `abandoned_holder` | pass (a) |
  | V5 | `cancel` and a `timeout` end a request-bound lock wait (program, project, an overlay's request lock site); the overlay lifecycle waits (open, rebuild, drop, promote) are untimed and not ended (limit L2) | `cc_e3b` `cancel_while_waiting` | pass (a); 9.13 `cancel_while_waiting` pass (b) |
  | V6 | `protocolMin`, `protocolMax` in the endpoint file and the `ready` event | `cc_e1` (first test) | pass (a) |
  | V7 | the sidecar of every `fork_project` gains `purpose` and `disposable` | `cc_e2` `fork_sidecar` | pass (a) |
  | V8 | a sealed project refuses every writable path | `cc_e2` `sealed_refusal`, `candidate_then_seal` | pass (a) |
  | V9 | the work-conserving per-connection running cap, and the lane defaults | `cc_e3a` `v2_running_cap`, `v2_lane_defaults` | pass (a) |
  | V10 | the leave of a plain reader takes no exclusive lock | `cc_e3c` `reader_leave`, `reader_leave_all` | pass (a) |
  | V11 | concurrent forks to one destination give one success and `conflict` for the rest | `cc_e2a` `fork_race_conflict` | pass (a) |
  | V12 | a request that failed because another process holds a file or folder of the project answers `busy` with `details.path` and `suggest:"retry"` (v3 also `details.reason:"file_held"` and `retryAfterMs`), where it got `bad_request` (`Unknown-File`), `not_found` or a bare `failed`; after the hold the same request succeeds without a reopen (A63, PROTOCOL-3.md 8.15) | `dt_held.py`: `held_open_program`, `held_property_file`, `held_fork_source`, `held_save`, `held_open_project`, `held_version_file`, `held_import` (a v2 and a v3 connection; a daemon test, not a `cc_` test of the stock 1.0.0 client) | pass (c) |

  (a) `client_compat_tests.py` with every `cc_*.py`, run by the stock 1.0.0 client: 52 of 52 on the candidate
  `3b8a2f751a` and again on the `w2/GATE1` fixes (gate 9.4, gates-1). It was not re-run on the final install.
  (b) `daemon_tests.py` items of gate 9.13 on a quiet machine, 10 of 10 (gates-5).
  (c) The final daemon suite on install `final-h4` (`integration/w3` `79a9122e8c`, stamped `12.3-hydra.4`): all seven
  `held_*` tests pass (`D:/Projects/Hydra/_logs/final/suite.out`); each failed on the build before the change
  (`D:/Projects/Hydra/_logs/gate10/red-unfixed*.log`).

- **Headless only.** There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by
  Ghidra 12.2 or 12.1.4.
- **A harness restart is needed once** after the Hydralysis catalog epoch (PROTOCOL-3.md 7.7).
- **State formats.** `CURRENT.log`, `MANIFEST.json`, `backup.json` and store v3 carry a `format` number. The engine of
  this release has no reader that refuses a newer `format` with `format_unreadable` (no `format_unreadable` in the
  engine sources), so the release does not claim it for the engine. Hydralysis carries that refusal for the files it
  reads (`backups.py`, `lineage.py`).
- **Build identity.** A local build says `<Ghidra version>-hydra.dev` and Hydralysis classifies it as stock
  Ghidra. The release workflow stamps `hydra.version` into `hydra.properties`; for a local build see the module
  README, "Stamping a local build". The workflow also checks that the stamp is inside the zip it built.

## 2. Release gates (PROTOCOL-3.md section 9)

"Pass" means the gate's command ran with a verified exit code and met the pass condition; the run is named. The
candidates are named by commit; the gate fixes were merged into `integration/w3` after their runs.

| Gate | Result | Run and evidence |
|---|---|---|
| 9.1 golden decompile diff | **pass** | candidate `3b8a2f751a`: KotOR 8,616 of 8,616 functions identical on `production` and `explicit`; the 8 public fixtures (3,959 functions read from the engine) identical; source tree hash unchanged by all 36 captures (gates-1) |
| 9.2 commit round trip | **pass** | 5 of 5 touched functions identical to the working copy, 25 of 25 untouched identical to generation 0 (gates-1) |
| 9.3 characterization | **pass** with the `w2/GATE1` fixes (merged `3c3c100d8b`) | on the candidate p2 2 of 7 (an added `lockWaiters` key) and p3 12 of 13 (a stamped golden): fail; with the fixes p2 7 of 7, p3 13 of 13 with `--require-v3`, the R1 hello golden `v3/r1-hello.json` recorded and verified (gates-1); the stamp masker of `w2/GATE5` gives p3 13 of 13 and p2 7 of 7 on a `12.3-hydra.4`-stamped install |
| 9.4 engine suites | **pass on NTFS**; ReFS part not testable on the release machine, owner decision 2026-10-30 (8.12) | gates-1: `daemon_tests.py` with `--legacy-project` 194 of 194, `client_compat_tests.py` 52 of 52, `session_smoke.py` 1 of 1, `format_gate.py` exit 0, `contract_tests.py` 7 of 7 after the test-only fix `ba97a8dae6`. Final: `daemon_tests.py` on `final-h4`, **210 of 211 passed**; `refcount_leak` failed only under load and passed when run alone; `legacy_overlay` and `upgrade_cache` ran and passed (`D:/Projects/Hydra/_logs/final/suite.out`) |
| 9.5 soak, 12 clients | superseded by 9.17 | |
| 9.6 upgrade and backup round trip | **pass** | first run (gates-1): every engine step passed, the Hydralysis commit could not run on the unanalysed fixture. Re-run on the analysed 12.1.4 fixture of `w2/GATE7` (`legacy-12.1.4-analysed`): every check true, `GATE 9.6 PASS`, exit 0 (`D:/Projects/Hydra/_logs/gate7/g96.out`) |
| 9.7 DB-version check | **pass** | `format_gate.py` exit 0, static and against the candidate; `hello.analysisIdentity.dbVersions` `{"program": 33, "dataTypes": 3}` (gates-1) |
| 9.8 compatibility | **pass, except the `bump_hydra.py` check against the hydra.4 zip**, which needs the published zip | raw protocol-2 transcript: fail on `3b8a2f751a` (`lockWaiters` in a v2 status), pass after `445e60ea28` (p2 7 of 7); client 1.1.0 against the released hydra.3 12 of 12; against a fake protocol-2 server 4 of 4; Hydralysis suite against hydra.4 1477 of 1477 and against hydra.3 (degraded set) 1477 of 1477 on Hydralysis `w2/GATE4` (gates-4); final Hydralysis real-engine run against `final-h4`: 1511 of 1511, 0 failed (`D:/Projects/Hydra/_logs/final/hy-integ.log`); `canonical-manifest.json` byte-identical and cross-verified after Hydralysis `93c17ba`; `bump_hydra.py` verified on the hydra.3 dist only |
| 9.9 fault matrices | **pass** | Hydralysis commit points with O1-O6 (`FaultMatrix` 10/10, `FaultMatrixOnE2` 11/11, `RealEngineFaultMatrix` 3/3 on hydra.4), engine `backup_fault`, Y0a torn and zero-length files (gates-4) |
| 9.10 measurements | **recorded** on NTFS (C:, D:, E:) | F: (Dev Drive) not attached and clone against copy not runnable (no ReFS, 8.12). Findings: the Hydralysis store lock was not fair (fixed in Hydralysis 0.6.0); the concurrent `fork_project` takes a median 1226 ms on hydra.4 against 313 ms on hydra.3 (time to first decompile +28%), **not fixed** (A65) (gates-5) |
| 9.11 hygiene | **pass** after `w2/GATE6` (merged `72c882ace6`) | every commit `v12.3-hydra.3..` authored and committed by `KelpHect <kellhect@gmail.com>`; `buildHeadless` with the IP check, BUILD SUCCESSFUL; ownership 47 package merges, 0 violations (A42-A56, 8.14); the 30 limits of 6.2 in the documents, 0 overclaims (gates-1, "Gate6") |
| 9.12 red before green | **partly run** | hydra.3: all 13 red-table rows red in both runs. hydra.4: C-poison 0 of 40 and C-fork 0 of 33/43 in both runs (not reproduced); BP3, BP7-BP11 not reproduced; BP4, BP5, BP6, BP13, BP14 still red where 3.10 decides KEEP or BOUND. X0 self-test: `chaos_engine_injectors` failed (a test that predates E9's job), fixed by `w2/GATE14` (merged `fe330f4eb6`, red without, green with); `oracle_crash_c_forks` not runnable (the crash-C corpus is pruned) (gates-5) |
| 9.13 non-blocking gate | **not met: `s11`** (A65, 8.17) | `s11` reader throughput under four view writers 0.760 and 0.756 of the no-writer baseline (0.9 required), reproduced twice on a quiet machine; by owner decision 2026-10-30 not a release requirement for hydra.4, threshold unchanged. Every other item passed: the ten daemon tests, `s1` a/b/c 0 refused, `s5` 0 busy, `s7` 0 refused, `s13` 51.2 and 20.6 ms (100 ms allowed), the 7th client's script, save and fork in 58-256 ms (1 s allowed), `s4` b dead client's queued write not applied; `s2` and `s4` a report only (gates-5) |
| 9.14 resource gate | **pass** | the 16 functional items (gates-2, on `3b8a2f751a`; their `e9_*`, `e7_*` and `p1b_*` tests passed again on `b91b3531a4` and in the final suite on `final-h4`) and the throughput item (median 659 functions/s against A's 200-417; gates-5) |
| 9.15 crash gate | **pass on NTFS**; the 200 ReFS save kills not testable on the release machine (8.12) | candidate `b91b3531a4` (`w2/GATE2`, merged `4f6480641c`), counted trigger-timed kills, K1-K17 after every kill, 0 failures in every batch: save 563 (Wilson 95% upper bound 0.48% one-sided, 0.68% two-sided), `fork_project` 330, `promote_overlay` 211, Hydralysis generation publish 224, daemon kill with 8 clients 50, control 20 (gates-2) |
| 9.16 view cost | **pass on NTFS**; ReFS not runnable (8.12) | `named_view_cost`, 5 runs: shared base 143 / 302 / 444.5 ms, rebuilt base 259 / 359.5 / 491 ms at 1 / 4 / 12 views (gates-5) |
| 9.17 chaos and soak | **not passed** | A64 (8.16): for hydra.4 the soak is the PR lane plus `nightly-2`. PR lane `pr-r3b` (4 agents x 2 projects plus 2 Hydralysis agents, 614 s): **pass**, all fault classes at their minimum, 0 violations, 0 unexpected errors, `waits.foreignBlocked` 0. `nightly-2` (16 agents x 4 projects plus 4 Hydralysis agents, NTFS, stopped by the owner after 1 h 47 min 41 s): **fail**, 4 K8 `view_differs_from_replay` (finding H, a Hydralysis defect: a view rebuilt behind the head took the head's content; fixed in Hydralysis `360ed47`, tests `test_view_base` and `RealEngineViewBase`, not re-run in a nightly); and two fault classes below their minimum because the run was stopped early, handle holder 8 of 10 and backup lane 3 of 4. 168 kills (150 required), `waits.foreignBlocked` 0 in every final sample, 0 unexplained `busy` (gates-3) |
| 9.18 compatibility and performance | **pass** | interleaved A/B at 12 agents: throughput hydra.4 / hydra.3 1.013 (0.9 required), CPU-seconds per function +0.0% (10% allowed) (gates-5). V12 has a daemon test, not a `cc_` test |
| 9.19 claims | **pass for the engine and Hydralysis documents** | `tests/test_claims.py` passes; the D52 grep finds 0 hits in the engine README, module README, CHANGELOG, Hydralysis README, CHANGELOG and skills (re-run for this release). The site repository is the site owner's (S2) and is not part of this release: on its branch `w2/GATE4` the ledger check is in place (its `vite build` was not run) and the grep finds 0 D52 hits; on its main checkout the gate6 run found three lines of the corruption wording whose "in the tests listed" lacks D52's parentheses (gates-1 "Gate6", gates-4) |
| 9.20 spikes | **pass** | SP3, SP4, SP5, SP6 and SP10 go; SP7 not required (no publish latency figure is quoted) (gates-5) |

## 3. The guarantees (PROTOCOL-3.md 6.1)

Scope of every row: a process crash (`TerminateProcess`, a client kill) on NTFS, not a power loss or an OS crash. These
are the rows marked "hydra.4" in 6.1. A row is stated as holding only where its result column says pass.

| # | Guarantee (6.1 wording, shortened) | Test that can fail | Gate result |
|---|---|---|---|
| GR1 | master, generations and uninvolved projects are not written; hydra.4 refuses every writable path of a sealed project (an accident guard, not a security boundary) | K1/K9 in every chaos iteration; `cc_e2` `sealed_refusal`, `candidate_then_seal`; `dt_e2` `seal_union` | **pass**: K1-K17 after every counted kill of 9.15, 0 violations (gates-2); `cc_e2` in `client_compat_tests.py` 52 of 52 (9.4, gates-1); `seal_union` in the final suite |
| GR2 | corruption can touch only a disposable, unpublished artefact; a candidate generation is verified before it becomes head; a kill during a save does not leave an unopenable newest version | K2, K3, K6; 300 candidate-save kills; 400 save kills (200 NTFS, 200 ReFS); planted X1 | **pass for the NTFS part**: 563 counted NTFS save kills with 0 unopenable and 0 unrepaired, "below 0.75% at 95%" on NTFS alone (A59; 0.68% two-sided), K2, K3, K6 after every kill (9.15, gates-2); X1 flagged by `oracle_selftest` (final suite). The 200 ReFS save kills are not testable on the release machine (8.12) and no separate counted batch of candidate-save kills was run, so the row as written in 6.1 is **not stated as passed** |
| GR6 | no client's request waits on a lock another client holds, outside the residual list of 3.9 | K13 and the reruns of B's `s1`, `s2`, `s4`, `s5`, `s7`, `s11`, `s13` | **not met**: `s11` failed (0.760 and 0.756, A65); K13 (`waits.foreignBlocked` 0) held in 9.15 and 9.17, and `s1`, `s4` b, `s5`, `s7`, `s13` passed (gates-5). The row is not stated |
| GR7 | a client crash never harms the daemon or other clients, and a dead client's queued write is never applied | K10; B `s4_dead` S4b; C scenario e | **pass**: K10 after every counted kill of 9.15 (gates-2); `s4` b, the dead client's queued write not applied, in both 9.13 runs, and `dead_write_not_applied` (gates-5; final suite). C scenario e was not run as a separate gate batch |
| GR8 | at the configured budgets the daemon answers `busy` instead of running out of memory | `-Xmx256m` / `-Xmx512m` runs, K14 | **pass**: `e9_admission_256` (6 opened, 18 `busy` capacity, 0 out-of-memory), `e9_admission_512` (24 of 24), `e9_view_probe` (refused at `maxViews`) (9.14, gates-2); K14 after every counted kill of 9.15 |
| GR9 | a native decompiler crash, hang or kill fails one request; a daemon kill leaves no orphan decompiler | the decompiler-kill lap, K7 | **pass**: `e9_decompiler_faults`, `e9_decompiler_hang`, `e9_job_containment` (suspended decompilers, with the no-job control showing survivors), `e7_daemon_kill` (9.14, gates-2); SP3 go (9.20, gates-5); K7 found 0 orphans in every 9.15 batch |
| GR10 | a fork path is absent or complete, and no staging artefact survives the next sweep | K6; at least 300 kills during `fork_project` | **pass**: 330 counted `fork_project` kills, 0 `.gpr` without `.rep` at any instant, 0 `.rep` without `.gpr` and 0 leftovers after the sweep, 0 blocked retries (9.15 on `b91b3531a4`, with the sweep at daemon start and `open_project` of A57) (gates-2) |
| GR11 | a killed daemon is recoverable without manual repair, and operations in one project never change or delay another | K8, K9, K10; B's `s5`/`s13` | **pass in 9.15 and 9.13**: K8, K9, K10 after every counted kill of 9.15 (gates-2); `s5` 0 busy and `s13` 51.2 / 20.6 ms in both runs (gates-5). In 9.17 `nightly-2` K8 failed 4 times on Hydralysis views (finding H, a Hydralysis defect fixed in Hydralysis 0.6.0, not re-run in a nightly), so the row is not stated for the soak |

The script worker (E7, `isolation:"worker"`): its 9.14 items passed (`e7_edited_view`, `e7_cost`, `e7_kill_by_hand`,
`e7_cancel_cap`; start-up CPU 16,546 ms of 23,000, working set 345-416 MB of 650; gates-2). A script that ignores cancel
and runs in the worker is ended at its timeout; one that runs inside the daemon (`shared`, `exclusive` or `private`
isolation) is still bounded and quarantined, not stopped (limit L1).

## 4. Fixes made during the gate runs

Each fix has a test that failed on the build before it and passes with it; the result column is the final run.

| Fix | Test | Result |
|---|---|---|
| A file or folder held by another process answers `busy` (`file_held` on v3), never `bad_request`, `not_found` or a bare `failed`; after the hold the request succeeds without a reopen (A63, V12; `w2/GATE10`) | `dt_held.py`, seven tests | pass in the final suite |
| A save whose folder listing is briefly held no longer leaves the program unsaveable until a daemon restart (soak `nightly-1`; `w2/GATE8`) | `dt_hh.py` `hh_listing_hold`, `hh_rename_hold`, `hh_reopen_after_failed_commit`, `hh_control_unfixed` | pass in the final suite |
| Script loads during an analysis's script load wait for the OSGi lock instead of failing with `OverlappingFileLockException` (soak finding B; `w2/GATE9`) | `dt_osgi.py` `osgi_lock_analysis`, `osgi_lock_control_unfixed` | pass in the final suite |
| Fork and promote leftovers are swept at daemon start and at `open_project`, not only at the next `fork_project` (A57); a killed writable open's empty Ghidra time probe is removed at the next writable open (A61); the sidecar's temporary file names its writer, and a dead writer's file is swept (A62) (`w2/GATE2`) | `e2a_sweep_at_start`, `e2a_open_probe`, `e2a_sidecar_tmp_writer`; the 9.15 fork and promote batches | pass in the final suite and in 9.15 |
| The client launcher writes its shared launch files under per-writer temporary names; two clients launching against one state directory no longer collide on the rename (WinError 32; `w2/GATE12`) | `client_compat_tests.py --offline` `concurrent_classpath_write` | 10 of 10 (`D:/Projects/Hydra/_logs/gate12/cc_offline.log`); `p1b_concurrent_launchers` passes in the final suite |
| `lockWaiters` appears in a program status on protocol 3 only; a protocol 2 status is byte-identical to hydra.3 again (`w2/GATE1`) | characterization `--protocol 2` | 7 of 7 (gates-1); `lock_queue_full`, which reads the key at v3, passes in the final suite |

## 5. Not met, not run, and limits

- **9.13 `s11` is not met** (A65): reader throughput under four concurrent view writers is about 0.76 of the
  no-writer baseline (0.9 is the threshold, unchanged for the next release). The documents make no claim that readers
  keep their throughput under concurrent view writers.
- **Fork cost** (A65): a concurrent `fork_project` takes a median 1226 ms on hydra.4 against 313 ms on hydra.3; the
  open of the fork is faster (31.5 ms against 713 ms) and the time to the first decompile is 28% longer. Recorded, not
  fixed. The documents make no claim that forks are as fast as on hydra.3.
- **Soak scope** (A64): the hydra.4 soak is the PR lane plus `nightly-2` (16 agents x 4 projects, NTFS, 1 h 47 min
  41 s, stopped early by the owner). `nightly-2` failed (four K8 findings, a Hydralysis defect since fixed), and two
  fault classes stayed below their minimum (handle holder 8 of 10, backup lane 3 of 4). Three consecutive nightlies,
  the 24 x 6 four-hour run and a ReFS run were not run and are not release requirements for hydra.4. Scale is stated
  as "tested with up to 4 clients" (claim U1 is not flipped).
- **Not run or not testable:** every ReFS part of 9.4, 9.15, 9.16 and 9.17 (no ReFS volume, owner decision
  2026-10-30, 8.12); 9.10 on F: and clone against copy; `oracle_crash_c_forks` of 9.12 (corpus pruned); `bump_hydra.py`
  against the hydra.4 zip (after the zip is published); the `cc_*.py` tests were not re-run on the final install.
- **Limits.** Every limit of PROTOCOL-3.md 6.2 is stated, one by one, in the module README, "Limits of 12.3-hydra.4
  and protocol 3" (L1 to L19 and R6.1 to R6.11), and summarised in `CHANGELOG.md`: a script that ignores cancel is
  ended only in the script worker and is bounded and quarantined inside the daemon; the overlay lifecycle waits are not
  cancel-aware; Windows x64 and JDK 25 only, no Linux or macOS claim; no power-cut test; nothing about ReFS is tested
  for this release (NTFS is the release file system); the upgrade gate and the backup check are guards against
  accidents, not a security boundary.

## 6. Claims audit (PROTOCOL-3.md 8.3)

| Claim | Status for hydra.4 |
|---|---|
| C1 (write collisions) | not flipped: 9.17 did not pass; writes are serialized, collisions are detected when the client passes `expect` |
| C2 contained-script visibility | unchanged wording: other clients can see a contained script's changes while it runs |
| C3 (analysis and questions) | not flipped: 9.13 did not pass as a whole (`s11`) |
| C4 (programs and their waits) | not flipped: 9.13 `s5` and `s13` passed, but GR6 is not met |
| C5 (cleanup of a dead client) | the bounded release is stated with its tests (`dead_client_lock_wait`, `owner_leave_bounded`, `dead_client_released`), which pass; the script worker ends a non-cooperative script only with `isolation:"worker"` |
| C6 queued import waits | `cc_e3a` `import_wait` passes |
| C7 `cancel` of a lock wait | `cc_e3b` `cancel_while_waiting` passes, for the request-bound waits only (L2) |
| C8, C9, C10 | no engine test (C9 is Z2, C10 is Z13) |
| C11 number of modified Ghidra files | `NOTICE-HYDRA` lists every modified core file; the gate-run fixes added some (`LocalFolderItem` by A63, `Database` by `w2/GATE8`, `OSGiParallelLock` and `FileChannelLock` by `w2/GATE9`), each listed there |
| U1 scale | not flipped: "tested with up to 4 clients" (A64 allows "16 agents on 4 projects for 1 h 47 min" only with the run's verdict, which is fail) |
| U2 per-connection fairness | `cc_e3a` `v2_running_cap` passes; 9.17 did not pass |
| U3 serialized writes | "no corruption was seen in the tests listed"; 9.15 passed, 9.17 did not |
| U4 replay from the store | Hydralysis Y1, Y2 tests pass; 9.15 publish batch 224 kills, 0 failures |
| U13 stale versions | flips when Hydralysis runs `tools/bump_hydra.py` for this release against the published zip, after the release |

## 7. Hello golden

The full protocol 3 hello of the release (PROTOCOL-3.md 9.3) is `examples/characterization/v3/r1-hello.json`, recorded
by `examples/char_r1.py` (`w2/GATE1` `f0b77ba75e`, listed in `certification.manifest`). Its completeness check passed:
every capability, limit and policy name declared in `Advertised.java` is present in the engine's reply. It was verified
identical on the candidate and on the `w2/GATE1` install (gates-1). To check an install again:

```
set HYDRA_RELEASE_GOLDEN=1
python Ghidra/Features/HeadlessSession/examples/characterization_tests.py --ghidra <install> --work <empty dir> ^
    --protocol 3 --require-v3 --only r1-hello
```

## 8. After the release: the Hydralysis pin

Hydralysis 0.6.0 pins this release. Once the release zip is published, with its `SHA256SUMS`:

```
python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder with the published files> --write [--site-root <site repository>]
python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder> --check
```
