# Hydra Engine 12.3-hydra.6: release notes (draft, non-functional lane)

Draft. This file holds what the non-functional lane (WS-I) measured for the semantic trace. The gates of the other
workstreams (store, protocol, capture, relations, checks, imports, concurrency) are recorded by their own lanes and
are **not claimed here**. Nothing in this file has been released, tagged or published.

Rule (as in the hydra.5 notes): a claim appears only with the run that produced it. Scope of every result: a process
tree on Windows x64 with JDK 25 on NTFS, on one shared machine (system requirements in `README.md`). Nothing is stated
about ReFS, power loss, Linux or macOS.

Evidence (all under `_logs/trace-lnfr/`): `bench/rounds2-report.md` (daemon impact), `mp-report.md` (multi-project soak),
`bench/aff4-report.md` (4 logical CPUs), `constrained/constrained1.json`, `scale.log`, `daemon_tests_trace.log`.
Privacy tests: `crates/hydra-trace/tests/privacy.rs` (7 tests, commit 30d1b21a68).

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
