# The JVM floor of the Hydra Engine daemon (h7-jvm)

The daemon stays on the JVM (Ghidra core is Java). This is what was measured to lower its fixed
memory and CPU cost, which flags became defaults in the launcher (`support/ghidra_session.py`), and
which were rejected and why. Every kept flag is a default: nothing is opt-in, a caller's `vmargs`
still come last and win, and each setting has a config key (README, "Configuration").

## Method

* Install: `final2b` (hydra.6) copied to `C:\dev-overflow\hydra-engines\h7-jvm`; only the launcher
  file was changed in the copy. JDK 25.0.5+8 (Temurin). `final2b` itself was not touched and is the
  "before" in the final comparison.
* Workload: `examples/multiagent_bench.py run` (16 agents, 825 ops, KotOR + fixture project, one
  shared daemon, Hydralysis agents), fresh daemon per run, `--cpu-profile auto`. Configurations
  interleaved in rotating order, 3 to 7 rounds, **medians**. Figures: workload wall, process-tree CPU
  (java, decompile.exe, agent Pythons), JVM CPU, peak/mean committed memory (private bytes) of the
  tree, peak JVM private bytes, working set (added to the bench for this lane: ZGC maps its heap more
  than once, so its private bytes undercount), p50/p99 per op, `foreignBlocked` waits, reply digest.
* Guard for the long-running case (the bench workload is 5 s): `examples/cpu_bench.py` on
  `swkotor.exe` (import + auto-analysis, 300 decompiles; analysis is 100 to 200 s of Java).
* Idle floor: `idle.py` (empty daemon, 8 to 20 s settle), plus native memory tracking (NMT) for
  where the bytes are.
* The machine was shared with other lanes while this ran (busy cores 10 to 15 of 24 in the bench
  records); wall times and p99 move by tens of percent between rounds, so decisions rest on CPU and
  memory medians and on repeats, and the p99 columns are only used as "not worse".
* Every run: digest `285b55a2f873abb9...` (412 reply keys), `waits.foreignBlocked.total` 0, one
  `bad_request` on an edit (the same single error as the unmodified engine's runs).
* Raw results, scripts, logs: `E:\Projects\Hydra\_logs\h7\jvm\` (`res\*.json`, `rounds.sh`,
  `cfgs.sh`, `summ.py`, `idle.py`, `cpub.sh`, `gc.log`, `b2` to `b8`, `fin*`, `con*`).

## Result (default engine before and after)

Multi-agent bench, 16 agents, medians of 7 interleaved rounds (`fin2*`):

| | before (final2b) | after (h7) | change |
|---|---|---|---|
| process-tree CPU, s | 20.6 | 16.4 | -20 % |
| JVM CPU, s | 15.4 | 11.7 | -24 % |
| peak committed (tree), MB | 1066 | 935 | -12 % |
| mean committed (tree), MB | 766 | 665 | -13 % |
| peak JVM private, MB | 728 | 595 | -18 % |
| peak / mean working set (tree), MB | 1210 / 833 | 1082 / 750 | -11 % / -10 % |
| committed heap at the end of the run, MB | 192 | 144 | -25 % |
| decompile_fresh p50 / p99, ms | 12.9 / 130 | 6.7 / 104 | not worse |
| decompile_hot p50 / p99, ms | 0.5 / 120 | 0.4 / 90 | not worse |
| decompile_overlay p50 / p99, ms | 83 / 342 | 73 / 288 | not worse |
| empty daemon, JVM private bytes (3 runs each) | 232, 284, 234 | 201, 198, 198 | -34 MB |
| import + analysis of KotOR (`cpu_bench`, wall of analysis, auto profile; 2 runs each, the machine shared) | 84, 98 s | 86, 103 s (tier scale + GC threads); 86, 100 s (with GCTimeRatio 4 and the free ratios too) | no slower |

Constrained run (`--affinity 4`, `-Xmx2g`; a 4-CPU, 8 GB machine's defaults), 5 rounds (`con*`):
tree CPU 19.5 -> 16.4 s (-16 %), JVM CPU 14.2 -> 11.3 s, peak 911 -> 861 MB, mean 760 -> 693 MB,
wall 6.4 -> 6.0 s, decompile_fresh p50/p99 55/296 -> 44/268 ms; digest, waits and errors as above.
(Measured before `MarkStackSize` was added; that flag cannot make a 2 GB heap worse, it only commits
less.)

Not moved, and not claimed: the idle working set (173 -> 177 MB) and the native decompiler host
(~180 MB at the peak), which are outside the JVM options. The empty daemon's floor is class data,
metaspace, the CDS archive and G1 structures: of 208 MB committed in NMT at idle, heap 72, G1 61,
metaspace 21, code 17, shared class space 15.

## Kept (now defaults)

| Flag | Where | Effect measured |
|---|---|---|
| `-XX:Tier4InvocationThreshold=20000 -XX:Tier4MinInvocationThreshold=2400 -XX:Tier4CompileThreshold=60000 -XX:Tier4BackEdgeThreshold=160000` (the JDK's x 4; `jitTier4Scale`) | `jit_tier_args` | Largest lever: JVM CPU 15.9 -> 12.5 s, tree CPU 22.3 -> 18.7 s (6 rounds); decompile p99 -35 %; import+analysis of KotOR not slower (2 runs each, noise +-20 %). C2 only compiles code that stays hot; C1 still compiles everything early. |
| `-XX:ParallelGCThreads=max(4, CPUs/4)` above 8 CPUs, the JDK's up to 8 (`gcThreads`) | `gc_thread_args` | NMT: G1 structures at idle 61 -> 42 MB with 4 workers (-19 MB commit charge), 52 MB with 8; bench latency and CPU unchanged. |
| `-XX:GCTimeRatio=4` (`gcTimeRatio`, was opt-in 0) | `gc_args` | Over 6 rounds: peak 1016 -> 900 MB, mean 769 -> 701 MB, peak JVM 730 -> 656 MB, same CPU, decompile p99 130 -> 91 ms. `=2` behaves alike (no further gain). The earlier "no CPU gain" was right and is not what this is for: the heap stays nearer the ~100 MB live set instead of running to 3-5 times it. |
| `-XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=25` (were 15 / 40) | `gc_args` | Mean 760 -> 724 MB alone (5 rounds), heap committed at the end 176 -> 148 MB. Used together with GCTimeRatio=4. |
| `-XX:MarkStackSize=1m` | `gc_args` | G1 commits the 4M-entry mark stack (32 MB commit charge) at start; peak 943 -> 901 MB, mean 700 -> 649 MB, working set -33 MB mean, same CPU (6 rounds). G1 grows the stack itself if a mark overflows it. |

Kept unchanged (already in the launcher, re-checked): G1; `-Xms64m` and small initial heap;
`G1PeriodicGCInterval=300000` (idle daemons return heap; without it an idle daemon kept 276 vs
235 MB in one sample); `UseStringDeduplication` (turning it off: no CPU difference, 2 MB more);
`jitOneShot` compiler directives; `-XX:+UseCompactObjectHeaders` and
`-XX:InitialRAMPercentage=0.1` (both in the install's `launch.properties`, so every run above
already had compact headers; the "coh" rounds were therefore no-ops, and the live set after young
collections is the same, 96-111 MB, with and without it); AOT cache only when trained (below).

## Tried and rejected

| Flag / change | Result | Why rejected |
|---|---|---|
| `-XX:+UseSerialGC` | idle 159 vs 235 MB; bench peak JVM 591 vs 701 MB (3 rounds); CPU equal | Single-threaded pauses stop every request thread of 16 agents: decompile_fresh p99 352 vs 196 ms, overlay p50 236 vs 107 ms, and a full collection with a multi-GB live set (big programs, many projects) stalls the whole daemon for seconds. Wrong trade for a concurrent server; the JDK already picks Serial on 1 CPU / <1.8 GB. |
| `-XX:+UseParallelGC` | idle 431 MB, peak 1439 vs 1047, mean 1249 vs 766 MB | Eats the heap it is given. |
| `-XX:+UseZGC` (generational, the only mode in 25) | tree CPU 27.9 vs 24.8 s (+13 %); idle private 103 MB but working set 281 vs 173 MB; p99 fresh 359 vs 196 ms | Private bytes undercount (multi-mapped heap); resident cost and CPU are higher. |
| `-XX:+UseShenandoahGC` | peak 2434 vs 1047 MB, idle 399 MB | Larger in every measure. |
| `-XX:TieredStopAtLevel=1` (C1 only) | tree CPU -28 %, JVM CPU 17.3 -> 10.6 s, peak -12 % | Import + auto-analysis of KotOR 35 to 60 % slower (analysis 203/172 s vs 146/106 s, 259/232 vs 193/115 for the two profiles): throws away C2 where long analysis needs it. This is why the default scales C2's thresholds instead. |
| `-XX:CompileThresholdScaling=2 / 3` | JVM CPU -17 % / -12 %, less than tier-4 scaling and it also delays C1 | Superseded by the tier-4-only scale. |
| Tier-4 scale x2 / x6 / x10 | JVM CPU 14.1 / 12.2 s; x10 one outlier round of 16 s wall | x4 is in the flat part; x10 delays too long for no more gain, x2 gives less. |
| `-XX:CICompilerCount=4` | JVM CPU -1 s (noise), no memory change | The existing `jitThreads` stays opt-in. |
| `-XX:+UnlockExperimentalVMOptions -XX:G1MaxNewSizePercent=20 / 10` | peak 1321 / 2023 MB vs 1004 | A capped young generation makes G1 collect more and grow the old generation: worse. |
| `-XX:GCTimeRatio=2` | like 4 (peak 911 vs 900) | No further gain. |
| `-XX:ParallelGCThreads=8` / 4 on small machines | within noise | The default keeps the JDK's count up to 8 CPUs. |
| `-Xss512k -XX:CompilerThreadStackSize=512 -XX:VMThreadStackSize=512` | peak -45 MB / CPU +4 % vs defaults, within round-to-round noise; thread memory is 5-7 MB of the JVM at the peak | Nothing real to gain; deeper recursion in analysis code would be at risk. |
| `-XX:ReservedCodeCacheSize=64m` | CPU +9 %, one round with 4 op errors | Code cache is 17-34 MB committed; the reserve is virtual. Not worth the risk. |
| `-Xmx` smaller (512 m / 2 g / 11 g) | idle 225 / 223 / 235 MB; 31 g: 291 MB | The floor is almost independent of `-Xmx` up to ~11 g; above that G1's card table and bitmaps cost more commit (a 64 GB machine's default 16 g and 31 g ceilings). Not changed: `-Xmx` is the governor's budget base (`minXmxMb` 512 untouched). |
| JDK 25 AOT cache (`-XX:AOTCache`, class loading + linking + method profiles; trained with `ghidra_session.py aot --shared`, 72 MB file) | tree CPU 21.6 -> 20.5 s (-5 %); idle +30 MB private, +24 MB working set; with tier scaling no extra CPU gain (17.6 vs 17.2 s) | The earlier "+47 MB" holds (this run +30 MB private / +24 MB resident idle). It needs a training step, so it cannot be a default for every state dir, and once the tier thresholds are scaled it saves nothing measurable. The launcher still uses a cache when one exists. |
| `-XX:+UseCompactObjectHeaders` | already on (install `launch.properties`) | Nothing to change. |
| `-XX:-UseStringDeduplication` | CPU -1.7 s within noise, +2 MB | Keep dedup (large programs' symbol strings). |
| `-XX:G1PeriodicGCInterval=0` | single idle sample +40 MB | Keep the existing 300 s periodic uncommit. |

Not separately measured (reason): `-XX:+AlwaysPreTouch` (off by default, never set), metaspace and
class unloading flags (35 to 38 MB metaspace committed at the peak is live class metadata; the
class-cache and jitOneShot work already cut it), `MALLOC_ARENA_MAX` (not applicable on Windows),
`-Xshare` (the launcher already drops `-Xshare:off` in fast mode, so the default CDS archive is in
use: 15 MB shared class space).

NMT at the bench peak (one polled run, 1 s resolution): total 501 MB committed: heap 254, G1 67,
metaspace 35, code 26, compiler arenas 41 (peak 84 over the run), symbols 8, class 9, threads 5.
The compiler arenas are what C2 compiles cost in memory; with the tier-4 scale the sampled arenas
stayed under 10 MB.

## Governor and small machines

* Nothing here touches `-Xmx` or the governor's budgets (`heapSoftPct`, `nativeBudgetMb`,
  `minXmxMb`); a lower committed heap at the same live set leaves their inputs (heap after GC,
  Xmx) unchanged.
* Up to 8 granted CPUs the GC thread count is the JDK's; the constrained run above (4 CPUs, 2 GB
  heap) improved in CPU and memory alike.
* Rollbacks, per key, for a machine where one setting is wrong: `jitTier4Scale: 1`,
  `gcThreads: -1`, `gcTimeRatio: 0` (or `vmargs` with the specific `-XX`).
