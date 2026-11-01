# CPU tuning profiles

Hydra runs on any x64 CPU. Worker counts come at run time from what the OS grants the process, and a
**tuning profile** may change performance knobs for a CPU we have measured. A profile never changes results.

Code: `Ghidra/Framework/Utility/src/main/java/ghidra/util/cpu/HydraCpu.java` (module Utility).
The same profile list is mirrored for other callers of the native library in
`Ghidra/Framework/HydraNative/crates/hydra-native/src/profile.rs` (see "The C ABI mirror" below).
Benchmark: `Ghidra/Features/HeadlessSession/examples/cpu_bench.py` (a script; there is no Gradle task).
Tests: `Ghidra/Features/HeadlessSession/examples/dt_cpu.py` (`cpu_selftest`, `cpu_profile_override`,
`cpu_granted_limits`, `cpu_profile_identical`).

## What is detected

| fact | source |
| --- | --- |
| vendor, family, model, stepping | CPUID through the native library (`ghidra.util.HydraCpu`, module HydraNative); the OS' `PROCESSOR_IDENTIFIER` (Windows) or `/proc/cpuinfo` is the fallback identity when the library is unavailable |
| SIMD level (baseline, SSE4.2, AVX2, AVX-512) | CPUID, and the OS xsave state (AVX-512 only when the OS saves the state) |
| granted CPUs | the process affinity mask (CPU sets the process may use), lowered to a job object hard CPU-rate cap rounded up (the cap of the process's immediate job; the daemon reads it before it enters its own job); on Linux the JVM's count, which applies cgroup limits. Never below 1, never above `Runtime.availableProcessors()`. On a machine with more than one processor group: the JVM's count lowered to the job cap |
| core classes | `GetSystemCpuSetInformation` `EfficiencyClass`: the highest class among the granted CPU sets is "performance", the others "efficiency". The CPU is **hybrid** only when the granted sets hold more than one class, and never on a machine with more than one processor group |
| physical cores per class, last-level and L2 cache groups | the native library's topology report |
| memory the process may use | the lower of a job object or cgroup memory limit and the machine's memory (the native library) |
| active profile | `HYDRA_CPU_PROFILE` (environment) or `-Dhydra.cpu.profile` (system property, wins), `auto` when neither is set |

The Windows CPU-set calls go through `java.lang.foreign` and are made only when the module has native access
(`--enable-native-access=ALL-UNNAMED`). `support/launch.properties` sets it for every Ghidra launch, so the GUI,
`analyzeHeadless` and the daemon all detect granted CPUs natively; `-Dhydra.cpu.noNative=true` turns every native
call off (and no library is opened). Without native access every answer comes from the JVM, the facts are unknown,
and nothing is placed. Check what a machine reports with:

    java --enable-native-access=ALL-UNNAMED -cp <install>/Ghidra/Framework/Utility/lib/Utility.jar ghidra.util.cpu.HydraCpu
    java ... ghidra.util.cpu.HydraCpu --selftest

The daemon logs the same report at start-up (`cpu: {vendor=..., grantedCpus=..., profile=..., reason=...}`).

## Where the numbers are used

| knob | generic | profile |
| --- | --- | --- |
| `SystemUtilities.getDefaultThreadPoolSize()` (analysis pool, `GThreadPool`s) | granted + 1, with Ghidra's fixed pool cap of 10 | the same, unless the profile sizes the analysis pool (below) |
| analysis pool (`AutoAnalysisManager`'s shared pool) | the default above | the profile's `analysis` rule: threads over the granted **performance** and **efficiency** CPUs (all logical, or one per physical core per class), capped at the granted CPUs |
| decompiler gate permits | `min(granted, nativeBudget / 200 MB)` | the profile's `decompilers` rule, lowered by the memory budget in the same way |
| native memory budget (`nativeBudgetMb`) | half of the **memory the process may use** minus the heap (at least 200 MB): a job/cgroup memory limit lowers it, so a process held to 8 GB on a 64 GB host budgets 4 GB of decompilers, not 28 GB | the same |
| daemon lanes (`maxQuick`, `maxLong` defaults) | `max(granted, the JVM's processor count)`: never fewer slots than before (lane slots are request concurrency, not CPU work; on a host whose affinity grants 16 of 24 CPUs, 16 slots refused readers `busy` that 24 served) | the same |
| thread placement | none | on a hybrid CPU: daemon request threads (`Connection` workers) select the performance CPU sets; a `GThreadPool` thread (analysis, parallel decompile) selects the efficiency CPU sets only when it starts while its own pool has more live threads than there are performance CPUs (so a small pool is never confined to E-cores while P-cores idle). The daemon's guarded loops (accept, governor sampling, reaper) are never placed: they mostly sleep, and the governor is the memory-safety sampler |
| decompiler pipeline window, reply page buffer | the call's own default | the profile's `batchWindow` / `readBufferBytes` when it sets one (0: the call's default) |

Placement uses `SetThreadSelectedCpuSets`. Each class takes at most as many placed threads as it has granted
logical CPUs (`latencyShare` / `backgroundShare` of them); a thread past that budget is left unplaced and may run on
any CPU, so placement never makes work wait for a core class. Virtual threads are never placed. Placement is a
no-op on other operating systems, on non-hybrid CPUs (including a hybrid CPU whose process is only granted one
class) and under the generic profile.

An independent rule: every CPU-sized pool is sized from the **granted** CPUs, never from a fixed number; the fixed
pool cap of 10 is Ghidra's existing ceiling for the default pools and stays the generic behaviour (the profile can
name a per-core-class size instead). Pools share one queue, so a pool balances itself across unequal cores: the
fastest free thread takes the next task.

## The profile format (what a contributor PR adds)

A profile is data. In Java it is a `HydraCpu.Profile` record:

| field | meaning |
| --- | --- |
| `name` | the name `HYDRA_CPU_PROFILE` selects it by; lower-case, `vendor-family` style (`raptorlake-hybrid`, `zen4-ccd2`), unique, not `auto` or `generic` |
| `matches` | the predicate `auto` tries (vendor, family, model, hybrid); the generic profile matches nothing and is only the fallback |
| `placeThreads`, `latencyShare`, `backgroundShare` | whether and how much of each core class may take placed threads (see above) |
| `pools.analysis`, `pools.decompilers` | a `Rule`: the use of the performance and the efficiency class — `NONE`, `ONE_PER_CORE` (physical cores, SMT siblings free) or `ALL_LOGICAL`; `Rule.DEFAULT` leaves that pool at the generic sizing |
| `pools.batchWindow`, `pools.readBufferBytes` | optional batch/buffer sizes; 0 keeps the call's default |
| `description` | one line for reports |

A rule that names a class with no granted CPU (an affinity mask of E-cores only) gives no size and the generic
sizing applies; no rule gives more threads than the granted CPUs.

```java
/** Intel Raptor Lake hybrid (CPUID family 6, model 0xB7/0xBA/0xBF) with P and E cores. */
public static final Profile RAPTORLAKE_HYBRID = new Profile("raptorlake-hybrid",
    cpu -> "GenuineIntel".equals(cpu.vendor()) && cpu.family() == 6 &&
        (cpu.model() == 0xB7 || cpu.model() == 0xBA || cpu.model() == 0xBF) && cpu.hybrid(),
    true, 1.0, 1.0,
    new Pools(Rule.ALL, Rule.ALL, 0, 0),
    "Intel Raptor Lake hybrid: request threads on P-cores, background work on E-cores");
```

Constraints, checked by `HydraCpu.selfTest()` and `dt_cpu.py`:

* a profile changes performance knobs only: the same functions decompile to the same C on every profile;
* `auto` selects the first entry of `AUTO_PROFILES` that matches, else `generic`; a profile joins
  `AUTO_PROFILES` only in the PR that carries its measured numbers;
* the generic path is never made slower to benefit a profile: a profile's numbers are compared against
  `HYDRA_CPU_PROFILE=generic` on the same machine, interleaved;
* the generic path stays correct and fast on any x64 CPU: no profile is needed for it to work.

## The C ABI mirror

`hydra_native` (module HydraNative) answers other callers with the same CPU facts and a profile of its own
(`profile.rs`, documented in `Ghidra/Framework/HydraNative/PROFILES.md`). The two tables are separate on purpose
(the Java table drives the engine's pools and placement; the C table drives native callers), so a profile PR adds
its entry to both, and `HydraCpu.selfTest()` fails when `auto` selects a different profile than the native library
on a hybrid CPU. The C ABI's `HydraCpuInfo.profile_name` and the engine's `cpu: {...}` line then agree.

## Selecting a profile

`HYDRA_CPU_PROFILE` (environment) or `-Dhydra.cpu.profile=` (system property, wins):

* `auto` (default): the first entry of `HydraCpu.AUTO_PROFILES` whose matcher accepts the CPU, else `generic`;
* `generic`: no placement, pools from granted CPUs;
* `<name>`: that profile, forced (its placement still needs a hybrid CPU);
* an unknown name: `generic` (the reason says so in the log).

The reason in the report names the source that chose (`HYDRA_CPU_PROFILE=...` or `-Dhydra.cpu.profile=...`).

Profiles today:

| name | matches | knobs | numbers |
| --- | --- | --- | --- |
| `generic` | everything (fallback) | no placement; default pools | — |
| `raptorlake-hybrid` | `GenuineIntel`, family 6, model 0xB7/0xBA/0xBF, hybrid granted CPUs (auto) | request threads on P-cores, a pool's threads past the P-core count on E-cores; analysis pool over every granted logical CPU (`Rule.ALL`); decompilers over every granted logical CPU | see "Measured numbers" |

## Measured numbers

Contributor numbers are medians of interleaved rounds on the same machine, with the load stated.
The generic and profile runs alternate, so a shared machine moves both alike.

`raptorlake-hybrid`, i7-13700KF (8 P-cores + SMT = 16 logical, 8 E-cores; AVX2, no AVX-512), 24
logical CPUs granted, `swkotor.exe` import + analysis + 500 decompiles, 5 interleaved rounds, a
quiet machine window (another lane held 8 of 24 CPUs):

| profile | analyze_s | decompile_s | total_s |
| --- | --- | --- | --- |
| `generic` | 71.26 | 2.31 | 73.57 |
| `raptorlake-hybrid` | 69.09 | 2.39 | 71.48 |
| change | −3.0 % | +3.8 % | −2.8 % |

Every round: `placed latency 2`, background 8-16 (the analysis pool's cumulative placements; at
most 8 at once); outputs identical (the decompiled C of every function hashed, digest
`7f699adf2369`). The per-round pairs are −3.3, −2.2, −3.4, −1.5 and −3.4 s:
the analysis pool over every granted logical CPU is a consistent 2-5 % win, and 500 single-function
decompiles are unchanged within noise.

16 agents, the shared `multiagent_bench.py` fixed 825-op workload, 3 rotated interleaved rounds
(bench-h4 / o2-integration4 / generic / auto), machine shared with three lanes:

| metric (median) | h4 | int4 | `generic` | `raptorlake-hybrid` |
| --- | --- | --- | --- | --- |
| workload ops/s | 27.38 | 70.03 | 83.42 | 77.90 |
| workload tree CPU s | 65.53 | 36.63 | 36.07 | **35.29** |
| workload CPU ms/op | 79.4 | 44.4 | 43.7 | **42.8** |
| setup CPU s | 31.22 | 25.42 | 21.45 | **17.31** |
| total CPU s (setup+workload) | 107.00 | 62.53 | 57.62 | **53.76** |
| total wall s | 48.24 | 22.00 | 19.04 | **18.72** |
| peak / mean MB | 1673 / 1094 | 1140 / 781 | 1042 / 801 | 1047 / 815 |
| 825 ops / total wall s | 17.1 | 37.5 | 43.3 | **44.1** |

All 12 runs have 412/412 reply keys, 0 differing and no error replies. `generic` is 46 % below h4
and 7.9 % below int4 in total CPU; `raptorlake-hybrid` adds a further 6.7 %. The workload wall of
this session is load-limited (the first auto round overlapped another lane's heavy job), so CPU,
not that one wall median, is the stable comparison; the per-op p50/p99 table and the second session
on the final build (workload CPU −6.6 %, total CPU −2.2 %) are in
the round-4 profiles report.

## Adding a profile (PR checklist)

1. Add a `Profile` constant to `HydraCpu` and list it in `PROFILES` (selectable by name). Add it to `AUTO_PROFILES`
   (more specific entries first) only in the PR that carries the step 4 numbers. Add the same entry to
   `profile.rs` (the C ABI mirror). Do not touch the generic profile's numbers for your CPU: the generic path is
   never made slower to benefit a profile.
2. Add the matching checks to `HydraCpu.selfTest()` (a synthetic `Cpu` of your model is selected by `auto`; a near
   miss is not; the rules give the expected thread counts).
3. Run the tests on your CPU: `python daemon_tests.py --ghidra <install> --work <dir> --exe C:/Windows/System32/choice.exe
   --dll C:/Windows/System32/version.dll --only cpu_selftest,cpu_profile_override,cpu_granted_limits,cpu_profile_identical`.
4. Run the benchmark on your CPU with the machine otherwise idle and paste its block into the PR:

       python Ghidra/Features/HeadlessSession/examples/cpu_bench.py --ghidra <install> --work <empty dir> \
           --profile <name> --rounds 5 [--exe <a larger binary>] [--limit 500]

   Each daemon is started with the machine's full affinity mask (every core class granted) unless
   `--keep-affinity`; `--profile generic` is rejected. It prints (medians over the rounds, interleaved generic /
   profile runs, fresh daemon per run):

       hydra-cpu-bench 1
       cpu       <vendor> family <f> model <m> | <n> logical, <g> granted | hybrid <true|false>
       workload  <exe>: import+analyze, decompile <k> functions | <r> rounds
       profile                  analyze_s  decompile_s    total_s  digest
       generic                     ...          ...         ...    <12 hex>
       <name>                      ...          ...         ...    <12 hex>
       change                       <+/-x.x%>    <+/-x.x%>   <+/-x.x%>
       placed    latency <n>, background <n> thread(s) in the last <name> run
       outputs   identical

   The run exits 1 when the outputs differ. A profile ships only with numbers that show it is faster on its CPU,
   `placed` above zero (otherwise the run measured generic against generic) and `outputs identical`.

5. Run the 16-agent benchmark (the daemon under the concurrent workload), rotated interleaved rounds of
   h4, the intermediate builds, generic and the profile (the round-4 `run_profiles_ab.py` harness ran the 12
   and wrote `results/bench16`; it is internal, not shipped).

   and paste the `summary` table (ops/s, tree CPU, CPU per op, peak/mean, per-op p50/p99) into the PR
   with the machine's load noted.
