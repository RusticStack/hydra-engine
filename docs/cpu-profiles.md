# CPU tuning profiles

Hydra runs on any x64 CPU. Worker counts come at run time from the CPUs the OS grants the process, and a
**tuning profile** may change performance knobs for a CPU we have measured. A profile never changes results.

Code: `Ghidra/Framework/Utility/src/main/java/ghidra/util/cpu/HydraCpu.java`.
Benchmark: `Ghidra/Features/HeadlessSession/examples/cpu_bench.py` (a script; there is no Gradle task).
Tests: `Ghidra/Features/HeadlessSession/examples/dt_cpu.py` (`cpu_selftest`, `cpu_profile_override`,
`cpu_granted_limits`, `cpu_profile_identical`).

## What is detected

| fact | source |
| --- | --- |
| vendor, family, model | `PROCESSOR_IDENTIFIER` (Windows, the CPUID values the OS reports), `/proc/cpuinfo` (Linux) |
| granted CPUs | the process affinity mask (CPU sets the process may use), lowered to a job object hard CPU-rate cap rounded up (the cap of the process's immediate job; the daemon reads it before it enters its own job); on Linux the JVM's count, which applies cgroup limits. Never below 1, never above `Runtime.availableProcessors()`. On a machine with more than one processor group: the JVM's count lowered to the job cap |
| core classes | `GetSystemCpuSetInformation` `EfficiencyClass`: the highest class among the granted CPU sets is "performance", the others "efficiency". The CPU is **hybrid** only when the granted sets hold more than one class, and never on a machine with more than one processor group |

The Windows calls go through `java.lang.foreign` and are made only when the module has native access
(`--enable-native-access=ALL-UNNAMED`). `support/launch.properties` sets it for every Ghidra launch, so the GUI,
`analyzeHeadless` and the daemon all detect granted CPUs natively; `-Dhydra.cpu.noNative=true` turns the native
path off. Without it every answer comes from the JVM and nothing is placed. Placement also needs a placing profile,
and `auto` selects none today (below), so no launch places threads unless a profile is forced. Check what a machine reports with:

    java --enable-native-access=ALL-UNNAMED -cp <install>/Ghidra/Framework/Utility/lib/Utility.jar ghidra.util.cpu.HydraCpu
    java ... ghidra.util.cpu.HydraCpu --selftest

The daemon logs the same report at start-up (`cpu: {vendor=..., grantedCpus=..., profile=..., reason=...}`).

## Where the numbers are used

| knob | generic | profile |
| --- | --- | --- |
| `SystemUtilities.getDefaultThreadPoolSize()` (analysis pool, `GThreadPool`s) | granted + 1 (the existing upper bound still applies) | the same: a profile moves threads, it does not shrink a pool |
| daemon lanes (`maxQuick`, `maxLong` defaults) | `max(granted, the JVM's processor count)`: never fewer slots than before (lane slots are request concurrency, not CPU work; on a host whose affinity grants 16 of 24 CPUs, 16 slots refused readers `busy` that 24 served) | the same |
| decompiler gate permits | `min(granted, nativeBudget / 200 MB)` | the same |
| thread placement | none | on a hybrid CPU: daemon request threads (`Connection` workers) select the performance CPU sets; a `GThreadPool` thread (analysis, parallel decompile) selects the efficiency CPU sets only when it starts while more pool threads are alive than there are performance CPUs (so a small pool is never confined to E-cores while P-cores idle). The daemon's guarded loops (accept, governor sampling, reaper) are never placed: they mostly sleep, and the governor is the memory-safety sampler |

Placement uses `SetThreadSelectedCpuSets`. Each class takes at most as many placed threads as it has granted
logical CPUs (`latencyShare` / `backgroundShare` of them); a thread past that budget is left unplaced and may run on
any CPU, so placement never makes work wait for a core class. Virtual threads are never placed. Placement is a
no-op on other operating systems, on non-hybrid CPUs (including a hybrid CPU whose process is only granted one
class) and under the generic profile.

## Selecting a profile

`HYDRA_CPU_PROFILE` (environment) or `-Dhydra.cpu.profile=` (system property, wins):

* `auto` (default): the first entry of `HydraCpu.AUTO_PROFILES` whose matcher accepts the CPU, else `generic`.
  `AUTO_PROFILES` is empty today: a profile joins it only with measured before/after numbers (step 4 below);
* `generic`: no placement, pools from granted CPUs;
* `<name>`: that profile, forced (its placement still needs a hybrid CPU);
* an unknown name: `generic` (the reason says so in the log).

The reason in the report names the source that chose (`HYDRA_CPU_PROFILE=...` or `-Dhydra.cpu.profile=...`).

Profiles today:

| name | matches | knobs |
| --- | --- | --- |
| `generic` | everything (fallback) | no placement |
| `raptorlake-hybrid` | `GenuineIntel`, family 6, model 0xB7/0xBA/0xBF, hybrid granted CPUs. **By name only** (not in `AUTO_PROFILES`): no before/after numbers yet | request threads on P-cores, pool threads past the P-core count on E-cores, budgets = class sizes |

## Adding a profile (PR checklist)

1. Add a `Profile` constant to `HydraCpu` and list it in `PROFILES` (selectable by name). Add it to `AUTO_PROFILES`
   (more specific entries first) only in the PR that carries the step 4 numbers. A profile is
   data: `name` (lower-case, `vendor-family` style such as `zen4-ccd2`), a matcher on `Cpu` (vendor, family, model,
   hybrid), `placeThreads`, `latencyShare`, `backgroundShare`, a one-line description. Do not touch the generic
   profile's numbers for your CPU: the generic path is never made slower to benefit a profile.
2. Add the matching checks to `HydraCpu.selfTest()` (a synthetic `Cpu` of your model is selected by `auto`; a near
   miss is not).
3. Run the tests on your CPU: `python daemon_tests.py --ghidra <install> --work <dir> --exe C:/Windows/System32/choice.exe
   --dll C:/Windows/System32/version.dll --only cpu_selftest,cpu_profile_override,cpu_granted_limits,cpu_profile_identical`.
4. Run the benchmark on your CPU with the machine otherwise idle and paste its block into the PR:

       python Ghidra/Features/HeadlessSession/examples/cpu_bench.py --ghidra <install> --work <empty dir> \
           --profile <name> --rounds 5 [--exe <a larger binary>]

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
