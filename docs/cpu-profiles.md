# CPU tuning profiles

Hydra runs on any x64 CPU. Worker counts come at run time from the CPUs the OS grants the process, and a
**tuning profile** may change performance knobs for a CPU we have measured. A profile never changes results.

Code: `Ghidra/Framework/Utility/src/main/java/ghidra/util/cpu/HydraCpu.java`.
Benchmark: `Ghidra/Features/HeadlessSession/examples/cpu_bench.py` (`hydraCpuBench`).
Tests: `Ghidra/Features/HeadlessSession/examples/dt_cpu.py` (`cpu_selftest`, `cpu_profile_override`,
`cpu_profile_identical`).

## What is detected

| fact | source |
| --- | --- |
| vendor, family, model | `PROCESSOR_IDENTIFIER` (Windows, the CPUID values the OS reports), `/proc/cpuinfo` (Linux) |
| granted CPUs | the process affinity mask (CPU sets the process may use), lowered to a job object hard CPU-rate cap rounded up; on Linux the JVM's count, which applies cgroup limits. Never below 1, never above `Runtime.availableProcessors()` |
| core classes | `GetSystemCpuSetInformation` `EfficiencyClass`: the highest class among the granted CPU sets is "performance", the others "efficiency". The CPU is **hybrid** only when the granted sets hold more than one class |

The Windows calls go through `java.lang.foreign` and are made only when the module has native access
(`--enable-native-access=ALL-UNNAMED`, which the Hydra daemon sets). Without it every answer comes from the JVM and
nothing is placed. Check what a machine reports with:

    java --enable-native-access=ALL-UNNAMED -cp <install>/Ghidra/Framework/Utility/lib/Utility.jar ghidra.util.cpu.HydraCpu
    java ... ghidra.util.cpu.HydraCpu --selftest

The daemon logs the same report at start-up (`cpu: {vendor=..., grantedCpus=..., profile=..., reason=...}`).

## Where the numbers are used

| knob | generic | profile |
| --- | --- | --- |
| `SystemUtilities.getDefaultThreadPoolSize()` (analysis pool, `GThreadPool`s) | granted + 1 (the existing upper bound still applies) | the same: a profile moves threads, it does not shrink a pool |
| daemon lanes (`maxQuick`, `maxLong` defaults) and decompiler gate permits | granted CPUs (gate: `min(granted, nativeBudget / 200 MB)`) | the same |
| thread placement | none | on a hybrid CPU: daemon request threads (`Connection` workers, the accept loop) select the performance CPU sets; `GThreadPool` threads (analysis, parallel decompile) and housekeeping loops (governor sampling, reaper) select the efficiency CPU sets |

Placement uses `SetThreadSelectedCpuSets`. Each class takes at most as many placed threads as it has granted
logical CPUs (`latencyShare` / `backgroundShare` of them); a thread past that budget is left unplaced and may run on
any CPU, so placement never makes work wait for a core class. Virtual threads are never placed. Placement is a
no-op on other operating systems, on non-hybrid CPUs (including a hybrid CPU whose process is only granted one
class) and under the generic profile.

## Selecting a profile

`HYDRA_CPU_PROFILE` (environment) or `-Dhydra.cpu.profile=` (system property, wins):

* `auto` (default): the first entry of `HydraCpu.PROFILES` whose matcher accepts the CPU, else `generic`;
* `generic`: no placement, pools from granted CPUs;
* `<name>`: that profile, forced (its placement still needs a hybrid CPU);
* an unknown name: `generic` (the reason says so in the log).

Profiles today:

| name | matches | knobs |
| --- | --- | --- |
| `generic` | everything (fallback) | no placement |
| `raptorlake-hybrid` | `GenuineIntel`, family 6, model 0xB7/0xBA/0xBF, hybrid granted CPUs | request threads on P-cores, background on E-cores, budgets = class sizes |

## Adding a profile (PR checklist)

1. Add a `Profile` constant to `HydraCpu` and list it in `PROFILES` (more specific entries first). A profile is
   data: `name` (lower-case, `vendor-family` style such as `zen4-ccd2`), a matcher on `Cpu` (vendor, family, model,
   hybrid), `placeThreads`, `latencyShare`, `backgroundShare`, a one-line description. Do not touch the generic
   profile's numbers for your CPU: the generic path is never made slower to benefit a profile.
2. Add the matching checks to `HydraCpu.selfTest()` (a synthetic `Cpu` of your model is selected by `auto`; a near
   miss is not).
3. Run the tests on your CPU: `python daemon_tests.py --ghidra <install> --work <dir> --exe C:/Windows/System32/choice.exe
   --dll C:/Windows/System32/version.dll --only cpu_selftest,cpu_profile_override,cpu_profile_identical`.
4. Run the benchmark on your CPU with the machine otherwise idle and paste its block into the PR:

       python Ghidra/Features/HeadlessSession/examples/cpu_bench.py --ghidra <install> --work <empty dir> \
           --profile <name> --rounds 5 [--exe <a larger binary>]

   It prints (medians over the rounds, interleaved generic / profile runs, fresh daemon per run):

       hydra-cpu-bench 1
       cpu       <vendor> family <f> model <m> | <n> logical, <g> granted | hybrid <true|false>
       workload  <exe>: import+analyze, decompile <k> functions | <r> rounds
       profile                  analyze_s  decompile_s    total_s  digest
       generic                     ...          ...         ...    <12 hex>
       <name>                      ...          ...         ...    <12 hex>
       change                       <+/-x.x%>    <+/-x.x%>   <+/-x.x%>
       outputs   identical

   The run exits 1 when the outputs differ. A profile ships only with numbers that show it is faster on its CPU and
   `outputs identical`.
