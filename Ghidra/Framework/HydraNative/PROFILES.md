# CPU tuning profiles

Hydra runs on any x64 CPU. Worker counts come from what the OS grants the process (affinity, CPU sets,
job object or cgroup quota), never from a fixed number. On top of that, a **tuning profile** adjusts
performance knobs for a CPU family whose behaviour we have measured.

## Rules

* A profile changes **performance knobs only**: pool sizes per core class and a placement hint. It never
  changes what is computed. Output is identical on every profile; tests run with the profile forced off
  (`generic`) and on.
* `generic` is the default and the fallback for every CPU without a profile. It must stay correct and
  fast everywhere; it is never made slower to benefit a profile.
* A profile ships with before/after numbers measured on its CPU (a quiet machine, several runs each).
  The numbers go in the pull request that adds or changes it.
* `raptorlake-hybrid` is in place so selection can be tested and seen; its pool split is provisional
  until the pool-sizing package measures it, and nothing reads it before then.

## Selection

At start-up `hydra_cpu_query` identifies the CPU (CPUID vendor, family, model, hybrid flag) and the
topology (OS efficiency classes), then takes the first profile in `PROFILES` (`crates/hydra-native/src/profile.rs`)
whose `matches` describes the CPU, else `generic`.

The override, `HYDRA_CPU_PROFILE` (or the Java system property `hydra.cpu.profile`, which wins):

| value | effect |
| --- | --- |
| unset, empty or `auto` | automatic selection |
| `generic` | `generic`, whatever the CPU |
| a profile name | that profile, whatever the CPU (names are case-insensitive) |
| anything else | `generic`; the source is reported as an unknown override |

`ghidra.util.HydraCpu.get()` (or `cargo run --example cpu`) shows the profile, why it was chosen and the
pool sizes it gives.

## Format

A profile is one `Profile` constant in `crates/hydra-native/src/profile.rs`, listed in `PROFILES`:

```rust
pub const RAPTORLAKE_HYBRID: Profile = Profile {
    name: "raptorlake-hybrid",             // lowercase, under 32 bytes, not "auto"
    matches: Some(Match {
        vendor: Vendor::Intel,             // from the CPUID vendor string
        family: 6,                         // display family (extended family included)
        models: &[0xB7, 0xBA, 0xBF],       // display models (extended model included)
        hybrid: true,                      // only when the CPU has more than one core class
    }),
    latency: PoolRule { performance: Use::AllLogical, efficiency: Use::None },
    compute: PoolRule { performance: Use::AllLogical, efficiency: Use::AllLogical },
    background: PoolRule { performance: Use::None, efficiency: Use::AllLogical },
    placement: Placement::LatencyOnPerformanceCores,
};
```

* **Pools.** `latency` (answering a request), `compute` (batch decompile, analysis) and `background`
  (flushes, prefetch, maintenance). A `PoolRule` says how much of each core class the pool uses:
  `Use::None`, `Use::OnePerCore` (SMT siblings left free) or `Use::AllLogical`. Only **granted** CPUs
  count: "performance" is the machine's highest OS efficiency class, "efficiency" the lower ones (on a
  CPU with one class, every CPU is "performance"). The result is capped at the granted CPUs (after any
  quota) and is never below 1; a rule whose classes have no granted CPU gives every granted CPU.
* **Placement.** `Placement::Any` (the OS schedules everything) or
  `Placement::LatencyOnPerformanceCores` (latency work on P-cores, background work on E-cores).

## Adding a profile

1. Add the constant and list it in `PROFILES`, after `generic`. Profiles are tried in order, so list a
   narrower match before a broader one for the same CPUs.
2. Add a test in `profile.rs` with the CPUID leaves of your CPU (see `cpuid::tests::raptor_lake_13700kf`)
   and its topology: it is chosen automatically, it is not chosen for a near miss (another model, no
   hybrid), and its pool sizes on the full machine and under a small affinity or quota.
3. Run `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`.
4. Measure on your CPU, profile forced on and off (`HYDRA_CPU_PROFILE=<name>` / `generic`), and put the
   numbers in the pull request. The output must be identical in both runs.
