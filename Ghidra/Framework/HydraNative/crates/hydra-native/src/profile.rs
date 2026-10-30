//! Tuning profiles: per-CPU performance knobs, chosen at start-up.
//!
//! A profile only sets performance knobs (pool sizes per core class and a placement hint), never
//! anything that changes a result: every profile must give the same output. `generic` is the
//! default for any CPU; the others are chosen when the CPU matches them, or forced with
//! `HYDRA_CPU_PROFILE`. The format and how to contribute a profile: PROFILES.md in this module.

use crate::cpuid::{CpuId, Vendor};
use crate::topology::Summary;

/// The override variable: `generic`, `auto` (or unset/empty) or a profile name.
pub const OVERRIDE_ENV: &str = "HYDRA_CPU_PROFILE";

/// How much of one core class a pool uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    None,
    /// One thread per physical core of the class (SMT siblings left free).
    OnePerCore,
    /// One thread per logical CPU of the class.
    AllLogical,
}

/// How a pool is sized: from the granted performance and efficiency CPUs. When the classes a rule
/// uses have no granted CPU (an affinity mask of E-cores only, say), the pool gets every granted
/// CPU instead; it never has fewer than one thread or more than the granted CPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRule {
    pub performance: Use,
    pub efficiency: Use,
}

/// Where threads should run. The numbers are part of the C ABI (`HydraCpuInfo::placement`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Placement {
    /// No preference: the OS schedules every thread.
    Any = 0,
    /// Latency-critical work on the performance cores, background work on the efficiency cores.
    LatencyOnPerformanceCores = 1,
}

/// Which CPUs a profile is chosen for automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    pub vendor: Vendor,
    pub family: u32,
    pub models: &'static [u32],
    /// Only when the CPU has more than one core class (CPUID hybrid flag or OS efficiency classes).
    pub hybrid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    /// `None` for `generic`, which is never matched, only fallen back to.
    pub matches: Option<Match>,
    /// Threads for latency-critical work (a request being answered).
    pub latency: PoolRule,
    /// Threads for throughput work (batch decompile, analysis).
    pub compute: PoolRule,
    /// Threads for background work (flushes, prefetch, maintenance).
    pub background: PoolRule,
    pub placement: Placement,
}

const ALL: PoolRule = PoolRule {
    performance: Use::AllLogical,
    efficiency: Use::AllLogical,
};

/// The default for every CPU: every pool sized to the granted CPUs, no placement.
pub const GENERIC: Profile = Profile {
    name: "generic",
    matches: None,
    latency: ALL,
    compute: ALL,
    background: ALL,
    placement: Placement::Any,
};

/// Intel Raptor Lake hybrid (13th/14th gen Core with P- and E-cores, e.g. i7-13700KF).
/// The pool split is provisional: no pool reads it yet, and the numbers that make it a shipped
/// profile come from the measured pool-sizing package (see PROFILES.md).
pub const RAPTORLAKE_HYBRID: Profile = Profile {
    name: "raptorlake-hybrid",
    matches: Some(Match {
        vendor: Vendor::Intel,
        family: 6,
        // RAPTORLAKE (S/HX), RAPTORLAKE_P, RAPTORLAKE_S (Linux intel-family.h)
        models: &[0xB7, 0xBA, 0xBF],
        hybrid: true,
    }),
    latency: PoolRule {
        performance: Use::AllLogical,
        efficiency: Use::None,
    },
    compute: ALL,
    background: PoolRule {
        performance: Use::None,
        efficiency: Use::AllLogical,
    },
    placement: Placement::LatencyOnPerformanceCores,
};

/// Every profile, `generic` first. A new profile is one more entry here (see PROFILES.md).
pub const PROFILES: &[Profile] = &[GENERIC, RAPTORLAKE_HYBRID];

/// Why a profile was chosen. The numbers are part of the C ABI (`HydraCpuInfo::profile_source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Source {
    /// Chosen from the CPU (`auto`, the default).
    Auto = 0,
    /// Named by the override (`generic` or a profile name), whatever the CPU.
    Forced = 1,
    /// The override names no profile; `generic` is used.
    UnknownOverride = 2,
}

/// The thread counts a profile gives on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pools {
    pub latency: u32,
    pub compute: u32,
    pub background: u32,
}

pub fn find(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Whether `m` describes this CPU.
fn matches(m: &Match, cpu: &CpuId, topo: &Summary) -> bool {
    m.vendor == cpu.vendor
        && m.family == cpu.family
        && m.models.contains(&cpu.model)
        && (!m.hybrid || cpu.hybrid || topo.classes > 1)
}

/// Chooses the profile: the override when it names one, else the first profile matching the CPU,
/// else `generic`.
pub fn select(
    cpu: &CpuId,
    topo: &Summary,
    override_name: Option<&str>,
) -> (&'static Profile, Source) {
    match override_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(name) if !name.eq_ignore_ascii_case("auto") => match find(name) {
            Some(p) => (p, Source::Forced),
            None => (&GENERIC, Source::UnknownOverride),
        },
        _ => {
            let found = PROFILES
                .iter()
                .find(|p| p.matches.is_some_and(|m| matches(&m, cpu, topo)));
            (found.unwrap_or(&GENERIC), Source::Auto)
        }
    }
}

fn class(u: Use, cpus: u32, cores: u32) -> u32 {
    match u {
        Use::None => 0,
        Use::OnePerCore => cores,
        Use::AllLogical => cpus,
    }
}

fn size(rule: &PoolRule, topo: &Summary, granted: u32) -> u32 {
    let n = class(
        rule.performance,
        topo.performance_cpus,
        topo.performance_cores,
    ) + class(rule.efficiency, topo.efficiency_cpus, topo.efficiency_cores);
    let granted = granted.max(1);
    if n == 0 { granted } else { n.min(granted) }
}

impl Profile {
    /// The pool sizes on a machine with `topo`, where the process can keep `granted` CPUs busy.
    pub fn pools(&self, topo: &Summary, granted: u32) -> Pools {
        Pools {
            latency: size(&self.latency, topo, granted),
            compute: size(&self.compute, topo, granted),
            background: size(&self.background, topo, granted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpuid::{self, SimdLevel};
    use crate::topology::{self, Topology};

    fn raptor() -> (CpuId, Summary) {
        (
            cpuid::decode(&cpuid::tests::raptor_lake_13700kf()),
            topology::tests::raptor_lake_13700kf().summary(),
        )
    }

    #[test]
    fn raptor_lake_is_chosen_automatically() {
        let (cpu, topo) = raptor();
        assert_eq!(
            select(&cpu, &topo, None),
            (&RAPTORLAKE_HYBRID, Source::Auto)
        );
        assert_eq!(
            select(&cpu, &topo, Some("auto")),
            (&RAPTORLAKE_HYBRID, Source::Auto)
        );
        assert_eq!(
            select(&cpu, &topo, Some(" ")),
            (&RAPTORLAKE_HYBRID, Source::Auto)
        );
        for model in [0xBA, 0xBF] {
            let cpu = CpuId {
                model,
                ..cpu.clone()
            };
            assert_eq!(select(&cpu, &topo, None).0, &RAPTORLAKE_HYBRID);
        }
    }

    #[test]
    fn other_cpus_get_generic() {
        let (cpu, topo) = raptor();
        let zen4 = cpuid::decode(&cpuid::tests::zen4_7950x());
        let flat = Topology::uniform(32).summary();
        assert_eq!(select(&zen4, &flat, None), (&GENERIC, Source::Auto));
        // Alder Lake (model 0x97) is hybrid but has no profile yet.
        let alder = CpuId {
            model: 0x97,
            ..cpu.clone()
        };
        assert_eq!(select(&alder, &topo, None).0, &GENERIC);
        // A Raptor Lake model without E-cores (i3-13100: model 0xBF, one core class).
        let i3 = CpuId {
            model: 0xBF,
            hybrid: false,
            ..cpu.clone()
        };
        assert_eq!(
            select(&i3, &Topology::uniform(8).summary(), None).0,
            &GENERIC
        );
        // The OS efficiency classes alone are enough to call it hybrid.
        let no_flag = CpuId {
            hybrid: false,
            ..cpu
        };
        assert_eq!(select(&no_flag, &topo, None).0, &RAPTORLAKE_HYBRID);
        assert_eq!(CpuId::unknown().simd, SimdLevel::Baseline);
        assert_eq!(select(&CpuId::unknown(), &flat, None).0, &GENERIC);
    }

    #[test]
    fn override_forces_a_profile_on_any_cpu() {
        let (cpu, topo) = raptor();
        assert_eq!(
            select(&cpu, &topo, Some("generic")),
            (&GENERIC, Source::Forced)
        );
        assert_eq!(
            select(&cpu, &topo, Some("GENERIC")),
            (&GENERIC, Source::Forced)
        );
        let zen4 = cpuid::decode(&cpuid::tests::zen4_7950x());
        let flat = Topology::uniform(32).summary();
        assert_eq!(
            select(&zen4, &flat, Some("raptorlake-hybrid")),
            (&RAPTORLAKE_HYBRID, Source::Forced)
        );
        assert_eq!(
            select(&cpu, &topo, Some("no-such-cpu")),
            (&GENERIC, Source::UnknownOverride)
        );
    }

    #[test]
    fn generic_pools_are_the_granted_cpus() {
        let (_, topo) = raptor();
        let all = Pools {
            latency: 24,
            compute: 24,
            background: 24,
        };
        assert_eq!(GENERIC.pools(&topo, 24), all);
        let four = Pools {
            latency: 4,
            compute: 4,
            background: 4,
        };
        assert_eq!(GENERIC.pools(&topo, 4), four);
    }

    #[test]
    fn raptor_lake_pools_split_by_core_class() {
        let (_, topo) = raptor();
        let pools = RAPTORLAKE_HYBRID.pools(&topo, 24);
        let split = Pools {
            latency: 16,
            compute: 24,
            background: 8,
        };
        assert_eq!(pools, split);
        // A CPU quota of 6 caps every pool.
        assert_eq!(RAPTORLAKE_HYBRID.pools(&topo, 6).compute, 6);
        assert_eq!(RAPTORLAKE_HYBRID.pools(&topo, 6).latency, 6);
    }

    #[test]
    fn a_class_without_granted_cpus_falls_back_to_all_granted() {
        // Affinity 0xF on the 13700KF: four P-core threads, no E-core.
        let mut t = topology::tests::raptor_lake_13700kf();
        for (i, c) in t.cpus.iter_mut().enumerate() {
            c.granted = i < 4;
        }
        let pools = RAPTORLAKE_HYBRID.pools(&t.summary(), 4);
        let four = Pools {
            latency: 4,
            compute: 4,
            background: 4,
        };
        assert_eq!(pools, four);
    }

    #[test]
    fn one_per_core_leaves_smt_siblings_free() {
        let (_, topo) = raptor();
        let rule = PoolRule {
            performance: Use::OnePerCore,
            efficiency: Use::None,
        };
        assert_eq!(size(&rule, &topo, 24), 8);
    }

    #[test]
    fn profile_names_are_unique_and_generic_matches_nothing() {
        for (i, p) in PROFILES.iter().enumerate() {
            assert!(
                PROFILES[i + 1..]
                    .iter()
                    .all(|q| !q.name.eq_ignore_ascii_case(p.name))
            );
            assert!(
                p.name.len() < 32,
                "{} does not fit HydraCpuInfo::profile_name",
                p.name
            );
            assert!(!p.name.eq_ignore_ascii_case("auto"));
        }
        assert_eq!(PROFILES[0], GENERIC);
        assert!(GENERIC.matches.is_none());
    }
}
