//! The machine as the OS describes it: every logical CPU with its core, core class and cache
//! groups, and whether this process may run on it. The OS layer (`os`) fills it in; everything
//! here is plain data, so the summaries are tested with machines we do not have.

/// One logical CPU of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalCpu {
    /// The physical core; SMT siblings share it. Unique on the machine.
    pub core: u32,
    /// The OS's efficiency class: higher is faster. On a hybrid CPU the P-cores have the highest
    /// class; on other CPUs every CPU has the same class (0).
    pub efficiency_class: u8,
    /// The last-level cache group. Unique on the machine.
    pub llc: u32,
    /// The L2 cache group (E-cores share one L2 per cluster of four), if the OS reports it.
    pub l2: Option<u32>,
    /// Whether this process may run on it (affinity mask, CPU sets, cgroup cpuset).
    pub granted: bool,
}

/// Every logical CPU of the machine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Topology {
    pub cpus: Vec<LogicalCpu>,
}

/// The counts the tuning profiles and the C ABI use. Every `*_cpus` and `*_cores` count is of
/// the granted CPUs only, except `system_cpus`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Logical CPUs on the machine.
    pub system_cpus: u32,
    /// Logical CPUs this process may run on (before any CPU rate or quota limit).
    pub affinity_cpus: u32,
    /// Granted logical CPUs in the machine's highest efficiency class (all of them when the
    /// machine has one class).
    pub performance_cpus: u32,
    /// Granted logical CPUs in a lower efficiency class.
    pub efficiency_cpus: u32,
    pub performance_cores: u32,
    pub efficiency_cores: u32,
    /// Last-level cache groups with at least one granted CPU.
    pub llc_groups: u32,
    /// L2 cache groups with at least one granted CPU (0 when the OS does not report L2).
    pub l2_groups: u32,
    /// Distinct efficiency classes on the machine; more than one means a hybrid CPU.
    pub classes: u32,
}

fn count<T: Ord>(mut v: Vec<T>) -> u32 {
    v.sort_unstable();
    v.dedup();
    v.len() as u32
}

impl Topology {
    /// A machine of `n` identical logical CPUs, one per core, all granted: what is known when
    /// the OS cannot be asked.
    pub fn uniform(n: u32) -> Topology {
        let cpus = (0..n.max(1))
            .map(|i| LogicalCpu {
                core: i,
                efficiency_class: 0,
                llc: 0,
                l2: None,
                granted: true,
            })
            .collect();
        Topology { cpus }
    }

    pub fn summary(&self) -> Summary {
        let top = self
            .cpus
            .iter()
            .map(|c| c.efficiency_class)
            .max()
            .unwrap_or(0);
        let granted: Vec<&LogicalCpu> = self.cpus.iter().filter(|c| c.granted).collect();
        let (perf, eff): (Vec<&LogicalCpu>, Vec<&LogicalCpu>) =
            granted.iter().partition(|c| c.efficiency_class == top);
        Summary {
            system_cpus: self.cpus.len() as u32,
            affinity_cpus: granted.len() as u32,
            performance_cpus: perf.len() as u32,
            efficiency_cpus: eff.len() as u32,
            performance_cores: count(perf.iter().map(|c| c.core).collect()),
            efficiency_cores: count(eff.iter().map(|c| c.core).collect()),
            llc_groups: count(granted.iter().map(|c| c.llc).collect()),
            l2_groups: count(granted.iter().filter_map(|c| c.l2).collect()),
            classes: count(self.cpus.iter().map(|c| c.efficiency_class).collect()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An i7-13700KF as Windows reports it: 8 P-cores with two threads each (class 1, one L2
    /// each), then 8 E-cores (class 0, one L2 per four), all on one L3.
    pub(crate) fn raptor_lake_13700kf() -> Topology {
        let mut cpus = Vec::new();
        for core in 0..8 {
            for _ in 0..2 {
                cpus.push(LogicalCpu {
                    core,
                    efficiency_class: 1,
                    llc: 0,
                    l2: Some(core),
                    granted: true,
                });
            }
        }
        for core in 8..16 {
            cpus.push(LogicalCpu {
                core,
                efficiency_class: 0,
                llc: 0,
                l2: Some(8 + (core - 8) / 4),
                granted: true,
            });
        }
        Topology { cpus }
    }

    #[test]
    fn summarises_a_hybrid_machine() {
        let s = raptor_lake_13700kf().summary();
        assert_eq!(s.system_cpus, 24);
        assert_eq!(s.affinity_cpus, 24);
        assert_eq!((s.performance_cpus, s.performance_cores), (16, 8));
        assert_eq!((s.efficiency_cpus, s.efficiency_cores), (8, 8));
        assert_eq!((s.llc_groups, s.l2_groups, s.classes), (1, 10, 2));
    }

    #[test]
    fn counts_only_granted_cpus() {
        // Affinity 0xF: the first two P-cores with their SMT siblings.
        let mut t = raptor_lake_13700kf();
        for (i, c) in t.cpus.iter_mut().enumerate() {
            c.granted = i < 4;
        }
        let s = t.summary();
        assert_eq!((s.system_cpus, s.affinity_cpus), (24, 4));
        assert_eq!((s.performance_cpus, s.performance_cores), (4, 2));
        assert_eq!((s.efficiency_cpus, s.efficiency_cores), (0, 0));
        assert_eq!((s.l2_groups, s.classes), (2, 2));
    }

    #[test]
    fn a_single_class_is_all_performance() {
        let s = Topology::uniform(4).summary();
        assert_eq!(
            (s.performance_cpus, s.efficiency_cpus, s.classes),
            (4, 0, 1)
        );
        assert_eq!(s.l2_groups, 0);
        assert_eq!(Topology::uniform(0).summary().affinity_cpus, 1);
    }
}
