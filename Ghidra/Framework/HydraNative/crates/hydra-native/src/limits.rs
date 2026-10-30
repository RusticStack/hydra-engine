//! The CPU time and memory the OS grants the process beyond its affinity: a job object CPU rate
//! or cgroup `cpu.max` quota, and a job object or cgroup memory limit.

/// The limits the OS layer (`os`) reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// A hard CPU quota in thousandths of a CPU (a Windows job object CPU rate cap, or a cgroup
    /// `cpu.max` quota divided by its period), if one is set.
    pub cpu_quota_milli: Option<u64>,
    /// The memory the process may commit (a job object process or job memory limit, or a cgroup
    /// `memory.max`), if one is set.
    pub memory_limit: Option<u64>,
    /// The machine's physical memory in bytes (0 when unknown).
    pub physical_memory: u64,
}

impl Limits {
    /// The logical CPUs the process can keep busy: the CPUs it may run on, lowered to the CPU
    /// quota rounded up, and never below one.
    pub fn granted_cpus(&self, affinity_cpus: u32) -> u32 {
        let affinity = affinity_cpus.max(1);
        match self.cpu_quota_milli {
            Some(q) => {
                let quota = q.div_ceil(1000).clamp(1, u64::from(u32::MAX)) as u32;
                affinity.min(quota)
            }
            None => affinity,
        }
    }

    /// The memory the process may use: the lower of the limit and physical memory (0 when
    /// neither is known).
    pub fn memory(&self) -> u64 {
        match (self.memory_limit, self.physical_memory) {
            (Some(l), 0) => l,
            (Some(l), p) => l.min(p),
            (None, p) => p,
        }
    }
}

/// Converts a Windows job object CPU rate (hundredths of a percent of the whole machine) to
/// thousandths of a CPU.
pub fn rate_to_milli(rate: u32, system_cpus: u32) -> u64 {
    u64::from(rate) * u64::from(system_cpus) / 10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_lowers_the_affinity_rounding_up() {
        let l = Limits {
            cpu_quota_milli: Some(1500),
            ..Limits::default()
        };
        assert_eq!(l.granted_cpus(24), 2);
        assert_eq!(l.granted_cpus(1), 1);
        let none = Limits::default();
        assert_eq!(none.granted_cpus(24), 24);
        assert_eq!(none.granted_cpus(0), 1);
        let tiny = Limits {
            cpu_quota_milli: Some(1),
            ..Limits::default()
        };
        assert_eq!(tiny.granted_cpus(24), 1);
    }

    #[test]
    fn job_rate_is_a_share_of_the_machine() {
        // 25% of a 24-CPU machine is six CPUs; 100% is all of them.
        assert_eq!(rate_to_milli(2500, 24), 6000);
        assert_eq!(rate_to_milli(10000, 24), 24000);
        assert_eq!(rate_to_milli(1, 4), 0);
    }

    #[test]
    fn memory_is_the_lower_of_limit_and_physical() {
        let gib = 1u64 << 30;
        let l = |limit, physical| Limits {
            cpu_quota_milli: None,
            memory_limit: limit,
            physical_memory: physical,
        };
        assert_eq!(l(Some(4 * gib), 32 * gib).memory(), 4 * gib);
        assert_eq!(l(Some(64 * gib), 32 * gib).memory(), 32 * gib);
        assert_eq!(l(None, 32 * gib).memory(), 32 * gib);
        assert_eq!(l(Some(gib), 0).memory(), gib);
    }
}
