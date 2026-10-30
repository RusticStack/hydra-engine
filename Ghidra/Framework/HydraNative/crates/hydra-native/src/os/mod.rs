//! What the OS says about the machine and the process: the topology and the limits.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod sysfs;
#[cfg(windows)]
mod windows;

use crate::limits::Limits;
use crate::topology::Topology;

/// Reads the topology and the limits. When the OS cannot be asked (or lists no CPU), the
/// topology is the standard library's count of CPUs, all granted.
pub fn detect() -> (Topology, Limits) {
    #[cfg(windows)]
    let (topo, limits) = windows::detect();
    #[cfg(target_os = "linux")]
    let (topo, limits) = linux::detect();
    #[cfg(not(any(windows, target_os = "linux")))]
    let (topo, limits) = (Topology::default(), Limits::default());

    if topo.cpus.iter().any(|c| c.granted) {
        (topo, limits)
    } else {
        let n = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
        (Topology::uniform(n), limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_granted_cpus() {
        let (topo, limits) = detect();
        let s = topo.summary();
        assert!(s.affinity_cpus >= 1 && s.affinity_cpus <= s.system_cpus);
        assert_eq!(s.performance_cpus + s.efficiency_cpus, s.affinity_cpus);
        assert!(s.performance_cores >= 1);
        assert!(s.llc_groups >= 1);
        assert!(limits.physical_memory > 0);
        assert!(limits.granted_cpus(s.affinity_cpus) <= s.affinity_cpus);
    }

    #[cfg(windows)]
    #[test]
    fn every_cpu_has_an_l2_group() {
        // Windows reports the L2 caches of every core; the last records in its buffer are the
        // last cores' (the E-cores' on a hybrid CPU).
        let (topo, _) = detect();
        assert!(topo.cpus.iter().all(|c| c.l2.is_some()), "{topo:?}");
    }
}
