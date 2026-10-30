//! Linux: sysfs for the cores, core types (`cpu_core`/`cpu_atom` on Intel hybrid CPUs) and
//! caches; sched_getaffinity for what is granted; cgroup v2 (or v1) for the CPU quota and memory
//! limit.

use std::fs;
use std::mem::{size_of, zeroed};

use super::sysfs;
use crate::limits::Limits;
use crate::topology::{LogicalCpu, Topology};

const CPU: &str = "/sys/devices/system/cpu";
const CGROUP: &str = "/sys/fs/cgroup";

fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_u32(path: &str) -> Option<u32> {
    read(path)?.trim().parse().ok()
}

/// The CPUs sched_getaffinity grants the process (None when the call fails). Linux keeps a mask
/// per thread; the process's is its main thread's (pid), not the calling thread's (0), so a pool
/// thread pinned to some cores does not shrink what the whole process is granted.
fn affinity() -> Option<Vec<bool>> {
    // SAFETY: all zeroes is an empty cpu_set_t.
    let mut set: libc::cpu_set_t = unsafe { zeroed() };
    let pid = std::process::id() as libc::pid_t;
    // SAFETY: `set` is a cpu_set_t of the size passed.
    if unsafe { libc::sched_getaffinity(pid, size_of::<libc::cpu_set_t>(), &mut set) } != 0 {
        return None;
    }
    let max = 8 * size_of::<libc::cpu_set_t>();
    // SAFETY: CPU_ISSET reads bit `i` of the set, below its size.
    Some(
        (0..max)
            .map(|i| unsafe { libc::CPU_ISSET(i, &set) })
            .collect(),
    )
}

/// The cache group (the lowest CPU sharing it) of `cpu` at `level`, or the last level when
/// `level` is None.
fn cache_group(cpu: u32, level: Option<u32>) -> Option<u32> {
    let mut best: Option<(u32, u32)> = None;
    for index in 0.. {
        let dir = format!("{CPU}/cpu{cpu}/cache/index{index}");
        let Some(l) = read_u32(&format!("{dir}/level")) else {
            break;
        };
        if read(&format!("{dir}/type")).is_some_and(|t| t.trim() == "Instruction") {
            continue;
        }
        let shared = sysfs::cpu_list(&read(&format!("{dir}/shared_cpu_list"))?);
        let group = shared.into_iter().min().unwrap_or(cpu);
        match level {
            Some(want) if l == want => return Some(group),
            None if best.is_none_or(|(bl, _)| l > bl) => best = Some((l, group)),
            _ => {}
        }
    }
    best.map(|(_, g)| g)
}

fn topology() -> Topology {
    let online = read(&format!("{CPU}/online"))
        .map(|s| sysfs::cpu_list(&s))
        .unwrap_or_default();
    let granted = affinity();
    // Intel hybrid: the P-cores are listed under cpu_core, the E-cores under cpu_atom.
    let p_cores = read("/sys/devices/cpu_core/cpus").map(|s| sysfs::cpu_list(&s));
    let cpus = online
        .iter()
        .map(|&cpu| {
            let topo = format!("{CPU}/cpu{cpu}/topology");
            let package = read_u32(&format!("{topo}/physical_package_id")).unwrap_or(0);
            let core = read_u32(&format!("{topo}/core_id")).unwrap_or(cpu);
            LogicalCpu {
                core: package << 16 | core,
                efficiency_class: u8::from(p_cores.as_ref().is_some_and(|p| p.contains(&cpu))),
                llc: cache_group(cpu, None).unwrap_or(0),
                l2: cache_group(cpu, Some(2)),
                granted: granted
                    .as_ref()
                    .is_none_or(|g| g.get(cpu as usize).copied().unwrap_or(false)),
            }
        })
        .collect();
    Topology { cpus }
}

fn limits() -> Limits {
    let cgroup = read("/proc/self/cgroup").unwrap_or_default();
    let (cpu_quota_milli, memory_limit) = sysfs::cgroup_limits(&cgroup, CGROUP, read);
    // SAFETY: sysconf has no preconditions.
    let (pages, page) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    Limits {
        cpu_quota_milli,
        memory_limit,
        physical_memory: if pages > 0 && page > 0 {
            pages as u64 * page as u64
        } else {
            0
        },
    }
}

pub fn detect() -> (Topology, Limits) {
    (topology(), limits())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affinity_is_the_process_not_the_calling_thread() {
        let process = affinity().unwrap();
        let Some(first) = process.iter().position(|&g| g) else {
            return;
        };
        let pinned = std::thread::spawn(move || {
            // SAFETY: all zeroes is an empty cpu_set_t; `set` is a cpu_set_t of the size passed.
            unsafe {
                let mut set: libc::cpu_set_t = zeroed();
                libc::CPU_SET(first, &mut set);
                assert_eq!(
                    libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set),
                    0
                );
            }
            affinity().unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(pinned, process);
    }
}
