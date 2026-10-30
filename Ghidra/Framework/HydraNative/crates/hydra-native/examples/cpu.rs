//! Prints what hydra_native detects for this process, as the engine sees it:
//! `cargo run --example cpu` (with `HYDRA_CPU_PROFILE` to force a profile).

use hydra_native::HydraCpuInfo;

fn text(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn main() {
    let name = std::env::var(hydra_native::profile::OVERRIDE_ENV).ok();
    let i = HydraCpuInfo::detect(name.as_deref());
    println!(
        "cpu       {} ({}) family {:#x} model {:#x} stepping {}",
        text(&i.brand),
        text(&i.vendor_id),
        i.family,
        i.model,
        i.stepping
    );
    println!(
        "features  hybrid {} simd level {}",
        i.hybrid != 0,
        i.simd_level
    );
    println!(
        "cpus      granted {} of {} (affinity {}, quota {} milli-CPUs)",
        i.granted_cpus, i.system_cpus, i.affinity_cpus, i.cpu_quota_milli
    );
    println!(
        "classes   performance {} CPUs / {} cores, efficiency {} CPUs / {} cores",
        i.performance_cpus, i.performance_cores, i.efficiency_cpus, i.efficiency_cores
    );
    println!(
        "caches    {} last-level groups, {} L2 groups",
        i.llc_groups, i.l2_groups
    );
    println!(
        "memory    {} MiB of {} MiB physical",
        i.memory_limit >> 20,
        i.physical_memory >> 20
    );
    println!(
        "profile   {} (source {}, placement {}) threads latency {} compute {} background {}",
        text(&i.profile_name),
        i.profile_source,
        i.placement,
        i.latency_threads,
        i.compute_threads,
        i.background_threads
    );
}
