//! The Hydra Engine native core (`hydra_native`), called from Java through the foreign function
//! API (`ghidra.util.HydraCpu`) with normal downcalls.
//!
//! This first part answers what the process may use and what it runs on: the logical CPUs the OS
//! grants it (affinity, CPU sets, job object or cgroup quota), its memory limit, the CPU's
//! identification and topology, and the tuning profile chosen for it. The C ABI is
//! `include/hydra_native.h`; its version is [`ABI_VERSION`].

pub mod cpuid;
pub mod limits;
pub mod os;
pub mod profile;
pub mod reply;
pub mod topology;

use cpuid::CpuId;
use limits::Limits;
use topology::Topology;

/// The version of the C ABI below. It changes whenever a function or `HydraCpuInfo` changes.
pub const ABI_VERSION: u32 = 1;

/// `hydra_cpu_query` succeeded.
pub const OK: i32 = 0;
/// `out` was null.
pub const ERR_NULL: i32 = -1;
/// `out_size` is smaller than `HydraCpuInfo`.
pub const ERR_SIZE: i32 = -2;
/// The override is not UTF-8.
pub const ERR_OVERRIDE: i32 = -3;

/// What `hydra_cpu_query` reports, laid out for C and for Java's `MemorySegment` reads (every
/// field at its natural alignment, no padding). Counts of CPUs and cores are of the CPUs the
/// process may run on, except `system_cpus`. Strings are NUL-terminated UTF-8, cut to fit.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HydraCpuInfo {
    /// `size_of::<HydraCpuInfo>()`.
    pub size: u32,
    pub abi_version: u32,
    /// Bytes the process may use: the lower of its memory limit and physical memory.
    pub memory_limit: u64,
    pub physical_memory: u64,
    /// Logical CPUs on the machine.
    pub system_cpus: u32,
    /// Logical CPUs the process may run on.
    pub affinity_cpus: u32,
    /// Logical CPUs the process can keep busy: `affinity_cpus`, lowered by any CPU quota.
    pub granted_cpus: u32,
    pub performance_cpus: u32,
    pub efficiency_cpus: u32,
    pub performance_cores: u32,
    pub efficiency_cores: u32,
    pub llc_groups: u32,
    pub l2_groups: u32,
    /// A hard CPU quota in thousandths of a CPU; 0 when none is set.
    pub cpu_quota_milli: u32,
    /// [`cpuid::Vendor`].
    pub vendor: u32,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// 1 when the CPU has more than one core class (CPUID or OS efficiency classes).
    pub hybrid: u32,
    /// [`cpuid::SimdLevel`].
    pub simd_level: u32,
    pub latency_threads: u32,
    pub compute_threads: u32,
    pub background_threads: u32,
    /// [`profile::Placement`].
    pub placement: u32,
    /// [`profile::Source`].
    pub profile_source: u32,
    pub reserved: u32,
    pub vendor_id: [u8; 16],
    pub profile_name: [u8; 32],
    pub brand: [u8; 64],
}

fn c_string<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut end = s.len().min(N - 1);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    out[..end].copy_from_slice(&s.as_bytes()[..end]);
    out
}

impl HydraCpuInfo {
    /// Builds the report from what was detected (or, in tests, made up).
    pub fn new(cpu: &CpuId, topo: &Topology, limits: &Limits, override_name: Option<&str>) -> Self {
        let s = topo.summary();
        let granted = limits.granted_cpus(s.affinity_cpus);
        let (profile, source) = profile::select(cpu, &s, override_name);
        let pools = profile.pools(&s, granted);
        HydraCpuInfo {
            size: size_of::<HydraCpuInfo>() as u32,
            abi_version: ABI_VERSION,
            memory_limit: limits.memory(),
            physical_memory: limits.physical_memory,
            system_cpus: s.system_cpus,
            affinity_cpus: s.affinity_cpus,
            granted_cpus: granted,
            performance_cpus: s.performance_cpus,
            efficiency_cpus: s.efficiency_cpus,
            performance_cores: s.performance_cores,
            efficiency_cores: s.efficiency_cores,
            llc_groups: s.llc_groups,
            l2_groups: s.l2_groups,
            cpu_quota_milli: limits
                .cpu_quota_milli
                .map_or(0, |q| q.clamp(1, u64::from(u32::MAX)) as u32),
            vendor: cpu.vendor as u32,
            family: cpu.family,
            model: cpu.model,
            stepping: cpu.stepping,
            hybrid: u32::from(cpu.hybrid || s.classes > 1),
            simd_level: cpu.simd as u32,
            latency_threads: pools.latency,
            compute_threads: pools.compute,
            background_threads: pools.background,
            placement: profile.placement as u32,
            profile_source: source as u32,
            reserved: 0,
            vendor_id: c_string(&cpu.vendor_id),
            profile_name: c_string(profile.name),
            brand: c_string(&cpu.brand),
        }
    }

    /// Detects everything for the calling process.
    pub fn detect(override_name: Option<&str>) -> Self {
        let (topo, limits) = os::detect();
        HydraCpuInfo::new(&cpuid::identify(), &topo, &limits, override_name)
    }
}

/// The version of this library's C ABI ([`ABI_VERSION`]).
#[unsafe(no_mangle)]
pub extern "C" fn hydra_native_abi_version() -> u32 {
    ABI_VERSION
}

/// `sizeof(HydraCpuInfo)`.
#[unsafe(no_mangle)]
pub extern "C" fn hydra_cpu_info_size() -> usize {
    size_of::<HydraCpuInfo>()
}

/// Detects the granted CPUs, memory limit, CPU and profile of the calling process into `out`.
///
/// `profile_override` (`override_len` bytes of UTF-8, not NUL-terminated) is `auto`, `generic` or
/// a profile name, as `HYDRA_CPU_PROFILE`; empty means `auto`, and a null pointer means "read
/// `HYDRA_CPU_PROFILE`". Returns [`OK`], or [`ERR_NULL`], [`ERR_SIZE`] or [`ERR_OVERRIDE`] with
/// `out` untouched. Takes a few system calls (no lock is held); call it once and keep the result.
///
/// # Safety
/// `out` must be valid for writes of `out_size` bytes; `profile_override`, when not null, must be
/// valid for reads of `override_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hydra_cpu_query(
    profile_override: *const u8,
    override_len: usize,
    out: *mut HydraCpuInfo,
    out_size: usize,
) -> i32 {
    if out.is_null() {
        return ERR_NULL;
    }
    if out_size < size_of::<HydraCpuInfo>() {
        return ERR_SIZE;
    }
    let env;
    let name = if profile_override.is_null() {
        env = std::env::var(profile::OVERRIDE_ENV).ok();
        env.as_deref()
    } else {
        // SAFETY: the caller guarantees `override_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(profile_override, override_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => Some(s),
            Err(_) => return ERR_OVERRIDE,
        }
    };
    let info = HydraCpuInfo::detect(name);
    // SAFETY: the caller guarantees `out` is valid for `out_size` >= size_of::<HydraCpuInfo>()
    // bytes; it may be unaligned (a Java segment at any offset).
    unsafe { out.write_unaligned(info) };
    OK
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;
    use crate::profile::{Placement, Source};

    #[test]
    fn layout_is_the_documented_one() {
        // The offsets Java reads (HydraCpu.java) and the header declares.
        assert_eq!(size_of::<HydraCpuInfo>(), 224);
        assert_eq!(align_of::<HydraCpuInfo>(), 8);
        assert_eq!(offset_of!(HydraCpuInfo, memory_limit), 8);
        assert_eq!(offset_of!(HydraCpuInfo, system_cpus), 24);
        assert_eq!(offset_of!(HydraCpuInfo, granted_cpus), 32);
        assert_eq!(offset_of!(HydraCpuInfo, cpu_quota_milli), 60);
        assert_eq!(offset_of!(HydraCpuInfo, vendor), 64);
        assert_eq!(offset_of!(HydraCpuInfo, simd_level), 84);
        assert_eq!(offset_of!(HydraCpuInfo, latency_threads), 88);
        assert_eq!(offset_of!(HydraCpuInfo, profile_source), 104);
        assert_eq!(offset_of!(HydraCpuInfo, vendor_id), 112);
        assert_eq!(offset_of!(HydraCpuInfo, profile_name), 128);
        assert_eq!(offset_of!(HydraCpuInfo, brand), 160);
    }

    fn text(b: &[u8]) -> &str {
        std::str::from_utf8(&b[..b.iter().position(|&c| c == 0).unwrap()]).unwrap()
    }

    #[test]
    fn reports_a_raptor_lake_under_a_job_quota() {
        let cpu = cpuid::decode(&cpuid::tests::raptor_lake_13700kf());
        let topo = topology::tests::raptor_lake_13700kf();
        let limits = Limits {
            cpu_quota_milli: Some(limits::rate_to_milli(2500, 24)),
            memory_limit: Some(8 << 30),
            physical_memory: 32 << 30,
        };
        let info = HydraCpuInfo::new(&cpu, &topo, &limits, None);
        assert_eq!(
            (info.system_cpus, info.affinity_cpus, info.granted_cpus),
            (24, 24, 6)
        );
        assert_eq!((info.cpu_quota_milli, info.memory_limit), (6000, 8 << 30));
        assert_eq!((info.family, info.model, info.hybrid), (6, 0xB7, 1));
        assert_eq!(text(&info.profile_name), "raptorlake-hybrid");
        assert_eq!(info.profile_source, Source::Auto as u32);
        assert_eq!(info.placement, Placement::LatencyOnPerformanceCores as u32);
        assert_eq!(
            (
                info.latency_threads,
                info.compute_threads,
                info.background_threads
            ),
            (6, 6, 6)
        );
        assert_eq!(text(&info.vendor_id), "GenuineIntel");
        assert_eq!(text(&info.brand), "13th Gen Intel(R) Core(TM) i7-13700KF");

        let forced = HydraCpuInfo::new(&cpu, &topo, &limits, Some("generic"));
        assert_eq!(text(&forced.profile_name), "generic");
        assert_eq!(forced.profile_source, Source::Forced as u32);
        assert_eq!(forced.placement, Placement::Any as u32);
        // A profile changes pool sizes and placement only; the detected facts are the same.
        assert_eq!(
            (forced.granted_cpus, forced.memory_limit, forced.model),
            (info.granted_cpus, info.memory_limit, info.model)
        );
    }

    #[test]
    fn strings_are_cut_on_a_character_boundary() {
        assert_eq!(c_string::<4>("abcdef"), *b"abc\0");
        assert_eq!(c_string::<4>("aé"), [b'a', 0xC3, 0xA9, 0]);
        assert_eq!(c_string::<4>("abé"), *b"ab\0\0");
    }

    #[test]
    fn query_checks_its_arguments() {
        let mut info = HydraCpuInfo::detect(None);
        let size = size_of::<HydraCpuInfo>();
        // SAFETY: the pointers are valid as documented, or null where the test says so.
        unsafe {
            assert_eq!(
                hydra_cpu_query(std::ptr::null(), 0, std::ptr::null_mut(), size),
                ERR_NULL
            );
            assert_eq!(
                hydra_cpu_query(std::ptr::null(), 0, &mut info, size - 1),
                ERR_SIZE
            );
            let bad = [0xFFu8];
            assert_eq!(
                hydra_cpu_query(bad.as_ptr(), 1, &mut info, size),
                ERR_OVERRIDE
            );
            let name = b"raptorlake-hybrid";
            assert_eq!(
                hydra_cpu_query(name.as_ptr(), name.len(), &mut info, size),
                OK
            );
        }
        assert_eq!(text(&info.profile_name), "raptorlake-hybrid");
        assert_eq!(info.profile_source, Source::Forced as u32);
        assert_eq!(info.size as usize, hydra_cpu_info_size());
        assert_eq!(info.abi_version, hydra_native_abi_version());
        assert!(info.granted_cpus >= 1 && info.granted_cpus <= info.affinity_cpus);
    }
}
