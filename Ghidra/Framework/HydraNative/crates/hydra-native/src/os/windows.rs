//! Windows: CPU sets (GetSystemCpuSetInformation) for the cores, efficiency classes and last-level
//! caches; GetLogicalProcessorInformationEx for the L2 groups; the process affinity and default
//! CPU sets for what is granted; the job object for the CPU rate and memory limits.

use std::mem::{offset_of, size_of, zeroed};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE, JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::SystemInformation::{
    CACHE_RELATIONSHIP, CpuSetInformation, GROUP_AFFINITY, GetLogicalProcessorInformationEx,
    GetSystemCpuSetInformation, GlobalMemoryStatusEx, LOGICAL_PROCESSOR_RELATIONSHIP,
    MEMORYSTATUSEX, RelationCache, SYSTEM_CPU_SET_INFORMATION,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessAffinityMask, GetProcessDefaultCpuSets, GetProcessGroupAffinity,
};
use windows_sys::core::BOOL;

use crate::limits::{self, Limits};
use crate::topology::{LogicalCpu, Topology};

/// One entry of GetSystemCpuSetInformation.
struct CpuSet {
    id: u32,
    group: u16,
    index: u8,
    core: u8,
    llc: u8,
    class: u8,
}

/// Calls `fill(buffer, length)` twice, first to learn the size; returns the bytes it wrote (in
/// u64s, so the buffer is aligned for the first record).
fn query(mut fill: impl FnMut(*mut u8, &mut u32) -> BOOL) -> Option<Vec<u64>> {
    let mut len = 0u32;
    if fill(null_mut(), &mut len) == 0 {
        // SAFETY: reads the calling thread's last error, set by the call above.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if fill(buf.as_mut_ptr().cast(), &mut len) == 0 {
        return None;
    }
    buf.truncate((len as usize).div_ceil(8));
    Some(buf)
}

/// The records of a buffer of variable-size records, as (start, size in bytes): `size_at` is the
/// offset of each record's u32 size. A record can be shorter than its Rust type (whose union is
/// as large as the largest member), so callers read only the parts its size covers, and with
/// `read_unaligned` since the OS may pack the records.
fn records(buf: &[u64], size_at: usize) -> Vec<(*const u8, usize)> {
    let bytes = buf.len() * 8;
    let base = buf.as_ptr().cast::<u8>();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + size_at + 4 <= bytes {
        // SAFETY: the record's size field lies inside the buffer (checked above).
        let ptr = unsafe { base.add(off) };
        // SAFETY: as above.
        let size = unsafe { ptr.add(size_at).cast::<u32>().read_unaligned() } as usize;
        if size == 0 || off + size > bytes {
            break;
        }
        out.push((ptr, size));
        off += size;
    }
    out
}

fn cpu_sets(process: HANDLE) -> Vec<CpuSet> {
    let buf = query(|ptr, len| {
        // SAFETY: `ptr` is null with length 0, or a buffer of `len` bytes.
        unsafe { GetSystemCpuSetInformation(ptr.cast(), *len, len, process, 0) }
    });
    let Some(buf) = buf else {
        return Vec::new();
    };
    records(&buf, offset_of!(SYSTEM_CPU_SET_INFORMATION, Size))
        .into_iter()
        .filter(|&(_, size)| size >= size_of::<SYSTEM_CPU_SET_INFORMATION>())
        .map(|(ptr, _)| {
            // SAFETY: the record covers the whole struct (filtered above).
            unsafe { ptr.cast::<SYSTEM_CPU_SET_INFORMATION>().read_unaligned() }
        })
        .filter(|r| r.Type == CpuSetInformation)
        .map(|r| {
            // SAFETY: Type is CpuSetInformation, so CpuSet is the union member written.
            let s = unsafe { r.Anonymous.CpuSet };
            CpuSet {
                id: s.Id,
                group: s.Group,
                index: s.LogicalProcessorIndex,
                core: s.CoreIndex,
                llc: s.LastLevelCacheIndex,
                class: s.EfficiencyClass,
            }
        })
        .collect()
}

/// The (group, mask) pairs the process may run on.
fn affinity(process: HANDLE) -> Vec<(u16, usize)> {
    let mut groups = [0u16; 64];
    let mut count = groups.len() as u16;
    // SAFETY: `groups` has room for `count` entries.
    if unsafe { GetProcessGroupAffinity(process, &mut count, groups.as_mut_ptr()) } == 0 {
        return Vec::new();
    }
    let groups = &groups[..count as usize];
    let (mut mask, mut system) = (0usize, 0usize);
    // SAFETY: plain out-parameters. The call reports 0 masks for a process in several groups.
    let ok = unsafe { GetProcessAffinityMask(process, &mut mask, &mut system) } != 0;
    match groups {
        [g] if ok && mask != 0 => vec![(*g, mask)],
        _ => groups.iter().map(|&g| (g, usize::MAX)).collect(),
    }
}

/// The process's default CPU set ids (empty: none set).
fn default_cpu_sets(process: HANDLE) -> Vec<u32> {
    let mut required = 0u32;
    // SAFETY: a null buffer of length 0 asks for the count.
    if unsafe { GetProcessDefaultCpuSets(process, null_mut(), 0, &mut required) } != 0 {
        return Vec::new();
    }
    let mut ids = vec![0u32; required as usize];
    // SAFETY: `ids` has room for `required` ids.
    let ok =
        unsafe { GetProcessDefaultCpuSets(process, ids.as_mut_ptr(), required, &mut required) };
    if ok == 0 {
        return Vec::new();
    }
    ids.truncate(required as usize);
    ids
}

/// The L2 group of each (group, logical index), numbered in the order Windows lists the caches.
fn l2_groups() -> Vec<(u16, usize, u32)> {
    let buf = query(|ptr, len| {
        // SAFETY: `ptr` is null with length 0, or a buffer of `len` bytes.
        unsafe { GetLogicalProcessorInformationEx(RelationCache, ptr.cast(), len) }
    });
    let Some(buf) = buf else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut next = 0u32;
    let body = offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Anonymous);
    let masks_at = body + offset_of!(CACHE_RELATIONSHIP, Anonymous);
    for (ptr, size) in records(
        &buf,
        offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Size),
    ) {
        // SAFETY: every record starts with Relationship (records() read its Size after it).
        let relationship = unsafe {
            ptr.cast::<LOGICAL_PROCESSOR_RELATIONSHIP>()
                .read_unaligned()
        };
        if relationship != RelationCache || size < masks_at + size_of::<GROUP_AFFINITY>() {
            continue;
        }
        // SAFETY: a cache record covers the CACHE_RELATIONSHIP up to its first mask (checked).
        let cache = unsafe { ptr.add(body).cast::<CACHE_RELATIONSHIP>().read_unaligned() };
        if cache.Level != 2 {
            continue;
        }
        // GroupCount 0 (before Windows 11) means the one GroupMask.
        let n = usize::from(cache.GroupCount.max(1))
            .min((size - masks_at) / size_of::<GROUP_AFFINITY>());
        // SAFETY: `masks_at` is inside the record (checked above).
        let masks = unsafe { ptr.add(masks_at) }.cast::<GROUP_AFFINITY>();
        for i in 0..n {
            // SAFETY: the record holds `n` masks from `masks_at` on (bounded by its size above).
            let m = unsafe { masks.add(i).read_unaligned() };
            out.push((m.Group, m.Mask, next));
        }
        next += 1;
    }
    out
}

fn in_job(process: HANDLE) -> bool {
    let mut result: BOOL = 0;
    // SAFETY: a null job handle asks about any job.
    unsafe { IsProcessInJob(process, std::ptr::null_mut(), &mut result) != 0 && result != 0 }
}

fn job_info<T>(class: i32) -> Option<T> {
    // SAFETY: T is a plain C struct for which all zeroes is valid.
    let mut info: T = unsafe { zeroed() };
    // SAFETY: a null job handle means the job of the calling process; `info` is `size_of::<T>()`.
    let ok = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            class,
            (&mut info as *mut T).cast(),
            size_of::<T>() as u32,
            null_mut(),
        )
    };
    (ok != 0).then_some(info)
}

/// The hard CPU rate cap of the job, in hundredths of a percent of the machine.
fn job_cpu_rate() -> Option<u32> {
    let info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION =
        job_info(JobObjectCpuRateControlInformation)?;
    let flags = info.ControlFlags;
    if flags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE == 0
        || flags & JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED != 0
    {
        return None;
    }
    if flags & JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE != 0 {
        // SAFETY: with MIN_MAX_RATE the union holds MinRate/MaxRate.
        return Some(u32::from(unsafe { info.Anonymous.Anonymous.MaxRate }));
    }
    if flags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP != 0 {
        // SAFETY: without WEIGHT_BASED or MIN_MAX_RATE the union holds CpuRate.
        return Some(unsafe { info.Anonymous.CpuRate });
    }
    None
}

fn job_memory_limit() -> Option<u64> {
    let info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = job_info(JobObjectExtendedLimitInformation)?;
    let flags = info.BasicLimitInformation.LimitFlags;
    let process = (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0).then_some(info.ProcessMemoryLimit);
    let job = (flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0).then_some(info.JobMemoryLimit);
    process.into_iter().chain(job).map(|v| v as u64).min()
}

fn physical_memory() -> u64 {
    // SAFETY: all zeroes is a valid MEMORYSTATUSEX; dwLength is set before the call.
    let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: `status` is a MEMORYSTATUSEX with its length set.
    if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
        status.ullTotalPhys
    } else {
        0
    }
}

pub fn detect() -> (Topology, Limits) {
    // SAFETY: the pseudo handle of the current process; it needs no closing.
    let process = unsafe { GetCurrentProcess() };
    let sets = cpu_sets(process);
    let allowed = affinity(process);
    let defaults = default_cpu_sets(process);
    let l2 = l2_groups();

    let cpus = sets
        .iter()
        .map(|s| {
            let bit = 1usize.checked_shl(u32::from(s.index)).unwrap_or(0);
            let in_mask = allowed.iter().any(|&(g, m)| g == s.group && m & bit != 0);
            let in_sets = defaults.is_empty() || defaults.contains(&s.id);
            LogicalCpu {
                core: u32::from(s.group) << 8 | u32::from(s.core),
                efficiency_class: s.class,
                llc: u32::from(s.group) << 8 | u32::from(s.llc),
                l2: l2
                    .iter()
                    .find(|&&(g, m, _)| g == s.group && m & bit != 0)
                    .map(|&(_, _, n)| n),
                granted: in_mask && in_sets,
            }
        })
        .collect();

    let topo = Topology { cpus };
    let job = in_job(process);
    let limits = Limits {
        cpu_quota_milli: job
            .then(job_cpu_rate)
            .flatten()
            .map(|rate| limits::rate_to_milli(rate, topo.cpus.len() as u32)),
        memory_limit: job.then(job_memory_limit).flatten(),
        physical_memory: physical_memory(),
    };
    (topo, limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer of records laid out as the OS lays them out: each a u32 size at `size_at`.
    fn buffer(size_at: usize, sizes: &[u32]) -> Vec<u64> {
        let mut bytes = Vec::new();
        for &size in sizes {
            let mut rec = vec![0u8; size as usize];
            rec[size_at..size_at + 4].copy_from_slice(&size.to_le_bytes());
            bytes.extend(rec);
        }
        bytes.resize(bytes.len().div_ceil(8) * 8, 0);
        bytes
            .chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn walks_records_shorter_than_their_type() {
        // Cache records (56 bytes) are shorter than SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        // (80, sized by its largest member): the last ones must not be dropped.
        assert!(size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>() > 56);
        let buf = buffer(4, &[48, 56, 56, 56]);
        let sizes: Vec<usize> = records(&buf, 4).into_iter().map(|(_, s)| s).collect();
        assert_eq!(sizes, vec![48, 56, 56, 56]);
    }

    #[test]
    fn stops_at_a_record_that_overruns_the_buffer() {
        let mut buf = buffer(0, &[32, 32]);
        buf.truncate(6); // 48 bytes: the second record is cut short
        assert_eq!(records(&buf, 0).len(), 1);
        let mut zero = buffer(0, &[32, 32]);
        zero[0] = 0; // a size of 0 ends the walk
        assert!(records(&zero, 0).is_empty());
    }
}
