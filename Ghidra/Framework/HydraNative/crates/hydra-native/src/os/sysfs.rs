//! Parsers for the Linux files the OS layer reads (sysfs CPU lists, cgroup v1 and v2 limits).
//! Plain text in, numbers out, so they are tested on every platform.

/// Parses a CPU list such as `0-3,8,10-11` (sysfs `online`, `shared_cpu_list`, `cpus`).
pub fn cpu_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.trim().split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) {
            out.extend(lo..=hi.max(lo));
        }
    }
    out
}

/// Parses cgroup v2 `cpu.max` (`<quota> <period>` or `max <period>`) into thousandths of a CPU.
pub fn cpu_max(s: &str) -> Option<u64> {
    let mut it = s.split_whitespace();
    let quota = it.next()?.parse::<u64>().ok()?;
    let period = it.next().map_or(Some(100_000), |p| p.parse::<u64>().ok())?;
    quota_milli(quota, period)
}

/// cgroup v1 `cpu.cfs_quota_us` and `cpu.cfs_period_us` (quota -1: no limit).
pub fn cfs_quota(quota: &str, period: &str) -> Option<u64> {
    let quota = quota.trim().parse::<i64>().ok().filter(|&q| q > 0)?;
    quota_milli(quota as u64, period.trim().parse().ok()?)
}

fn quota_milli(quota: u64, period: u64) -> Option<u64> {
    (period > 0).then(|| quota.saturating_mul(1000) / period)
}

/// Parses cgroup v2 `memory.max` or v1 `memory.limit_in_bytes` (`max`, or a value so large it
/// means no limit, gives `None`).
pub fn memory_max(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok().filter(|&v| v < (1u64 << 62))
}

/// The cgroup v2 path of the process from `/proc/self/cgroup` (the `0::<path>` line).
pub fn cgroup_v2_path(proc_cgroup: &str) -> Option<&str> {
    proc_cgroup.lines().find_map(|l| l.strip_prefix("0::"))
}

/// The cgroup v1 path of `controller` from `/proc/self/cgroup` (`<id>:<controllers>:<path>`).
pub fn cgroup_v1_path<'a>(proc_cgroup: &'a str, controller: &str) -> Option<&'a str> {
    proc_cgroup.lines().find_map(|l| {
        let mut parts = l.splitn(3, ':');
        let (_, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
        controllers
            .split(',')
            .any(|c| c == controller)
            .then_some(path)
    })
}

/// The directories from `path` up to the cgroup root, deepest first: a limit set on any of them
/// applies to the process.
pub fn ancestors(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = path.trim().trim_end_matches('/').to_string();
    loop {
        out.push(if p.is_empty() {
            "/".to_string()
        } else {
            p.clone()
        });
        match p.rfind('/') {
            Some(i) => p.truncate(i),
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(cpu_list("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(cpu_list("5"), vec![5]);
        assert_eq!(cpu_list(""), Vec::<u32>::new());
        assert_eq!(cpu_list("x,2"), vec![2]);
    }

    #[test]
    fn parses_cpu_quotas() {
        assert_eq!(cpu_max("150000 100000\n"), Some(1500));
        assert_eq!(cpu_max("max 100000"), None);
        assert_eq!(cpu_max("50000"), Some(500));
        assert_eq!(cpu_max("1 0"), None);
        assert_eq!(cfs_quota("-1", "100000"), None);
        assert_eq!(cfs_quota("400000\n", "100000\n"), Some(4000));
    }

    #[test]
    fn parses_memory_limits() {
        assert_eq!(memory_max("max\n"), None);
        assert_eq!(memory_max("4294967296\n"), Some(4 << 30));
        // cgroup v1 reports "no limit" as the largest page-aligned i64.
        assert_eq!(memory_max("9223372036854771712"), None);
    }

    #[test]
    fn finds_cgroup_paths() {
        let v2 = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            cgroup_v2_path(v2),
            Some("/user.slice/user-1000.slice/session-2.scope")
        );
        let v1 = "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n1:name=systemd:/x\n";
        assert_eq!(cgroup_v1_path(v1, "cpu"), Some("/docker/abc"));
        assert_eq!(cgroup_v1_path(v1, "memory"), Some("/docker/abc"));
        assert_eq!(cgroup_v1_path(v1, "cpuset"), None);
        assert_eq!(cgroup_v2_path(v1), None);
    }

    #[test]
    fn lists_ancestors_deepest_first() {
        assert_eq!(ancestors("/a/b/c"), vec!["/a/b/c", "/a/b", "/a", "/"]);
        assert_eq!(ancestors("/"), vec!["/"]);
        assert_eq!(ancestors(""), vec!["/"]);
    }
}
