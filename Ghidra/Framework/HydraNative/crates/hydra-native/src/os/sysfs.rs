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

/// The CPU quota (thousandths of a CPU) and memory limit of the cgroup in `/proc/self/cgroup`,
/// the lowest set on it or any ancestor, with `read` reading the files under `root`
/// (`/sys/fs/cgroup`). A limit cgroup v2 does not give is looked up in v1: hybrid hosts list a
/// `0::` line while the controllers are mounted as v1 under `<root>/<controller>`.
pub fn cgroup_limits(
    proc_cgroup: &str,
    root: &str,
    read: impl Fn(&str) -> Option<String>,
) -> (Option<u64>, Option<u64>) {
    let file = |dir: &str, name: &str| read(&format!("{dir}/{name}"));
    let v2 = |parse: &dyn Fn(&str) -> Option<u64>| {
        cgroup_v2_path(proc_cgroup).and_then(|p| lowest(root, p, parse))
    };
    // In a container without its own cgroup namespace the path is the host's (`/docker/<id>`)
    // while the container's cgroup is mounted as the root, so the root is read too.
    let v1 = |controller: &str, limit: &dyn Fn(&str) -> Option<u64>| {
        cgroup_v1_path(proc_cgroup, controller)
            .and_then(|p| lowest(&format!("{root}/{controller}"), p, limit))
    };
    let cpu = v2(&|dir| cpu_max(&file(dir, "cpu.max")?)).or_else(|| {
        v1("cpu", &|dir| {
            cfs_quota(
                &file(dir, "cpu.cfs_quota_us")?,
                &file(dir, "cpu.cfs_period_us")?,
            )
        })
    });
    let memory = v2(&|dir| memory_max(&file(dir, "memory.max")?)).or_else(|| {
        v1("memory", &|dir| {
            memory_max(&file(dir, "memory.limit_in_bytes")?)
        })
    });
    (cpu, memory)
}

/// The lowest limit `limit` finds in the directory under `base` of the cgroup `path` or of any
/// of its ancestors.
fn lowest(base: &str, path: &str, limit: impl Fn(&str) -> Option<u64>) -> Option<u64> {
    ancestors(path)
        .iter()
        .filter_map(|dir| limit(&format!("{base}{}", dir.trim_end_matches('/'))))
        .min()
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

    fn files(entries: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |path| map.get(path).cloned()
    }

    #[test]
    fn reads_cgroup_v1_limits_from_the_lowest_ancestor() {
        // Docker on a cgroup v1 host: the path is the host's, the container's cgroup is the root.
        let proc_cgroup = "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n";
        let fs = files(&[
            ("/cg/cpu/cpu.cfs_quota_us", "200000\n"),
            ("/cg/cpu/cpu.cfs_period_us", "100000\n"),
            ("/cg/memory/memory.limit_in_bytes", "2147483648\n"),
        ]);
        assert_eq!(
            cgroup_limits(proc_cgroup, "/cg", fs),
            (Some(2000), Some(2 << 30))
        );
        // The lowest quota wins, each read with the period of its own directory.
        let fs = files(&[
            ("/cg/cpu/a/b/cpu.cfs_quota_us", "300000"),
            ("/cg/cpu/a/b/cpu.cfs_period_us", "100000"),
            ("/cg/cpu/a/cpu.cfs_quota_us", "100000"),
            ("/cg/cpu/a/cpu.cfs_period_us", "50000"),
            ("/cg/cpu/cpu.cfs_quota_us", "-1"),
            ("/cg/cpu/cpu.cfs_period_us", "100000"),
        ]);
        assert_eq!(cgroup_limits("4:cpu:/a/b", "/cg", fs), (Some(2000), None));
    }

    #[test]
    fn reads_cgroup_v1_limits_on_hybrid_hosts() {
        // systemd hybrid: a 0:: line for the unified hierarchy, the controllers mounted as v1.
        let proc_cgroup = "4:cpu,cpuacct:/user.slice\n3:memory:/user.slice\n0::/user.slice\n";
        let fs = files(&[
            ("/cg/cpu/user.slice/cpu.cfs_quota_us", "150000"),
            ("/cg/cpu/user.slice/cpu.cfs_period_us", "100000"),
            ("/cg/memory/user.slice/memory.limit_in_bytes", "1073741824"),
        ]);
        assert_eq!(
            cgroup_limits(proc_cgroup, "/cg", fs),
            (Some(1500), Some(1 << 30))
        );
    }

    #[test]
    fn reads_cgroup_v2_limits() {
        let fs = files(&[
            ("/cg/a/b/cpu.max", "max 100000"),
            ("/cg/a/cpu.max", "50000 100000"),
            ("/cg/a/b/memory.max", "4294967296"),
            ("/cg/memory.max", "max"),
        ]);
        assert_eq!(
            cgroup_limits("0::/a/b\n", "/cg", fs),
            (Some(500), Some(4 << 30))
        );
        assert_eq!(cgroup_limits("0::/\n", "/cg", files(&[])), (None, None));
    }
}
