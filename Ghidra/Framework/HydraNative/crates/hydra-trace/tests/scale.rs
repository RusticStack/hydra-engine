//! Scale gate (M0): 1M synthetic events at bounded memory, ingest rate, p95 of indexed queries
//! under 250 ms, and a diff inside its event budget that is byte-identical over three runs.
//! The 1M run is `#[ignore]`d in debug builds; run it with
//! `cargo test --release --test scale -- --ignored --nocapture`. A 50k smoke version always runs.

use hydra_trace::align::{AlignSpec, diff_aligned_default};
use hydra_trace::query::{self, Filter};
use hydra_trace::session::{self, Session};
use hydra_trace::store::Options;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Instant;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hydra-scale-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(windows)]
fn peak_rss() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: an all-zero counters struct with cb set is the documented input; the pseudo handle
    // of the current process is always valid.
    unsafe {
        let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            c.PeakWorkingSetSize as u64
        } else {
            0
        }
    }
}

#[cfg(windows)]
fn cpu_secs() -> f64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let z = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    // SAFETY: the pseudo handle is valid and the out pointers are live locals.
    unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
    let t = |f: FILETIME| {
        ((u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)) as f64 / 1e7
    };
    t(k) + t(u)
}

#[cfg(not(windows))]
fn cpu_secs() -> f64 {
    0.0
}

#[cfg(not(windows))]
fn peak_rss() -> u64 {
    0
}

fn event(i: u64, seed: u64) -> Value {
    let kind = match i % 5 {
        0 => "core.resource.open",
        1 | 2 => "core.state.write",
        3 => "app.request",
        _ => "app.completion",
    };
    let corr = format!("c{}", (i - i % 5) / 5 + seed);
    json!({
        "kind": kind, "source_id": "bench", "source_seq": i, "producer_gen": 1, "clock_domain": "c",
        "t_mono_ns": 1000 + i * 10, "confidence": "exact", "process_id": 7, "thread_id": 1 + i % 8,
        "payload": {"key": format!("res/{}", i % 5000), "object": i % 4096, "new": i % 100, "corr": corr}
    })
}

fn load(root: &std::path::Path, id: &str, n: u64, seed: u64) -> (Session, f64) {
    let (mut s, _) = Session::open(root, id, Options::default()).unwrap();
    let t = Instant::now();
    let mut i = 0;
    while i < n {
        let end = (i + 10_000).min(n);
        let batch: Vec<Value> = (i..end).map(|k| event(k, seed)).collect();
        let bt = Instant::now();
        let r = s.append(&batch).unwrap();
        assert_eq!(r.accepted, end - i);
        if std::env::var_os("HYDRA_SCALE_BATCHES").is_some() {
            println!(
                "batch@{end}: {:.0} ev/s",
                (end - i) as f64 / bt.elapsed().as_secs_f64()
            );
        }
        i = end;
    }
    (s, n as f64 / t.elapsed().as_secs_f64())
}

fn run(n: u64, rss_limit: u64) {
    let dir = scratch(&format!("n{n}"));
    let cpu0 = cpu_secs();
    let (s, rate) = load(&dir, "big", n, 0);
    println!(
        "ingest cpu: {:.1} s (includes bench event construction)",
        cpu_secs() - cpu0
    );
    println!("loaded in {:.1}s", n as f64 / rate);
    let rss_after_ingest = peak_rss();
    println!(
        "ingest: {n} events, {rate:.0} events/s, peak working set {} MiB",
        rss_after_ingest >> 20
    );
    assert_eq!(s.store().event_count().unwrap(), n);
    assert!(
        rss_after_ingest < rss_limit,
        "peak working set {rss_after_ingest} exceeds {rss_limit}"
    );
    drop(s);

    let store = session::reader(&dir, "big").unwrap();
    let mut times = Vec::new();
    for round in 0..40u64 {
        let filters = [
            Filter {
                kinds: vec!["app.request".into()],
                after: (round * 997) as i64 % n as i64,
                limit: 100,
                ..Filter::default()
            },
            Filter {
                resource_key: Some(format!("res/{}", round * 31 % 5000)),
                limit: 100,
                ..Filter::default()
            },
            Filter {
                corr: Some(format!("c{}", round * 17 % (n / 5))),
                limit: 100,
                ..Filter::default()
            },
            Filter {
                state_key: Some(format!("0:{}#?:hp", round % 4096)),
                limit: 100,
                ..Filter::default()
            },
        ];
        for f in &filters {
            let t = Instant::now();
            let page = query::query(&store, f).unwrap();
            times.push(t.elapsed().as_secs_f64() * 1000.0);
            assert!(page.rows.len() <= 100);
        }
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p95 = times[times.len() * 95 / 100];
    println!(
        "indexed query: p50 {:.2} ms, p95 {p95:.2} ms over {} queries",
        times[times.len() / 2],
        times.len()
    );
    assert!(p95 < 250.0, "p95 {p95} ms");

    // Relations are computed on demand from the indexed candidates; report what that costs.
    let t = Instant::now();
    let c0 = cpu_secs();
    let (rels, source) = hydra_trace::relations::current(&store).unwrap();
    println!(
        "relations on demand: {} relations ({source}) in {:.2} s wall, {:.2} s cpu",
        rels.len(),
        t.elapsed().as_secs_f64(),
        cpu_secs() - c0
    );

    // Diff against a smaller second session, inside a fixed event budget, three runs.
    let (b, _) = load(&dir, "other", n / 4, 1);
    drop(b);
    let other = session::reader(&dir, "other").unwrap();
    let spec = AlignSpec {
        keys: vec!["kind".into(), "process".into()],
        event_budget: n as usize + 1,
        ..AlignSpec::default()
    };
    let t = Instant::now();
    let c0 = cpu_secs();
    let first =
        serde_json::to_string(&diff_aligned_default(&store, &other, &spec).unwrap()).unwrap();
    let secs = t.elapsed().as_secs_f64();
    println!("aligned diff cpu {:.2} s", cpu_secs() - c0);
    println!("aligned diff: {secs:.2} s, {} bytes of reply", first.len());
    for _ in 0..2 {
        assert_eq!(
            first,
            serde_json::to_string(&diff_aligned_default(&store, &other, &spec).unwrap()).unwrap()
        );
    }
    // Worker threads are sized from the CPU grants; the reply must not depend on them, so a
    // single-thread grant (generic profile on a small box) equals a wide one (auto profile).
    for (compute, background) in [(1, 1), (2, 1), (8, 4)] {
        hydra_trace::workers::configure(compute, background);
        assert_eq!(
            first,
            serde_json::to_string(&diff_aligned_default(&store, &other, &spec).unwrap()).unwrap(),
            "diff differs with {compute} compute threads"
        );
    }
    let tight = AlignSpec {
        event_budget: 1000,
        ..spec
    };
    let d = diff_aligned_default(&store, &other, &tight).unwrap();
    assert!(d.limitations.contains(&"budget-reached".to_string()));
    assert!(d.scanned_a <= 1000);
    assert!(
        peak_rss() < rss_limit,
        "peak working set after queries and diff: {}",
        peak_rss()
    );
    println!("peak working set at the end: {} MiB", peak_rss() >> 20);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn smoke_50k() {
    run(50_000, 1 << 30);
}

#[test]
#[ignore = "1M events: run with --release -- --ignored"]
fn one_million_events() {
    let n = std::env::var("HYDRA_SCALE_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    run(n, 1536 << 20);
}
