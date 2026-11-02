//! The consumer's run: arguments, the process tree, the writer thread, health, and the refusal path.

use crate::etw::{self, InfoCache, Session};
use crate::events::{Prop, Provider, kind_of, payload};
use crate::segment::Chain;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;

const QUEUE: usize = 65_536;
const SYNC_EVERY: u64 = 1 << 20;

#[derive(Debug, Default)]
struct Args {
    dir: PathBuf,
    session: String,
    pids: Vec<u32>,
    key_file: PathBuf,
    gen_: u32,
    providers: Vec<Provider>,
    stop_file: Option<PathBuf>,
    duration: Option<Duration>,
    kernel_filter: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        gen_: 1,
        providers: Provider::ALL.to_vec(),
        ..Args::default()
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--dir" => out.dir = PathBuf::from(value()?),
            "--session" => out.session = value()?,
            "--pid" => out
                .pids
                .push(value()?.parse().map_err(|_| "--pid is a number")?),
            "--key-file" => out.key_file = PathBuf::from(value()?),
            "--gen" => out.gen_ = value()?.parse().map_err(|_| "--gen is a number")?,
            "--providers" => {
                out.providers = value()?
                    .split(',')
                    .map(|n| Provider::from_name(n).ok_or_else(|| format!("unknown provider {n}")))
                    .collect::<Result<_, _>>()?;
            }
            "--stop-file" => out.stop_file = Some(PathBuf::from(value()?)),
            "--duration-ms" => {
                out.duration = Some(Duration::from_millis(
                    value()?.parse().map_err(|_| "--duration-ms is a number")?,
                ));
            }
            "--kernel-filter" => out.kernel_filter = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if out.dir.as_os_str().is_empty()
        || out.session.is_empty()
        || out.pids.is_empty()
        || out.key_file.as_os_str().is_empty()
    {
        return Err("--dir, --session, --pid and --key-file are required".into());
    }
    Ok(out)
}

fn frequency() -> u64 {
    let mut f = 0i64;
    // SAFETY: valid out pointer.
    unsafe { QueryPerformanceFrequency(&raw mut f) };
    u64::try_from(f).unwrap_or(10_000_000).max(1)
}

fn clock_domain(freq: u64) -> String {
    if freq == 10_000_000 {
        "qpc-10mhz".into()
    } else {
        format!("qpc-{freq}hz")
    }
}

/// The writer's counters, shared with the callback and the health file.
#[derive(Debug, Default)]
struct Counters {
    seen: AtomicU64,
    outside_tree: AtomicU64,
    matched: AtomicU64,
    queue_dropped: AtomicU64,
    decode_failed: AtomicU64,
    partial: AtomicU64,
    written: AtomicU64,
    write_failed: AtomicU64,
    bytes: AtomicU64,
}

fn get(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// An event on its way to the segment.
#[derive(Debug)]
struct Pending {
    kind: &'static str,
    ticks: u64,
    pid: u32,
    tid: u32,
    payload: Value,
}

/// The only writer of the segment.
#[derive(Debug)]
struct Writer {
    file: File,
    chain: Chain,
    seq: u64,
    gen_: u32,
    freq: u64,
    unsynced: u64,
    gap_seen: u64,
}

impl Writer {
    fn open(dir: &Path, segment_id: &str, gen_: u32, freq: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("etw.seg"))?;
        Ok(Self {
            file,
            chain: Chain::new(segment_id),
            seq: 0,
            gen_,
            freq,
            unsynced: 0,
            gap_seen: 0,
        })
    }

    fn put(
        &mut self,
        counters: &Counters,
        kind: &str,
        t_ns: u64,
        pid: Option<u32>,
        tid: Option<u32>,
        payload: Value,
    ) {
        let mut e = Map::new();
        e.insert("kind".into(), kind.into());
        e.insert("source_id".into(), "etw".into());
        e.insert("source_seq".into(), self.seq.into());
        e.insert("producer_gen".into(), self.gen_.into());
        e.insert("clock_domain".into(), clock_domain(self.freq).into());
        e.insert("t_mono_ns".into(), t_ns.into());
        e.insert("confidence".into(), "exact".into());
        e.insert("acquisition".into(), "atomic".into());
        if let Some(p) = pid {
            e.insert("process_id".into(), p.into());
        }
        if let Some(t) = tid {
            e.insert("thread_id".into(), t.into());
        }
        e.insert("payload".into(), payload);
        self.seq += 1;
        match self.chain.push(e) {
            Ok(line) => match self.file.write_all(&line) {
                Ok(()) => {
                    counters.written.fetch_add(1, Ordering::Relaxed);
                    counters
                        .bytes
                        .fetch_add(line.len() as u64, Ordering::Relaxed);
                    self.unsynced += line.len() as u64;
                    if self.unsynced >= SYNC_EVERY {
                        let _ = self.file.sync_data();
                        self.unsynced = 0;
                    }
                }
                Err(_) => {
                    counters.write_failed.fetch_add(1, Ordering::Relaxed);
                }
            },
            Err(_) => {
                counters.decode_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn ns(&self, ticks: u64) -> u64 {
        u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(self.freq)).unwrap_or(u64::MAX)
    }
}

fn now_ns(freq: u64) -> u64 {
    let mut t = 0i64;
    // SAFETY: valid out pointer.
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&raw mut t) };
    u64::try_from(u128::from(u64::try_from(t).unwrap_or(0)) * 1_000_000_000 / u128::from(freq))
        .unwrap_or(0)
}

/// Roots plus every descendant already running (`ToolHelp` snapshot).
fn initial_tree(roots: &[u32]) -> HashSet<u32> {
    let mut tree: HashSet<u32> = roots.iter().copied().collect();
    let mut rows = Vec::new();
    // SAFETY: standard ToolHelp walk; the snapshot handle is closed below.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if !snap.is_null() && snap as isize != -1 {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &raw mut entry);
            while ok != 0 {
                rows.push((entry.th32ProcessID, entry.th32ParentProcessID));
                ok = Process32NextW(snap, &raw mut entry);
            }
            windows_sys::Win32::Foundation::CloseHandle(snap);
        }
    }
    loop {
        let before = tree.len();
        for (pid, parent) in &rows {
            if tree.contains(parent) && *pid != 0 {
                tree.insert(*pid);
            }
        }
        if tree.len() == before {
            return tree;
        }
    }
}

fn prop_int(props: &[(String, Prop)], name: &str) -> Option<u32> {
    props
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .and_then(|(_, p)| {
            if let Prop::Int(v) = p {
                u32::try_from(*v).ok()
            } else {
                None
            }
        })
}

fn write_health(dir: &Path, value: &Value) {
    let tmp = dir.join("etw.health.json.tmp");
    if std::fs::write(&tmp, value.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("etw.health.json"));
    }
}

fn write_head(dir: &Path, w: &Writer, finalized: bool) {
    let info = json!({"records": w.chain.count(), "head": w.chain.head(), "finalized": finalized});
    let tmp = dir.join("etw.seg.head.tmp");
    if std::fs::write(&tmp, info.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("etw.seg.head"));
    }
}

/// Run the consumer; the process exit code.
pub(crate) fn run(raw: &[String]) -> i32 {
    let args = match parse(raw) {
        Ok(a) => a,
        Err(message) => {
            eprintln!("hydra-etw: {message}");
            return 2;
        }
    };
    let key = match std::fs::read(&args.key_file) {
        Ok(k) if k.len() == 32 => k,
        _ => {
            eprintln!("hydra-etw: --key-file must hold the 32-byte scope key");
            return 2;
        }
    };
    let freq = frequency();
    let segment_id = format!("{}/etw/{}", args.session, args.gen_);
    let counters = Arc::new(Counters::default());
    let mut writer = match Writer::open(&args.dir, &segment_id, args.gen_, freq) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hydra-etw: cannot open the segment: {e}");
            return 2;
        }
    };
    let provider_names: Vec<&str> = args.providers.iter().map(|p| p.short()).collect();

    // Refuse cleanly without elevation: the refusal is recorded as missing coverage.
    if !etw::is_elevated() {
        let reason =
            "real-time kernel ETW needs an elevated token (or the Performance Log Users group)";
        writer.put(&counters, "core.capture.source", now_ns(freq), None, None, json!({
            "source_type": "etw", "state": "refused", "reason": reason, "limitation": "etw-not-elevated", "providers": provider_names}));
        write_head(&args.dir, &writer, true);
        write_health(
            &args.dir,
            &json!({"source": "etw", "state": "refused", "limitation": "etw-not-elevated", "reason": reason,
            "producer": {"events_lost": null, "buffers_lost": null}, "transport": {}, "writer": {"written": get(&counters.written)},
            "claims": {"attached": false, "observing": false, "finalized": true}}),
        );
        let _ = writer.file.sync_data();
        return 3;
    }

    let session_name = format!(
        "hydra-etw-{}-{}",
        std::process::id(),
        now_ns(freq) & 0xFFFF_FFFF
    );
    let mut session = match Session::start(&session_name) {
        Ok(s) => s,
        Err(status) => {
            writer.put(&counters, "core.capture.source", now_ns(freq), None, None, json!({
                "source_type": "etw", "state": "refused", "reason": format!("StartTrace failed with Win32 error {status}"), "win32_error": status}));
            write_health(
                &args.dir,
                &json!({"source": "etw", "state": "failed", "win32_error": status}),
            );
            return 2;
        }
    };
    let tree = Arc::new(Mutex::new(initial_tree(&args.pids)));
    let roots: Vec<u32> = tree
        .lock()
        .map(|t| t.iter().copied().collect())
        .unwrap_or_default();
    let mut enable_report = Vec::new();
    let mut enabled = 0;
    for p in &args.providers {
        let filter: &[u32] = if args.kernel_filter { &roots } else { &[] };
        let status = session.enable(*p, filter);
        if status == 0 {
            enabled += 1;
        }
        enable_report.push(json!({"provider": p.name(), "short": p.short(), "status": status, "enabled": status == 0,
            "kernel_filter": args.kernel_filter && status == 0}));
    }
    writer.put(&counters, "core.capture.source", now_ns(freq), None, None, json!({
        "source_type": "etw", "state": if enabled > 0 { "activated" } else { "refused" }, "session": session_name,
        "producer_gen": args.gen_, "providers": enable_report, "tree_roots": args.pids, "tree_size_at_start": roots.len(),
        "filter": if args.kernel_filter { "kernel pid filter on the roots (children created later are missed until re-enabled) plus tree filter" } else { "tree filter in the consumer" },
        "clock": {"domain": clock_domain(freq), "unit": "qpc-tick", "frequency_hz": freq}}));
    if enabled == 0 {
        session.stop();
        write_health(
            &args.dir,
            &json!({"source": "etw", "state": "failed", "providers": enable_report}),
        );
        return 2;
    }

    // Consumer callback: filter, decode, hand to the writer. A full queue is counted, never blocked on.
    let (tx, rx): (SyncSender<Pending>, _) = sync_channel(QUEUE);
    let cb_counters = Arc::clone(&counters);
    let cb_tree = Arc::clone(&tree);
    let cb_key = key;
    let mut cache = InfoCache::new();
    let callback: etw::Callback = Box::new(move |ev| {
        cb_counters.seen.fetch_add(1, Ordering::Relaxed);
        let Some(provider) = ev.provider else { return };
        let mut subject = ev.pid;
        let in_tree = |pid: u32| cb_tree.lock().is_ok_and(|t| t.contains(&pid));
        let mut decoded = None;
        if provider == Provider::Process && matches!(ev.id, 1..=6) {
            decoded = ev.properties(&mut cache);
            if let Some((props, _)) = &decoded {
                if let Some(p) = prop_int(props, "ProcessID") {
                    subject = p;
                }
                if ev.id == 1
                    && let (Some(child), Some(parent)) = (
                        prop_int(props, "ProcessID"),
                        prop_int(props, "ParentProcessID"),
                    )
                    && let Ok(mut t) = cb_tree.lock()
                    && (t.contains(&parent) || t.contains(&ev.pid))
                {
                    t.insert(child);
                }
            }
        }
        if !in_tree(subject) && !in_tree(ev.pid) {
            cb_counters.outside_tree.fetch_add(1, Ordering::Relaxed);
            return;
        }
        cb_counters.matched.fetch_add(1, Ordering::Relaxed);
        let decoded = decoded.or_else(|| ev.properties(&mut cache));
        let (props, partial) = if let Some(v) = decoded {
            v
        } else {
            cb_counters.decode_failed.fetch_add(1, Ordering::Relaxed);
            (Vec::new(), true)
        };
        if partial {
            cb_counters.partial.fetch_add(1, Ordering::Relaxed);
        }
        if provider == Provider::Process
            && ev.id == 2
            && let Ok(mut t) = cb_tree.lock()
        {
            t.remove(&subject); // the pid may be reused
        }
        let item = Pending {
            kind: kind_of(provider, ev.id),
            ticks: ev.ticks,
            pid: subject,
            tid: ev.tid,
            payload: payload(
                provider, ev.id, ev.version, ev.opcode, &props, partial, &cb_key,
            ),
        };
        if tx.try_send(item).is_err() {
            cb_counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
        }
    });
    let consumer_name = session_name;
    let consumer = std::thread::spawn(move || etw::consume(&consumer_name, callback));

    let wdir = args.dir.clone();
    let wcounters = Arc::clone(&counters);
    let writer_thread = std::thread::spawn(move || {
        let mut last_health = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(item) => {
                    let dropped = get(&wcounters.queue_dropped);
                    if dropped > writer.gap_seen {
                        let missing = dropped - writer.gap_seen;
                        writer.gap_seen = dropped;
                        let first = writer.seq;
                        writer.seq += missing;
                        let t = writer.ns(item.ticks);
                        writer.put(&wcounters, "core.capture.gap", t, None, None, json!({
                            "reason": "ring-overflow", "dropped": missing, "detail": "consumer queue full", "out_of_band": false,
                            "first_missing_source_seq": first, "last_missing_source_seq": first + missing - 1}));
                    }
                    let t = writer.ns(item.ticks);
                    writer.put(
                        &wcounters,
                        item.kind,
                        t,
                        Some(item.pid),
                        Some(item.tid),
                        item.payload,
                    );
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if last_health.elapsed() >= Duration::from_millis(250) {
                write_head(&wdir, &writer, false);
                last_health = Instant::now();
            }
        }
        writer
    });

    // Wait for the stop signal; keep the health file fresh.
    let started = Instant::now();
    let mut last_health: Option<Instant> = None;
    loop {
        let stop = args.stop_file.as_ref().is_some_and(|p| p.exists())
            || args.duration.is_some_and(|d| started.elapsed() >= d)
            || consumer.is_finished();
        if last_health.is_none_or(|t| t.elapsed() >= Duration::from_millis(500)) {
            let s = session.stats();
            write_health(&args.dir, &health("active", &counters, &s, &enable_report));
            last_health = Some(Instant::now());
        }
        if stop {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let final_stats = session.stats();
    session.stop();
    let consume_result = consumer.join();
    etw::clear_callback();
    let Ok(mut writer) = writer_thread.join() else {
        return 2;
    };
    let t_end = now_ns(freq);
    if final_stats.events_lost > 0
        || final_stats.buffers_lost > 0
        || final_stats.real_time_buffers_lost > 0
    {
        writer.put(&counters, "core.capture.gap", t_end, None, None, json!({
            "reason": "producer-lost", "dropped": final_stats.events_lost, "out_of_band": true, "hop": "etw-session",
            "events_lost": final_stats.events_lost, "buffers_lost": final_stats.buffers_lost,
            "real_time_buffers_lost": final_stats.real_time_buffers_lost}));
    }
    let report = health("stopped", &counters, &final_stats, &enable_report);
    writer.put(
        &counters,
        "core.capture.source",
        t_end,
        None,
        None,
        json!({
        "source_type": "etw", "state": "deactivated", "reason": "stopped", "health": report}),
    );
    let _ = writer.file.sync_data();
    write_head(&args.dir, &writer, true);
    write_health(
        &args.dir,
        &health("stopped", &counters, &final_stats, &enable_report),
    );
    match consume_result {
        Ok(Ok(0 | _)) => 0,
        _ => 2,
    }
}

fn health(state: &str, c: &Counters, s: &etw::SessionStats, providers: &[Value]) -> Value {
    json!({
        "source": "etw", "state": state,
        "producer": {"events_lost": s.events_lost, "buffers_lost": s.buffers_lost, "real_time_buffers_lost": s.real_time_buffers_lost,
                     "buffers_written": s.buffers_written, "provider_enable_failures": providers.iter().filter(|p| p["enabled"] == false).count(),
                     "providers": providers},
        "transport": {"seen": get(&c.seen), "outside_tree": get(&c.outside_tree), "matched": get(&c.matched),
                      "queue_dropped": get(&c.queue_dropped), "decode_failed": get(&c.decode_failed), "partial_decode": get(&c.partial)},
        "writer": {"written": get(&c.written), "bytes": get(&c.bytes), "write_failed": get(&c.write_failed)},
    })
}
