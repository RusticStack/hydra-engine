//! Worker thread counts for the trace's parallel work (aligned diff scans), sized by the host
//! from its CPU grants. `hydra-native` sets them from the detected pools at start-up; without
//! that the counts come from the OS parallelism, never above the CPUs the process may use.

use std::sync::atomic::{AtomicUsize, Ordering};

static COMPUTE: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND: AtomicUsize = AtomicUsize::new(0);

fn fallback() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// Sets the thread counts of the compute (batch) and background pools. Zero is clamped to one.
pub fn configure(compute: usize, background: usize) {
    COMPUTE.store(compute.max(1), Ordering::Relaxed);
    BACKGROUND.store(background.max(1), Ordering::Relaxed);
}

/// Threads for throughput work such as a diff scan.
pub fn compute() -> usize {
    match COMPUTE.load(Ordering::Relaxed) {
        0 => fallback(),
        n => n,
    }
}

/// Threads for low-priority work such as ingest side jobs.
pub fn background() -> usize {
    match BACKGROUND.load(Ordering::Relaxed) {
        0 => fallback(),
        n => n,
    }
}
