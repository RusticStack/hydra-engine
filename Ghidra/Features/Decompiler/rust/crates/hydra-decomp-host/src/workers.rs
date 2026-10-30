//! The snapshot backend's worker pool, with store affinity.
//!
//! A worker builds its own `SnapshotArchitecture` for every store (program generation) it runs a
//! job for, and keeps up to `HYDRA_SNAPSHOT_ARCHS` (default 4) of them (C++ `workerArchs`, an LRU
//! per thread). A work-stealing pool (rayon) hands each job to whichever thread is free, so after a
//! while every worker holds an Architecture for every busy store: N workers x stores Architectures,
//! each built (registration, specs parsed, the type factory warmed from the store) N times.
//!
//! This pool sends a job for store S to a worker that already holds S when one is idle, else to
//! an idle worker (preferring one that holds the fewest stores, so no other store's Architecture is
//! evicted), else queues it behind the least loaded warm worker. So the number of Architectures
//! per store follows the number of decompiles of that store that actually run at once, not the
//! pool size; an idle worker never waits while another one's queue is non-empty for long, because
//! a job is queued behind a busy worker only when every worker is busy.
//!
//! The pool mirrors each worker's C++ LRU (same capacity, same most-recently-used order) to know
//! which worker holds which store; the mirror is a hint only (a stale entry costs one Architecture
//! build, never a wrong result: the C++ side looks the store up itself).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

type Task = Box<dyn FnOnce() + Send + 'static>;

struct Worker {
    q: Mutex<VecDeque<Task>>,
    cv: Condvar,
}

struct State {
    /// Jobs queued on or running in each worker.
    load: Vec<usize>,
    /// Each worker's stores, most recently used first (mirror of the C++ LRU).
    warm: Vec<VecDeque<usize>>,
}

/// Worker threads with per-worker queues and store affinity.
pub struct Pool {
    workers: Vec<Arc<Worker>>,
    st: Mutex<State>,
    archs: usize,
}

fn archs_per_worker() -> usize {
    std::env::var("HYDRA_SNAPSHOT_ARCHS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0 && *n < 1000)
        .unwrap_or(4)
}

impl Pool {
    /// Starts `n` workers (named `decomp-snapshot-<i>`, `stack` bytes of stack each).
    pub fn new(n: usize, stack: usize) -> Result<Arc<Pool>, String> {
        let n = n.max(1);
        let pool = Arc::new(Pool {
            workers: (0..n)
                .map(|_| {
                    Arc::new(Worker {
                        q: Mutex::new(VecDeque::new()),
                        cv: Condvar::new(),
                    })
                })
                .collect(),
            st: Mutex::new(State {
                load: vec![0; n],
                warm: vec![VecDeque::new(); n],
            }),
            archs: archs_per_worker(),
        });
        for (i, w) in pool.workers.iter().enumerate() {
            let w = Arc::clone(w);
            std::thread::Builder::new()
                .name(format!("decomp-snapshot-{i}"))
                .stack_size(stack)
                .spawn(move || {
                    loop {
                        let task = {
                            let mut q = w.q.lock().unwrap_or_else(PoisonError::into_inner);
                            loop {
                                if let Some(t) = q.pop_front() {
                                    break t;
                                }
                                q = w.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
                            }
                        };
                        task();
                    }
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(pool)
    }

    /// Number of workers.
    pub fn current_num_threads(&self) -> usize {
        self.workers.len()
    }

    /// The worker a job for store `key` goes to (its load is counted).
    fn pick(&self, key: usize) -> usize {
        let mut s = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        let n = self.workers.len();
        let holds = |s: &State, i: usize| s.warm[i].contains(&key);
        let idle_warm = (0..n).find(|&i| s.load[i] == 0 && holds(&s, i));
        let i = match idle_warm {
            Some(i) => i,
            None => match (0..n)
                .filter(|&i| s.load[i] == 0)
                .min_by_key(|&i| s.warm[i].len())
            {
                Some(i) => i,
                None => (0..n)
                    .filter(|&i| holds(&s, i))
                    .min_by_key(|&i| s.load[i])
                    .unwrap_or_else(|| (0..n).min_by_key(|&i| s.load[i]).unwrap_or(0)),
            },
        };
        s.load[i] += 1;
        let w = &mut s.warm[i];
        if let Some(p) = w.iter().position(|k| *k == key) {
            w.remove(p);
        }
        w.push_front(key);
        w.truncate(self.archs);
        i
    }

    /// Queues `f` on worker `i`; `after` runs once the worker's load no longer counts the job.
    fn push(self: &Arc<Self>, i: usize, f: Task, after: Option<Task>) {
        let me = Arc::clone(self);
        let task: Task = Box::new(move || {
            // the job itself catches panics; the load is released whatever happens
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            me.st.lock().unwrap_or_else(PoisonError::into_inner).load[i] -= 1;
            if let Some(a) = after {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(a));
            }
        });
        let w = &self.workers[i];
        w.q.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(task);
        w.cv.notify_one();
    }

    /// Runs `f` for store `key` on the chosen worker without waiting.
    pub fn spawn_for(self: &Arc<Self>, key: usize, f: impl FnOnce() + Send + 'static) {
        let i = self.pick(key);
        self.push(i, Box::new(f), None);
    }

    /// Runs `f` for store `key` on the chosen worker and waits for its result.
    pub fn install_for<R: Send + 'static>(
        self: &Arc<Self>,
        key: usize,
        f: impl FnOnce() -> R + Send + 'static,
    ) -> Option<R> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let slot = Arc::new(Mutex::new(None));
        let put = Arc::clone(&slot);
        let i = self.pick(key);
        self.push(
            i,
            Box::new(move || {
                *put.lock().unwrap_or_else(PoisonError::into_inner) = Some(f());
            }),
            Some(Box::new(move || {
                let _ = tx.send(());
            })),
        );
        rx.recv().ok()?;
        slot.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    /// Runs `f` once on every worker (after the jobs queued there) and waits for all of them.
    pub fn broadcast(self: &Arc<Self>, f: impl Fn() + Send + Sync + 'static) {
        let f = Arc::new(f);
        let (tx, rx) = std::sync::mpsc::channel();
        for i in 0..self.workers.len() {
            let f = Arc::clone(&f);
            let tx = tx.clone();
            self.st.lock().unwrap_or_else(PoisonError::into_inner).load[i] += 1;
            self.push(
                i,
                Box::new(move || f()),
                Some(Box::new(move || {
                    let _ = tx.send(());
                })),
            );
        }
        drop(tx);
        while rx.recv().is_ok() {}
        let mut s = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        for w in s.warm.iter_mut() {
            w.clear();
        }
    }

    /// Forgets store `key` (closed): no worker is preferred for it any more.
    pub fn forget(&self, key: usize) {
        let mut s = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        for w in s.warm.iter_mut() {
            w.retain(|k| *k != key);
        }
    }

    /// How many workers hold each store (diagnostics/tests).
    pub fn holders(&self, key: usize) -> usize {
        let s = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        s.warm.iter().filter(|w| w.contains(&key)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn sequential_jobs_of_one_store_stay_on_one_worker() {
        let p = Pool::new(8, 1 << 20).unwrap();
        for _ in 0..50 {
            p.install_for(7, || ()).unwrap();
        }
        assert_eq!(
            p.holders(7),
            1,
            "one Architecture for a store decompiled one at a time"
        );
    }

    #[test]
    fn concurrent_jobs_spread_to_idle_workers() {
        let p = Pool::new(4, 1 << 20).unwrap();
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..4 {
            let (r, pk, tx) = (Arc::clone(&running), Arc::clone(&peak), tx.clone());
            p.spawn_for(9, move || {
                let now = r.fetch_add(1, Ordering::SeqCst) + 1;
                pk.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                r.fetch_sub(1, Ordering::SeqCst);
                tx.send(()).unwrap();
            });
        }
        for _ in 0..4 {
            rx.recv().unwrap();
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            4,
            "4 jobs on 4 idle workers run at once"
        );
        assert_eq!(p.holders(9), 4);
    }

    #[test]
    fn other_stores_avoid_evicting_warm_workers() {
        let p = Pool::new(4, 1 << 20).unwrap();
        p.install_for(1, || ()).unwrap();
        p.install_for(2, || ()).unwrap();
        // an idle worker holding nothing is preferred over the one holding store 1
        assert_eq!(p.holders(1), 1);
        assert_eq!(p.holders(2), 1);
        p.forget(1);
        assert_eq!(p.holders(1), 0);
        p.broadcast(|| ());
        assert_eq!(p.holders(2), 0, "broadcast (release) clears the mirror");
    }
}
