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
//! pool size. Affinity is a preference, not a binding: a worker whose own queue is empty steals a
//! queued job from another worker (one for a store it holds first, else the oldest job of the
//! longest queue), so no job waits behind a busy worker while another worker is idle. The queues
//! and the bookkeeping share one lock, so choosing a worker and queueing on it is atomic with a
//! worker's decision to wait (no lost wakeup). Jobs last milliseconds, so one lock is not contended.
//!
//! The pool mirrors each worker's C++ LRU (same capacity, same most-recently-used order) to know
//! which worker holds which store; the mirror is a hint only (a stale entry costs one Architecture
//! build, never a wrong result: the C++ side looks the store up itself, and a stolen job builds or
//! finds its Architecture on the thief's thread).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

type Task = Box<dyn FnOnce() + Send + 'static>;

struct Job {
    /// The store, or `None` for a job that must run on its own worker (broadcast).
    key: Option<usize>,
    f: Task,
    /// Runs once the worker's load no longer counts the job.
    after: Option<Task>,
}

struct State {
    /// Jobs queued on or running in each worker.
    load: Vec<usize>,
    /// Each worker's stores, most recently used first (mirror of the C++ LRU).
    warm: Vec<VecDeque<usize>>,
    /// Each worker's queue.
    q: Vec<VecDeque<Job>>,
    /// Whether each worker is running a job (only a running worker's queue is stolen from: an
    /// idle one takes its own jobs).
    running: Vec<bool>,
    /// Set when the pool could not start: the workers already started exit.
    shutdown: bool,
}

/// Worker threads with per-worker queues, store affinity and work stealing.
pub struct Pool {
    cv: Vec<Condvar>,
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

/// Marks `key` most recently used in a worker's LRU mirror.
fn touch(w: &mut VecDeque<usize>, key: usize, cap: usize) {
    if let Some(p) = w.iter().position(|k| *k == key) {
        w.remove(p);
    }
    w.push_front(key);
    w.truncate(cap);
}

impl Pool {
    /// Starts `n` workers (named `decomp-snapshot-<i>`, `stack` bytes of stack each). If a thread
    /// cannot be started, the ones already started exit and the error is returned.
    pub fn new(n: usize, stack: usize) -> Result<Arc<Pool>, String> {
        let (pool, r) = Self::start(n, stack, None);
        r.map(|()| pool)
    }

    /// `fail_at`: tests inject a spawn failure at that worker.
    fn start(n: usize, stack: usize, fail_at: Option<usize>) -> (Arc<Pool>, Result<(), String>) {
        let n = n.max(1);
        let pool = Arc::new(Pool {
            cv: (0..n).map(|_| Condvar::new()).collect(),
            st: Mutex::new(State {
                load: vec![0; n],
                warm: vec![VecDeque::new(); n],
                q: (0..n).map(|_| VecDeque::new()).collect(),
                running: vec![false; n],
                shutdown: false,
            }),
            archs: archs_per_worker(),
        });
        for i in 0..n {
            let me = Arc::clone(&pool);
            let r = if fail_at == Some(i) {
                Err("injected spawn failure".to_string())
            } else {
                std::thread::Builder::new()
                    .name(format!("decomp-snapshot-{i}"))
                    .stack_size(stack)
                    .spawn(move || me.work(i))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            };
            if let Err(e) = r {
                pool.lock().shutdown = true;
                for c in &pool.cv {
                    c.notify_all();
                }
                return (pool, Err(e));
            }
        }
        (pool, Ok(()))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next job for worker `i`: its own queue first, else one stolen from another worker;
    /// `None` once the pool is shut down.
    fn next(&self, i: usize) -> Option<Job> {
        let mut s = self.lock();
        loop {
            if s.shutdown {
                return None;
            }
            if let Some(j) = s.q[i].pop_front().or_else(|| self.steal(&mut s, i)) {
                s.running[i] = true;
                return Some(j);
            }
            s = self.cv[i].wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Takes a stealable job for idle worker `i` from another worker's queue, moving its load.
    fn steal(&self, s: &mut State, i: usize) -> Option<Job> {
        let n = s.q.len();
        let mut from: Option<(usize, usize)> = None;
        // a job for a store worker i already holds, most recently used store first
        'warm: for &key in s.warm[i].iter() {
            for v in (0..n).filter(|&v| v != i && s.running[v]) {
                if let Some(p) = s.q[v].iter().position(|j| j.key == Some(key)) {
                    from = Some((v, p));
                    break 'warm;
                }
            }
        }
        if from.is_none() {
            // else the oldest stealable job of the longest queue
            from = (0..n)
                .filter(|&v| v != i && s.running[v])
                .filter_map(|v| {
                    s.q[v]
                        .iter()
                        .position(|j| j.key.is_some())
                        .map(|p| (s.q[v].len(), v, p))
                })
                .max_by_key(|&(len, _, _)| len)
                .map(|(_, v, p)| (v, p));
        }
        let (v, p) = from?;
        let job = s.q[v].remove(p)?;
        s.load[v] -= 1;
        s.load[i] += 1;
        if let Some(key) = job.key {
            touch(&mut s.warm[i], key, self.archs);
        }
        Some(job)
    }

    fn work(&self, i: usize) {
        while let Some(job) = self.next(i) {
            // the job itself catches panics; the load is released whatever happens
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.f));
            {
                let mut s = self.lock();
                s.load[i] -= 1;
                s.running[i] = false;
            }
            if let Some(a) = job.after {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(a));
            }
        }
    }

    /// Number of workers.
    pub fn current_num_threads(&self) -> usize {
        self.cv.len()
    }

    /// Chooses the worker for a job for store `key` and queues the job there (one critical
    /// section, so a worker going idle either is chosen or sees the job to steal).
    fn submit(&self, key: usize, f: Task, after: Option<Task>) {
        let mut s = self.lock();
        let n = s.load.len();
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
        touch(&mut s.warm[i], key, self.archs);
        s.q[i].push_back(Job {
            key: Some(key),
            f,
            after,
        });
        drop(s);
        self.cv[i].notify_one();
    }

    /// Runs `f` for store `key` on the chosen worker without waiting.
    pub fn spawn_for(self: &Arc<Self>, key: usize, f: impl FnOnce() + Send + 'static) {
        self.submit(key, Box::new(f), None);
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
        self.submit(
            key,
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
    /// These jobs are never stolen.
    pub fn broadcast(self: &Arc<Self>, f: impl Fn() + Send + Sync + 'static) {
        let f = Arc::new(f);
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let mut s = self.lock();
            for i in 0..s.q.len() {
                let f = Arc::clone(&f);
                let tx = tx.clone();
                s.load[i] += 1;
                s.q[i].push_back(Job {
                    key: None,
                    f: Box::new(move || f()),
                    after: Some(Box::new(move || {
                        let _ = tx.send(());
                    })),
                });
            }
        }
        for c in &self.cv {
            c.notify_one();
        }
        drop(tx);
        while rx.recv().is_ok() {}
        let mut s = self.lock();
        for w in s.warm.iter_mut() {
            w.clear();
        }
    }

    /// Forgets store `key` (closed): no worker is preferred for it any more.
    pub fn forget(&self, key: usize) {
        let mut s = self.lock();
        for w in s.warm.iter_mut() {
            w.retain(|k| *k != key);
        }
    }

    /// How many workers hold each store (diagnostics/tests).
    pub fn holders(&self, key: usize) -> usize {
        let s = self.lock();
        s.warm.iter().filter(|w| w.contains(&key)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

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

    /// Review repro: store 2 warm on one worker that is then busy for 1.5 s, the other worker
    /// busy for 50 ms; four 20 ms jobs for store 2 must run on the worker that goes idle, not
    /// wait for the long job.
    #[test]
    fn idle_worker_steals_jobs_queued_behind_a_long_job() {
        let p = Pool::new(2, 1 << 20).unwrap();
        p.install_for(2, || ()).unwrap();
        let t0 = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        p.spawn_for(2, || std::thread::sleep(Duration::from_millis(1500)));
        p.spawn_for(3, || std::thread::sleep(Duration::from_millis(50)));
        for _ in 0..4 {
            let tx = tx.clone();
            p.spawn_for(2, move || {
                std::thread::sleep(Duration::from_millis(20));
                tx.send(t0.elapsed()).unwrap();
            });
        }
        for _ in 0..4 {
            let done = rx.recv().unwrap();
            assert!(
                done < Duration::from_millis(1000),
                "a queued job waited {done:?} behind a busy worker while another was idle"
            );
        }
    }

    #[test]
    fn broadcast_runs_once_on_every_worker_and_is_not_stolen() {
        let p = Pool::new(4, 1 << 20).unwrap();
        p.spawn_for(1, || std::thread::sleep(Duration::from_millis(100)));
        let names = Arc::new(Mutex::new(Vec::new()));
        let n2 = Arc::clone(&names);
        p.broadcast(move || {
            let name = std::thread::current().name().unwrap_or("").to_string();
            n2.lock().unwrap().push(name);
        });
        let mut v = names.lock().unwrap().clone();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), 4, "one run on each of the 4 workers: {v:?}");
    }

    #[test]
    fn failed_start_stops_the_started_workers() {
        let (pool, r) = Pool::start(3, 1 << 20, Some(2));
        assert!(r.is_err());
        let weak = Arc::downgrade(&pool);
        drop(pool);
        // each started worker holds the pool; they release it only by exiting
        let deadline = Instant::now() + Duration::from_secs(5);
        while weak.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "started workers still running after a failed start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
