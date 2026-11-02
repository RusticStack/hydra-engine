//! Background WAL checkpointing. A checkpoint copies the WAL into the main file and syncs it; run
//! inside a commit that stalls ingest for seconds once the index is large. The writer instead
//! asks this thread to run a passive checkpoint (which never blocks writers or readers) when the
//! WAL has grown past a threshold. Crash safety is unchanged: the WAL stays authoritative until
//! a checkpoint has finished.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;

/// WAL size at which a checkpoint is requested.
const WAL_THRESHOLD: u64 = 64 << 20;

pub(crate) struct Checkpointer {
    tx: Option<Sender<()>>,
    busy: Arc<AtomicBool>,
    wal: PathBuf,
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Checkpointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Checkpointer")
    }
}

impl Checkpointer {
    /// Starts the thread for the database at `db`; `None` when it cannot be opened.
    pub(crate) fn start(db: &Path) -> Option<Self> {
        let conn = Connection::open(db).ok()?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let (tx, rx) = channel::<()>();
        let busy = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&busy);
        let handle = std::thread::Builder::new()
            .name("hydra-trace-checkpoint".into())
            .spawn(move || {
                for () in rx {
                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
                    flag.store(false, Ordering::Release);
                }
            })
            .ok()?;
        let mut wal = db.as_os_str().to_owned();
        wal.push("-wal");
        Some(Self {
            tx: Some(tx),
            busy,
            wal: PathBuf::from(wal),
            handle: Some(handle),
        })
    }

    /// Called after a commit: requests a checkpoint when the WAL is large and none is running.
    pub(crate) fn after_commit(&self) {
        let big = std::fs::metadata(&self.wal).is_ok_and(|m| m.len() >= WAL_THRESHOLD);
        if big
            && self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            && let Some(tx) = &self.tx
            && tx.send(()).is_err()
        {
            self.busy.store(false, Ordering::Release);
        }
    }
}

impl Drop for Checkpointer {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
