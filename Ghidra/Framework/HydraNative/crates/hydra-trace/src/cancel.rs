//! Cooperative cancellation of one request on the calling thread.
//!
//! The C ABI (`hydra_trace_set_cancel`) installs a check before a long command and removes it
//! after; the long loops (`export`, `resymbolize`) call [`cancelled`] between units of work and
//! stop with [`crate::store::Error::Cancelled`], leaving nothing visible behind (an export is
//! staged and renamed; a resymbolization is one transaction that is not committed).

use std::cell::RefCell;
use std::sync::Arc;

/// A cancel check; shared, so a worker thread a request starts can inherit it.
pub type Check = Arc<dyn Fn() -> bool + Send + Sync>;

type Progress = Box<dyn Fn(u64, u64)>;

thread_local! {
    static CHECK: RefCell<Option<Check>> = const { RefCell::new(None) };
    static PROGRESS: RefCell<Option<Progress>> = const { RefCell::new(None) };
}

/// Installs (or, with `None`, removes) the progress sink of this thread: long loops report
/// `(done, total)` units of work, `total` 0 when unknown.
pub fn set_progress(sink: Option<Progress>) {
    PROGRESS.with(|c| *c.borrow_mut() = sink);
}

/// Report progress of the request running on this thread (a no-op without a sink).
pub fn progress(done: u64, total: u64) {
    PROGRESS.with(|c| {
        if let Some(f) = c.borrow().as_ref() {
            f(done, total);
        }
    });
}

/// Installs (or, with `None`, removes) the cancel check of this thread.
pub fn set(check: Option<Box<dyn Fn() -> bool + Send + Sync>>) {
    CHECK.with(|c| *c.borrow_mut() = check.map(Arc::from));
}

/// The check of this thread, to hand to a worker thread of the same request.
pub fn current() -> Option<Check> {
    CHECK.with(|c| c.borrow().clone())
}

/// Installs a check taken from [`current`] on another thread.
pub fn inherit(check: Option<Check>) {
    CHECK.with(|c| *c.borrow_mut() = check);
}

/// Whether the request running on this thread was cancelled.
pub fn cancelled() -> bool {
    CHECK.with(|c| c.borrow().as_ref().is_some_and(|f| f()))
}

/// `Err(Cancelled)` when the request was cancelled.
pub fn check() -> crate::store::Result<()> {
    if cancelled() {
        Err(crate::store::Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_is_per_thread_and_removable() {
        assert!(!cancelled());
        set(Some(Box::new(|| true)));
        assert!(cancelled());
        assert!(check().is_err());
        std::thread::spawn(|| assert!(!cancelled())).join().unwrap();
        set(None);
        assert!(check().is_ok());
        let seen = std::rc::Rc::new(std::cell::Cell::new((0, 0)));
        let sink = seen.clone();
        set_progress(Some(Box::new(move |d, t| sink.set((d, t)))));
        progress(3, 9);
        assert_eq!(seen.get(), (3, 9));
        set_progress(None);
        progress(4, 9);
        assert_eq!(seen.get(), (3, 9));
    }
}
