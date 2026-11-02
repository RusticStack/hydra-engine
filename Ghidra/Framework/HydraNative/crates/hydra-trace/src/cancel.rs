//! Cooperative cancellation of one request on the calling thread.
//!
//! The C ABI (`hydra_trace_set_cancel`) installs a check before a long command and removes it
//! after; the long loops (`export`, `resymbolize`) call [`cancelled`] between units of work and
//! stop with [`crate::store::Error::Cancelled`], leaving nothing visible behind (an export is
//! staged and renamed; a resymbolization is one transaction that is not committed).

use std::cell::RefCell;

type Check = Box<dyn Fn() -> bool>;

thread_local! {
    static CHECK: RefCell<Option<Check>> = const { RefCell::new(None) };
}

/// Installs (or, with `None`, removes) the cancel check of this thread.
pub fn set(check: Option<Check>) {
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
    }
}
