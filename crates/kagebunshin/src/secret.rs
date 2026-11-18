//! The one type that holds a secret value.
//!
//! `SecretValue` zeroes its buffer on drop and has no `Display`, `Serialize`
//! or `Clone`. Its `Debug` output is a fixed placeholder so that containers can
//! derive `Debug` without leaking. Reading the value requires `expose()`.
//!
//! The value lives in locked, dump-excluded pages of its own
//! ([`crate::sys::LockedStr`]). When it cannot be locked, usually because
//! `RLIMIT_MEMLOCK` is used up, it stays on the heap, still zeroed on drop,
//! with one warning per process; [`SecretValue::is_locked`] tells which, so
//! the daemon can refuse under `strict_memory`.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize, Zeroizing};

use crate::sys::LockedStr;

pub struct SecretValue(Buf);

enum Buf {
    Locked(LockedStr),
    Heap(Zeroizing<String>),
}

static WARNED: AtomicBool = AtomicBool::new(false);

impl SecretValue {
    /// Copies the value into locked pages and zeroes `value`, or, if the
    /// pages cannot be locked, keeps `value`'s buffer.
    pub fn new(mut value: String) -> Self {
        match LockedStr::new(&value) {
            Ok(locked) => {
                value.zeroize();
                Self(Buf::Locked(locked))
            }
            Err(e) => {
                if !WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        error = %e,
                        "cannot lock memory for a secret value; keeping values in ordinary memory, \
                         which can be swapped out. Raise RLIMIT_MEMLOCK, or set strict_memory = true \
                         to refuse instead"
                    );
                }
                Self(Buf::Heap(Zeroizing::new(value)))
            }
        }
    }

    pub fn expose(&self) -> &str {
        match &self.0 {
            Buf::Locked(l) => l.as_str(),
            Buf::Heap(h) => h,
        }
    }

    pub fn len(&self) -> usize {
        self.expose().len()
    }

    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }

    /// Whether the value is in locked memory rather than on the heap.
    pub fn is_locked(&self) -> bool {
        matches!(self.0, Buf::Locked(_))
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    #[test]
    fn formatting_never_shows_the_value() {
        let canary = Canary::new();
        let v = SecretValue::new(canary.value().to_owned());
        assert_no_canary(&canary, &format!("{v:?}"));
        assert_no_canary(&canary, &format!("{v:#?}"));

        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            v: SecretValue,
        }
        assert_no_canary(&canary, &format!("{:?}", Holder { v }));
    }

    #[test]
    fn expose_returns_the_value() {
        let v = SecretValue::new("abc".to_owned());
        assert_eq!(v.expose(), "abc");
        assert_eq!(v.len(), 3);
        assert!(!v.is_empty());
        assert!(v.is_locked());
    }

    #[test]
    fn falls_back_to_the_heap_when_memory_cannot_be_locked() {
        use crate::test_support::{in_child, without_locked_memory};
        if !in_child("secret::tests::falls_back_to_the_heap_when_memory_cannot_be_locked")
            || !without_locked_memory()
        {
            return;
        }
        let v = SecretValue::new("abc".to_owned());
        assert!(!v.is_locked());
        assert_eq!(v.expose(), "abc");
    }
}
