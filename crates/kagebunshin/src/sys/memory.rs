//! Memory for secret values, and process settings that keep them out of
//! core dumps and debuggers.

use std::io;
use std::ptr::NonNull;

use zeroize::Zeroize;

/// Whole pages of their own, locked in RAM so they are never swapped out
/// and, on Linux, left out of core dumps. Zeroed, unlocked and unmapped on
/// drop.
///
/// Every value gets its own pages because `mlock` does not count: unlocking
/// one of two values that shared a page would unlock both.
pub struct LockedPages {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the pages are a private mapping only this value points to, so
// moving or sharing it across threads is like moving or sharing a `Box<[u8]>`.
unsafe impl Send for LockedPages {}
// SAFETY: as above; `&LockedPages` only reads.
unsafe impl Sync for LockedPages {}

impl LockedPages {
    /// Maps and locks enough whole pages for `size` bytes, at least one.
    /// Fails when the memory cannot be locked, typically because
    /// `RLIMIT_MEMLOCK` is used up.
    pub fn new(size: usize) -> io::Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|&p| p > 0)
            .unwrap_or(4096);
        let len = size.max(1).div_ceil(page) * page;
        // SAFETY: an anonymous private mapping at an address the kernel
        // picks; nothing else is touched. The result is checked below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pages = Self {
            ptr: NonNull::new(ptr.cast()).ok_or_else(|| io::Error::other("mmap returned null"))?,
            len,
        };
        // SAFETY: `ptr..ptr+len` is the mapping made above.
        if unsafe { libc::mlock(ptr, len) } != 0 {
            // Dropping unmaps it; munlock of unlocked pages is harmless.
            return Err(io::Error::last_os_error());
        }
        // Best effort: without it the pages are still locked and zeroed.
        #[cfg(target_os = "linux")]
        // SAFETY: as above.
        unsafe {
            libc::madvise(ptr, len, libc::MADV_DONTDUMP);
        }
        Ok(pages)
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the mapping is `len` readable bytes, valid until drop, and
        // only reachable through `self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` makes this the only
        // reference.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Overwrites every byte with zero, as drop does before unmapping.
    pub fn wipe(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for LockedPages {
    fn drop(&mut self) {
        self.wipe();
        let ptr = self.ptr.as_ptr().cast();
        // SAFETY: the mapping made in `new`, unmapped exactly once, here;
        // nothing refers to it after drop.
        unsafe {
            libc::munlock(ptr, self.len);
            libc::munmap(ptr, self.len);
        }
    }
}

/// A string copied into [`LockedPages`] of its own.
pub struct LockedStr {
    pages: LockedPages,
    len: usize,
}

impl LockedStr {
    pub fn new(s: &str) -> io::Result<Self> {
        let mut pages = LockedPages::new(s.len())?;
        pages.as_mut_slice()[..s.len()].copy_from_slice(s.as_bytes());
        Ok(Self {
            pages,
            len: s.len(),
        })
    }

    pub fn as_str(&self) -> &str {
        let bytes = &self.pages.as_slice()[..self.len];
        // SAFETY: these bytes were copied from a `&str` in `new` and are
        // never written again until drop.
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

/// Keeps secrets in this process out of core dumps: a soft `RLIMIT_CORE`
/// of 0 (the hard limit is left, so a child may raise it again), the soft
/// `RLIMIT_MEMLOCK` raised to the hard one, and on
/// Linux `PR_SET_DUMPABLE` 0, which also stops other processes of the user
/// from attaching a debugger or reading `/proc/<pid>/mem` and `environ`.
pub fn harden_process() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    limit.rlim_cur = 0;
    // SAFETY: `limit` is a valid rlimit; lowering the soft limit is always
    // allowed.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for more locked values: the soft RLIMIT_MEMLOCK up to the hard
    // one. Best effort; values that do not fit fall back to the heap.
    // SAFETY: `limit` is a valid rlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } == 0
        && limit.rlim_cur < limit.rlim_max
    {
        limit.rlim_cur = limit.rlim_max;
        // SAFETY: `limit` is a valid rlimit; raising the soft limit up to
        // the hard one is always allowed.
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) };
    }
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are unused.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The soft `RLIMIT_CORE` and, on Linux, `PR_GET_DUMPABLE`, for tests.
pub fn dump_settings() -> io::Result<(u64, Option<i32>)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    // SAFETY: PR_GET_DUMPABLE takes no arguments.
    let dumpable = Some(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) });
    #[cfg(not(target_os = "linux"))]
    let dumpable = None;
    #[allow(clippy::unnecessary_cast)]
    Ok((limit.rlim_cur as u64, dumpable))
}

/// Sets the soft and hard `RLIMIT_MEMLOCK`, for tests of the fallback.
pub fn set_memlock_limit(bytes: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    // SAFETY: `limit` is a valid rlimit; lowering limits is always allowed.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_whole_and_read_zero_after_a_wipe() {
        let mut p = LockedPages::new(10).unwrap();
        assert!(p.as_slice().len() >= 4096);
        assert_eq!(p.as_slice().len() % 4096, 0);
        p.as_mut_slice().fill(0xa5);
        p.wipe();
        assert!(p.as_slice().iter().all(|&b| b == 0));
        let big = LockedPages::new(3 * 4096 + 1).unwrap();
        assert!(big.as_slice().len() > 3 * 4096);
        assert_eq!(LockedStr::new("héllo").unwrap().as_str(), "héllo");
        assert_eq!(LockedStr::new("").unwrap().as_str(), "");
    }

    #[test]
    fn hardening_turns_off_core_dumps() {
        if !crate::test_support::in_child("sys::memory::tests::hardening_turns_off_core_dumps") {
            return;
        }
        harden_process().unwrap();
        let (core, dumpable) = dump_settings().unwrap();
        assert_eq!(core, 0);
        #[cfg(target_os = "linux")]
        assert_eq!(dumpable, Some(0));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(dumpable, None);
    }
}
