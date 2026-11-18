use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::PeerCred;

pub fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<PeerCred> {
    let raw = fd.as_raw_fd();

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `raw` is a valid descriptor for the duration of the borrow, and
    // `uid`/`gid` are writable locals.
    if unsafe { libc::getpeereid(raw, &raw mut uid, &raw mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut pid: libc::pid_t = 0;
    let mut len = mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: as above; `pid`/`len` are writable locals of the size we pass.
    let rc = unsafe {
        libc::getsockopt(
            raw,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<libc::pid_t>() {
        return Err(io::Error::other("short LOCAL_PEERPID result"));
    }

    Ok(PeerCred { uid, gid, pid })
}
