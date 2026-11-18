use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::PeerCred;

pub fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid descriptor for the duration of the borrow, and
    // `cred`/`len` are writable locals of exactly the size we pass.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<libc::ucred>() {
        return Err(io::Error::other("short SO_PEERCRED result"));
    }
    Ok(PeerCred {
        uid: cred.uid,
        gid: cred.gid,
        pid: cred.pid,
    })
}
