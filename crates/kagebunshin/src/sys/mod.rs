//! Thin OS bindings. This is the only module tree allowed to use `unsafe`;
//! every block carries a `SAFETY:` comment.
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("kagebunshin supports Linux and macOS only");

mod memory;
#[cfg(target_os = "linux")]
mod peercred_linux;
#[cfg(target_os = "macos")]
mod peercred_macos;
#[cfg(target_os = "linux")]
mod proc_linux;
#[cfg(target_os = "macos")]
mod proc_macos;

use std::io;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicI32, Ordering};

use serde::{Deserialize, Serialize};

pub use memory::{LockedPages, LockedStr, dump_settings, harden_process, set_memlock_limit};

#[cfg(target_os = "linux")]
use peercred_linux as peercred_impl;
#[cfg(target_os = "macos")]
use peercred_macos as peercred_impl;
#[cfg(target_os = "linux")]
use proc_linux as proc_impl;
#[cfg(target_os = "macos")]
use proc_macos as proc_impl;

/// Credentials of the process on the other end of a unix socket, as reported
/// by the kernel. The client cannot choose these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Linux: `SO_PEERCRED` (credentials captured at `connect`).
/// macOS: `getpeereid` for uid/gid and `LOCAL_PEERPID` for the pid. We use the
/// real pid, not `LOCAL_PEEREPID`, which a process can set via delegation.
pub fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<PeerCred> {
    let cred = peercred_impl::peer_cred(fd)?;
    if cred.pid <= 0 {
        // Linux reports 0 for a peer in a pid namespace we cannot see.
        return Err(io::Error::other("peer pid is not visible to the daemon"));
    }
    Ok(cred)
}

/// When a process started, in an OS-specific unit. Together with the pid it
/// identifies one process: a reused pid gets a different start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcStart(pub u64);

/// Linux: field 22 of `/proc/<pid>/stat` (clock ticks since boot).
/// macOS: `proc_pidinfo(PROC_PIDTBSDINFO)` start time in microseconds.
/// Fails for a process that has exited, including a zombie its parent has
/// not reaped yet.
pub fn process_start(pid: i32) -> io::Result<ProcStart> {
    proc_impl::process_start(pid).map(ProcStart)
}

/// The parent of `pid`: field 4 of `/proc/<pid>/stat` on Linux,
/// `proc_pidinfo(PROC_PIDTBSDINFO)` on macOS. A process whose parent exited
/// has been reparented, usually to pid 1.
pub fn parent_pid(pid: i32) -> io::Result<i32> {
    proc_impl::parent_pid(pid)
}

/// What the kernel calls process `pid`: `/proc/<pid>/comm` on Linux, the
/// name in `proc_pidinfo(PROC_PIDTBSDINFO)` on macOS. Short (15 bytes on
/// Linux), and the process's own to set: it identifies nothing.
pub fn process_name(pid: i32) -> io::Result<String> {
    proc_impl::process_name(pid)
}

/// Has `cmd` start in a session of its own, with no controlling terminal:
/// Ctrl+C in the terminal it was started from, and that terminal closing,
/// do not reach it.
pub fn own_session(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the child between fork and exec, and
    // calls only `setsid`, which is async-signal-safe and touches no memory.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The year, month (1 to 12) and day of the month of `secs` since the epoch
/// in this machine's time zone; `None` if the C library cannot say.
pub fn local_date(secs: u64) -> Option<(i32, u32, u32)> {
    let time = libc::time_t::try_from(secs).ok()?;
    // SAFETY: a zeroed `tm` is a valid value for `localtime_r` to fill in.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to live values of the right type, and
    // `localtime_r` keeps neither.
    let filled = unsafe { libc::localtime_r(&raw const time, &raw mut tm) };
    if filled.is_null() {
        return None;
    }
    Some((
        tm.tm_year.checked_add(1900)?,
        u32::try_from(tm.tm_mon).ok()?.checked_add(1)?,
        u32::try_from(tm.tm_mday).ok()?,
    ))
}

/// The child `run` waits on; 0 before there is one.
static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let pid = CHILD.load(Ordering::SeqCst);
    // A SIGINT from the terminal (no sending process) reached the child
    // too, since they share the process group; pass on only one that a
    // process sent to us.
    // SAFETY: with SA_SIGINFO the kernel passes a valid siginfo_t.
    if sig == libc::SIGINT && unsafe { (*info).si_pid() } == 0 {
        return;
    }
    if pid > 0 {
        // SAFETY: kill is async-signal-safe and takes plain integers.
        unsafe { libc::kill(pid, sig) };
    }
}

/// For `run` while it waits on `child`: SIGTERM, SIGHUP
/// and SIGINT are passed on to the child, so it ends and the caller still
/// cleans up after it. A SIGINT from the terminal is not passed on, since
/// the terminal sends it to the child too. Call after spawning, so the
/// child keeps the dispositions it inherited.
pub fn forward_signals_to(child: u32) -> io::Result<()> {
    CHILD.store(child as i32, Ordering::SeqCst);
    for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
        // SAFETY: a zeroed sigaction is a valid starting point; the handler
        // only calls async-signal-safe functions.
        let rc = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = forward
                as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
                as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
            libc::sigemptyset(&raw mut sa.sa_mask);
            libc::sigaction(sig, &raw const sa, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Ends this process with signal `sig`, as the child `run` waited on ended,
/// so the caller's shell sees the same thing. Falls back to exit status
/// 128 + `sig`, the shell convention, if the signal does not end us.
pub fn exit_by_signal(sig: i32) -> ! {
    // SAFETY: restoring the default disposition and raising a signal have no
    // preconditions.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
    std::process::exit(128 + sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_cred_of_a_socketpair_is_ourselves() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = peer_cred(a.as_fd()).unwrap();
        assert_eq!(cred.pid, std::process::id() as i32);
        assert_eq!(cred.uid, effective_uid());
    }

    #[test]
    fn process_start_is_stable_and_fails_for_missing_pids() {
        let me = std::process::id() as i32;
        let a = process_start(me).unwrap();
        let b = process_start(me).unwrap();
        assert_eq!(a, b);
        assert!(a.0 > 0);
        // Above the default pid_max on both OSes.
        assert!(process_start(i32::MAX).is_err());
    }

    #[test]
    fn parent_pid_of_a_child_is_us() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let parent = parent_pid(child.id() as i32);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(parent.unwrap(), std::process::id() as i32);
        assert!(parent_pid(i32::MAX).is_err());
    }

    #[test]
    fn a_zombie_has_no_start_time() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(process_start(pid).is_ok());
        child.kill().unwrap();
        // Not reaped yet, so a zombie once the kill lands.
        let start = std::time::Instant::now();
        while process_start(pid).is_ok() {
            assert!(start.elapsed().as_secs() < 5, "still alive");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // A zombie, not gone. macOS's proc_pidinfo already fails for one.
        #[cfg(target_os = "linux")]
        assert!(parent_pid(pid).is_ok(), "still in the process table");
        child.wait().unwrap();
    }

    #[test]
    fn a_child_started_later_has_a_later_start_time() {
        let me = process_start(std::process::id() as i32).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let theirs = process_start(child.id() as i32);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(theirs.unwrap().0 >= me.0);
    }
}
