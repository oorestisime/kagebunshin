use std::io;
use std::mem::{self, MaybeUninit};

pub fn process_start(pid: i32) -> io::Result<u64> {
    let info = bsd_info(pid)?;
    if info.pbi_status == libc::SZOMB {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the process has exited",
        ));
    }
    Ok(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

pub fn parent_pid(pid: i32) -> io::Result<i32> {
    let info = bsd_info(pid)?;
    i32::try_from(info.pbi_ppid).map_err(io::Error::other)
}

pub fn process_name(pid: i32) -> io::Result<String> {
    let info = bsd_info(pid)?;
    // The long name where there is one; `pbi_comm` is cut at 16 bytes.
    let name = if info.pbi_name[0] == 0 {
        &info.pbi_comm[..]
    } else {
        &info.pbi_name[..]
    };
    let bytes: Vec<u8> = name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.to_ne_bytes()[0])
        .collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn bsd_info(pid: i32) -> io::Result<libc::proc_bsdinfo> {
    let size = mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is a writable buffer of exactly `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    if n != size {
        return Err(io::Error::other("short proc_pidinfo result"));
    }
    // SAFETY: the buffer was zero-initialised (valid for this plain C struct)
    // and the kernel filled all `size` bytes.
    Ok(unsafe { info.assume_init() })
}
