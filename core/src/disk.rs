//! Platform disk free-space query for the receiver safety check (`docs/M2-PLAN.md` §6a.2:
//! require available space >= `size + 64 MiB` before accepting a file offer).

use std::path::Path;

/// Query available bytes for an unprivileged user on the filesystem containing `path`.
/// If `path` does not yet exist, walks up to the nearest existing ancestor directory.
pub fn available_disk_space(path: &Path) -> Result<u64, String> {
    let mut probe = path;
    while !probe.exists() {
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p,
            _ => {
                probe = Path::new(".");
                break;
            }
        }
    }
    platform_available_bytes(probe)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn platform_available_bytes(path: &Path) -> Result<u64, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "invalid path (interior NUL)".to_string())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(format!(
            "statvfs failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let bsize = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    let avail = (stat.f_bavail as u64).saturating_mul(bsize);
    Ok(avail)
}

#[cfg(all(windows, any(feature = "net", feature = "system-opener")))]
fn platform_available_bytes(path: &Path) -> Result<u64, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free_for_caller: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_for_caller,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "GetDiskFreeSpaceExW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(free_for_caller)
}

#[cfg(not(any(unix, all(windows, any(feature = "net", feature = "system-opener")))))]
fn platform_available_bytes(_path: &Path) -> Result<u64, String> {
    Ok(u64::MAX)
}
