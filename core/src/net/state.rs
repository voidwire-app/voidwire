//! Persistent app state (keys, group log, settings) and where it lives.
//!
//! * Desktop: one file in the app data dir, written atomically (temp file,
//!   fsync, rename). Linux: mode 0600. Windows: the blob is wrapped with DPAPI
//!   (`CryptProtectData`, current-user scope) before it touches the disk.
//! * Android: the app supplies a [`StateStore`] (UniFFI callback) that wraps
//!   the blob with an AndroidKeyStore AES-GCM key.

use std::path::PathBuf;

use zeroize::Zeroizing;

/// Where a state blob is kept. Implementations must write atomically.
pub trait StateStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn save(&self, data: &[u8]) -> Result<(), String>;
    fn data_dir(&self) -> Option<PathBuf> {
        None
    }
}

/// In-memory store (tests, and "don't persist" runs).
#[derive(Debug, Default)]
pub struct MemoryStateStore(std::sync::Mutex<Option<Vec<u8>>>);

impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.lock().map_err(|e| e.to_string())?.clone())
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = Some(data.to_vec());
        Ok(())
    }
}

/// A file in the app data directory (see module docs for protection).
#[derive(Debug, Clone)]
pub struct FileStateStore {
    path: PathBuf,
}

impl FileStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileStateStore { path: path.into() }
    }
}

impl StateStore for FileStateStore {
    fn data_dir(&self) -> Option<PathBuf> {
        self.path.parent().map(|p| p.to_path_buf())
    }

    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(&self.path).map(Zeroizing::new) {
            Ok(b) => protect::unprotect(&b).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("read state: {e}")),
        }
    }

    fn save(&self, data: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let blob = Zeroizing::new(protect::protect(data)?);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create dir: {e}"))?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| format!("write state: {e}"))?;
        f.write_all(&blob)
            .map_err(|e| format!("write state: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync state: {e}"))?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename state: {e}"))?;
        #[cfg(unix)]
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

/// Create `dir` (and parents) and make it private to the current user:
/// mode 0700 on Unix; on Windows a **protected** DACL granting full control
/// to the current user and SYSTEM only, inherited by files created inside
/// (the replay cache, state and their temp files).
///
/// Files **already** in `dir` (from an earlier build, before the directory
/// was locked down) get the same treatment (QA nit N3): mode 0600 on Unix, a
/// protected user + SYSTEM DACL on Windows. `SetFileSecurityW` on the
/// directory alone doesn't re-ACL existing children.
pub fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    acl::restrict_to_current_user(dir)?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Regular files only; never follow links out of the directory.
        if !entry.file_type()?.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        acl::restrict_file_to_current_user(&entry.path())?;
    }
    Ok(())
}

#[cfg(windows)]
pub mod acl {
    //! Per-user directory ACL (Windows). `unsafe` FFI, kept small.
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SetFileSecurityW, TokenUser, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// SAFETY: `p` must point at a NUL-terminated UTF-16 string.
    unsafe fn from_wide(p: *const u16) -> String {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    /// The current process user's SID as a string (`S-1-5-21-…`).
    pub fn current_user_sid() -> io::Result<String> {
        // SAFETY: standard token query; every out-pointer is valid for the
        // call, the buffer is u64-aligned (TOKEN_USER needs pointer
        // alignment), and LocalAlloc'd outputs are freed.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            let out = from_wide(s);
            LocalFree(s.cast());
            Ok(out)
        }
    }

    /// Replace `path`'s DACL with a protected one: full control for the
    /// current user and SYSTEM, inherited by children (OI|CI). Nothing else.
    pub fn restrict_to_current_user(path: &Path) -> io::Result<()> {
        let sid = current_user_sid()?;
        set_protected_dacl(path, &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"))
    }

    /// Same for an existing file (no inheritance flags): N3.
    pub fn restrict_file_to_current_user(path: &Path) -> io::Result<()> {
        let sid = current_user_sid()?;
        set_protected_dacl(path, &format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)"))
    }

    fn set_protected_dacl(path: &Path, sddl: &str) -> io::Result<()> {
        let sddl = wide(OsStr::new(sddl));
        let target = wide(path.as_os_str());
        // SAFETY: NUL-terminated wide strings live across the calls; the
        // security descriptor is LocalAlloc'd by the converter and freed.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let ok = SetFileSecurityW(
                target.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            );
            let err = io::Error::last_os_error();
            LocalFree(sd.cast());
            if ok == 0 {
                return Err(err);
            }
        }
        Ok(())
    }

    /// `path`'s DACL as SDDL (tests and diagnostics).
    pub fn dacl_sddl(path: &Path) -> io::Result<String> {
        let target = wide(path.as_os_str());
        // SAFETY: out-pointers valid; the descriptor and the string are
        // LocalAlloc'd by the API and freed here.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let rc = GetNamedSecurityInfoW(
                target.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            let mut s: *mut u16 = null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                null_mut(),
            );
            LocalFree(sd.cast());
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let out = from_wide(s);
            LocalFree(s.cast());
            Ok(out)
        }
    }

    /// How `sid` is spelled as a trustee in SDDL that Windows emits (tests).
    /// Windows abbreviates well-known SIDs: the built-in local Administrator
    /// (`S-1-5-21-…-500`, the CI runner's account) comes back as `LA`, so a
    /// test must not look for the raw `S-1-5-…` string in `dacl_sddl` output.
    pub fn sddl_trustee(sid: &str) -> io::Result<String> {
        let sddl = wide(OsStr::new(&format!("D:(A;;FA;;;{sid})")));
        // SAFETY: as in `set_protected_dacl` and `dacl_sddl`: NUL-terminated
        // input, valid out-pointers, LocalAlloc'd outputs freed.
        let round_trip = unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut s: *mut u16 = null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                null_mut(),
            );
            LocalFree(sd.cast());
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let out = from_wide(s);
            LocalFree(s.cast());
            out
        };
        round_trip
            .rsplit_once(";;;")
            .and_then(|(_, t)| t.strip_suffix(')'))
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other(format!("unexpected SDDL: {round_trip}")))
    }
}

#[cfg(not(windows))]
mod protect {
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}

#[cfg(windows)]
mod protect {
    //! DPAPI, current-user scope (`unsafe` FFI; the other block is `acl`).
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn run(data: &[u8], seal: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).map_err(|_| "state too large".to_string())?,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: `input` points at `data` for the duration of the call; on
        // success `out` is a LocalAlloc'd buffer we copy and then free.
        let ok = unsafe {
            if seal {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            }
        };
        if ok == 0 || out.pbData.is_null() {
            return Err("DPAPI refused the state blob".into());
        }
        // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`.
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        // SAFETY: allocated by DPAPI with LocalAlloc.
        unsafe { LocalFree(out.pbData as _) };
        Ok(v)
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, true)
    }
    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, false)
    }
}

// ---- tiny binary codec -------------------------------------------------------

/// Encoder for the state blobs, which hold secret keys (QA nit N2).
///
/// It never lets `Vec` grow on its own: `Vec`'s reallocation would free the
/// old buffer with the secrets still in it. The buffer starts pre-sized
/// ([`Writer::INITIAL_CAPACITY`], enough for a typical state blob) and, if it
/// ever needs more, [`Writer::reserve`] copies into a larger allocation and
/// zeroizes the old one (spare capacity included) before freeing it. Callers
/// wrap the final `Vec` in `Zeroizing`.
pub(crate) struct Writer(pub Vec<u8>);

impl Writer {
    pub const INITIAL_CAPACITY: usize = 16 * 1024;

    pub fn new(magic: &[u8]) -> Self {
        let mut w = Writer(Vec::with_capacity(Self::INITIAL_CAPACITY.max(magic.len())));
        w.raw(magic);
        w
    }
    fn reserve(&mut self, n: usize) {
        let need = self.0.len() + n;
        if need <= self.0.capacity() {
            return;
        }
        let mut bigger = Vec::with_capacity(need.max(self.0.capacity() * 2));
        bigger.extend_from_slice(&self.0);
        // Wipes len and spare capacity of the old allocation, then frees it.
        zeroize::Zeroize::zeroize(&mut self.0);
        self.0 = bigger;
    }
    pub fn u8(&mut self, v: u8) {
        self.reserve(1);
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }
    pub fn raw(&mut self, b: &[u8]) {
        self.reserve(b.len());
        self.0.extend_from_slice(b);
    }
    pub fn bytes8(&mut self, b: &[u8]) {
        self.u8(b.len() as u8);
        self.raw(b);
    }
    pub fn bytes16(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.raw(b);
    }
    pub fn bytes32(&mut self, b: &[u8]) {
        self.raw(&(b.len() as u32).to_be_bytes());
        self.raw(b);
    }
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader(b)
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|b| b.try_into().expect("32"))
    }
    pub fn bytes8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    pub fn bytes16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    pub fn bytes32(&mut self) -> Option<&'a [u8]> {
        let b = self.take(4)?;
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        self.take(n)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Secret material read from a blob, zeroized on drop.
pub(crate) type Secret32 = Zeroizing<[u8; 32]>;

pub(crate) fn read_secret(r: &mut Reader<'_>) -> Option<Secret32> {
    Some(Zeroizing::new(r.arr32()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trip_and_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "vw-state-{:x}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let store = FileStateStore::new(dir.join("state.bin"));
        assert_eq!(store.load().unwrap(), None);
        store.save(b"hello").unwrap();
        store.save(b"hello again").unwrap();
        assert_eq!(store.load().unwrap().as_deref(), Some(&b"hello again"[..]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("state.bin"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn writer_grows_only_through_its_wiping_reserve_n2() {
        let mut w = Writer::new(b"MAGIC");
        assert!(w.0.capacity() >= Writer::INITIAL_CAPACITY);
        let start_ptr = w.0.as_ptr();
        w.raw(&[7u8; 1000]);
        assert_eq!(
            w.0.as_ptr(),
            start_ptr,
            "no reallocation for a typical blob"
        );
        // Past the initial capacity: still correct, grown by `reserve`.
        let big = vec![9u8; Writer::INITIAL_CAPACITY * 3];
        w.bytes16(&big[..40_000]);
        w.raw(&big);
        assert_eq!(&w.0[..5], b"MAGIC");
        assert_eq!(w.0.len(), 5 + 1000 + 2 + 40_000 + big.len());
        assert!(w.0[5..1005].iter().all(|b| *b == 7));
    }

    #[test]
    fn private_dir_is_user_only() {
        let dir = std::env::temp_dir().join(format!(
            "vw-private-{:x}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let sub = dir.join("data");
        // N3: a file left by an earlier build, before the dir was private.
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("old"), b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(sub.join("old"), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        private_dir(&sub).unwrap();
        private_dir(&sub).unwrap(); // idempotent
        std::fs::write(sub.join("f"), b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(sub.join("old"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "existing file locked down too");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sub).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        #[cfg(windows)]
        {
            // The user's trustee as Windows spells it in SDDL (`LA` for the
            // built-in Administrator on CI runners, else `S-1-5-21-…`), as
            // an exact ACE trustee field.
            let sid = format!(
                ";;;{})",
                acl::sddl_trustee(&acl::current_user_sid().unwrap()).unwrap()
            );
            let sddl = acl::dacl_sddl(&sub).unwrap();
            assert!(sddl.starts_with("D:P"), "protected DACL: {sddl}");
            assert!(sddl.contains(&sid), "current user granted: {sddl}");
            for other in [";;;WD)", ";;;BU)", ";;;AU)", ";;;BA)"] {
                assert!(!sddl.contains(other), "{other} must not be granted: {sddl}");
            }
            // A file created inside inherits the user-only ACL.
            let f = acl::dacl_sddl(&sub.join("f")).unwrap();
            assert!(f.contains(&sid) && !f.contains(";;;BU)"), "{f}");
            // N3: and the file that was there before got one explicitly.
            let old = acl::dacl_sddl(&sub.join("old")).unwrap();
            assert!(old.starts_with("D:P") && old.contains(&sid), "{old}");
            for other in [";;;WD)", ";;;BU)", ";;;AU)", ";;;BA)"] {
                assert!(!old.contains(other), "{other} on existing file: {old}");
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
