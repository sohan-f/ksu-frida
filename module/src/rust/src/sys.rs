use std::ffi::{CStr, CString, NulError, c_char, c_int, c_void};
use std::io;

pub const RTLD_NOW: c_int = 2;

pub const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();

unsafe extern "C" {
    pub fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub fn dlerror() -> *mut c_char;
}

#[cfg(target_os = "android")]
pub const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
#[cfg(target_os = "android")]
pub const ANDROID_DLEXT_FORCE_LOAD: u64 = 0x40;

#[cfg(target_os = "android")]
#[repr(C)]
pub struct AndroidDlextInfo {
    pub flags: u64,
    pub reserved_addr: *mut c_void,
    pub reserved_size: usize,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: i64,
    pub library_namespace: *mut c_void,
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    pub fn android_dlopen_ext(
        filename: *const c_char,
        flags: c_int,
        info: *const AndroidDlextInfo,
    ) -> *mut c_void;
}

#[cfg(any(target_os = "android", test))]
pub fn memfd_create(name: *const c_char, flags: c_int) -> c_int {
    // SAFETY: plain syscall with a valid name; the fd (or -1) is checked by the caller.
    unsafe { libc::syscall(libc::SYS_memfd_create, name, flags) as c_int }
}

#[cfg(any(target_os = "android", test))]
pub const MFD_CLOEXEC: c_int = 0x0001;

pub const MREMAP_MAYMOVE: c_int = 1;
pub const MREMAP_FIXED: c_int = 2;

unsafe extern "C" {
    pub fn mremap(
        old_address: *mut c_void,
        old_size: usize,
        new_size: usize,
        flags: c_int,
        ...
    ) -> *mut c_void;
}

#[repr(C)]
pub struct DlPhdrInfo {
    pub addr: usize,
    pub name: *const c_char,
    pub phdr: *const c_void,
    pub phnum: u16,
}

pub type DlIterateCb = unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int;

unsafe extern "C" {
    pub fn dl_iterate_phdr(cb: DlIterateCb, data: *mut c_void) -> c_int;
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

#[cfg(target_os = "android")]
pub fn android_log(prio: c_int, msg: &str) {
    // SAFETY: static tag/format literals; `msg` is copied into a `CString` so no interior NUL reaches the varargs.
    unsafe {
        let c_msg = CString::new(msg).unwrap_or_default();
        __android_log_print(prio, c"KsuFrida".as_ptr(), c"%s".as_ptr(), c_msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

#[cfg(not(target_os = "android"))]
pub fn set_errno(value: c_int) {
    // SAFETY: returns a valid writable pointer to the calling thread's errno slot.
    unsafe {
        *__errno_location() = value;
    }
}

#[cfg(target_os = "android")]
pub fn set_errno(value: c_int) {
    // SAFETY: returns a valid writable pointer to the calling thread's errno slot.
    unsafe {
        *libc::__errno() = value;
    }
}

/// # Safety
/// `fd_in`/`fd_out` must be open files; `len` bounds the transfer.
pub fn copy_file_range(fd_in: c_int, fd_out: c_int, len: usize) -> Result<u64, io::Error> {
    // SAFETY: two live fds with NULL offsets (file-offset form); return/errno is read immediately.
    let n = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            fd_in,
            std::ptr::null::<libc::c_void>(),
            fd_out,
            std::ptr::null::<libc::c_void>(),
            len,
            0 as libc::c_uint,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as u64)
    }
}

pub fn dlerror_string() -> String {
    // SAFETY: `dlerror()` returns null or a libc-owned NUL-terminated string, copied before any later dl call.
    unsafe {
        let err = dlerror();
        if err.is_null() {
            return "(null)".to_string();
        }
        CStr::from_ptr(err).to_string_lossy().into_owned()
    }
}

pub fn cstring(s: &str) -> Result<CString, NulError> {
    CString::new(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstring_accepts_ordinary_paths() {
        assert_eq!(
            cstring("/data/local/tmp/libsec/a.so").unwrap(),
            c"/data/local/tmp/libsec/a.so".to_owned()
        );
    }

    #[test]
    fn cstring_rejects_an_interior_nul() {
        assert!(cstring("a\0b").is_err());
        assert!(cstring("\0").is_err());
    }
}
