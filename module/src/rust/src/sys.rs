
use std::ffi::{CStr, CString, NulError, c_char, c_int, c_void};

pub const RTLD_NOW: c_int = 2;

pub const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();

unsafe extern "C" {
    pub fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub fn dlerror() -> *mut c_char;
}

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

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

#[cfg(target_os = "android")]
pub fn android_log(prio: c_int, msg: &str) {
    // SAFETY: `tag` and `fmt` are static `c"..."` literals; `msg` is copied into
    // a `CString`, so no interior NUL can reach the varargs (a NUL-containing
    // message logs as an empty line, matching the old behaviour), and the
    // return value is a status nobody reads — same contract as the C++ LOG_*.
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
    // SAFETY: glibc/musl document `__errno_location()` as returning a valid
    // writable pointer to the calling thread's errno slot; it is never null.
    unsafe {
        *__errno_location() = value;
    }
}

#[cfg(target_os = "android")]
pub fn set_errno(value: c_int) {
    // SAFETY: bionic documents `__errno()` with the same contract.
    unsafe {
        *libc::__errno() = value;
    }
}

pub fn dlerror_string() -> String {
    // SAFETY: `dlerror()` returns null or a valid NUL-terminated string owned by libc; it is copied before any later dl call.
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
