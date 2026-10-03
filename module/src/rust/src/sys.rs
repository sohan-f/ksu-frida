
use std::ffi::{CStr, CString, c_char, c_int, c_void};

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

pub fn dlerror_string() -> String {
    unsafe {
        let err = dlerror();
        if err.is_null() {
            return "(null)".to_string();
        }
        CStr::from_ptr(err).to_string_lossy().into_owned()
    }
}

pub fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|e| {
        let before = e.into_vec();
        CString::new(before).unwrap_or_default()
    })
}
