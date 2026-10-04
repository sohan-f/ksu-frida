use std::ffi::{c_char, c_int, c_void};

pub const XDL_TRY_FORCE_LOAD: c_int = 0x01;

#[cfg(target_os = "android")]
unsafe extern "C" {
    pub fn xdl_open(filename: *const c_char, flags: c_int) -> *mut c_void;
}

#[cfg(not(target_os = "android"))]
pub unsafe fn xdl_open(_filename: *const c_char, _flags: c_int) -> *mut c_void {
    std::ptr::null_mut()
}
