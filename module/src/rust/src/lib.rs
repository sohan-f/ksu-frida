
mod child_gating;
mod config;
mod inject;
mod log;
mod remap;
mod sys;
mod xdl;

use std::ffi::{CStr, c_char};

/// # Safety
/// `app_name` must be null or a valid NUL-terminated C string (JNI
/// `GetStringUTFChars` output). It must not be mutated while this runs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ksufrida_check_and_inject(app_name: *const c_char) -> bool {
    if app_name.is_null() {
        return false;
    }
    // SAFETY: `app_name` comes from JNI `GetStringUTFChars` — valid, NUL-terminated.
    let app_name = unsafe { CStr::from_ptr(app_name) }.to_string_lossy();
    inject::check_and_inject(&app_name)
}
