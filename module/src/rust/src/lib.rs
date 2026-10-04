#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod child_gating;
mod config;
mod inject;
mod linkmap;
mod log;
mod remap;
mod sys;
mod xdl;

use std::ffi::{CStr, c_char};

// Exposes config parsing to the cargo-fuzz harness; only compiled under `cargo fuzz`.
#[cfg(fuzzing)]
pub fn fuzz_parse_config(module_dir: &str, app_name: &str) -> Option<String> {
    config::load_config(module_dir, app_name).map(|cfg| cfg.app_name)
}

/// Returns true when the caller must keep the module loaded.
///
/// # Safety
/// `app_name` must be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ksufrida_check_and_inject(app_name: *const c_char) -> bool {
    if app_name.is_null() {
        return false;
    }
    // SAFETY: `app_name` is null-checked above; the caller guarantees a valid NUL-terminated string.
    let app_name = unsafe { CStr::from_ptr(app_name) }.to_string_lossy();
    inject::check_and_inject(&app_name)
}
