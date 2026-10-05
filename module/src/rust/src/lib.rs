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
    // Fail closed: a panic must never unwind into the Zygisk host.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: null-checked above; the caller guarantees a valid NUL-terminated string.
        let app_name = unsafe { CStr::from_ptr(app_name) }.to_string_lossy();
        inject::check_and_inject(&app_name)
    }))
    .unwrap_or(false)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ksufrida_{prefix}_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Deref for TempDir {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TempDir {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
