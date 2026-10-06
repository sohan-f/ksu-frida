#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod child_gating;
mod config;
mod inject;
mod jni;
mod linkmap;
mod log;
mod remap;
mod sys;
mod thread_names;
mod xdl;

pub use jni::ksufrida_handle_app;

// Exposes config parsing to the cargo-fuzz harness; only compiled under `cargo fuzz`.
#[cfg(fuzzing)]
pub fn fuzz_parse_config(module_dir: &str, app_name: &str) -> Option<String> {
    config::load_config(module_dir, app_name).map(|cfg| cfg.app_name)
}

// Feeds adversarial ELF images to the linkmap scrubber; only compiled under `cargo fuzz`.
#[cfg(fuzzing)]
pub fn fuzz_scrub_elf(data: &[u8]) {
    linkmap::fuzz_scrub_elf(data);
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
