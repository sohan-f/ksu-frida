#![forbid(unsafe_code)]

use std::ffi::c_int;

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;

#[cfg(target_os = "android")]
const VERBOSE_PATH: &str = "/data/local/tmp/libsec/verbose";

#[cfg(any(target_os = "android", test))]
fn log_enabled_for(path: &std::path::Path) -> bool {
    path.exists()
}

#[cfg(target_os = "android")]
fn verbose() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| log_enabled_for(std::path::Path::new(VERBOSE_PATH)))
}

#[cfg(not(target_os = "android"))]
fn verbose() -> bool {
    true
}

pub fn logi(msg: impl AsRef<str>) {
    if verbose() {
        log(ANDROID_LOG_INFO, msg.as_ref());
    }
}

pub fn loge(msg: impl AsRef<str>) {
    if verbose() {
        log(ANDROID_LOG_ERROR, msg.as_ref());
    }
}

/// Formats only when verbose is on; avoids allocation otherwise.
pub fn logi_fmt(args: std::fmt::Arguments<'_>) {
    if verbose() {
        log(ANDROID_LOG_INFO, &args.to_string());
    }
}

/// Formats only when verbose is on; avoids allocation otherwise.
pub fn loge_fmt(args: std::fmt::Arguments<'_>) {
    if verbose() {
        log(ANDROID_LOG_ERROR, &args.to_string());
    }
}

fn log(prio: c_int, msg: &str) {
    #[cfg(target_os = "android")]
    crate::sys::android_log(prio, msg);

    #[cfg(not(target_os = "android"))]
    {
        let level = if prio == ANDROID_LOG_ERROR { "E" } else { "I" };
        eprintln!("[{level} KsuFrida] {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_flag_follows_file_existence() {
        let dir = std::env::temp_dir().join(format!("ksufrida-verbose-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("verbose");

        assert!(!log_enabled_for(&flag));
        std::fs::write(&flag, b"").unwrap();
        assert!(log_enabled_for(&flag));

        std::fs::remove_dir_all(&dir).ok();
    }
}
