#![forbid(unsafe_code)]

use std::ffi::c_int;

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;

pub fn logi(msg: impl AsRef<str>) {
    log(ANDROID_LOG_INFO, msg.as_ref());
}

pub fn loge(msg: impl AsRef<str>) {
    log(ANDROID_LOG_ERROR, msg.as_ref());
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
