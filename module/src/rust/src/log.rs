
#[cfg(target_os = "android")]
use std::ffi::CString;
use std::ffi::c_int;

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_print(
        prio: c_int,
        tag: *const std::ffi::c_char,
        fmt: *const std::ffi::c_char,
        ...
    ) -> c_int;
}

pub fn logi(msg: impl AsRef<str>) {
    log(ANDROID_LOG_INFO, msg.as_ref());
}

pub fn loge(msg: impl AsRef<str>) {
    log(ANDROID_LOG_ERROR, msg.as_ref());
}

fn log(prio: c_int, msg: &str) {
    #[cfg(target_os = "android")]
    unsafe {
        let c_msg = CString::new(msg).unwrap_or_default();
        __android_log_print(prio, c"KsuFrida".as_ptr(), c"%s".as_ptr(), c_msg.as_ptr());
    }

    #[cfg(not(target_os = "android"))]
    {
        let level = if prio == ANDROID_LOG_ERROR { "E" } else { "I" };
        eprintln!("[{level} KsuFrida] {msg}");
    }
}
