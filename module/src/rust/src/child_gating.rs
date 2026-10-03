
use std::ffi::{c_int, c_void};
use std::thread;
use std::time::Duration;

use crate::config::ChildGatingConfig;
use crate::inject::{current_app_name, stage_and_inject};
use crate::log::logi;
use crate::sys::{RTLD_DEFAULT, dlsym};

type ForkFn = unsafe extern "C" fn() -> libc::pid_t;

static mut ORIG_FORK: Option<ForkFn> = None;
static mut ORIG_VFORK: Option<ForkFn> = None;

static CHILD_GATING_MODE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static INJECTED_LIBRARIES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn ksufrida_dobby_hook(
        addr: *mut c_void,
        replace: *mut c_void,
        orig: *mut *mut c_void,
    ) -> c_int;
}

#[cfg(not(target_os = "android"))]
unsafe fn ksufrida_dobby_hook(
    _addr: *mut c_void,
    _replace: *mut c_void,
    _orig: *mut *mut c_void,
) -> c_int {
    0
}

unsafe extern "C" fn fork_replacement() -> libc::pid_t {
    let parent_pid = unsafe { libc::getpid() };
    logi(format!(
        "[child_gating][pid {parent_pid}] detected fork/vfork"
    ));

    let orig = unsafe { ORIG_FORK }.expect("fork hook used before installation");
    let child_pid = unsafe { orig() };
    if child_pid != 0 {
        logi(format!(
            "[child_gating][pid {parent_pid}] returning from forking {child_pid}"
        ));
        return child_pid;
    }

    crate::remap::after_fork();

    let child_pid = unsafe { libc::getpid() };
    let context = format!("[child_gating][pid {child_pid}] ");

    let mode = CHILD_GATING_MODE
        .get()
        .map(String::as_str)
        .unwrap_or_default();

    match mode {
        "kill" => {
            logi(format!("{context}killing child process"));
            unsafe { libc::exit(0) };
        }
        "freeze" => {
            logi(format!("{context}freezing child process"));
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        "inject" => {
            if let Some(libraries) = INJECTED_LIBRARIES.get() {
                let app_name = current_app_name();
                for lib_path in libraries {
                    stage_and_inject(lib_path, &app_name, &context);
                }
            }
            0
        }
        other => {
            logi(format!("{context}unknown child_gating_mode {other}"));
            0
        }
    }
}

pub fn enable_child_gating(cfg: &ChildGatingConfig) {
    let _ = CHILD_GATING_MODE.set(cfg.mode.clone());
    let _ = INJECTED_LIBRARIES.set(cfg.injected_libraries.clone());

    logi("[child_gating] enabling child gating");

    let fork_addr = unsafe { dlsym(RTLD_DEFAULT, c"fork".as_ptr()) };
    logi(format!("[child_gating] fork address {fork_addr:p}"));
    let vfork_addr = unsafe { dlsym(RTLD_DEFAULT, c"vfork".as_ptr()) };
    logi(format!("[child_gating] vfork address {vfork_addr:p}"));

    let replacement = fork_replacement as *const () as *mut c_void;

    unsafe {
        ksufrida_dobby_hook(fork_addr, replacement, (&raw mut ORIG_FORK).cast());
    }
    logi("[child_gating] fork hook installed");

    unsafe {
        ksufrida_dobby_hook(vfork_addr, replacement, (&raw mut ORIG_VFORK).cast());
    }
    logi("[child_gating] vfork hook installed");

    logi("[child_gating] child gating enabled");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_shim_is_callable() {
        let mut orig: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                ksufrida_dobby_hook(std::ptr::null_mut(), std::ptr::null_mut(), &raw mut orig)
            },
            0
        );
    }

    #[test]
    fn state_is_write_once() {
        let cfg = ChildGatingConfig {
            enabled: true,
            mode: "kill".to_string(),
            injected_libraries: vec!["/a.so".to_string()],
        };
        let _ = CHILD_GATING_MODE.set(cfg.mode.clone());
        let _ = INJECTED_LIBRARIES.set(cfg.injected_libraries.clone());
        assert_eq!(CHILD_GATING_MODE.get().map(String::as_str), Some("kill"));
        assert_eq!(INJECTED_LIBRARIES.get().map(Vec::len), Some(1));
    }
}
