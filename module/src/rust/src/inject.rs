
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::thread;
use std::time::Duration;

use crate::child_gating::enable_child_gating;
use crate::config::{TargetConfig, load_config};
use crate::log::{loge, logi};
use crate::remap::remap_lib;
use crate::sys::{RTLD_NOW, cstring, dlerror_string, dlopen};
use crate::xdl::{XDL_TRY_FORCE_LOAD, xdl_open};

const MODULE_DIR: &str = "/data/local/tmp/libsec";

pub fn check_and_inject(app_name: &str) -> bool {
    let Some(cfg) = load_config(MODULE_DIR, app_name) else {
        return false;
    };

    let pid = unsafe { libc::getpid() };

    logi(format!("App detected: {app_name}"));
    logi(format!("PID: {pid}"));

    if !cfg.enabled {
        logi(format!("Injection disabled for {app_name}"));
        return false;
    }

    thread::spawn(move || inject_libs(&cfg, pid));

    true
}

fn get_process_name() -> String {
    fs::read("/proc/self/cmdline")
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn wait_for_init(app_name: &str) {
    logi("Wait for process to complete init");

    while !get_process_name().contains(app_name) {
        thread::sleep(Duration::from_millis(10));
    }

    thread::sleep(Duration::from_millis(100));

    logi("Process init completed");
}

fn delay_start_up(start_up_delay_ms: u64) {
    if start_up_delay_ms == 0 {
        return;
    }

    logi(format!(
        "Waiting for configured start up delay {start_up_delay_ms}ms"
    ));

    let mut delay = start_up_delay_ms;
    let mut countdown = 0;
    let mut i = 0;
    while i < 10 && delay > 1000 {
        delay -= 1000;
        countdown += 1;
        i += 1;
    }

    thread::sleep(Duration::from_millis(delay));

    let mut i = countdown;
    while i > 0 {
        logi(format!("Injecting libs in {i} seconds"));
        thread::sleep(Duration::from_secs(1));
        i -= 1;
    }
}

fn copy_file(src: &str, dst: &str) -> bool {
    let mut input = match File::open(src) {
        Ok(file) => file,
        Err(_) => {
            loge(format!("stage: open src failed: {src}"));
            return false;
        }
    };

    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(dst)
    {
        Ok(file) => file,
        Err(_) => {
            loge(format!("stage: open dst failed: {dst}"));
            return false;
        }
    };

    let mut buf = [0u8; 65536];
    while let Ok(n) = input.read(&mut buf) {
        if n == 0 {
            break;
        }
        if output.write_all(&buf[..n]).is_err() {
            loge(format!("stage: write failed for {dst}"));
            return false;
        }
    }

    true
}

fn with_config_suffix(path: &str) -> String {
    let mut result = path.to_string();
    if let Some(dot) = result.rfind(".so") {
        result.insert_str(dot, ".config");
    }
    result
}

fn split_lib_path(src_lib_path: &str) -> (&str, &str) {
    match src_lib_path.rfind('/') {
        Some(slash) => (&src_lib_path[..slash], &src_lib_path[slash + 1..]),
        None => (".", src_lib_path),
    }
}

fn stage_gadget(app_name: &str, src_lib_path: &str) -> String {
    let stage_dir = format!("/data/data/{app_name}/.cache");
    unsafe {
        libc::mkdir(cstring(&stage_dir).as_ptr(), 0o700);
    }

    let (src_dir, lib_name) = split_lib_path(src_lib_path);
    let cfg_name = with_config_suffix(lib_name);
    let src_cfg = format!("{src_dir}/{cfg_name}");
    let dst_lib = format!("{stage_dir}/{lib_name}");
    let dst_cfg = format!("{stage_dir}/{cfg_name}");

    logi(format!("Staging gadget: {src_lib_path} -> {dst_lib}"));

    if !copy_file(src_lib_path, &dst_lib) {
        return String::new();
    }

    copy_file(&src_cfg, &dst_cfg);
    dst_lib
}

fn unlink_staged(staged_lib_path: &str) {
    unsafe {
        libc::unlink(cstring(staged_lib_path).as_ptr());
    }

    let cfg = with_config_suffix(staged_lib_path);
    unsafe {
        libc::unlink(cstring(&cfg).as_ptr());
    }

    if let Some(slash) = staged_lib_path.rfind('/') {
        unsafe {
            libc::rmdir(cstring(&staged_lib_path[..slash]).as_ptr());
        }
    }

    logi("Staged files removed");
}

pub fn inject_lib(lib_path: &str, log_context: &str) {
    let c_path = cstring(lib_path);

    let handle = unsafe { xdl_open(c_path.as_ptr(), XDL_TRY_FORCE_LOAD) };
    if !handle.is_null() {
        logi(format!(
            "{log_context}Injected {lib_path} with handle {handle:p}"
        ));
        return;
    }
    let xdl_err = dlerror_string();

    let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
    if !handle.is_null() {
        logi(format!(
            "{log_context}Injected {lib_path} with handle {handle:p} (dlopen fallback)"
        ));
        remap_lib(lib_path);
        return;
    }
    let dlopen_err = dlerror_string();

    loge(format!(
        "{log_context}Failed to inject {lib_path} (xdl_open): {xdl_err}"
    ));
    loge(format!(
        "{log_context}Failed to inject {lib_path} (dlopen): {dlopen_err}"
    ));
}

fn inject_libs(cfg: &TargetConfig, pid: libc::pid_t) {
    wait_for_init(&cfg.app_name);

    if cfg.child_gating.enabled {
        enable_child_gating(&cfg.child_gating);
    }

    if cfg.kernel_assisted_evasion {
        logi(format!("KSIE enabled for PID: {pid}"));
    }

    delay_start_up(cfg.start_up_delay_ms);

    for lib_path in &cfg.injected_libraries {
        let staged = stage_gadget(&cfg.app_name, lib_path);
        let inject_path = if staged.is_empty() { lib_path } else { &staged };

        logi(format!("Injecting {inject_path}"));
        inject_lib(inject_path, "");

        if !staged.is_empty() {
            unlink_staged(&staged);
        }
    }

    thread::sleep(Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_suffix_matches_original() {
        assert_eq!(with_config_suffix("libsecmon.so"), "libsecmon.config.so");
        assert_eq!(
            with_config_suffix("/a/b/libgadget-arm64.so"),
            "/a/b/libgadget-arm64.config.so"
        );
        assert_eq!(with_config_suffix("no_suffix"), "no_suffix");
        assert_eq!(with_config_suffix("/dir.so/file"), "/dir.config.so/file");
    }

    #[test]
    fn lib_path_split_matches_original() {
        assert_eq!(split_lib_path("/data/x/lib.so"), ("/data/x", "lib.so"));
        assert_eq!(split_lib_path("lib.so"), (".", "lib.so"));
        assert_eq!(split_lib_path(""), (".", ""));
    }
}
