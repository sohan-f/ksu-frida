
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::thread;
use std::time::Duration;

use crate::child_gating::enable_child_gating;
use crate::config::{TargetConfig, load_config};
use crate::linkmap::scrub_dlpi_name;
use crate::log::{loge, logi};
use crate::remap::remap_lib;
use crate::sys::{RTLD_NOW, cstring, dlerror_string, dlopen};
use crate::xdl::{XDL_TRY_FORCE_LOAD, xdl_open};

const MODULE_DIR: &str = "/data/local/tmp/libsec";

pub fn check_and_inject(app_name: &str) -> bool {
    let Some(cfg) = load_config(MODULE_DIR, app_name) else {
        return false;
    };

    // SAFETY: `getpid(2)` cannot fail.
    let pid = unsafe { libc::getpid() };

    logi(format!("App detected: {app_name}"));
    logi(format!("PID: {pid}"));

    if !cfg.enabled {
        logi(format!("Injection disabled for {app_name}"));
        return false;
    }

    if !needs_injection_thread(&cfg) {
        logi(format!("Nothing to inject for {app_name}"));
        return false;
    }

    thread::spawn(move || inject_libs(&cfg, pid));

    true
}

fn needs_injection_thread(cfg: &TargetConfig) -> bool {
    !cfg.injected_libraries.is_empty() || cfg.child_gating.enabled
}

pub(crate) fn current_app_name() -> String {
    fs::read("/proc/self/cmdline")
        .ok()
        .and_then(|bytes| {
            bytes
                .split(|b| *b == 0)
                .next()
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
        })
        .unwrap_or_default()
}

fn package_of(app_name: &str) -> &str {
    app_name.split(':').next().unwrap_or(app_name)
}

const INIT_TIMEOUT: Duration = Duration::from_secs(60);

fn wait_for_init(app_name: &str) -> bool {
    wait_for_init_within(app_name, INIT_TIMEOUT)
}

fn wait_for_init_within(app_name: &str, timeout: Duration) -> bool {
    logi("Wait for process to complete init");

    let deadline = std::time::Instant::now() + timeout;
    while current_app_name() != app_name {
        if std::time::Instant::now() >= deadline {
            loge(format!("Timed out waiting for process init: {app_name}"));
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }

    thread::sleep(Duration::from_millis(100));

    logi("Process init completed");
    true
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
        Err(err) => {
            loge(format!("stage: open src failed: {src}: {err}"));
            return false;
        }
    };

    let src_len = match input.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            loge(format!("stage: stat src failed: {src}: {err}"));
            return false;
        }
    };

    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dst)
    {
        Ok(file) => file,
        Err(err) => {
            loge(format!("stage: open dst failed: {dst}: {err}"));
            return false;
        }
    };

    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `zeroed` stat as an output slot; no invariants yet.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstat` on our own open fd writes only into `st` above.
        if unsafe { libc::fstat(output.as_raw_fd(), &mut st) } != 0 {
            loge(format!(
                "stage: fstat dst failed: {dst}: {}",
                io::Error::last_os_error()
            ));
            return false;
        }
        #[allow(clippy::unnecessary_cast)]
        let (ifmt, ifreg) = (libc::S_IFMT as u32, libc::S_IFREG as u32);
        let fmt = st.st_mode & ifmt;
        // SAFETY: `geteuid(2)` takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if fmt != ifreg || st.st_uid != euid {
            loge(format!("stage: refusing non-file dst {dst}"));
            return false;
        }
    }

    match copy_file_range_all(&input, &output, src, dst, src_len) {
        RangeOutcome::Done => true,
        RangeOutcome::Failed => false,
        RangeOutcome::Unsupported => copy_file_loop(&mut input, &mut output, src, dst, 0, src_len),
    }
}

#[derive(PartialEq, Eq)]
enum RangeOutcome {
    Done,
    Failed,
    Unsupported,
}

fn copy_file_range_all(
    input: &File,
    output: &File,
    src: &str,
    dst: &str,
    src_len: u64,
) -> RangeOutcome {
    use std::os::unix::io::AsRawFd;

    let mut remaining = src_len;
    let mut first = true;
    while remaining > 0 {
        let chunk = remaining.min(1 << 30) as usize;
        match crate::sys::copy_file_range(input.as_raw_fd(), output.as_raw_fd(), chunk) {
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                if first
                    && matches!(
                        err.raw_os_error(),
                        Some(libc::ENOSYS)
                            | Some(libc::EXDEV)
                            | Some(libc::EINVAL)
                            | Some(libc::EOPNOTSUPP)
                    )
                {
                    return RangeOutcome::Unsupported;
                }
                loge(format!(
                    "stage: kernel copy of {src} -> {dst} failed: {err}"
                ));
                return RangeOutcome::Failed;
            }
            Ok(0) => break,
            Ok(n) => {
                remaining -= n;
                first = false;
            }
        }
    }

    if remaining != 0 {
        loge(format!(
            "stage: short kernel copy of {src} -> {dst}: {} of {src_len} bytes",
            src_len - remaining
        ));
        return RangeOutcome::Failed;
    }
    RangeOutcome::Done
}

fn copy_file_loop(
    input: &mut File,
    output: &mut File,
    src: &str,
    dst: &str,
    already: u64,
    src_len: u64,
) -> bool {
    let mut buf = [0u8; 65536];
    let mut copied: u64 = already;
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                loge(format!("stage: read failed for {src}: {err}"));
                return false;
            }
        };

        if let Err(err) = output.write_all(&buf[..n]) {
            loge(format!("stage: write failed for {dst}: {err}"));
            return false;
        }
        copied += n as u64;
    }

    if copied != src_len {
        loge(format!(
            "stage: short copy of {src}: {copied} of {src_len} bytes"
        ));
        return false;
    }

    true
}

fn stage_cpath(path: &str) -> Option<CString> {
    cstring(path)
        .inspect_err(|err| {
            loge(format!(
                "stage: refusing path with interior NUL {path:?}: {err}"
            ))
        })
        .ok()
}

fn ensure_dir(path: &str, mode: libc::mode_t) -> bool {
    let Some(c_path) = stage_cpath(path) else {
        return false;
    };
    // SAFETY: `c_path` is NUL-terminated and the return value is checked below.
    let mkdir_ok = unsafe { libc::mkdir(c_path.as_ptr(), mode) } == 0;
    if !mkdir_ok {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            loge(format!("stage: mkdir {path} failed: {err}"));
            return false;
        }
    }

    // SAFETY: `zeroed` stat as an output slot; no invariants yet.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `lstat` on our NUL-terminated path writes only into `st` above.
    if unsafe { libc::lstat(c_path.as_ptr(), &mut st) } != 0 {
        loge(format!(
            "stage: stat {path} failed: {}",
            io::Error::last_os_error()
        ));
        return false;
    }
    #[allow(clippy::unnecessary_cast)]
    let (ifmt, iflnk, ifdir) = (
        libc::S_IFMT as u32,
        libc::S_IFLNK as u32,
        libc::S_IFDIR as u32,
    );
    let fmt = st.st_mode & ifmt;
    if fmt == iflnk {
        loge(format!("stage: refusing symlinked dir {path}"));
        return false;
    }
    if fmt != ifdir {
        loge(format!("stage: not a directory: {path}"));
        return false;
    }
    true
}

fn remove_file(path: &str) -> bool {
    let Some(c_path) = stage_cpath(path) else {
        return false;
    };
    // SAFETY: `c_path` is NUL-terminated and the return value is checked below.
    if unsafe { libc::unlink(c_path.as_ptr()) } == 0 {
        return true;
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        return true;
    }
    loge(format!("stage: unlink {path} failed: {err}"));
    false
}

fn remove_dir(path: &str) -> bool {
    let Some(c_path) = stage_cpath(path) else {
        return false;
    };
    // SAFETY: `c_path` is NUL-terminated and the return value is checked below.
    if unsafe { libc::rmdir(c_path.as_ptr()) } == 0 {
        return true;
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        return true;
    }
    loge(format!("stage: rmdir {path} failed: {err}"));
    false
}

fn with_config_suffix(path: &str) -> String {
    let boundary = path.rfind('/').map_or(0, |slash| slash + 1);
    let base = &path[boundary..];
    let Some(dot) = base.rfind(".so") else {
        return path.to_string();
    };

    let insert_at = boundary + dot;
    let mut result = String::with_capacity(path.len() + ".config".len());
    result.push_str(&path[..insert_at]);
    result.push_str(".config");
    result.push_str(&path[insert_at..]);
    result
}

fn split_lib_path(src_lib_path: &str) -> (&str, &str) {
    match src_lib_path.rfind('/') {
        Some(slash) => (&src_lib_path[..slash], &src_lib_path[slash + 1..]),
        None => (".", src_lib_path),
    }
}

fn remove_stage_dir_contents(dir: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.map_while(Result::ok) {
        if entry
            .file_type()
            .map(|t| t.is_file() || t.is_symlink())
            .unwrap_or(false)
        {
            remove_file(&entry.path().to_string_lossy());
        }
    }
}

fn sweep_stale_stage_dirs(cache_dir: &str) {
    let Ok(entries) = fs::read_dir(cache_dir) else {
        return;
    };
    // SAFETY: `getpid(2)` cannot fail.
    let own_pid = unsafe { libc::getpid() };
    for entry in entries.map_while(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<libc::pid_t>() else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        // SAFETY: signal 0 sends nothing; the return value is purely the
        // existence check below.
        if unsafe { libc::kill(pid, 0) } == 0 {
            continue;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            continue;
        }
        let dir = format!("{cache_dir}/{name}");
        remove_stage_dir_contents(&dir);
        if remove_dir(&dir) {
            logi(format!("Swept stale stage dir {dir}"));
        }
    }
}

fn stage_gadget(app_name: &str, src_lib_path: &str) -> String {
    let cache_dir = format!("/data/data/{}/.cache", package_of(app_name));
    if !ensure_dir(&cache_dir, 0o700) {
        return String::new();
    }
    sweep_stale_stage_dirs(&cache_dir);
    // SAFETY: `getpid(2)` cannot fail.
    let stage_dir = format!("{cache_dir}/{}", unsafe { libc::getpid() });
    if !ensure_dir(&stage_dir, 0o700) {
        return String::new();
    }

    let (src_dir, lib_name) = split_lib_path(src_lib_path);
    let cfg_name = with_config_suffix(lib_name);
    let src_cfg = format!("{src_dir}/{cfg_name}");
    let dst_lib = format!("{stage_dir}/{lib_name}");
    let dst_cfg = format!("{stage_dir}/{cfg_name}");

    logi(format!("Staging gadget: {src_lib_path} -> {dst_lib}"));

    if !copy_file(src_lib_path, &dst_lib) {
        remove_file(&dst_lib);
        remove_file(&dst_cfg);
        remove_dir(&stage_dir);
        return String::new();
    }

    if !copy_file(&src_cfg, &dst_cfg) {
        remove_file(&dst_cfg);
    }
    dst_lib
}

fn unlink_staged(staged_lib_path: &str) {
    let lib_ok = remove_file(staged_lib_path);
    let cfg_ok = remove_file(&with_config_suffix(staged_lib_path));

    let dir_ok = match staged_lib_path.rfind('/') {
        Some(slash) => remove_dir(&staged_lib_path[..slash]),
        None => true,
    };

    if lib_ok && cfg_ok && dir_ok {
        logi("Staged files removed");
    }
}

pub fn inject_lib(lib_path: &str, log_context: &str, hide_maps: bool) {
    let c_path = match cstring(lib_path) {
        Ok(c_path) => c_path,
        Err(err) => {
            loge(format!(
                "{log_context}refusing library path with interior NUL {lib_path:?}: {err}"
            ));
            return;
        }
    };

    // SAFETY: `c_path` is a live `CString`; the returned handle is checked for null below.
    let handle = unsafe { xdl_open(c_path.as_ptr(), XDL_TRY_FORCE_LOAD) };
    if !handle.is_null() {
        logi(format!(
            "{log_context}Injected {lib_path} with handle {handle:p}"
        ));
        hide_or_show(lib_path, log_context, hide_maps);
        return;
    }
    let xdl_err = dlerror_string();

    // SAFETY: `c_path` is a live `CString`; the returned handle is checked for null below.
    let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
    if !handle.is_null() {
        logi(format!(
            "{log_context}Injected {lib_path} with handle {handle:p} (dlopen fallback)"
        ));
        hide_or_show(lib_path, log_context, hide_maps);
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

fn hide_or_show(lib_path: &str, log_context: &str, hide_maps: bool) {
    if hide_maps {
        remap_lib(lib_path);
    } else {
        logi(format!("{log_context}Map hiding disabled for {lib_path}"));
    }
    scrub_dlpi_name(lib_path);
}

pub(crate) fn stage_and_inject(lib_path: &str, app_name: &str, log_context: &str, hide_maps: bool) {
    let staged = stage_gadget(app_name, lib_path);
    let inject_path = if staged.is_empty() {
        loge(format!(
            "{log_context}Staging {lib_path} failed; falling back to the raw path"
        ));
        lib_path
    } else {
        &staged
    };

    logi(format!("{log_context}Injecting {inject_path}"));
    inject_lib(inject_path, log_context, hide_maps);

    if !staged.is_empty() {
        unlink_staged(&staged);
    }
}

fn inject_libs(cfg: &TargetConfig, pid: libc::pid_t) {
    if !wait_for_init(&cfg.app_name) {
        loge(format!(
            "Skipping injection into PID {pid}: process never reached expected name"
        ));
        return;
    }

    if cfg.child_gating.enabled {
        enable_child_gating(&cfg.child_gating);
    }

    if cfg.kernel_assisted_evasion {
        logi(format!("KSIE enabled for PID: {pid}"));
    }

    delay_start_up(cfg.start_up_delay_ms);

    for lib_path in &cfg.injected_libraries {
        stage_and_inject(lib_path, &cfg.app_name, "", cfg.hide_maps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChildGatingConfig;

    #[test]
    fn config_suffix_is_anchored_to_the_basename() {
        assert_eq!(with_config_suffix("libsecmon.so"), "libsecmon.config.so");
        assert_eq!(
            with_config_suffix("/a/b/libgadget-arm64.so"),
            "/a/b/libgadget-arm64.config.so"
        );
        assert_eq!(with_config_suffix("no_suffix"), "no_suffix");
        assert_eq!(with_config_suffix("/dir.so/file"), "/dir.so/file");
        assert_eq!(
            with_config_suffix("/dir.so/libx.so"),
            "/dir.so/libx.config.so"
        );
        assert_eq!(with_config_suffix("./libx.so"), "./libx.config.so");
    }

    #[test]
    fn empty_targets_need_no_injection_thread() {
        let base = || TargetConfig {
            enabled: true,
            app_name: "com.a.b".to_string(),
            child_gating: ChildGatingConfig {
                enabled: false,
                mode: "kill".to_string(),
                injected_libraries: Vec::new(),
            },
            ..TargetConfig::default()
        };

        assert!(!needs_injection_thread(&base()));

        let mut with_library = base();
        with_library.injected_libraries = vec!["/a.so".to_string()];
        assert!(needs_injection_thread(&with_library));

        let mut gated = base();
        gated.child_gating.enabled = true;
        assert!(needs_injection_thread(&gated));
    }

    #[test]
    fn lib_path_split_matches_original() {
        assert_eq!(split_lib_path("/data/x/lib.so"), ("/data/x", "lib.so"));
        assert_eq!(split_lib_path("lib.so"), (".", "lib.so"));
        assert_eq!(split_lib_path(""), (".", ""));
    }

    #[test]
    fn package_of_strips_subprocess_suffix() {
        assert_eq!(package_of("com.a.b"), "com.a.b");
        assert_eq!(package_of("com.a.b:push"), "com.a.b");
        assert_eq!(package_of(""), "");
    }

    #[test]
    fn wait_for_init_gives_up_after_timeout() {
        let start = std::time::Instant::now();
        assert!(!wait_for_init_within(
            "definitely-no-such-process-name",
            Duration::from_millis(30)
        ));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn wait_for_init_returns_when_name_matches() {
        let arg0 = current_app_name();
        assert!(wait_for_init_within(&arg0, Duration::from_secs(5)));
    }

    #[test]
    fn wait_for_init_does_not_match_a_prefix_of_the_process_name() {
        let arg0 = current_app_name();
        let mut prefix = arg0.clone();
        prefix.pop();
        if prefix.is_empty() {
            return;
        }

        let start = std::time::Instant::now();
        assert!(!wait_for_init_within(&prefix, Duration::from_millis(50)));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ksufrida-{}-{name}", std::process::id()))
    }

    #[test]
    fn copy_file_copies_every_byte() {
        let dir = scratch("copy-ok");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");

        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        assert!(copy_file(src.to_str().unwrap(), dst.to_str().unwrap()));
        assert_eq!(fs::read(&dst).unwrap(), payload);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn copy_file_rejects_a_missing_source() {
        let dir = scratch("copy-missing");
        fs::create_dir_all(&dir).unwrap();
        let dst = dir.join("dst.bin");

        assert!(!copy_file(
            dir.join("no-such-file").to_str().unwrap(),
            dst.to_str().unwrap()
        ));
        assert!(!dst.exists());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn copy_file_fails_on_a_directory_source() {
        let dir = scratch("copy-dir");
        fs::create_dir_all(&dir).unwrap();
        let dst = dir.join("dst.bin");

        assert!(!copy_file(dir.to_str().unwrap(), dst.to_str().unwrap()));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn copy_file_loop_copies_every_byte() {
        let dir = scratch("loop-direct");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");

        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        let mut input = File::open(&src).unwrap();
        let len = input.metadata().unwrap().len();
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dst)
            .unwrap();
        assert!(copy_file_loop(
            &mut input,
            &mut output,
            "src",
            "dst",
            0,
            len
        ));
        assert_eq!(fs::read(&dst).unwrap(), payload);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn copy_file_range_matches_source_size() {
        let dir = scratch("range");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");

        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        let input = File::open(&src).unwrap();
        let len = input.metadata().unwrap().len();
        let output = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dst)
            .unwrap();
        match copy_file_range_all(&input, &output, "src", "dst", len) {
            RangeOutcome::Done => assert_eq!(fs::read(&dst).unwrap(), payload),
            RangeOutcome::Unsupported => {}
            RangeOutcome::Failed => panic!("kernel copy failed outright"),
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_helpers_treat_missing_entries_as_clean() {
        let dir = scratch("remove-clean");
        fs::create_dir_all(&dir).unwrap();

        assert!(remove_file(dir.join("never-existed").to_str().unwrap()));
        assert!(remove_dir(dir.to_str().unwrap()));
        assert!(!dir.exists());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ensure_dir_refuses_symlink_plant() {
        let dir = scratch("mkdir-link");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real");
        fs::create_dir_all(&target).unwrap();

        let link = dir.join("planted");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!ensure_dir(link.to_str().unwrap(), 0o700));

        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("no-such-target"), &dangling).unwrap();
        assert!(!ensure_dir(dangling.to_str().unwrap(), 0o700));

        assert!(ensure_dir(target.to_str().unwrap(), 0o700));
        assert!(ensure_dir(dir.join("fresh").to_str().unwrap(), 0o700));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn copy_file_refuses_symlink_and_special_files() {
        let dir = scratch("copy-plant");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        fs::write(&src, b"payload").unwrap();

        let elsewhere = dir.join("elsewhere.bin");
        std::os::unix::fs::symlink(&elsewhere, dir.join("link.bin")).unwrap();
        assert!(!copy_file(
            src.to_str().unwrap(),
            dir.join("link.bin").to_str().unwrap()
        ));
        assert!(!elsewhere.exists());

        let fifo = dir.join("fifo.bin");
        let c_fifo = CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c_fifo` is NUL-terminated; creates a test-owned node.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        assert!(!copy_file(src.to_str().unwrap(), fifo.to_str().unwrap()));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_dir_reports_a_leftover_stage() {
        let dir = scratch("remove-nonempty");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("leftover.bin"), b"x").unwrap();

        assert!(!remove_dir(dir.to_str().unwrap()));

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg_attr(miri, ignore)]
    fn dead_pid() -> libc::pid_t {
        // SAFETY: the child exits immediately; the parent reaps it below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork(2)");
        if pid == 0 {
            // SAFETY: child-only path, never returns.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        // SAFETY: `pid` is our child; blocking reap of exactly it.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        pid
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sweep_removes_only_dead_pid_dirs() {
        let cache = scratch("sweep");
        fs::create_dir_all(&cache).unwrap();
        let cache = cache.to_str().unwrap().to_string();

        // SAFETY: `getpid(2)` cannot fail.
        let live = unsafe { libc::getpid() }.to_string();
        let dead = dead_pid().to_string();

        fs::create_dir_all(format!("{cache}/{dead}")).unwrap();
        fs::write(format!("{cache}/{dead}/libsecmon.so"), b"x").unwrap();
        fs::write(format!("{cache}/{dead}/libsecmon.config.so"), b"y").unwrap();
        fs::create_dir_all(format!("{cache}/{live}")).unwrap();
        fs::write(format!("{cache}/{live}/libsecmon.so"), b"x").unwrap();
        fs::create_dir_all(format!("{cache}/not-a-pid")).unwrap();
        fs::write(format!("{cache}/mydata.bin"), b"app file").unwrap();

        sweep_stale_stage_dirs(&cache);

        assert!(
            !std::path::Path::new(&format!("{cache}/{dead}")).exists(),
            "stale stage dir must go"
        );
        assert!(
            std::path::Path::new(&format!("{cache}/{live}/libsecmon.so")).exists(),
            "live pid dir must stay"
        );
        assert!(
            std::path::Path::new(&format!("{cache}/not-a-pid")).exists(),
            "foreign dir must stay"
        );
        assert!(
            std::path::Path::new(&format!("{cache}/mydata.bin")).exists(),
            "app file must stay"
        );

        fs::remove_dir_all(&cache).ok();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sweep_leaves_unexpected_subdirs_alone() {
        let cache = scratch("sweep-subdir");
        fs::create_dir_all(&cache).unwrap();
        let cache = cache.to_str().unwrap().to_string();

        let dead = dead_pid().to_string();
        fs::create_dir_all(format!("{cache}/{dead}")).unwrap();
        fs::write(format!("{cache}/{dead}/libsecmon.so"), b"x").unwrap();
        fs::create_dir_all(format!("{cache}/{dead}/weird")).unwrap();
        fs::write(format!("{cache}/{dead}/weird/nested.bin"), b"y").unwrap();

        sweep_stale_stage_dirs(&cache);

        assert!(
            !std::path::Path::new(&format!("{cache}/{dead}/libsecmon.so")).exists(),
            "top-level staged file must go"
        );
        assert!(
            std::path::Path::new(&format!("{cache}/{dead}/weird/nested.bin")).exists(),
            "nested contents must stay"
        );
        assert!(
            std::path::Path::new(&format!("{cache}/{dead}")).exists(),
            "non-empty dir must stay for remove_dir to report"
        );

        fs::remove_dir_all(&cache).ok();
    }
}
