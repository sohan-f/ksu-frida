use std::ffi::CString;
#[cfg(any(target_os = "android", test))]
use std::ffi::c_int;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::thread;
use std::time::Duration;

use crate::child_gating::enable_child_gating;
use crate::config::{TargetConfig, load_config};
use crate::linkmap::scrub_dlpi_name;
use crate::log::{basename, loge_fmt, logi, logi_fmt};
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

    logi_fmt(format_args!("App detected: {app_name}"));
    logi_fmt(format_args!("PID: {pid}"));

    if !cfg.enabled {
        logi_fmt(format_args!("Injection disabled for {app_name}"));
        return false;
    }

    if !needs_injection_thread(&cfg) {
        logi_fmt(format_args!("Nothing to inject for {app_name}"));
        return false;
    }

    if std::thread::Builder::new()
        .name("ksufrida-inject".to_string())
        .spawn(move || inject_libs(&cfg, pid))
        .is_err()
    {
        loge_fmt(format_args!("Thread spawn failed for {app_name}"));
        return false;
    }

    true
}

const fn needs_injection_thread(cfg: &TargetConfig) -> bool {
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
    // Exact match; a substring test confuses com.foo with com.foobar.
    while current_app_name() != app_name {
        if std::time::Instant::now() >= deadline {
            loge_fmt(format_args!(
                "Timed out waiting for process init: {app_name}"
            ));
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

    logi_fmt(format_args!(
        "Waiting for configured start up delay {start_up_delay_ms}ms"
    ));

    // Countdown logs cover at most the last 10 seconds; the rest sleeps silently.
    let countdown_secs = (start_up_delay_ms / 1000).min(10);
    thread::sleep(Duration::from_millis(
        start_up_delay_ms - countdown_secs * 1000,
    ));

    for remaining in (1..=countdown_secs).rev() {
        logi_fmt(format_args!("Injecting libs in {remaining} seconds"));
        thread::sleep(Duration::from_secs(1));
    }
}

fn open_dst_hardened(dst: &str) -> Option<File> {
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    {
        use std::os::unix::io::FromRawFd;
        let c_path = cstring(dst).ok()?;
        let how = crate::sys::OpenHow {
            flags: (libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_TRUNC
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK) as u64,
            mode: 0o700,
            resolve: crate::sys::RESOLVE_NO_SYMLINKS | crate::sys::RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: `c_path` live, `how` fully init; fd checked below.
        let fd = unsafe { crate::sys::openat2(libc::AT_FDCWD, c_path.as_ptr(), &raw const how) };
        if fd >= 0 {
            // SAFETY: fd is ours from openat2 above.
            return Some(unsafe { File::from_raw_fd(fd) });
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(code) if code == libc::ENOSYS || code == libc::EINVAL => {}
            // openat2 exists but refused the call; fall back and say why.
            Some(code) => loge_fmt(format_args!("stage: openat2 failed ({code}); falling back")),
            None => {}
        }
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        // Refuses symlink plants and keeps fifo plants from hanging the open.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dst)
        .ok()
}

fn copy_file(src: &str, dst: &str) -> bool {
    let mut input = match File::open(src) {
        Ok(file) => file,
        Err(err) => {
            loge_fmt(format_args!("stage: open src failed: {src}: {err}"));
            return false;
        }
    };

    let src_len = match input.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            loge_fmt(format_args!("stage: stat src failed: {src}: {err}"));
            return false;
        }
    };

    let mut output = match open_dst_hardened(dst) {
        Some(file) => file,
        None => {
            loge_fmt(format_args!("stage: open dst failed: {dst}"));
            return false;
        }
    };

    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `zeroed` stat as an output slot; no invariants yet.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstat` on our own open fd writes only into `st` above.
        if unsafe { libc::fstat(output.as_raw_fd(), &raw mut st) } != 0 {
            loge_fmt(format_args!(
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
            loge_fmt(format_args!("stage: refusing non-file dst {dst}"));
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

#[allow(clippy::unnested_or_patterns)]
fn is_unsupported(code: Option<i32>) -> bool {
    matches!(
        code,
        Some(libc::ENOSYS) | Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
    )
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
        // 1 GiB chunks: len is 32-bit size_t on 32-bit ABIs.
        let chunk = remaining.min(1 << 30) as usize;
        match crate::sys::copy_file_range(input.as_raw_fd(), output.as_raw_fd(), chunk) {
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                // Only the first call may report Unsupported; support cannot change mid-file.
                if first && is_unsupported(err.raw_os_error()) {
                    return RangeOutcome::Unsupported;
                }
                loge_fmt(format_args!(
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
        loge_fmt(format_args!(
            "stage: short kernel copy of {src} -> {dst}: {} of {src_len} bytes",
            src_len - remaining
        ));
        return RangeOutcome::Failed;
    }
    RangeOutcome::Done
}

#[allow(clippy::large_stack_arrays)]
fn copy_file_loop(
    input: &mut File,
    output: &mut File,
    src: &str,
    dst: &str,
    already: u64,
    src_len: u64,
) -> bool {
    // Stack avoids post-fork malloc; bench shows heap has no win.
    let mut buf = [0u8; 65536];
    let mut copied: u64 = already;
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                loge_fmt(format_args!("stage: read failed for {src}: {err}"));
                return false;
            }
        };

        if let Err(err) = output.write_all(&buf[..n]) {
            loge_fmt(format_args!("stage: write failed for {dst}: {err}"));
            return false;
        }
        copied += n as u64;
    }

    if copied != src_len {
        loge_fmt(format_args!(
            "stage: short copy of {src}: {copied} of {src_len} bytes"
        ));
        return false;
    }

    true
}

fn stage_cpath(path: &str) -> Option<CString> {
    cstring(path)
        .inspect_err(|err| {
            loge_fmt(format_args!(
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
            loge_fmt(format_args!("stage: mkdir {path} failed: {err}"));
            return false;
        }
    }

    // SAFETY: `zeroed` stat as an output slot; no invariants yet.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `lstat` on our NUL-terminated path writes only into `st` above.
    if unsafe { libc::lstat(c_path.as_ptr(), &raw mut st) } != 0 {
        loge_fmt(format_args!(
            "stage: stat {path} failed: {}",
            io::Error::last_os_error()
        ));
        return false;
    }
    // lstat, not stat: mkdir reports EEXIST for a symlink final component.
    #[allow(clippy::unnecessary_cast)]
    let (ifmt, iflnk, ifdir) = (
        libc::S_IFMT as u32,
        libc::S_IFLNK as u32,
        libc::S_IFDIR as u32,
    );
    let fmt = st.st_mode & ifmt;
    if fmt == iflnk {
        loge_fmt(format_args!("stage: refusing symlinked dir {path}"));
        return false;
    }
    if fmt != ifdir {
        loge_fmt(format_args!("stage: not a directory: {path}"));
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
    loge_fmt(format_args!("stage: unlink {path} failed: {err}"));
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
    loge_fmt(format_args!("stage: rmdir {path} failed: {err}"));
    false
}

fn with_config_suffix(path: &str) -> String {
    let (dir, base) = match path.rsplit_once('/') {
        Some((dir, base)) => (Some(dir), base),
        None => (None, path),
    };
    let Some((stem, rest)) = base.rsplit_once(".so") else {
        return path.to_string();
    };
    match dir {
        Some(dir) => format!("{dir}/{stem}.config.so{rest}"),
        None => format!("{stem}.config.so{rest}"),
    }
}

fn split_lib_path(src_lib_path: &str) -> (&str, &str) {
    match src_lib_path.rsplit_once('/') {
        Some((dir, base)) => (dir, base),
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

fn pid_is_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return true;
    }
    // pidfd is race-free (no PID reuse); fall back to kill(0) when unsupported.
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    {
        // SAFETY: plain pidfd_open; fd closed immediately, errno read on failure.
        let fd = crate::sys::pidfd_open(pid, 0);
        if fd >= 0 {
            // SAFETY: fd is ours from above.
            unsafe { libc::close(fd) };
            return true;
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(code) if code == libc::ESRCH => return false,
            Some(code) if code == libc::ENOSYS => {} // Fall through to kill below.
            _ => return true,
        }
    }
    // SAFETY: signal 0 sends nothing; the return value is purely the
    // existence check below.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    // ESRCH means dead; any other error leaves the dir alone (treated alive).
    io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
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
        if pid_is_alive(pid) {
            continue;
        }
        let dir = format!("{cache_dir}/{name}");
        remove_stage_dir_contents(&dir);
        if remove_dir(&dir) {
            logi_fmt(format_args!("Swept stale stage dir {dir}"));
        }
    }
}

fn cache_dir_for(app_name: &str) -> String {
    let pkg = package_of(app_name);
    for base in ["/data/user/0", "/data/data"] {
        let dir = format!("{base}/{pkg}/.cache");
        if ensure_dir(&dir, 0o700) {
            return dir;
        }
    }
    String::new()
}

fn stage_gadget(app_name: &str, src_lib_path: &str) -> String {
    let cache_dir = cache_dir_for(app_name);
    if cache_dir.is_empty() {
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

    logi_fmt(format_args!(
        "Staging gadget {} -> {dst_lib}",
        basename(src_lib_path)
    ));

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
    let base = basename(lib_path);
    let c_path = match cstring(lib_path) {
        Ok(c_path) => c_path,
        Err(err) => {
            loge_fmt(format_args!(
                "{log_context}refusing library path with interior NUL {lib_path:?}: {err}"
            ));
            return;
        }
    };

    // SAFETY: `c_path` is a live `CString`; the returned handle is checked for null below.
    let handle = unsafe { xdl_open(c_path.as_ptr(), XDL_TRY_FORCE_LOAD) };
    if !handle.is_null() {
        logi_fmt(format_args!(
            "{log_context}Injected {base} with handle {handle:p}"
        ));
        hide_or_show(lib_path, log_context, hide_maps);
        return;
    }
    let xdl_err = dlerror_string();

    // SAFETY: `c_path` is a live `CString`; the returned handle is checked for null below.
    let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
    if !handle.is_null() {
        logi_fmt(format_args!(
            "{log_context}Injected {base} with handle {handle:p} (dlopen fallback)"
        ));
        hide_or_show(lib_path, log_context, hide_maps);
        return;
    }
    let dlopen_err = dlerror_string();

    loge_fmt(format_args!(
        "{log_context}Failed to inject {base} (xdl_open): {xdl_err}"
    ));
    loge_fmt(format_args!(
        "{log_context}Failed to inject {base} (dlopen): {dlopen_err}"
    ));
}

fn hide_or_show(lib_path: &str, log_context: &str, hide_maps: bool) {
    if hide_maps {
        remap_lib(lib_path);
    } else {
        logi_fmt(format_args!(
            "{log_context}Map hiding disabled for {}",
            basename(lib_path)
        ));
    }
    scrub_dlpi_name(lib_path);
}

#[cfg(any(target_os = "android", test))]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn hide_or_show_memfd(log_context: &str, hide_maps: bool) {
    use crate::linkmap::scrub_memfd;
    use crate::remap::remap_memfd;
    if hide_maps {
        remap_memfd();
    } else {
        logi_fmt(format_args!("{log_context}Map hiding disabled for memfd"));
    }
    scrub_memfd();
}

#[cfg(any(target_os = "android", test))]
fn write_memfd(src_lib_path: &str) -> Option<c_int> {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

    let c_name = match cstring(crate::sys::MEMFD_NAME) {
        Ok(c_name) => c_name,
        Err(_) => return None,
    };
    // SAFETY: static name above; the fd is checked below and owned here.
    // MFD_EXEC first: vm.memfd_noexec=1 forces NX and =2 rejects flagless.
    let mut fd = crate::sys::memfd_create(
        c_name.as_ptr(),
        crate::sys::MFD_CLOEXEC | crate::sys::MFD_ALLOW_SEALING | crate::sys::MFD_EXEC,
    );
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = crate::sys::memfd_create(
            c_name.as_ptr(),
            crate::sys::MFD_CLOEXEC | crate::sys::MFD_ALLOW_SEALING,
        );
    }
    if fd < 0 {
        loge_fmt(format_args!(
            "stage: memfd_create failed: {}",
            io::Error::last_os_error()
        ));
        return None;
    }

    let mut input = match File::open(src_lib_path) {
        Ok(file) => file,
        Err(err) => {
            loge_fmt(format_args!(
                "stage: open src failed: {src_lib_path}: {err}"
            ));
            // SAFETY: `fd` is ours from above.
            unsafe { libc::close(fd) };
            return None;
        }
    };
    let src_len = match input.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            loge_fmt(format_args!(
                "stage: stat src failed: {src_lib_path}: {err}"
            ));
            // SAFETY: as above.
            unsafe { libc::close(fd) };
            return None;
        }
    };
    // SAFETY: `fd` is ours from above and disowned exactly once below.
    let mut output = unsafe { File::from_raw_fd(fd) };
    let ok = match copy_file_range_all(&input, &output, src_lib_path, "memfd", src_len) {
        RangeOutcome::Done => true,
        RangeOutcome::Failed => false,
        RangeOutcome::Unsupported => {
            copy_file_loop(&mut input, &mut output, src_lib_path, "memfd", 0, src_len)
        }
    };
    if !ok {
        return None;
    }
    #[cfg(any(target_os = "android", test))]
    if let Err(err) = crate::sys::seal_memfd_fixed(output.as_raw_fd()) {
        loge_fmt(format_args!("stage: seal memfd failed: {err}"));
    }
    // SAFETY: disown without closing; the caller closes after loading.
    Some(output.into_raw_fd())
}

#[cfg(target_os = "android")]
fn try_memfd_inject(src_lib_path: &str, log_context: &str, hide_maps: bool) -> bool {
    use crate::sys::{ANDROID_DLEXT_FORCE_LOAD, ANDROID_DLEXT_USE_LIBRARY_FD};

    let Some(fd) = write_memfd(src_lib_path) else {
        return false;
    };
    let c_path = match cstring(src_lib_path) {
        Ok(c_path) => c_path,
        Err(_) => {
            // SAFETY: `fd` is ours from above.
            unsafe { libc::close(fd) };
            return false;
        }
    };
    let info = crate::sys::AndroidDlextInfo {
        flags: ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD,
        reserved_addr: std::ptr::null_mut(),
        reserved_size: 0,
        relro_fd: 0,
        library_fd: fd,
        library_fd_offset: 0,
        library_namespace: std::ptr::null_mut(),
    };
    // SAFETY: `c_path` is live and `info` fully initialized; the returned
    // handle is checked for null below.
    let handle = unsafe { crate::sys::android_dlopen_ext(c_path.as_ptr(), RTLD_NOW, &info) };
    // SAFETY: `fd` is ours from above.
    if unsafe { libc::close(fd) } != 0 {
        loge_fmt(format_args!(
            "{log_context}memfd close failed: {}",
            io::Error::last_os_error()
        ));
    }
    if handle.is_null() {
        loge_fmt(format_args!(
            "{log_context}memfd load failed for {src_lib_path}: {}",
            dlerror_string()
        ));
        return false;
    }
    logi_fmt(format_args!(
        "{log_context}Injected {src_lib_path} from memfd with handle {handle:p}"
    ));
    hide_or_show_memfd(log_context, hide_maps);
    true
}

#[cfg(not(any(target_os = "android", test)))]
#[allow(dead_code)]
fn hide_or_show_memfd(_log_context: &str, _hide_maps: bool) {}

#[cfg(not(target_os = "android"))]
fn try_memfd_inject(_src_lib_path: &str, _log_context: &str, _hide_maps: bool) -> bool {
    false
}

// stage=false injects the source directly; only gated children stage.
pub(crate) fn stage_and_inject(
    lib_path: &str,
    app_name: &str,
    log_context: &str,
    hide_maps: bool,
    stage: bool,
) {
    if try_memfd_inject(lib_path, log_context, hide_maps) {
        return;
    }
    let staged = if stage {
        stage_gadget(app_name, lib_path)
    } else {
        logi_fmt(format_args!("{log_context}Staging skipped for {lib_path}"));
        String::new()
    };
    let inject_path = if staged.is_empty() {
        if stage {
            loge_fmt(format_args!(
                "{log_context}Staging {} failed; falling back to the raw path",
                basename(lib_path)
            ));
        }
        lib_path
    } else {
        &staged
    };

    logi_fmt(format_args!(
        "{log_context}Injecting {}",
        basename(inject_path)
    ));
    inject_lib(inject_path, log_context, hide_maps);

    if !staged.is_empty() {
        unlink_staged(&staged);
    }
}

fn inject_libs(cfg: &TargetConfig, pid: libc::pid_t) {
    if !wait_for_init(&cfg.app_name) {
        loge_fmt(format_args!(
            "Skipping injection into PID {pid}: process never reached expected name"
        ));
        return;
    }

    if cfg.child_gating.enabled {
        enable_child_gating(&cfg.child_gating, &cfg.app_name);
    }

    if cfg.kernel_assisted_evasion {
        logi_fmt(format_args!("KSIE enabled for PID: {pid}"));
    }

    sweep_stale_stage_dirs(&format!(
        "/data/user/0/{}/.cache",
        package_of(&cfg.app_name)
    ));
    sweep_stale_stage_dirs(&format!("/data/data/{}/.cache", package_of(&cfg.app_name)));

    delay_start_up(cfg.start_up_delay_ms);

    for lib_path in &cfg.injected_libraries {
        stage_and_inject(lib_path, &cfg.app_name, "", cfg.hide_maps, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChildGatingConfig, ChildMode};
    use crate::test_support::TempDir;

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
                mode: ChildMode::Kill,
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

    #[test]
    fn copy_file_copies_every_byte() {
        let dir = TempDir::new("copy-ok");
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");

        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        assert!(copy_file(src.to_str().unwrap(), dst.to_str().unwrap()));
        assert_eq!(fs::read(&dst).unwrap(), payload);
    }

    #[test]
    fn copy_file_rejects_a_missing_source() {
        let dir = TempDir::new("copy-missing");
        let dst = dir.join("dst.bin");

        assert!(!copy_file(
            dir.join("no-such-file").to_str().unwrap(),
            dst.to_str().unwrap()
        ));
        assert!(!dst.exists());
    }

    #[test]
    fn copy_file_fails_on_a_directory_source() {
        let dir = TempDir::new("copy-dir");
        let dst = dir.join("dst.bin");

        assert!(!copy_file(dir.to_str().unwrap(), dst.to_str().unwrap()));
    }

    #[test]
    fn copy_file_loop_copies_every_byte() {
        let dir = TempDir::new("loop-direct");
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
    }

    #[test]
    fn copy_file_range_matches_source_size() {
        let dir = TempDir::new("range");
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
    }

    #[test]
    fn unsupported_errnos_map_to_fallback() {
        assert!(is_unsupported(Some(libc::ENOSYS)));
        assert!(is_unsupported(Some(libc::EXDEV)));
        assert!(is_unsupported(Some(libc::EINVAL)));
        assert!(is_unsupported(Some(libc::EOPNOTSUPP)));
        assert!(!is_unsupported(Some(
            libc::ENOSYS | libc::EXDEV | libc::EINVAL | libc::EOPNOTSUPP
        )));
        assert!(!is_unsupported(Some(0)));
        assert!(!is_unsupported(None));
    }

    #[test]
    fn remove_helpers_treat_missing_entries_as_clean() {
        let dir = TempDir::new("remove-clean");

        assert!(remove_file(dir.join("never-existed").to_str().unwrap()));
        assert!(remove_dir(dir.to_str().unwrap()));
        assert!(!dir.exists());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real symlinks are outside miri's filesystem
    fn ensure_dir_refuses_symlink_plant() {
        let dir = TempDir::new("mkdir-link");
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
    }

    #[test]
    #[cfg_attr(miri, ignore)] // symlinks/fifos are outside miri's filesystem
    fn copy_file_refuses_symlink_and_special_files() {
        let dir = TempDir::new("copy-plant");
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
    }

    #[test]
    fn remove_dir_reports_a_leftover_stage() {
        let dir = TempDir::new("remove-nonempty");
        fs::write(dir.join("leftover.bin"), b"x").unwrap();

        assert!(!remove_dir(dir.to_str().unwrap()));
    }

    #[cfg_attr(miri, ignore)] // fork(2) is not interpretable
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
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        pid
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses fork(2) via dead_pid()
    fn sweep_removes_only_dead_pid_dirs() {
        let stage = TempDir::new("sweep");
        let cache = stage.path().to_str().unwrap().to_string();

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
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses fork(2) via dead_pid()
    fn sweep_leaves_unexpected_subdirs_alone() {
        let stage = TempDir::new("sweep-subdir");
        let cache = stage.path().to_str().unwrap().to_string();

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
    }

    #[test]
    fn no_stage_injects_without_touching_the_filesystem() {
        let dir = TempDir::new("no-stage");

        stage_and_inject(
            dir.join("missing.so").to_str().unwrap(),
            "com.example.app",
            "[test] ",
            true,
            false,
        );

        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn write_memfd_roundtrips_source_bytes() {
        let dir = TempDir::new("memfd");
        let src = dir.join("src.bin");

        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        let fd = write_memfd(src.to_str().unwrap()).expect("memfd stage");
        let back = fs::read(format!("/proc/self/fd/{fd}")).unwrap();
        // SAFETY: `fd` is ours from above; done with it.
        unsafe { libc::close(fd) };
        assert_eq!(back, payload);
    }
}
