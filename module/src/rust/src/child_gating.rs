use std::ffi::{CStr, c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::{ChildGatingConfig, ChildMode};
use crate::inject::stage_and_inject;
use crate::log::{loge, loge_fmt, logi, logi_fmt};
use crate::sys::{dlerror_string, set_errno};

type ForkFn = unsafe extern "C" fn() -> libc::pid_t;

// Null until the Release store in `enable_child_gating` publishes the trampoline.
static ORIG_FORK: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static CHILD_GATING_MODE: std::sync::OnceLock<ChildMode> = std::sync::OnceLock::new();
static INJECTED_LIBRARIES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
// Parent cmdline at enable time, COW-visible in fork child: avoids /proc re-read post-fork.
static GATING_APP_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
// Header scrubbing follows the parent target; atomics only, safe post-fork.
static GATING_SCRUB_HEADER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
// Map hiding follows the parent target like scrubbing does.
static GATING_HIDE_MAPS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn ksufrida_dobby_hook(
        addr: *mut c_void,
        replace: *mut c_void,
        orig: *mut *mut c_void,
    ) -> c_int;
}

#[cfg(not(target_os = "android"))]
const unsafe fn ksufrida_dobby_hook(
    _addr: *mut c_void,
    _replace: *mut c_void,
    _orig: *mut *mut c_void,
) -> c_int {
    0
}

unsafe extern "C" {
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> c_int;
}

// Child-only reset: atomics only, no alloc/log/locks — safe post-fork.
unsafe extern "C" fn atfork_child() {
    crate::remap::after_fork();
}

fn enable_atfork_reset() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: handlers are plain fns; child only stores atomics.
        let rc = unsafe { pthread_atfork(None, None, Some(atfork_child)) };
        if rc != 0 {
            loge_fmt(format_args!(
                "[child_gating] pthread_atfork failed: {rc}; fork child keeps parent rebuild state"
            ));
        }
    });
}

// Kill/Freeze/Pass allocate nothing and log nothing: the child inherits every lock held at fork time.
// Inject reuses parent-prepared strings and stays silent (child-quiet logs cover
// every verbose gate); staging allocs and dlopen remain, so it stays best-effort.
fn run_child_action(action: ChildMode, libraries: &[String], app_name: &str) -> libc::pid_t {
    match action {
        ChildMode::Kill => {
            // SAFETY: `_exit(2)` takes a plain status and never returns.
            unsafe { libc::_exit(0) }
        }
        ChildMode::Freeze => loop {
            thread::sleep(Duration::from_secs(3600));
        },
        ChildMode::Inject => {
            if libraries.is_empty() {
                return 0;
            }
            let scrub = GATING_SCRUB_HEADER.load(Ordering::Relaxed);
            let hide_maps = GATING_HIDE_MAPS.load(Ordering::Relaxed);
            for lib_path in libraries {
                stage_and_inject(lib_path, app_name, "", hide_maps, scrub, true);
            }
            0
        }
        ChildMode::Pass => 0,
    }
}

unsafe extern "C" fn fork_replacement() -> libc::pid_t {
    // Fail the fork rather than unwind into bionic/Dobby.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(fork_inner)) {
        Ok(pid) => pid,
        Err(_) => {
            set_errno(libc::EAGAIN);
            -1
        }
    }
}

fn fork_inner() -> libc::pid_t {
    let orig_ptr = ORIG_FORK.load(Ordering::Acquire);
    if orig_ptr.is_null() {
        logi("[child_gating] fork hook fired before its origin was published");
        set_errno(libc::EAGAIN);
        return -1;
    }
    // SAFETY: non-null trampoline published by `enable_child_gating`.
    let orig: ForkFn = unsafe { std::mem::transmute(orig_ptr) };

    let mode = CHILD_GATING_MODE.get().copied().unwrap_or_default();

    // SAFETY: `getpid(2)` cannot fail.
    let parent_pid = unsafe { libc::getpid() };
    logi_fmt(format_args!(
        "[child_gating][pid {parent_pid}] detected fork/vfork (child_gating_mode {mode:?})"
    ));

    // The vfork hook resumes via the fork trampoline, turning vfork into fork.
    // SAFETY: `orig` is the published trampoline and behaves as `fork(2)`.
    let child_pid = unsafe { orig() };
    if child_pid != 0 {
        logi_fmt(format_args!(
            "[child_gating][pid {parent_pid}] returning from forking {child_pid}"
        ));
        return child_pid;
    }

    crate::remap::after_fork();

    // Silence first: every log line below would malloc and take liblog locks.
    crate::log::set_fork_child_quiet(true);

    let libraries = INJECTED_LIBRARIES
        .get()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let app_name = GATING_APP_NAME
        .get()
        .map(String::as_str)
        .unwrap_or_default();
    run_child_action(mode, libraries, app_name)
}

/// Address of a hook target by name, if resolvable in any visible scope.
fn lookup_hook_target(name: &CStr) -> Option<*mut c_void> {
    let addr = crate::sys::lookup_symbol(name);
    if addr.is_none() && crate::log::verbose() {
        loge_fmt(format_args!(
            "[child_gating] lookup failed for {}: {}",
            name.to_string_lossy(),
            dlerror_string()
        ));
    }
    addr
}

pub fn enable_child_gating(
    cfg: &ChildGatingConfig,
    app_name: &str,
    scrub_header: bool,
    hide_maps: bool,
) {
    if CHILD_GATING_MODE.set(cfg.mode).is_err() {
        loge("[child_gating] already enabled; ignoring second config");
        return;
    }
    let _ = INJECTED_LIBRARIES.set(cfg.injected_libraries.clone());
    let _ = GATING_APP_NAME.set(app_name.to_string());
    GATING_SCRUB_HEADER.store(scrub_header, Ordering::Relaxed);
    GATING_HIDE_MAPS.store(hide_maps, Ordering::Relaxed);

    if cfg.mode == ChildMode::Pass {
        loge("[child_gating] mode is pass; children will run ungated");
    }

    logi("[child_gating] enabling child gating");
    enable_atfork_reset();

    let fork_addr = lookup_hook_target(c"fork");
    if let Some(addr) = fork_addr {
        logi_fmt(format_args!("[child_gating] fork address {addr:p}"));
    }
    let vfork_addr = lookup_hook_target(c"vfork");
    if let Some(addr) = vfork_addr {
        logi_fmt(format_args!("[child_gating] vfork address {addr:p}"));
    }

    let replacement = fork_replacement as *const () as *mut c_void;

    // Without a published fork origin, a working vfork hook would fail every
    // spawn, so both hooks stand or fall together.
    let mut fork_ok = false;
    if let Some(fork_addr) = fork_addr {
        // Stack local: only this thread observes it, so the publish cannot race hooks on other threads.
        let mut fork_trampoline: *mut c_void = std::ptr::null_mut();
        // SAFETY: `fork_addr` non-null from the lookup above, `fork_trampoline` lives in this frame.
        let rc = unsafe { ksufrida_dobby_hook(fork_addr, replacement, &raw mut fork_trampoline) };
        if rc == 0 {
            ORIG_FORK.store(fork_trampoline, Ordering::Release);
            fork_ok = true;
            logi("[child_gating] fork hook installed");
        } else {
            loge_fmt(format_args!(
                "[child_gating] fork hook installation failed: {rc}"
            ));
        }
    } else {
        loge("[child_gating] fork address null; skipping fork hook");
    }

    // Discarded: the vfork hook resumes through the fork trampoline above.
    if !fork_ok {
        loge("[child_gating] skipping vfork hook without a fork origin");
    } else if let Some(vfork_addr) = vfork_addr {
        let mut vfork_trampoline: *mut c_void = std::ptr::null_mut();
        // SAFETY: non-null from the lookup above; nothing ever reads the value.
        let rc = unsafe { ksufrida_dobby_hook(vfork_addr, replacement, &raw mut vfork_trampoline) };
        if rc == 0 {
            logi("[child_gating] vfork hook installed");
        } else {
            loge_fmt(format_args!(
                "[child_gating] vfork hook installation failed: {rc}"
            ));
        }
    } else {
        loge("[child_gating] vfork address null; skipping vfork hook");
    }

    logi("[child_gating] child gating enabled");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChildMode;
    use std::sync::atomic::AtomicI32;
    use std::sync::{Mutex, MutexGuard};

    static ORIGIN_LOCK: Mutex<()> = Mutex::new(());

    fn lock_origin() -> MutexGuard<'static, ()> {
        ORIGIN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    static ATEXIT_PROBE_FD: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn atexit_probe() {
        let fd = ATEXIT_PROBE_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return;
        }
        let byte = [1u8];
        // SAFETY: test-owned pipe write end; a one-byte write either lands or fails.
        unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    }

    fn pipe_pair() -> (i32, i32) {
        let mut fds = [0; 2];
        // SAFETY: valid two-element output buffer for `pipe(2)`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe(2)");
        (fds[0], fds[1])
    }

    unsafe extern "C" fn stand_in_fork() -> libc::pid_t {
        4242
    }

    fn stand_in_ptr() -> *mut c_void {
        stand_in_fork as *const () as *mut c_void
    }

    #[test]
    fn hook_shim_is_callable() {
        let mut orig: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            // SAFETY: the host stub accepts null arguments.
            unsafe {
                ksufrida_dobby_hook(std::ptr::null_mut(), std::ptr::null_mut(), &raw mut orig)
            },
            0
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)] // raw dlsym(3) has no Miri shim
    fn lookup_resolves_libc_symbols_on_host() {
        // glibc exports both, so the default-namespace branch hits.
        assert!(
            !lookup_hook_target(c"fork")
                .unwrap_or(std::ptr::null_mut())
                .is_null()
        );
        assert!(
            !lookup_hook_target(c"vfork")
                .unwrap_or(std::ptr::null_mut())
                .is_null()
        );
    }

    #[test]
    fn state_is_write_once() {
        let cfg = ChildGatingConfig {
            enabled: true,
            mode: ChildMode::Kill,
            injected_libraries: vec!["/a.so".to_string()],
        };
        let _ = CHILD_GATING_MODE.set(cfg.mode);
        let _ = INJECTED_LIBRARIES.set(cfg.injected_libraries.clone());
        assert_eq!(CHILD_GATING_MODE.get(), Some(&ChildMode::Kill));
        assert_eq!(INJECTED_LIBRARIES.get().map(Vec::len), Some(1));
    }

    #[test]
    fn child_hide_flag_round_trips() {
        GATING_HIDE_MAPS.store(true, Ordering::Relaxed);
        assert!(GATING_HIDE_MAPS.load(Ordering::Relaxed));
        GATING_HIDE_MAPS.store(false, Ordering::Relaxed);
        assert!(!GATING_HIDE_MAPS.load(Ordering::Relaxed));
        GATING_HIDE_MAPS.store(true, Ordering::Relaxed);
    }

    #[test]
    fn child_mode_parse_matches_the_config_names() {
        assert_eq!(ChildMode::parse("kill"), Some(ChildMode::Kill));
        assert_eq!(ChildMode::parse("freeze"), Some(ChildMode::Freeze));
        assert_eq!(ChildMode::parse("inject"), Some(ChildMode::Inject));
        assert_eq!(ChildMode::parse(""), None);
        assert_eq!(ChildMode::parse("kilo"), None);
    }

    #[test]
    fn inject_without_libraries_stages_nothing() {
        assert_eq!(run_child_action(ChildMode::Inject, &[], "com.a.b"), 0);
    }

    #[test]
    fn pass_mode_ignores_the_library_list() {
        assert_eq!(
            run_child_action(ChildMode::Pass, &["/a.so".into()], "com.a.b"),
            0
        );
    }

    #[test]
    fn fork_hook_without_origin_fails_the_fork_instead_of_panicking() {
        let _guard = lock_origin();
        ORIG_FORK.store(std::ptr::null_mut(), Ordering::Release);

        // SAFETY: with no origin published the hook must fail without dereferencing anything.
        let pid = unsafe { fork_replacement() };

        assert_eq!(pid, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN),
            "a failed fork must report a defined errno"
        );
    }

    #[test]
    fn fork_hook_returns_the_result_of_the_real_fork() {
        let _guard = lock_origin();
        ORIG_FORK.store(stand_in_ptr(), Ordering::Release);

        // SAFETY: a valid published origin is installed for the call.
        let pid = unsafe { fork_replacement() };
        ORIG_FORK.store(std::ptr::null_mut(), Ordering::Release);

        assert_eq!(pid, 4242);
    }

    #[test]
    fn origin_publication_is_race_free_under_concurrent_hook_reads() {
        let _guard = lock_origin();
        let published = stand_in_ptr();
        let absent = std::ptr::null_mut();
        let iterations = if cfg!(miri) { 25 } else { 250 };

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..iterations {
                        // SAFETY: both outcomes of the published origin are valid.
                        match unsafe { fork_replacement() } {
                            -1 | 4242 => {}
                            other => panic!("fork_replacement returned {other}"),
                        }
                    }
                });
            }
            for i in 0..iterations {
                ORIG_FORK.store(
                    if i % 2 == 0 { published } else { absent },
                    Ordering::Release,
                );
            }
        });

        ORIG_FORK.store(std::ptr::null_mut(), Ordering::Release);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn kill_child_exits_zero_without_running_atexit_handlers() {
        let _guard = lock_origin();
        let _ = CHILD_GATING_MODE.set(ChildMode::Kill);

        static REGISTER: std::sync::Once = std::sync::Once::new();
        let (read_fd, write_fd) = pipe_pair();
        REGISTER.call_once(|| {
            // SAFETY: `extern "C" fn()` with process lifetime, registered exactly once.
            let _ = unsafe { libc::atexit(atexit_probe) };
        });
        ATEXIT_PROBE_FD.store(write_fd, Ordering::Relaxed);

        let fork_origin: ForkFn = libc::fork;
        ORIG_FORK.store(fork_origin as *const () as *mut c_void, Ordering::Release);

        // SAFETY: a valid origin is published for the call.
        let child = unsafe { fork_replacement() };
        assert!(child > 0, "the parent branch must return the child pid");

        let mut status = 0;
        // SAFETY: `child` is a live child of this process and `status` is a valid output slot.
        assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);

        ATEXIT_PROBE_FD.store(-1, Ordering::Relaxed);
        ORIG_FORK.store(std::ptr::null_mut(), Ordering::Release);
        // SAFETY: both ends are test-owned; closing the write end first makes an empty pipe report 0.
        unsafe {
            libc::close(write_fd);
            let mut byte = [0u8; 1];
            let n = libc::read(read_fd, byte.as_mut_ptr().cast(), 1);
            libc::close(read_fd);
            assert_eq!(n, 0, "the child ran atexit handlers: exit(3) was used");
        }

        assert!(
            libc::WIFEXITED(status),
            "the kill child must exit normally, not die to a signal"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn freeze_child_stays_alive_until_killed() {
        // SAFETY: plain fork; only the calling thread exists in the child.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork(2)");
        if child == 0 {
            run_child_action(ChildMode::Freeze, &[], "");
            // SAFETY: child-only path; never returns in a correct build.
            unsafe { libc::_exit(99) };
        }

        thread::sleep(Duration::from_millis(200));
        let mut status = 0;
        // SAFETY: `WNOHANG` reaps only if the child already exited.
        let seen = unsafe { libc::waitpid(child, &raw mut status, libc::WNOHANG) };
        if seen == 0 {
            // SAFETY: the child is ours and still running.
            unsafe { libc::kill(child, libc::SIGKILL) };
            // SAFETY: blocking reap of our own child.
            unsafe { libc::waitpid(child, &raw mut status, 0) };
        }

        assert_eq!(seen, 0, "the freeze child exited early");
        assert!(
            libc::WIFSIGNALED(status),
            "the freeze child must still have been alive to kill"
        );
    }
}
