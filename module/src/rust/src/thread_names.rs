use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::log::{loge, loge_fmt, logi};
use crate::sys::{RTLD_DEFAULT, RTLD_NOLOAD, RTLD_NOW, dlerror_string, dlopen, dlsym};

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

type SetnameFn = unsafe extern "C" fn(libc::pthread_t, *const c_char) -> c_int;

// Null until the Release store in `enable_thread_name_sanitizing`.
static ORIG_SETNAME: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Bland stand-in, well inside the 15-char task name limit.
const REPLACEMENT: &CStr = c"WorkerThread";

/// Keyword family detectors match on. Opaque shorts (`frbkd`) are not
/// keyword-matchable and stay out of scope by design.
pub(crate) fn is_blocked_thread_name(name: &[u8]) -> bool {
    // No allocation: the hook below runs on arbitrary threads.
    const NEEDLES: [&[u8]; 3] = [b"frida", b"gadget", b"gum"];
    NEEDLES.iter().any(|needle| {
        name.windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    })
}

unsafe extern "C" fn setname_replacement(thread: libc::pthread_t, name: *const c_char) -> c_int {
    // Fail the rename rather than unwind into bionic/Dobby.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| setname_inner(thread, name))) {
        Ok(rc) => rc,
        Err(_) => libc::EINVAL,
    }
}

fn setname_inner(thread: libc::pthread_t, name: *const c_char) -> c_int {
    let orig_ptr = ORIG_SETNAME.load(Ordering::Acquire);
    if orig_ptr.is_null() {
        // No origin yet: skip the rename (the thread keeps a neutral
        // default) instead of proceeding unwatched. Silent by design:
        // this fires on arbitrary threads, so minimal work wins.
        return libc::EINVAL;
    }
    // SAFETY: non-null trampoline published by `enable_thread_name_sanitizing`.
    let orig: SetnameFn = unsafe { std::mem::transmute(orig_ptr) };
    if name.is_null() {
        // SAFETY: as above; NULL passes through for libc to reject.
        return unsafe { orig(thread, name) };
    }
    // SAFETY: same read libc would perform on this pointer; read-only.
    let current = unsafe { CStr::from_ptr(name) }.to_bytes();
    let renamed = if is_blocked_thread_name(current) {
        REPLACEMENT.as_ptr()
    } else {
        name
    };
    // SAFETY: `renamed` is either the caller's live string or the static above.
    unsafe { orig(thread, renamed) }
}

/// First live thread name matching the blocked list, if any.
pub(crate) fn first_blocked_thread_name() -> Option<String> {
    first_blocked_in(std::path::Path::new("/proc/self/task"))
}

fn first_blocked_in(tasks: &std::path::Path) -> Option<String> {
    let Ok(entries) = std::fs::read_dir(tasks) else {
        return None;
    };
    for entry in entries.map_while(Result::ok) {
        let Ok(content) = std::fs::read(entry.path().join("comm")) else {
            continue;
        };
        let name = content.strip_suffix(b"\n".as_slice()).unwrap_or(&content);
        if is_blocked_thread_name(name) {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
    }
    None
}

pub fn enable_thread_name_sanitizing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let Some(addr) = lookup_setname() else {
            loge("setname hook: symbol address null; thread names stay as-is");
            return;
        };

        let replacement = setname_replacement as *const () as *mut c_void;
        // Stack local: filled synchronously below, published once after.
        let mut trampoline: *mut c_void = std::ptr::null_mut();
        // SAFETY: `addr` non-null from the lookup above, `trampoline` lives in this frame.
        let rc = unsafe { ksufrida_dobby_hook(addr, replacement, &raw mut trampoline) };
        if rc == 0 && !trampoline.is_null() {
            ORIG_SETNAME.store(trampoline, Ordering::Release);
            logi("setname hook installed");
        } else {
            loge_fmt(format_args!("setname hook installation failed: {rc}"));
        }
    });
}

/// Address of `pthread_setname_np` for the Dobby hook below, if resolvable.
fn lookup_setname() -> Option<*mut c_void> {
    const NAME: &CStr = c"pthread_setname_np";
    // Explicit handle first: the default scope provably misses from this
    // module, so the known scope leads. The handle is intentionally never
    // closed; it pins nothing new.
    // SAFETY: `RTLD_NOLOAD` takes no new reference beyond the
    // already-loaded library, and every result below is checked for null.
    let handle = unsafe { dlopen(c"libc.so".as_ptr(), RTLD_NOW | RTLD_NOLOAD) };
    if !handle.is_null() {
        // SAFETY: `handle` is live from above; `NAME` is NUL-terminated.
        let addr = unsafe { dlsym(handle, NAME.as_ptr()) };
        if !addr.is_null() {
            return Some(addr);
        }
        loge_fmt(format_args!(
            "setname hook: libc-scoped lookup failed: {}",
            dlerror_string()
        ));
    } else {
        loge_fmt(format_args!(
            "setname hook: libc handle lookup failed: {}",
            dlerror_string()
        ));
    }
    // Fallback: default scope covers non-libc targets and loaders where
    // the explicit handle does not resolve.
    // SAFETY: `RTLD_DEFAULT` is the documented sentinel handle; a null
    // return only skips the hook below.
    let addr = unsafe { dlsym(RTLD_DEFAULT, NAME.as_ptr()) };
    if addr.is_null() {
        loge_fmt(format_args!(
            "setname hook: default-namespace lookup failed: {}",
            dlerror_string()
        ));
        return None;
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static SETNAME_LOCK: Mutex<()> = Mutex::new(());

    fn lock_setname() -> MutexGuard<'static, ()> {
        SETNAME_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    static RECORDED: Mutex<Option<String>> = Mutex::new(None);

    unsafe extern "C" fn fake_setname(_thread: libc::pthread_t, name: *const c_char) -> c_int {
        let owned = if name.is_null() {
            String::new()
        } else {
            // SAFETY: test passes live literals or null, nothing else.
            unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned()
        };
        *RECORDED.lock().unwrap_or_else(|e| e.into_inner()) = Some(owned);
        0
    }

    fn recorded() -> Option<String> {
        RECORDED.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn fake_ptr() -> *mut c_void {
        fake_setname as *const () as *mut c_void
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
    fn blocked_names_catch_keyword_variants() {
        for bad in [
            &b"pool-frida"[..],
            &b"gdyhkfgadget"[..],
            &b"FRIDA"[..],
            &b"Gadget"[..],
            &b"gum_js"[..],
        ] {
            assert!(
                is_blocked_thread_name(bad),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        for ok in [
            &b"AppInitThread"[..],
            &b"HeapTaskDaemon"[..],
            &b"pool-14-thread-"[..],
            &b""[..],
        ] {
            assert!(!is_blocked_thread_name(ok));
        }
    }

    #[test]
    fn replacement_rewrites_blocked_names() {
        let _guard = lock_setname();
        ORIG_SETNAME.store(fake_ptr(), Ordering::Release);

        // SAFETY: live literals; a published fake origin is installed.
        unsafe {
            assert_eq!(setname_replacement(0, c"pool-frida".as_ptr()), 0);
            assert_eq!(recorded().as_deref(), Some("WorkerThread"));
            assert_eq!(setname_replacement(0, c"HeapTaskDaemon".as_ptr()), 0);
            assert_eq!(recorded().as_deref(), Some("HeapTaskDaemon"));
            assert_eq!(setname_replacement(0, std::ptr::null()), 0);
            assert_eq!(recorded().as_deref(), Some(""));
        }

        ORIG_SETNAME.store(std::ptr::null_mut(), Ordering::Release);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // raw dlsym(3) has no Miri shim
    fn lookup_resolves_on_host_libc() {
        // glibc exports the symbol, so the default-namespace branch hits.
        assert!(!lookup_setname().unwrap_or(std::ptr::null_mut()).is_null());
    }

    #[test]
    fn replacement_without_origin_fails_the_rename() {
        let _guard = lock_setname();
        ORIG_SETNAME.store(std::ptr::null_mut(), Ordering::Release);
        *RECORDED.lock().unwrap_or_else(|e| e.into_inner()) = None;

        // SAFETY: with no origin published the hook must fail without touching anything.
        unsafe {
            assert_eq!(setname_replacement(0, c"pool-frida".as_ptr()), libc::EINVAL);
        }
        assert_eq!(recorded(), None);
    }

    #[test]
    fn comm_scan_reports_blocked_names_in_a_task_dir() {
        use crate::test_support::TempDir;

        let dir = TempDir::new("taskdir");
        std::fs::create_dir_all(dir.path().join("123")).unwrap();
        std::fs::write(dir.path().join("123/comm"), b"pool-frida\n").unwrap();
        std::fs::create_dir_all(dir.path().join("124")).unwrap();
        std::fs::write(dir.path().join("124/comm"), b"main\n").unwrap();
        std::fs::create_dir_all(dir.path().join("125")).unwrap();
        assert_eq!(first_blocked_in(dir.path()).as_deref(), Some("pool-frida"));

        let clean = TempDir::new("taskdir-clean");
        std::fs::create_dir_all(clean.path().join("1")).unwrap();
        std::fs::write(clean.path().join("1/comm"), b"HeapTaskDaemon\n").unwrap();
        assert_eq!(first_blocked_in(clean.path()).as_deref(), None);
        assert_eq!(
            first_blocked_in(&clean.path().join("nope")).as_deref(),
            None
        );
    }
}
