use std::ffi::{CStr, CString, NulError, c_char, c_int, c_void};
use std::io;

pub const RTLD_NOW: c_int = 2;
pub const RTLD_NOLOAD: c_int = 0x04;

pub const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();

unsafe extern "C" {
    pub fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub fn dlerror() -> *mut c_char;
}

#[cfg(target_os = "android")]
pub const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
#[cfg(target_os = "android")]
pub const ANDROID_DLEXT_FORCE_LOAD: u64 = 0x40;

#[cfg(target_os = "android")]
#[repr(C)]
pub struct AndroidDlextInfo {
    pub flags: u64,
    pub reserved_addr: *mut c_void,
    pub reserved_size: usize,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: i64,
    pub library_namespace: *mut c_void,
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    pub fn android_dlopen_ext(
        filename: *const c_char,
        flags: c_int,
        info: *const AndroidDlextInfo,
    ) -> *mut c_void;
}

#[cfg(any(target_os = "android", test))]
pub fn memfd_create(name: *const c_char, flags: c_int) -> c_int {
    // SAFETY: plain syscall with a valid name; the fd (or -1) is checked by the caller.
    unsafe { libc::syscall(libc::SYS_memfd_create, name, flags) as c_int }
}

#[cfg(any(target_os = "android", test))]
pub const MFD_CLOEXEC: c_int = 0x0001;
#[cfg(any(target_os = "android", test))]
pub const MFD_ALLOW_SEALING: c_int = 0x0002;
// Kernel 6.3+: explicit MFD_EXEC defeats vm.memfd_noexec=1 (forced NX);
// at =2 explicit EXEC fails with EACCES and falls safe to file staging.
#[cfg(any(target_os = "android", test))]
pub const MFD_EXEC: c_int = 0x0010;

/// memfd staging name. Distinct from ART `dalvik-jit-code-cache` so
/// `contains` matching never hits the legit mapping.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub const MEMFD_NAME: &str = "dalvik-jit-cache";

#[cfg(any(target_os = "android", test))]
pub const MEMFD_CSTR: &CStr = c"dalvik-jit-cache";

// pidfd_open(2): race-free liveness check. Bionic exposes it since API 31;
// GKI 6.6 always has syscall 434. No safe libc wrapper on all targets,
// so raw syscall with immediate error capture.
#[cfg(any(target_os = "android", target_os = "linux", test))]
pub fn pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> c_int {
    // SAFETY: plain syscall with a pid + flags; fd (or -1) checked by caller.
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) as c_int }
}

// Seals for memfd staging: fixed size + no further seals change.
// Deliberately omits SEAL_WRITE/SEAL_EXEC so dlopen with exec segments keeps working.
#[cfg(any(target_os = "android", test))]
pub fn seal_memfd_fixed(fd: c_int) -> Result<(), io::Error> {
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    // SAFETY: fcntl on our own open fd; return/errno read immediately.
    let rc = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
pub const PR_SET_VMA: c_int = 0x5356_4D41;
#[cfg(any(target_os = "android", target_os = "linux", test))]
pub const PR_SET_VMA_ANON_NAME: c_int = 0;

// openat2 resolve flags from linux/openat2.h (NDK 29). Only NO_SYMLINKS +
// NO_MAGICLINKS are used for staging: BENEATH/IN_ROOT break absolute paths.
#[cfg(any(target_os = "android", target_os = "linux", test))]
#[allow(dead_code)] // Kept for explicitness; NO_SYMLINKS already implies it.
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(any(target_os = "android", target_os = "linux", test))]
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[repr(C)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

/// Best-effort openat2. Returns fd or -1 with errno (ENOSYS/EINVAL → fallback).
///
/// # Safety
/// `path` must be a valid NUL-terminated string; `how` must be a valid pointer.
#[cfg(any(target_os = "android", target_os = "linux", test))]
pub unsafe fn openat2(dirfd: c_int, path: *const c_char, how: *const OpenHow) -> c_int {
    // SAFETY: plain syscall; fd (or -1) checked by caller.
    unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd as libc::c_long,
            path,
            how,
            size_of::<OpenHow>(),
        ) as c_int
    }
}

/// Rename an anonymous VMA shown in /proc/self/maps. Best-effort: EINVAL/ENOSYS
/// means the kernel does not support it; caller decides whether to log.
///
/// # Safety
/// `addr..addr+len` must be a live anonymous mapping; `name` must be a valid
/// NUL-terminated string.
#[cfg(any(target_os = "android", target_os = "linux", test))]
pub unsafe fn set_vma_anon_name(
    addr: *mut c_void,
    len: usize,
    name: *const c_char,
) -> Result<(), io::Error> {
    // SAFETY: plain prctl with fully specified args; no pointers dereferenced
    // by the wrapper itself beyond passing them through.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            PR_SET_VMA as libc::c_long,
            PR_SET_VMA_ANON_NAME as libc::c_long,
            addr,
            len,
            name,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub const MREMAP_MAYMOVE: c_int = 1;
pub const MREMAP_FIXED: c_int = 2;

unsafe extern "C" {
    pub fn mremap(
        old_address: *mut c_void,
        old_size: usize,
        new_size: usize,
        flags: c_int,
        ...
    ) -> *mut c_void;
}

#[repr(C)]
pub struct DlPhdrInfo {
    pub addr: usize,
    pub name: *const c_char,
    pub phdr: *const c_void,
    pub phnum: u16,
}

pub type DlIterateCb = unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int;

unsafe extern "C" {
    pub fn dl_iterate_phdr(cb: DlIterateCb, data: *mut c_void) -> c_int;
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

#[cfg(target_os = "android")]
pub fn android_log(prio: c_int, msg: &str) {
    // SAFETY: static tag/format literals; `msg` is copied into a `CString` so no interior NUL reaches the varargs.
    unsafe {
        let c_msg = CString::new(msg).unwrap_or_default();
        __android_log_print(prio, c"KsuFrida".as_ptr(), c"%s".as_ptr(), c_msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

#[cfg(not(target_os = "android"))]
pub fn set_errno(value: c_int) {
    // SAFETY: returns a valid writable pointer to the calling thread's errno slot.
    unsafe {
        *__errno_location() = value;
    }
}

#[cfg(target_os = "android")]
pub fn set_errno(value: c_int) {
    // SAFETY: returns a valid writable pointer to the calling thread's errno slot.
    unsafe {
        *libc::__errno() = value;
    }
}

/// # Safety
/// `fd_in`/`fd_out` must be open files; `len` bounds the transfer.
// Raw syscall: libc copy_file_range needs API 34, floor is 31.
pub fn copy_file_range(fd_in: c_int, fd_out: c_int, len: usize) -> Result<u64, io::Error> {
    // SAFETY: two live fds with NULL offsets (file-offset form); return/errno is read immediately.
    let n = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            fd_in,
            std::ptr::null::<libc::c_void>(),
            fd_out,
            std::ptr::null::<libc::c_void>(),
            len,
            0 as libc::c_uint,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as u64)
    }
}

pub fn dlerror_string() -> String {
    // SAFETY: `dlerror()` returns null or a libc-owned NUL-terminated string, copied before any later dl call.
    unsafe {
        let err = dlerror();
        if err.is_null() {
            return "(null)".to_string();
        }
        CStr::from_ptr(err).to_string_lossy().into_owned()
    }
}

pub fn cstring(s: &str) -> Result<CString, NulError> {
    CString::new(s)
}

/// Address of a symbol, explicit `libc.so` first then default scope.
/// The handle is never closed; it pins nothing new.
pub fn lookup_symbol(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: `RTLD_NOLOAD` takes no new reference beyond the loaded lib; result checked.
    let handle = unsafe { dlopen(c"libc.so".as_ptr(), RTLD_NOW | RTLD_NOLOAD) };
    if !handle.is_null() {
        // SAFETY: `handle` live from above; `name` NUL-terminated.
        let addr = unsafe { dlsym(handle, name.as_ptr()) };
        if !addr.is_null() {
            return Some(addr);
        }
    }
    // SAFETY: `RTLD_DEFAULT` is the documented sentinel; null only skips the hook.
    let addr = unsafe { dlsym(RTLD_DEFAULT, name.as_ptr()) };
    if addr.is_null() { None } else { Some(addr) }
}

// Spins for a hook trampoline published between patching and our store; a
// hook call landing in that gap waits instead of failing the operation.
// Bounded: a failed install never publishes, so waiting forever is wrong.
// The gap is straight-line code after the hook call returns; a hundred
// thousand spins covers it by orders of magnitude while keeping both the
// failure path and contended readers in the microsecond range.
const HOOK_PUBLISH_SPIN: u32 = 100_000;

pub fn wait_for_hook_origin(origin: &std::sync::atomic::AtomicPtr<c_void>) -> *mut c_void {
    use std::sync::atomic::Ordering::{Acquire, Relaxed};
    let mut ptr = origin.load(Relaxed);
    for i in 0..HOOK_PUBLISH_SPIN {
        if !ptr.is_null() {
            break;
        }
        // Yield periodically: a pure spin would starve the descheduled
        // installer this wait is for. Not signal context, so this is safe.
        if i & 1023 == 0 {
            // SAFETY: plain syscall; no locks held, no invariants.
            unsafe { libc::sched_yield() };
        }
        std::hint::spin_loop();
        ptr = origin.load(Relaxed);
    }
    // Single Acquire so observing the pointer synchronizes with the
    // Release publish (the loop above intentionally stays Relaxed).
    origin.load(Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicPtr;

    #[test]
    fn hook_origin_wait_times_out_to_null() {
        static ORIGIN: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        assert!(wait_for_hook_origin(&ORIGIN).is_null());
    }

    #[test]
    fn hook_origin_wait_picks_up_late_publication() {
        static ORIGIN: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let published = 0x1234 as *mut c_void;
        // Scheduling may delay the setter past one bound; retry keeps the
        // test deterministic (bounded rounds, never hangs).
        for _ in 0..20 {
            ORIGIN.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Relaxed);
            let found = std::thread::scope(|scope| {
                scope.spawn(|| {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    ORIGIN.store(0x1234 as *mut c_void, std::sync::atomic::Ordering::Release);
                });
                wait_for_hook_origin(&ORIGIN) == published
            });
            if found {
                ORIGIN.store(std::ptr::null_mut(), std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }
        // Unreachable unless the scheduler starves the setter twenty times.
        panic!("late publication never observed");
    }

    #[test]
    fn cstring_accepts_ordinary_paths() {
        assert_eq!(
            cstring("/data/local/tmp/libsec/a.so").unwrap(),
            c"/data/local/tmp/libsec/a.so".to_owned()
        );
    }

    #[test]
    fn cstring_rejects_an_interior_nul() {
        assert!(cstring("a\0b").is_err());
        assert!(cstring("\0").is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // raw pidfd_open(2) has no Miri shim
    fn pidfd_opens_self() {
        // SAFETY: getpid cannot fail.
        let pid = unsafe { libc::getpid() };
        let fd = pidfd_open(pid, 0);
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            assert!(
                err.raw_os_error() == Some(libc::ENOSYS)
                    || err.raw_os_error() == Some(libc::EINVAL),
                "unexpected pidfd error: {err}"
            );
            return;
        }
        // SAFETY: fd is ours from above.
        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg_attr(miri, ignore)] // fork(2) is not interpretable
    fn pidfd_rejects_dead_pid() {
        // SAFETY: fork child exits immediately; parent reaps it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: child-only path, never returns.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        // SAFETY: `pid` is our child; blocking reap of exactly it.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        let fd = pidfd_open(pid, 0);
        if fd >= 0 {
            // SAFETY: fd is ours from above.
            unsafe { libc::close(fd) };
            // PID recycled between wait and open; alive is valid.
        } else {
            let err = std::io::Error::last_os_error();
            assert!(
                err.raw_os_error() == Some(libc::ESRCH)
                    || err.raw_os_error() == Some(libc::ENOSYS)
                    || err.raw_os_error() == Some(libc::EINVAL)
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // raw memfd_create(2) has no Miri shim
    fn memfd_seals_fix_size() {
        let name = cstring("jit-cache").unwrap();
        // SAFETY: static name; fd checked below.
        let fd = memfd_create(name.as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert!(fd >= 0);
        let res = seal_memfd_fixed(fd);
        // SAFETY: fd is ours from above.
        unsafe { libc::close(fd) };
        if let Err(e) = res {
            assert!(
                e.raw_os_error() == Some(libc::ENOSYS) || e.raw_os_error() == Some(libc::EINVAL),
                "unexpected seal error: {e}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2)/prctl(2) have no Miri shims
    fn vma_rename_is_best_effort() {
        const SIZE: usize = 4096;
        // SAFETY: fresh anon mapping owned by this test.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        // SAFETY: addr/size is our live anon mapping; name is a static literal.
        let r = unsafe { set_vma_anon_name(addr, SIZE, c"dalvik-jit".as_ptr()) };
        // SAFETY: cleanup our mapping.
        unsafe { libc::munmap(addr, SIZE) };
        if let Err(e) = r {
            assert!(
                e.raw_os_error() == Some(libc::EINVAL) || e.raw_os_error() == Some(libc::ENOSYS),
                "unexpected vma error: {e}"
            );
        }
    }
}
