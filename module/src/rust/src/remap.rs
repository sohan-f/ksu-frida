use std::ffi::c_void;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use libc::{self, c_int};

use crate::log::{basename, loge_fmt, logi, logi_fmt};

const GUARDED_SIGNALS: [c_int; 2] = [libc::SIGSEGV, libc::SIGBUS];

static PREVIOUS_HANDLER: [AtomicPtr<c_void>; 2] = [
    AtomicPtr::new(std::ptr::null_mut()),
    AtomicPtr::new(std::ptr::null_mut()),
];
static PREVIOUS_FLAGS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

static IN_FLIGHT_START: AtomicUsize = AtomicUsize::new(0);
// END is stored while START is zero, so non-zero START implies a stable END.
static IN_FLIGHT_END: AtomicUsize = AtomicUsize::new(0);

// The rebuilding thread must never park on its own fault.
static REBUILDER_TID: AtomicUsize = AtomicUsize::new(0);

static REBUILD_LOCK: AtomicBool = AtomicBool::new(false);

const PARK_SPIN_LIMIT: usize = 100_000_000;

struct ProcMapsInfo {
    start: usize,
    end: usize,
    perms: c_int,
    private: bool,
    path: String,
}

fn next_field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

fn is_private_mapping(perms: &str) -> bool {
    // 4th char is p/s: shared mappings must keep sharing, never convert to private anon.
    perms.as_bytes().get(3) != Some(&b's')
}

fn get_modules_by_name(m_name: &str) -> Vec<ProcMapsInfo> {
    let mut maps = Vec::new();

    let Ok(file) = File::open("/proc/self/maps") else {
        return maps;
    };

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if !line.contains(m_name) {
            continue;
        }

        let Some((range, rest)) = next_field(&line) else {
            continue;
        };
        let Some((perms, rest)) = next_field(rest) else {
            continue;
        };
        let Some((_offset, rest)) = next_field(rest) else {
            continue;
        };
        let Some((_dev, rest)) = next_field(rest) else {
            continue;
        };
        let Some((_inode, rest)) = next_field(rest) else {
            continue;
        };

        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start_hex, 16),
            usize::from_str_radix(end_hex, 16),
        ) else {
            continue;
        };

        let mut prot = 0;
        if perms.contains('r') {
            prot |= libc::PROT_READ;
        }
        if perms.contains('w') {
            prot |= libc::PROT_WRITE;
        }
        if perms.contains('x') {
            prot |= libc::PROT_EXEC;
        }
        // 4th char is p/s: shared mappings must keep sharing, never convert to private anon.
        let private = is_private_mapping(perms);

        maps.push(ProcMapsInfo {
            start,
            end,
            perms: prot,
            private,
            path: rest.trim().to_string(),
        });
    }

    maps
}

/// # Safety
/// Installed only by [`install_fault_retry`]; `info` comes from the kernel.
unsafe extern "C" fn park_or_forward(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let start = IN_FLIGHT_START.load(Ordering::Acquire);
    // SAFETY: `gettid(2)` takes no arguments, cannot fail and allocates nothing — safe inside a signal handler.
    let tid = unsafe { libc::gettid() };
    if start != 0 && tid != REBUILDER_TID.load(Ordering::Relaxed) as c_int {
        let end = IN_FLIGHT_END.load(Ordering::Relaxed);
        // SAFETY: the kernel hands SA_SIGINFO handlers a non-null `siginfo_t`; `si_addr` is defined for SIGSEGV/SIGBUS.
        let fault = unsafe { (*info).si_addr() } as usize;
        if (start..end).contains(&fault) {
            for _ in 0..PARK_SPIN_LIMIT {
                if IN_FLIGHT_START.load(Ordering::Acquire) == 0 {
                    return;
                }
                std::hint::spin_loop();
            }
        }
    }

    // SAFETY: `forward_fault` only chains to actions captured by `install_fault_retry` earlier in this rebuild.
    unsafe { forward_fault(sig, info, context) };
}

/// # Safety
/// Called only from [`park_or_forward`].
unsafe fn forward_fault(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let Some(index) = GUARDED_SIGNALS.iter().position(|&guarded| guarded == sig) else {
        return;
    };

    let handler = PREVIOUS_HANDLER[index].load(Ordering::Relaxed);
    if handler.addr() == libc::SIG_DFL || handler.addr() == libc::SIG_IGN {
        // SAFETY: plain `signal(2)`/`raise(2)` on the faulting thread; the pending signal is delivered before we return to it.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    }

    let flags = PREVIOUS_FLAGS[index].load(Ordering::Relaxed) as c_int;
    // SAFETY: `PREVIOUS_HANDLER`/`PREVIOUS_FLAGS` were read from a real `sigaction`, so the transmuted signature matches the flag branched on below.
    unsafe {
        if flags & libc::SA_SIGINFO != 0 {
            let handler: unsafe extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) =
                std::mem::transmute(handler);
            handler(sig, info, context);
        } else {
            let handler: unsafe extern "C" fn(c_int) = std::mem::transmute(handler);
            handler(sig);
        }
    }
}

struct RebuildGuard;

impl RebuildGuard {
    fn acquire() -> RebuildGuard {
        while REBUILD_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        RebuildGuard
    }
}

impl Drop for RebuildGuard {
    fn drop(&mut self) {
        REBUILD_LOCK.store(false, Ordering::Release);
    }
}

struct FaultRetry {
    previous: [libc::sigaction; 2],
    installed: [bool; 2],
    _rebuild: RebuildGuard,
}

fn install_fault_retry() -> FaultRetry {
    let mut retry = FaultRetry {
        // SAFETY: `libc::sigaction` is a plain FFI struct — all-zeroed is a valid starting state.
        previous: std::array::from_fn(|_| unsafe { std::mem::zeroed() }),
        installed: [false; 2],
        _rebuild: RebuildGuard::acquire(),
    };
    // SAFETY: `gettid(2)` cannot fail.
    REBUILDER_TID.store(unsafe { libc::gettid() } as usize, Ordering::Relaxed);

    for (index, &sig) in GUARDED_SIGNALS.iter().enumerate() {
        // SAFETY: output buffer for the query below; zeroed is valid padding-initialised state.
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: query-only call (`act == NULL`); fills the buffer above.
        if unsafe { libc::sigaction(sig, std::ptr::null(), &raw mut current) } != 0 {
            loge_fmt(format_args!(
                "fault retry: cannot read handler for signal {sig}: {}",
                io::Error::last_os_error()
            ));
            continue;
        }

        if current.sa_sigaction as usize == park_or_forward as *const () as usize {
            retry.previous[index] = current;
            continue;
        }

        PREVIOUS_HANDLER[index].store(
            std::ptr::with_exposed_provenance_mut(current.sa_sigaction),
            Ordering::Relaxed,
        );
        PREVIOUS_FLAGS[index].store(current.sa_flags as usize, Ordering::Relaxed);
        retry.previous[index] = current;

        // SAFETY: zeroed `sigaction` is the documented way to build a fresh action; every field used is set before install.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = park_or_forward as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        // SAFETY: installs the fully initialised `action` above; the kernel copies it synchronously.
        if unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) } != 0 {
            loge_fmt(format_args!(
                "fault retry: cannot install handler for signal {sig}: {}",
                io::Error::last_os_error()
            ));
            continue;
        }
        retry.installed[index] = true;
    }

    retry
}

impl Drop for FaultRetry {
    fn drop(&mut self) {
        for (index, &sig) in GUARDED_SIGNALS.iter().enumerate() {
            if !self.installed[index] {
                continue;
            }

            // SAFETY: output buffer for the restore-time query below.
            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: query-only call (`act == NULL`).
            if unsafe { libc::sigaction(sig, std::ptr::null(), &raw mut current) } != 0 {
                continue;
            }
            if current.sa_sigaction as usize != park_or_forward as *const () as usize {
                continue;
            }

            // SAFETY: only reached when the current handler is still ours; `previous` was saved at install time for this process.
            unsafe { libc::sigaction(sig, &raw const self.previous[index], std::ptr::null_mut()) };
        }
        REBUILDER_TID.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn after_fork() {
    IN_FLIGHT_START.store(0, Ordering::Release);
    IN_FLIGHT_END.store(0, Ordering::Relaxed);
    REBUILDER_TID.store(0, Ordering::Relaxed);
    REBUILD_LOCK.store(false, Ordering::Release);
}

fn begin_rebuild(start: usize, size: usize) {
    IN_FLIGHT_END.store(start + size, Ordering::Relaxed);
    IN_FLIGHT_START.store(start, Ordering::Release);
}

fn end_rebuild() {
    IN_FLIGHT_START.store(0, Ordering::Release);
}

#[derive(Debug)]
enum RelocateError {
    Allocate(io::Error),
    Protect(io::Error),
    Commit(io::Error),
    Restore(io::Error),
}

/// # Safety
/// `address` must be page aligned and backed by a mapping of exactly `size`
/// bytes. The caller must hold the rebuild lock, and must not itself be running
/// from inside the segment: the rebuild thread cannot park on its own faults.
unsafe fn relocate_segment(
    address: *mut c_void,
    size: usize,
    perms: c_int,
    path: &str,
) -> Result<(), RelocateError> {
    // SAFETY: anonymous private mapping of `size`, which comes from `/proc/self/maps` and is page-aligned.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(RelocateError::Allocate(io::Error::last_os_error()));
    }

    if perms & libc::PROT_READ == 0 {
        logi_fmt(format_args!("Removing memory protection: {path}"));
    }

    // Publish before touching protections: writers faulted below must park.
    begin_rebuild(address as usize, size);

    // Freeze writers during the copy: drop WRITE so concurrent writes fault
    // into park_or_forward instead of being lost. Restored after commit.
    let need_freeze = perms & libc::PROT_WRITE != 0;
    let copy_prot = if need_freeze {
        perms & !libc::PROT_WRITE
    } else if perms & libc::PROT_READ == 0 {
        libc::PROT_READ
    } else {
        perms
    };
    if copy_prot != perms {
        // SAFETY: `address`/`size` describe a live mapping from `/proc/self/maps`; the result is checked immediately.
        if unsafe { libc::mprotect(address, size, copy_prot) } != 0 {
            let err = io::Error::last_os_error();
            end_rebuild();
            // SAFETY: `map`/`size` are ours from the `mmap` above; best-effort cleanup, result deliberately ignored.
            unsafe { libc::munmap(map, size) };
            return Err(RelocateError::Protect(err));
        }
    }

    // SAFETY: source is the live segment, destination is the scratch mapping — both `size` bytes and non-overlapping.
    unsafe {
        std::ptr::copy(address as *const u8, map as *mut u8, size);

        let moved = crate::sys::mremap(
            map,
            size,
            size,
            crate::sys::MREMAP_MAYMOVE | crate::sys::MREMAP_FIXED,
            address,
        );
        if moved == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            end_rebuild();
            libc::munmap(map, size);
            return Err(RelocateError::Commit(err));
        }

        if libc::mprotect(address, size, perms) != 0 {
            let err = io::Error::last_os_error();
            end_rebuild();
            return Err(RelocateError::Restore(err));
        }

        // Grace with the range still published: late-delivered faults must still observe it.
        std::thread::sleep(std::time::Duration::from_millis(5));

        end_rebuild();
    }

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn tag_anon(address: *mut c_void, size: usize) {
    // SAFETY: `address`/`size` is the live anon mapping just rebuilt; name is a static literal.
    let r = unsafe { crate::sys::set_vma_anon_name(address, size, c"[anon:dalvik-jit]".as_ptr()) };
    if let Err(e) = r {
        match e.raw_os_error() {
            Some(code) if code == libc::EINVAL || code == libc::ENOSYS => {}
            _ => loge_fmt(format_args!("remap: anon rename failed: {e}")),
        }
    }
}

pub fn remap_lib(lib_path: &str) {
    remap_matches(basename(lib_path));
}

/// Remap memfd segments (`/memfd:dalvik-jit-cache`). The linker does not keep the
/// source path for fd loads, so basename matching misses them.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn remap_memfd() {
    #[cfg(any(target_os = "android", test))]
    remap_matches(crate::sys::MEMFD_NAME);
    #[cfg(not(any(target_os = "android", test)))]
    remap_matches("dalvik-jit-cache");
}

fn remap_matches(query: &str) {
    let maps = get_modules_by_name(query);
    if maps.is_empty() {
        return;
    }

    logi_fmt(format_args!("Remapping {query}"));

    let _retry = install_fault_retry();

    let mut seen_start = std::collections::HashSet::new();
    for info in &maps {
        if !info.private {
            logi_fmt(format_args!("Skipping shared mapping {}", info.path));
            continue;
        }
        if !seen_start.insert(info.start) {
            continue;
        }
        let address = info.start as *mut c_void;
        let size = info.end - info.start;

        // SAFETY: `address`/`size`/`perms` come from the maps scan for this exact path and we hold the rebuild lock via `install_fault_retry`; the full contract is on `relocate_segment`.
        match unsafe { relocate_segment(address, size, info.perms, &info.path) } {
            Ok(_) => {
                logi_fmt(format_args!("Remapped {address:p} size {size}"));
                #[cfg(any(target_os = "android", target_os = "linux"))]
                tag_anon(address, size);
            }
            Err(RelocateError::Allocate(e)) => {
                loge_fmt(format_args!("Failed to Allocate Memory: {e}"));
                return;
            }
            Err(RelocateError::Protect(e)) => {
                loge_fmt(format_args!("remap: cannot read {}: {e}", info.path));
            }
            Err(RelocateError::Commit(e)) => {
                loge_fmt(format_args!("mremap failed: {e}"));
            }
            Err(RelocateError::Restore(e)) => {
                loge_fmt(format_args!(
                    "remap: cannot restore protections on {}: {e}",
                    info.path
                ));
            }
        }
    }

    logi("Remapped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_fields() {
        let (field, rest) = next_field("  7ac49c2000-7ac4a26000 r--p 0 00:00 0 /a b").unwrap();
        assert_eq!(field, "7ac49c2000-7ac4a26000");
        let (perms, _) = next_field(rest).unwrap();
        assert_eq!(perms, "r--p");
    }

    #[test]
    fn shared_mappings_are_not_private() {
        assert!(is_private_mapping("r--p"));
        assert!(is_private_mapping("r-xp"));
        assert!(is_private_mapping("rw-p"));
        assert!(!is_private_mapping("rw-s"));
        assert!(!is_private_mapping("r--s"));
    }

    fn perms_at(addr: usize) -> String {
        for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
            let Some((range, rest)) = next_field(line) else {
                continue;
            };
            let Some((start_hex, end_hex)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start_hex, 16),
                usize::from_str_radix(end_hex, 16),
            ) else {
                continue;
            };
            if (start..end).contains(&addr) {
                return next_field(rest).unwrap().0.to_string();
            }
        }
        panic!("no mapping contains {addr:#x}");
    }

    #[test]
    fn relocate_segment_preserves_contents_and_protections() {
        let _state = lock_state();
        const SIZE: usize = 4096;
        let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

        let _retry = install_fault_retry();

        // SAFETY: fresh anonymous mapping for this test; failure is asserted inside the block.
        unsafe {
            let address = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(address, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            std::ptr::copy_nonoverlapping(expected.as_ptr(), address as *mut u8, SIZE);

            assert_eq!(libc::mprotect(address, SIZE, libc::PROT_READ), 0);
            assert_eq!(perms_at(address as usize), "r--p");

            relocate_segment(address, SIZE, libc::PROT_READ, "/test/libgadget.so")
                .expect("relocate_segment failed");

            let after = std::slice::from_raw_parts(address as *const u8, SIZE);
            assert_eq!(after, &expected[..], "segment contents must survive");
            assert_eq!(perms_at(address as usize), "r--p", "protections restored");

            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }

    #[test]
    fn module_filter_finds_self_maps() {
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap();
        let maps = get_modules_by_name(name);
        assert!(
            !maps.is_empty(),
            "expected to find {name} in /proc/self/maps"
        );
        assert!(maps.iter().all(|m| m.end > m.start));
    }

    static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_state() -> std::sync::MutexGuard<'static, ()> {
        STATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn current_handler(sig: c_int) -> usize {
        // SAFETY: output buffer for the query below.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`); fills the buffer above.
            unsafe { libc::sigaction(sig, std::ptr::null(), &raw mut action) },
            0
        );
        action.sa_sigaction as usize
    }

    #[test]
    fn fault_retry_restores_the_previous_handlers() {
        let _state = lock_state();
        let before = [
            current_handler(libc::SIGSEGV),
            current_handler(libc::SIGBUS),
        ];

        {
            let _retry = install_fault_retry();
            assert_eq!(
                current_handler(libc::SIGSEGV),
                park_or_forward as *const () as usize
            );
            assert_eq!(
                current_handler(libc::SIGBUS),
                park_or_forward as *const () as usize
            );
        }

        assert_eq!(
            [
                current_handler(libc::SIGSEGV),
                current_handler(libc::SIGBUS)
            ],
            before,
            "previous dispositions must be put back"
        );
    }

    #[test]
    fn fault_in_rebuilt_range_is_parked_until_commit() {
        let _state = lock_state();
        const SIZE: usize = 4096;
        const CONTENT: u8 = 0xA5;

        let _retry = install_fault_retry();

        // SAFETY: fresh anonymous mapping for this test; failure is asserted inside the block.
        unsafe {
            let address = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(address, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            std::ptr::write_bytes(address as *mut u8, CONTENT, SIZE);

            begin_rebuild(address as usize, SIZE);
            assert_eq!(libc::munmap(address, SIZE), 0);

            let base = address as usize;
            let reader = std::thread::spawn(move || {
                let byte = base as *const u8;
                for _ in 0..PARK_SPIN_LIMIT {
                    if std::ptr::read_volatile(byte) == CONTENT {
                        return true;
                    }
                }
                false
            });

            std::thread::sleep(std::time::Duration::from_millis(50));

            let rebuilt = libc::mmap(
                address,
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_eq!(rebuilt, address, "{}", io::Error::last_os_error());
            std::ptr::write_bytes(address as *mut u8, CONTENT, SIZE);
            end_rebuild();

            assert!(
                reader.join().expect("reader thread died"),
                "reader never resumed against the rebuilt segment"
            );
            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }

    #[test]
    #[ignore = "manual aarch64 exec-under-relocate stress test"]
    #[cfg(target_arch = "aarch64")]
    fn relocate_exec_segment_under_concurrent_execution() {
        use std::sync::atomic::AtomicBool;

        let _state = lock_state();
        let _retry = install_fault_retry();

        unsafe extern "C" {
            fn __clear_cache(begin: *mut c_void, end: *mut c_void);
        }

        const SIZE: usize = 4096;
        // SAFETY: fresh anonymous mapping owned by this test.
        let address = unsafe {
            let address = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(address, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            let code: [u32; 2] = [0x5280_0540, 0xD65F_03C0];
            std::ptr::copy_nonoverlapping(code.as_ptr().cast::<u8>(), address.cast::<u8>(), 8);
            assert_eq!(
                libc::mprotect(address, SIZE, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            __clear_cache(address, address.cast::<u8>().add(8).cast());
            address
        };
        // SAFETY: `address` holds the stub above for the whole test.
        let func: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(address) };
        // SAFETY: the stub returns 42 by construction.
        assert_eq!(unsafe { func() }, 42);

        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        // SAFETY: `address` stays mapped and executable for the
                        // whole scope; relocation preserves contents and perms.
                        let ret = unsafe { func() };
                        assert_eq!(ret, 42);
                    }
                });
            }

            for _ in 0..100 {
                // SAFETY: `address`/`SIZE` describe the live mapping above and
                // the rebuild lock is held via `install_fault_retry`.
                unsafe {
                    relocate_segment(
                        address,
                        SIZE,
                        libc::PROT_READ | libc::PROT_EXEC,
                        "/test/libexec.so",
                    )
                    .expect("relocate_segment failed");
                }
            }
            stop.store(true, Ordering::Relaxed);
        });

        // SAFETY: the mapping is still ours; relocation keeps the address.
        unsafe {
            assert_eq!(perms_at(address as usize), "r-xp");
            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }
}
