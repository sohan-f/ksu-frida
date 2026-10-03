
use std::ffi::c_void;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libc::{self, c_int};

use crate::log::{loge, logi};

const GUARDED_SIGNALS: [c_int; 2] = [libc::SIGSEGV, libc::SIGBUS];

static PREVIOUS_HANDLER: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
static PREVIOUS_FLAGS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

static IN_FLIGHT_START: AtomicUsize = AtomicUsize::new(0);
static IN_FLIGHT_END: AtomicUsize = AtomicUsize::new(0);

static REBUILDER_TID: AtomicUsize = AtomicUsize::new(0);

static REBUILD_LOCK: AtomicBool = AtomicBool::new(false);

const PARK_SPIN_LIMIT: usize = 100_000_000;

struct ProcMapsInfo {
    start: usize,
    end: usize,
    perms: c_int,
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

        maps.push(ProcMapsInfo {
            start,
            end,
            perms: prot,
            path: rest.trim().to_string(),
        });
    }

    maps
}

/// # Safety
/// Installed only by [`install_fault_retry`]; `info` comes from the kernel.
unsafe extern "C" fn park_or_forward(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let start = IN_FLIGHT_START.load(Ordering::Acquire);
    let tid = unsafe { libc::gettid() };
    if start != 0 && tid != REBUILDER_TID.load(Ordering::Relaxed) as c_int {
        let end = IN_FLIGHT_END.load(Ordering::Relaxed);
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

    unsafe { forward_fault(sig, info, context) };
}

/// # Safety
/// Called only from [`park_or_forward`].
unsafe fn forward_fault(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let Some(index) = GUARDED_SIGNALS.iter().position(|&guarded| guarded == sig) else {
        return;
    };

    let handler = PREVIOUS_HANDLER[index].load(Ordering::Relaxed);
    if handler == libc::SIG_DFL || handler == libc::SIG_IGN {
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    }

    let flags = PREVIOUS_FLAGS[index].load(Ordering::Relaxed) as c_int;
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
        previous: std::array::from_fn(|_| unsafe { std::mem::zeroed() }),
        installed: [false; 2],
        _rebuild: RebuildGuard::acquire(),
    };
    REBUILDER_TID.store(unsafe { libc::gettid() } as usize, Ordering::Relaxed);

    for (index, &sig) in GUARDED_SIGNALS.iter().enumerate() {
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(sig, std::ptr::null(), &mut current) } != 0 {
            loge(format!(
                "fault retry: cannot read handler for signal {sig}: {}",
                io::Error::last_os_error()
            ));
            continue;
        }

        if current.sa_sigaction as usize == park_or_forward as *const () as usize {
            retry.previous[index] = current;
            continue;
        }

        PREVIOUS_HANDLER[index].store(current.sa_sigaction as usize, Ordering::Relaxed);
        PREVIOUS_FLAGS[index].store(current.sa_flags as usize, Ordering::Relaxed);
        retry.previous[index] = current;

        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = park_or_forward as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        if unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) } != 0 {
            loge(format!(
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

            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(sig, std::ptr::null(), &mut current) } != 0 {
                continue;
            }
            if current.sa_sigaction as usize != park_or_forward as *const () as usize {
                continue;
            }

            unsafe { libc::sigaction(sig, &self.previous[index], std::ptr::null_mut()) };
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
) -> Result<*mut c_void, RelocateError> {
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
        logi(format!("Removing memory protection: {path}"));
        if unsafe { libc::mprotect(address, size, libc::PROT_READ) } != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::munmap(map, size) };
            return Err(RelocateError::Protect(err));
        }
    }

    unsafe {
        std::ptr::copy(address as *const u8, map as *mut u8, size);

        begin_rebuild(address as usize, size);

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

        let restore_error = if libc::mprotect(address, size, perms) != 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };

        end_rebuild();

        if let Some(err) = restore_error {
            loge(format!(
                "remap: cannot restore protections on {path}: {err}"
            ));
        }
    }

    Ok(map)
}

pub fn remap_lib(lib_path: &str) {
    let lib_name = match lib_path.rfind(['/', '\\']) {
        Some(slash) => &lib_path[slash + 1..],
        None => lib_path,
    };

    let maps = get_modules_by_name(lib_name);
    if maps.is_empty() {
        return;
    }

    logi(format!("Remapping {lib_name}"));

    let _retry = install_fault_retry();

    for info in &maps {
        let address = info.start as *mut c_void;
        let size = info.end - info.start;

        match unsafe { relocate_segment(address, size, info.perms, &info.path) } {
            Ok(map) => logi(format!("Allocated at address {map:p} with size of {size}")),
            Err(RelocateError::Allocate(e)) => {
                loge(format!("Failed to Allocate Memory: {e}"));
                return;
            }
            Err(RelocateError::Protect(e)) => {
                loge(format!("remap: cannot read {}: {e}", info.path));
            }
            Err(RelocateError::Commit(e)) => {
                loge(format!("mremap failed: {e}"));
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
        STATE_LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn current_handler(sig: c_int) -> usize {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(sig, std::ptr::null(), &mut action) },
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
}
