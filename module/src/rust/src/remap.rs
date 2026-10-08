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
// Seqlock version: odd = writing, even = stable. Single-atomic publish so a
// fault landing between the two stores above never transmutes a torn pair.
static PREVIOUS_VERSION: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

#[repr(align(64))]
struct PaddedUsize(AtomicUsize);
#[repr(align(64))]
struct PaddedBool(AtomicBool);

static IN_FLIGHT_START: PaddedUsize = PaddedUsize(AtomicUsize::new(0));
// END is stored while START is zero, so non-zero START implies a stable END.
static IN_FLIGHT_END: PaddedUsize = PaddedUsize(AtomicUsize::new(0));

// The rebuilding thread must never park on its own fault.
static REBUILDER_TID: PaddedUsize = PaddedUsize(AtomicUsize::new(0));

static REBUILD_LOCK: PaddedBool = PaddedBool(AtomicBool::new(false));

const PARK_SPIN_LIMIT: usize = 100_000_000;

struct ProcMapsInfo {
    start: usize,
    end: usize,
    perms: c_int,
    private: bool,
    path: String,
}

#[inline]
fn is_private_mapping(perms: &str) -> bool {
    // 4th char is p/s: shared mappings must keep sharing, never convert to private anon.
    perms.as_bytes().get(3) != Some(&b's')
}

#[inline]
fn prot_from_perms(perms: &str) -> c_int {
    let p = perms.as_bytes();
    let mut prot = 0;
    if p.first() == Some(&b'r') {
        prot |= libc::PROT_READ;
    }
    if p.get(1) == Some(&b'w') {
        prot |= libc::PROT_WRITE;
    }
    if p.get(2) == Some(&b'x') {
        prot |= libc::PROT_EXEC;
    }
    prot
}

#[inline]
fn parse_maps_line(line: &str) -> Option<ProcMapsInfo> {
    // The kernel separates the five fixed fields with single spaces, but the
    // pathname itself may contain spaces (shown unescaped), so split 6 ways.
    let mut parts = line.trim_start().splitn(6, ' ');
    let (range, perms, _, _, _, path) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );

    let (start_hex, end_hex) = range.split_once('-')?;
    let (Ok(start), Ok(end)) = (
        usize::from_str_radix(start_hex, 16),
        usize::from_str_radix(end_hex, 16),
    ) else {
        return None;
    };

    let prot = prot_from_perms(perms);
    // 4th char is p/s: shared mappings must keep sharing, never convert to private anon.
    let private = is_private_mapping(perms);

    Some(ProcMapsInfo {
        start,
        end,
        perms: prot,
        private,
        path: path.trim().to_string(),
    })
}

#[inline]
fn parse_maps_range(line: &str) -> Option<(usize, usize, c_int)> {
    // Same splitn(6,' ') contract as parse_maps_line, without the path alloc.
    let mut parts = line.trim_start().splitn(6, ' ');
    let (range, perms) = (parts.next()?, parts.next()?);
    let (s, e) = range.split_once('-')?;
    let (Ok(start), Ok(end)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
        return None;
    };
    Some((start, end, prot_from_perms(perms)))
}

fn maps_path_matches(path: &str, query: &str) -> bool {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    if query.contains('/') {
        // File load: exact staged path. Basename-only would rebuild a
        // foreign same-basename lib in another dir.
        return path == query;
    }
    path.rsplit_once('/').map_or(path, |(_, base)| base) == query
        || path
            .strip_prefix("/memfd:")
            .is_some_and(|name| name == query)
}

fn get_modules_by_name(m_name: &str) -> Vec<ProcMapsInfo> {
    let mut maps = Vec::new();

    let Ok(file) = File::open("/proc/self/maps") else {
        return maps;
    };

    let mut reader = BufReader::new(file);
    let mut line = String::with_capacity(256);
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        // An exact match always contains the query, so this pre-screen is sound.
        if !line.contains(m_name) {
            line.clear();
            continue;
        }
        let Some(info) = parse_maps_line(&line) else {
            line.clear();
            continue;
        };
        if maps_path_matches(&info.path, m_name) {
            maps.push(info);
        }
        line.clear();
    }

    maps
}

/// Kernel predicate from `asm-generic/siginfo.h` (`SI_FROMKERNEL`):
/// codes <= 0 (`SI_TKILL`, `SI_USER`, ...) are kill-delivered with garbage
/// in the `si_addr` slot; only positive codes name a real fault address.
#[inline]
fn is_synchronous_fault(code: c_int) -> bool {
    code > 0
}

/// # Safety
/// Installed only by [`install_fault_retry`]; `info` comes from the kernel.
unsafe extern "C" fn park_or_forward(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let start = IN_FLIGHT_START.0.load(Ordering::Acquire);
    if start == 0 {
        // SAFETY: `forward_fault` only chains to actions captured by `install_fault_retry` earlier in this rebuild.
        unsafe { forward_fault(sig, info, context) };
        return;
    }
    // SAFETY: `gettid(2)` takes no arguments, cannot fail and allocates nothing — safe inside a signal handler.
    // After the early-out above so idle faults skip the syscall.
    let tid = unsafe { libc::gettid() };
    if tid != REBUILDER_TID.0.load(Ordering::Relaxed) as c_int {
        // SAFETY: plain `c_int` field read of the kernel-provided `siginfo_t`.
        let code = unsafe { (*info).si_code };
        if is_synchronous_fault(code) {
            let end = IN_FLIGHT_END.0.load(Ordering::Relaxed);
            // SAFETY: the kernel hands SA_SIGINFO handlers a non-null `siginfo_t`; `si_addr` is defined for SIGSEGV/SIGBUS.
            let fault = unsafe { (*info).si_addr() } as usize;
            if (start..end).contains(&fault) {
                for _ in 0..PARK_SPIN_LIMIT {
                    // Relaxed poll (`ldr`, not `ldar`); single Acquire on exit.
                    if IN_FLIGHT_START.0.load(Ordering::Relaxed) == 0 {
                        IN_FLIGHT_START.0.load(Ordering::Acquire);
                        return;
                    }
                    std::hint::spin_loop();
                }
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

    let Some((handler, flags)) = load_previous(index) else {
        // Torn publish: fail closed via DFL re-raise instead of transmuting.
        // SAFETY: plain `signal(2)`/`raise(2)` on the faulting thread.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    };
    if handler.addr() == libc::SIG_IGN {
        // Preserve an explicitly ignored signal. In particular, SIGBUS can
        // be raised asynchronously; converting SIG_IGN to SIG_DFL would
        // unexpectedly terminate the process during a remap window.
        return;
    }

    if handler.addr() == libc::SIG_DFL {
        // SAFETY: plain `signal(2)`/`raise(2)` on the faulting thread; the pending signal is delivered before we return to it.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    }

    let flags = flags as c_int;
    // SAFETY: handler/flags were read from a real `sigaction` via a seqlock, so the transmuted signature matches the flag branched on below.
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

#[inline]
fn load_previous(index: usize) -> Option<(*mut c_void, usize)> {
    // Single-atomic publish: odd means the installer is mid-store.
    let v0 = PREVIOUS_VERSION[index].load(Ordering::Acquire);
    if v0 & 1 == 1 {
        for _ in 0..1000 {
            std::hint::spin_loop();
            if PREVIOUS_VERSION[index].load(Ordering::Relaxed) & 1 == 0 {
                break;
            }
        }
        let v = PREVIOUS_VERSION[index].load(Ordering::Acquire);
        if v & 1 == 1 {
            return None;
        }
        let h = PREVIOUS_HANDLER[index].load(Ordering::Relaxed);
        let f = PREVIOUS_FLAGS[index].load(Ordering::Relaxed);
        return if v == PREVIOUS_VERSION[index].load(Ordering::Acquire) {
            Some((h, f))
        } else {
            None
        };
    }
    let h = PREVIOUS_HANDLER[index].load(Ordering::Relaxed);
    let f = PREVIOUS_FLAGS[index].load(Ordering::Relaxed);
    if v0 == PREVIOUS_VERSION[index].load(Ordering::Acquire) {
        Some((h, f))
    } else {
        None
    }
}

#[inline]
fn publish_previous(index: usize, handler: *mut c_void, flags: usize) {
    PREVIOUS_VERSION[index].fetch_add(1, Ordering::Relaxed);
    PREVIOUS_HANDLER[index].store(handler, Ordering::Relaxed);
    PREVIOUS_FLAGS[index].store(flags, Ordering::Relaxed);
    PREVIOUS_VERSION[index].fetch_add(1, Ordering::Release);
}

impl RebuildGuard {
    fn acquire() -> RebuildGuard {
        while REBUILD_LOCK
            .0
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
        REBUILD_LOCK.0.store(false, Ordering::Release);
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
    REBUILDER_TID
        .0
        .store(unsafe { libc::gettid() } as usize, Ordering::Relaxed);

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

        publish_previous(
            index,
            std::ptr::with_exposed_provenance_mut(current.sa_sigaction),
            current.sa_flags as usize,
        );
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
        REBUILDER_TID.0.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn after_fork() {
    IN_FLIGHT_START.0.store(0, Ordering::Release);
    IN_FLIGHT_END.0.store(0, Ordering::Relaxed);
    REBUILDER_TID.0.store(0, Ordering::Relaxed);
    REBUILD_LOCK.0.store(false, Ordering::Release);
    // Unstick a publish interrupted mid-store: single bump to even.
    for v in &PREVIOUS_VERSION {
        if v.load(Ordering::Relaxed) & 1 == 1 {
            v.fetch_add(1, Ordering::Release);
        }
    }
}

#[inline]
fn begin_rebuild(start: usize, size: usize) {
    IN_FLIGHT_END.0.store(start + size, Ordering::Relaxed);
    IN_FLIGHT_START.0.store(start, Ordering::Release);
}

#[inline]
fn end_rebuild() {
    IN_FLIGHT_START.0.store(0, Ordering::Release);
}

#[derive(Debug)]
enum RelocateError {
    Allocate(io::Error),
    Protect(io::Error),
    Commit(io::Error),
    Restore(io::Error),
}

#[inline]
fn copy_prot_for(perms: c_int) -> c_int {
    // Freeze writers during the copy: drop WRITE so concurrent writes fault
    // into park_or_forward instead of being lost. Restored after commit.
    if perms & libc::PROT_WRITE != 0 {
        perms & !libc::PROT_WRITE
    } else if perms & libc::PROT_READ == 0 {
        libc::PROT_READ
    } else {
        perms
    }
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

    // Freeze writers during the copy, restored after commit (see `copy_prot_for`).
    let copy_prot = copy_prot_for(perms);
    if copy_prot != perms {
        // SAFETY: `address`/`size` describe a live mapping from `/proc/self/maps`; the result is checked immediately.
        if unsafe { libc::mprotect(address, size, copy_prot) } != 0 {
            let err = io::Error::last_os_error();
            // SAFETY: same range frozen above; best-effort repair of a partial apply.
            unsafe { libc::mprotect(address, size, perms) };
            end_rebuild();
            // SAFETY: `map`/`size` are ours from the `mmap` above; best-effort cleanup, result deliberately ignored.
            unsafe { libc::munmap(map, size) };
            return Err(RelocateError::Protect(err));
        }
    }

    // SAFETY: source is the live segment, destination is the fresh scratch
    // mapping from `mmap` without `FIXED` — both `size` bytes and non-overlapping.
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, map as *mut u8, size);

        let moved = crate::sys::mremap(
            map,
            size,
            size,
            crate::sys::MREMAP_MAYMOVE | crate::sys::MREMAP_FIXED,
            address,
        );
        if moved == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            if copy_prot != perms {
                libc::mprotect(address, size, perms);
            }
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
    let r = unsafe { crate::sys::set_vma_anon_name(address, size, c"dalvik-jit".as_ptr()) };
    if let Err(e) = r {
        match e.raw_os_error() {
            // Rename is cosmetic: unsupported (EINVAL/ENOSYS), a VMA miss
            // (ENOMEM), or transient pressure (EAGAIN) need no log.
            Some(code)
                if code == libc::EINVAL
                    || code == libc::ENOSYS
                    || code == libc::ENOMEM
                    || code == libc::EAGAIN => {}
            _ => loge_fmt(format_args!("remap: anon rename failed: {e}")),
        }
    }
}

pub fn remap_lib(lib_path: &str, scrub_header: bool) {
    remap_matches(lib_path, scrub_header);
}

pub(crate) fn maps_show(query: &str) -> bool {
    !get_modules_by_name(query).is_empty()
}

/// Protections of the single mapping containing `[start, end)`, if any.
pub(crate) fn mapped_perms(start: usize, end: usize) -> Option<c_int> {
    mapped_range(start).and_then(|(prot, map_end)| (end <= map_end).then_some(prot))
}

/// Start-mapped range end, if `start` sits in a live mapping.
pub(crate) fn mapped_range(start: usize) -> Option<(c_int, usize)> {
    let Ok(file) = File::open("/proc/self/maps") else {
        return None;
    };
    let mut reader = BufReader::new(file);
    let mut line = String::with_capacity(256);
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Some((s, e, prot)) = parse_maps_range(&line)
            && s <= start
            && start < e
        {
            return Some((prot, e));
        }
        line.clear();
    }
    None
}

/// Remap memfd segments (`/memfd:dalvik-jit-cache`). The linker does not keep the
/// source path for fd loads, so basename matching misses them.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn remap_memfd(scrub_header: bool) {
    remap_matches(crate::sys::MEMFD_NAME, scrub_header);
}

fn remap_matches(query: &str, scrub_header: bool) {
    let maps = get_modules_by_name(query);
    if maps.is_empty() {
        return;
    }

    logi_fmt(format_args!("Remapping {}", basename(query)));

    let _retry = install_fault_retry();

    let mut seen_start = Vec::with_capacity(maps.len());
    for info in &maps {
        if !info.private {
            logi_fmt(format_args!("Skipping shared mapping {}", info.path));
            continue;
        }
        if seen_start.contains(&info.start) {
            continue;
        }
        seen_start.push(info.start);
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
                loge_fmt(format_args!("remap: allocate failed: {e}"));
                return;
            }
            Err(RelocateError::Protect(e)) => {
                loge_fmt(format_args!("remap: cannot read {}: {e}", info.path));
            }
            Err(RelocateError::Commit(e)) => {
                loge_fmt(format_args!("remap: mremap failed: {e}"));
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

    if scrub_header {
        scrub_elf_magic_on(&maps, query);
    }
}

/// Fuzz driver for [`parse_maps_line`] + [`maps_path_matches`]: no panic
/// on any input, and file queries (containing `/`) match only on the
/// full stripped path — the exact-match invariant behind the remap fix.
#[cfg(fuzzing)]
pub fn fuzz_maps_match(data: &[u8]) {
    let split = data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(32.min(data.len()));
    let query = String::from_utf8_lossy(&data[..split]).into_owned();
    let rest = if split < data.len() {
        &data[split + 1..]
    } else {
        &[]
    };
    let line = String::from_utf8_lossy(rest);
    if let Some(info) = parse_maps_line(&line) {
        let matched = maps_path_matches(&info.path, &query);
        if query.contains('/') {
            let stripped = info.path.strip_suffix(" (deleted)").unwrap_or(&info.path);
            assert_eq!(
                matched,
                stripped == query,
                "file queries must compare full paths"
            );
        }
    }
}

/// Overwrites the ELF identification bytes of the lowest private mapping.
/// The header always sits at the base of a standard shared object, and the
/// loader is done with it by the time we run, so nothing reads it back.
fn scrub_elf_magic_on(maps: &[ProcMapsInfo], query: &str) {
    let mut target: Option<(usize, c_int)> = None;
    for info in maps {
        if !info.private {
            continue;
        }
        match target {
            Some((base, _)) if info.start >= base => {}
            _ => target = Some((info.start, info.perms)),
        }
    }

    let Some((base, perms)) = target else {
        return;
    };
    // SAFETY: `base` is the page-aligned start of a live mapping from the
    // scan above; only its first 16 bytes are touched below.
    if unsafe { wipe_elf_magic_at(base as *mut c_void, perms) } {
        logi_fmt(format_args!("Scrubbed ELF header for {}", basename(query)));
    }
}

/// Zeroes the 16 identification bytes at a mapping base, restoring protections.
unsafe fn wipe_elf_magic_at(base: *mut c_void, perms: c_int) -> bool {
    const IDENT_LEN: usize = 16;
    let rw = perms | libc::PROT_WRITE;
    if rw != perms {
        // SAFETY: `base` is page aligned with at least `IDENT_LEN` mapped bytes.
        if unsafe { libc::mprotect(base, IDENT_LEN, rw) } != 0 {
            loge_fmt(format_args!(
                "scrub: cannot unprotect ELF header: {}",
                io::Error::last_os_error()
            ));
            return false;
        }
    }
    // SAFETY: same bounded range, now writable by construction above.
    unsafe {
        std::ptr::write_bytes(base as *mut u8, 0, IDENT_LEN);
    }
    if rw != perms {
        // SAFETY: range from the successful call above; best-effort restore.
        if unsafe { libc::mprotect(base, IDENT_LEN, perms) } != 0 {
            loge_fmt(format_args!(
                "scrub: cannot re-protect ELF header: {}",
                io::Error::last_os_error()
            ));
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previous_publish_is_single_atomic() {
        let _state = lock_state();
        let h = 0x1234 as *mut c_void;
        publish_previous(0, h, 7);
        assert_eq!(load_previous(0), Some((h, 7)));
        // Odd version fails closed instead of returning a torn pair.
        PREVIOUS_VERSION[0].fetch_add(1, Ordering::Relaxed);
        assert_eq!(load_previous(0), None);
        PREVIOUS_VERSION[0].fetch_add(1, Ordering::Release);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2) have no Miri shims
    fn elf_magic_wipe_zeroes_ident_and_keeps_perms() {
        const SIZE: usize = 4096;
        const HEADER: &[u8; 16] = b"\x7fELF mock header";
        // SAFETY: fresh anonymous mapping owned by this test.
        let addr = unsafe {
            let addr = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(
                addr,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            addr
        };
        // SAFETY: `addr` is our live mapping; the wipe keeps its protections.
        unsafe {
            std::ptr::copy_nonoverlapping(HEADER.as_ptr(), addr as *mut u8, HEADER.len());
            assert!(wipe_elf_magic_at(addr, libc::PROT_READ | libc::PROT_WRITE));
            assert_eq!(
                std::slice::from_raw_parts(addr as *const u8, HEADER.len()),
                &[0u8; 16]
            );
            assert_eq!(
                prot_at(addr as usize),
                (libc::PROT_READ | libc::PROT_WRITE, true)
            );
        }
        // SAFETY: same mapping, still writable: rewrite the header, then drop
        // to read-only to exercise the mprotect path below.
        unsafe {
            std::ptr::copy_nonoverlapping(HEADER.as_ptr(), addr as *mut u8, HEADER.len());
            assert_eq!(libc::mprotect(addr, SIZE, libc::PROT_READ), 0);
        }
        // SAFETY: `addr` is our live read-only mapping.
        unsafe {
            assert!(wipe_elf_magic_at(addr, libc::PROT_READ));
            assert_eq!(
                std::slice::from_raw_parts(addr as *const u8, HEADER.len()),
                &[0u8; 16]
            );
            assert_eq!(prot_at(addr as usize), (libc::PROT_READ, true));
            assert_eq!(libc::munmap(addr, SIZE), 0);
        }
    }

    #[test]
    fn maps_line_with_spaced_path_parses() {
        let info =
            parse_maps_line("  7ac49c2000-7ac4a26000 r--p 00000000 00:00 0 /a b").expect("line");
        assert_eq!(info.start, 0x7ac49c2000);
        assert_eq!(info.end, 0x7ac4a26000);
        assert_eq!(info.perms, libc::PROT_READ);
        assert!(info.private);
        assert_eq!(info.path, "/a b");

        assert!(parse_maps_line("").is_none());
        assert!(parse_maps_line("7ac49c2000-7ac4a26000 r--p").is_none());
        assert!(parse_maps_line("zz-top r--p 0 00:00 0 /a").is_none());
    }

    #[test]
    fn maps_path_match_is_exact_and_handles_memfd_names() {
        assert!(maps_path_matches(
            "/data/app/libfoo.so",
            "/data/app/libfoo.so"
        ));
        assert!(maps_path_matches(
            "/data/app/libfoo.so (deleted)",
            "/data/app/libfoo.so"
        ));
        assert!(!maps_path_matches(
            "/data/app/other/libfoo.so",
            "/data/app/libfoo.so"
        ));
        assert!(!maps_path_matches("/data/app/libfoo.so.1", "libfoo.so"));
        assert!(!maps_path_matches(
            "/data/app/prefix-libfoo.so",
            "libfoo.so"
        ));
        assert!(maps_path_matches(
            "/memfd:dalvik-jit-cache (deleted)",
            "dalvik-jit-cache"
        ));
    }

    #[test]
    fn only_kernel_faults_park() {
        assert!(is_synchronous_fault(1)); // SEGV_MAPERR / BUS_ADRALN
        assert!(is_synchronous_fault(2)); // SEGV_ACCERR / BUS_ADRERR
        assert!(!is_synchronous_fault(0)); // SI_USER
        assert!(!is_synchronous_fault(-6)); // SI_TKILL
    }

    #[test]
    fn shared_mappings_are_not_private() {
        assert!(is_private_mapping("r--p"));
        assert!(is_private_mapping("r-xp"));
        assert!(is_private_mapping("rw-p"));
        assert!(!is_private_mapping("rw-s"));
        assert!(!is_private_mapping("r--s"));
    }

    #[test]
    fn copy_prot_drops_write_but_keeps_read() {
        assert_eq!(
            copy_prot_for(libc::PROT_READ | libc::PROT_WRITE),
            libc::PROT_READ
        );
        assert_eq!(copy_prot_for(libc::PROT_READ), libc::PROT_READ);
        assert_eq!(
            copy_prot_for(libc::PROT_READ | libc::PROT_EXEC),
            libc::PROT_READ | libc::PROT_EXEC
        );
        assert_eq!(copy_prot_for(libc::PROT_EXEC), libc::PROT_READ);
    }

    fn prot_at(addr: usize) -> (c_int, bool) {
        for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
            let Some(info) = parse_maps_line(line) else {
                continue;
            };
            if (info.start..info.end).contains(&addr) {
                return (info.perms, info.private);
            }
        }
        panic!("no mapping contains {addr:#x}");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2) have no Miri shims
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
            assert_eq!(prot_at(address as usize), (libc::PROT_READ, true));

            relocate_segment(address, SIZE, libc::PROT_READ, "/test/libgadget.so")
                .expect("relocate_segment failed");

            let after = std::slice::from_raw_parts(address as *const u8, SIZE);
            assert_eq!(after, &expected[..], "segment contents must survive");
            assert_eq!(
                prot_at(address as usize),
                (libc::PROT_READ, true),
                "protections restored"
            );

            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // asserts on Miri's own process layout, not our code
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
    #[cfg_attr(miri, ignore)] // sigaction(2) has no Miri shim
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
    #[cfg_attr(miri, ignore)] // mmap(2) has no Miri shim
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
            assert_eq!(
                prot_at(address as usize),
                (libc::PROT_READ | libc::PROT_EXEC, true)
            );
            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }
}
