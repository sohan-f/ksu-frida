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

// Saved sa_mask bytes, published with handler/flags above; 128B on glibc/Bionic.
// Single writer under REBUILD_LOCK (the handler only sets the fired flag),
// readers pair every access with the seqlock version, so the access below is sound.
struct MaskBytes(std::cell::UnsafeCell<[u8; SIGSET_LEN]>);
// SAFETY: only `store_mask_bytes` mutates (under REBUILD_LOCK) and every
// reader is version-gated; no concurrent access is observable.
unsafe impl Sync for MaskBytes {}
const SIGSET_LEN: usize = size_of::<libc::sigset_t>();
static PREVIOUS_MASK: [MaskBytes; 2] = [
    MaskBytes(std::cell::UnsafeCell::new([0; SIGSET_LEN])),
    MaskBytes(std::cell::UnsafeCell::new([0; SIGSET_LEN])),
];
// Set when a forwarded fault emulates SA_RESETHAND; Drop then leaves DFL.
static RESETHAND_FIRED: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

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

#[derive(Debug, Clone)]
struct ProcMapsInfo {
    start: usize,
    end: usize,
    perms: c_int,
    private: bool,
    path: String,
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
}

/// Device and inode identifying a mapped file, for disambiguating
/// kernel-escaped pathnames (`\n` vs literal `\012` render identically).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
}

#[inline]
fn parse_dev_inode(dev: &str, inode: &str) -> Option<(u32, u32, u64)> {
    // Device numbers print hex, inodes decimal (verified against stat).
    let (major, minor) = dev.split_once(':')?;
    let (Ok(major), Ok(minor), Ok(inode)) = (
        u32::from_str_radix(major, 16),
        u32::from_str_radix(minor, 16),
        inode.parse(),
    ) else {
        return None;
    };
    Some((major, minor, inode))
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
    // The five fixed fields are single-space separated; the kernel pads the
    // gap before the pathname to a fixed column, so only leading whitespace
    // is stripped there. Pathnames never start with whitespace (absolute,
    // bracketed, or empty), but trailing spaces are data. Newlines arrive
    // octal-escaped, so a literal `\n` is only ever the line terminator.
    let line = line.strip_suffix('\n').unwrap_or(line);
    let mut parts = line.trim_start().splitn(6, ' ');
    let (range, perms, _, dev, inode, path) = (
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
    let (dev_major, dev_minor, inode) = parse_dev_inode(dev, inode)?;

    let prot = prot_from_perms(perms);
    // 4th char is p/s: shared mappings must keep sharing, never convert to private anon.
    let private = is_private_mapping(perms);

    Some(ProcMapsInfo {
        start,
        end,
        perms: prot,
        private,
        path: path.trim_start().to_string(),
        dev_major,
        dev_minor,
        inode,
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
    if query.contains('/') {
        // Raw first: a literal ` (deleted)` filename must match itself.
        if path == query {
            return true;
        }
        let stripped = path.strip_suffix(" (deleted)").unwrap_or(path);
        if stripped == query {
            return true;
        }
        // Newlines arrive octal-escaped; try that form too, both ways.
        if let Some(escaped) = escaped_maps_query(query) {
            return path == escaped || stripped == escaped;
        }
        return false;
    }
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    path.rsplit_once('/').map_or(path, |(_, base)| base) == query
        || path
            .strip_prefix("/memfd:")
            .is_some_and(|name| name == query)
}

// The kernel's octal escape for a newline in a mapped pathname, if any.
fn escaped_maps_query(query: &str) -> Option<String> {
    query.contains('\n').then(|| query.replace('\n', "\\012"))
}

// Identity check for file queries: strings alone cannot tell a real
// newline from a literal `\012` (the kernel renders both the same), but
// device and inode can. Unknown identity (unstatable path) keeps the
// string verdict, so deleted-but-mapped files still match.
fn identity_matches(info: &ProcMapsInfo, query_id: Option<FileId>) -> bool {
    let Some(query_id) = query_id else {
        return true;
    };
    info.dev_major == query_id.dev_major
        && info.dev_minor == query_id.dev_minor
        && info.inode == query_id.inode
}

// Device and inode of a configured path, when it can be statted.
fn query_file_id(query: &str) -> Option<FileId> {
    if !query.contains('/') {
        return None;
    }
    let meta = std::fs::metadata(query).ok()?;
    use std::os::unix::fs::MetadataExt;
    // dev_t and the major/minor return types differ per ABI (u64/i32/u32
    // across glibc and Bionic targets); values are small and non-negative.
    Some(FileId {
        dev_major: libc::major(meta.dev() as libc::dev_t) as u32,
        dev_minor: libc::minor(meta.dev() as libc::dev_t) as u32,
        inode: meta.ino(),
    })
}

fn get_modules_by_name(m_name: &str) -> Vec<ProcMapsInfo> {
    let mut maps = Vec::new();

    let Ok(file) = File::open("/proc/self/maps") else {
        return maps;
    };

    let escaped = escaped_maps_query(m_name);
    let query_id = query_file_id(m_name);
    let mut reader = BufReader::new(file);
    let mut line = String::with_capacity(256);
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        // An exact match always contains the query, so this pre-screen is
        // sound; the escaped form covers newline pathnames the same way.
        let hit = line.contains(m_name) || escaped.as_deref().is_some_and(|q| line.contains(q));
        if !hit {
            line.clear();
            continue;
        }
        let Some(info) = parse_maps_line(&line) else {
            line.clear();
            continue;
        };
        if maps_path_matches(&info.path, m_name) && identity_matches(&info, query_id) {
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

// Forwards currently inside the wrapper per signal; teardown drains these
// (bounded) before deciding, so a paused claim settles first.
static IN_FLIGHT_FORWARD: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

struct FlightGuard {
    index: usize,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        // Saturating: a fork from inside a forwarded handler resets the
        // counter underneath this guard via after_fork; wrapping to
        // MAX would stall every later teardown drain in the child.
        let _ =
            IN_FLIGHT_FORWARD[self.index]
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }
}

/// # Safety
/// Called only from [`park_or_forward`].
unsafe fn forward_fault(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    let Some(index) = GUARDED_SIGNALS.iter().position(|&guarded| guarded == sig) else {
        return;
    };
    IN_FLIGHT_FORWARD[index].fetch_add(1, Ordering::Relaxed);
    let _flight = FlightGuard { index };

    // A fired reset stays fired: later faults in this window take DFL.
    if RESETHAND_FIRED[index].load(Ordering::Acquire) {
        // SAFETY: plain `signal(2)`/`raise(2)` on the faulting thread.
        unsafe { raise_dfl(sig) };
        return;
    }

    let Some((handler, flags, mask)) = load_previous(index) else {
        // Torn publish: fail closed via DFL re-raise instead of transmuting.
        // SAFETY: plain `signal(2)`/`raise(2)` on the faulting thread.
        unsafe { raise_dfl(sig) };
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
        unsafe { raise_dfl(sig) };
        return;
    }

    let flags = flags as c_int;
    if flags & libc::SA_RESETHAND != 0 && RESETHAND_FIRED[index].swap(true, Ordering::AcqRel) {
        // Lost the reset race: the first delivery already claimed the handler.
        // SAFETY: as above.
        unsafe { raise_dfl(sig) };
        return;
    }
    // Block the saved mask (+sig unless NODEFER) around the nested call.
    let mut blocked = mask;
    if flags & libc::SA_NODEFER == 0 {
        // SAFETY: pure bit op on our own stack set.
        unsafe { libc::sigaddset(&mut blocked, sig) };
    }
    // SAFETY: plain output slot for the block call below.
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: async-signal-safe; `old` restored after the nested call.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old) };
    // SAFETY: handler/flags/mask were read from a real `sigaction` via a seqlock, so the transmuted signature matches the flag branched on below.
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
    // SAFETY: paired restore of the block above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    if flags & libc::SA_RESETHAND != 0 {
        // Post-teardown claim: teardown already restored the one-shot and
        // left, so retire it here or a later fault re-runs it. A live
        // window shows our wrapper instead and keeps owning the flag.
        // SAFETY: output buffer for the query below.
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: query-only call (`act == NULL`).
        let retired = unsafe { libc::sigaction(sig, std::ptr::null(), &mut current) } == 0
            && current.sa_sigaction as usize != park_or_forward as *const () as usize
            && current.sa_sigaction as usize == handler.addr();
        if retired {
            // SAFETY: retiring the handler just invoked; zeroed action is DFL.
            let dfl: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: queried immediately above; best-effort retire.
            unsafe { libc::sigaction(sig, &dfl, std::ptr::null_mut()) };
            RESETHAND_FIRED[index].store(false, Ordering::Release);
        }
    }
}

/// Fail closed via DFL re-raise on the faulting thread.
///
/// # Safety
/// `sig` must be a guarded signal delivered to this thread.
#[inline]
unsafe fn raise_dfl(sig: c_int) {
    // SAFETY: plain `signal(2)`/`raise(2)`; the pending signal lands before return.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

struct RebuildGuard;

#[inline]
fn load_previous(index: usize) -> Option<(*mut c_void, usize, libc::sigset_t)> {
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
        let out = read_previous(index);
        return if v == PREVIOUS_VERSION[index].load(Ordering::Acquire) {
            Some(out)
        } else {
            None
        };
    }
    let out = read_previous(index);
    if v0 == PREVIOUS_VERSION[index].load(Ordering::Acquire) {
        Some(out)
    } else {
        None
    }
}

#[inline]
fn read_previous(index: usize) -> (*mut c_void, usize, libc::sigset_t) {
    let handler = PREVIOUS_HANDLER[index].load(Ordering::Relaxed);
    let flags = PREVIOUS_FLAGS[index].load(Ordering::Relaxed);
    // SAFETY: single writer under REBUILD_LOCK; version-checked by the caller.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: same contract; every byte lands in `mask`.
    let dst = unsafe { std::slice::from_raw_parts_mut(&mut mask as *mut _ as *mut u8, SIGSET_LEN) };
    // SAFETY: same single-writer/version contract as above.
    let src = unsafe { &*PREVIOUS_MASK[index].0.get() };
    dst.copy_from_slice(src);
    (handler, flags, mask)
}

#[inline]
fn publish_previous(index: usize, handler: *mut c_void, flags: usize, mask: &libc::sigset_t) {
    PREVIOUS_VERSION[index].fetch_add(1, Ordering::Relaxed);
    PREVIOUS_HANDLER[index].store(handler, Ordering::Relaxed);
    PREVIOUS_FLAGS[index].store(flags, Ordering::Relaxed);
    // SAFETY: single writer under REBUILD_LOCK; published by the bump below.
    let src = unsafe { std::slice::from_raw_parts(mask as *const _ as *const u8, SIGSET_LEN) };
    // SAFETY: same single-writer contract; readers are version-gated.
    let dst = unsafe { &mut *PREVIOUS_MASK[index].0.get() };
    dst.copy_from_slice(src);
    // A firing older than this publish is obsolete: a stale set flag must
    // not skip the freshly saved handler. The closing bump carries this out.
    RESETHAND_FIRED[index].store(false, Ordering::Relaxed);
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
    guarded: [bool; 2],
    _rebuild: RebuildGuard,
}

impl FaultRetry {
    /// True only when every guarded signal is parked by our handler.
    fn guards_active(&self) -> bool {
        self.guarded == [true, true]
    }
}

fn install_fault_retry() -> FaultRetry {
    let mut retry = FaultRetry {
        // SAFETY: `libc::sigaction` is a plain FFI struct — all-zeroed is a valid starting state.
        previous: std::array::from_fn(|_| unsafe { std::mem::zeroed() }),
        installed: [false; 2],
        guarded: [false; 2],
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
            retry.guarded[index] = true;
            continue;
        }

        publish_previous(
            index,
            std::ptr::with_exposed_provenance_mut(current.sa_sigaction),
            current.sa_flags as usize,
            &current.sa_mask,
        );
        retry.previous[index] = current;

        // SAFETY: zeroed `sigaction` is the documented way to build a fresh action; every field used is set before install.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = park_or_forward as *const () as usize;
        // The kernel picks the handler stack, mask deferral, and syscall
        // restart from the installed action: inherit all three per signal
        // so forwarded faults keep app semantics instead of wrapper defaults.
        action.sa_flags = libc::SA_SIGINFO
            | (current.sa_flags & (libc::SA_ONSTACK | libc::SA_NODEFER | libc::SA_RESTART));
        // The saved mask must be installed, not just reapplied later: until
        // the nested call blocks it, cross signals stay deliverable here.
        action.sa_mask = current.sa_mask;
        // SAFETY: installs the fully initialised `action` above; the kernel copies it synchronously.
        if unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) } != 0 {
            loge_fmt(format_args!(
                "fault retry: cannot install handler for signal {sig}: {}",
                io::Error::last_os_error()
            ));
            continue;
        }
        retry.installed[index] = true;
        retry.guarded[index] = true;
    }

    retry
}

impl Drop for FaultRetry {
    fn drop(&mut self) {
        for (index, &sig) in GUARDED_SIGNALS.iter().enumerate() {
            // A replaced app action must not leave a stale reset behind.
            if !self.installed[index] {
                continue;
            }

            // SAFETY: output buffer for the restore-time query below.
            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: query-only call (`act == NULL`).
            if unsafe { libc::sigaction(sig, std::ptr::null(), &raw mut current) } != 0 {
                RESETHAND_FIRED[index].store(false, Ordering::Relaxed);
                continue;
            }
            if current.sa_sigaction as usize != park_or_forward as *const () as usize {
                RESETHAND_FIRED[index].store(false, Ordering::Relaxed);
                continue;
            }

            // Drain paused claims first: a forward inside the wrapper must
            // settle (claim or finish) before teardown decides, or its
            // invoke escapes the reset. Bounded like the park spin; a
            // straggler past the bound keeps the previous behavior.
            for _ in 0..PARK_SPIN_LIMIT {
                if IN_FLIGHT_FORWARD[index].load(Ordering::Relaxed) == 0 {
                    break;
                }
                std::hint::spin_loop();
            }

            // The flag stays set until the replacement lands: concurrent
            // forwards in between must take DFL, never re-invoke.
            if RESETHAND_FIRED[index].load(Ordering::Acquire) {
                // Emulate the kernel reset: leave DFL, not the one-shot handler.
                // SAFETY: zeroed action is DFL (NULL handler).
                let dfl: libc::sigaction = unsafe { std::mem::zeroed() };
                // SAFETY: current handler is still ours (checked above).
                unsafe { libc::sigaction(sig, &dfl, std::ptr::null_mut()) };
                RESETHAND_FIRED[index].store(false, Ordering::Release);
            } else {
                // SAFETY: current handler is still ours (checked above); restores the saved action.
                unsafe {
                    libc::sigaction(sig, &raw const self.previous[index], std::ptr::null_mut())
                };
                // A concurrent forward may have claimed the one-shot between
                // the check above and this install: re-check and correct.
                if RESETHAND_FIRED[index].swap(false, Ordering::AcqRel) {
                    // SAFETY: best-effort correction toward the reset state.
                    let dfl: libc::sigaction = unsafe { std::mem::zeroed() };
                    // SAFETY: same installed handler as above.
                    unsafe { libc::sigaction(sig, &dfl, std::ptr::null_mut()) };
                }
            }
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
    for fired in &RESETHAND_FIRED {
        fired.store(false, Ordering::Relaxed);
    }
    for flight in &IN_FLIGHT_FORWARD {
        flight.store(0, Ordering::Relaxed);
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
    // Reading needs READ on every architecture: WRITE-only would leave
    // PROT_NONE (and W|X unreadable) and fault the copy itself, which the
    // rebuilder cannot park on.
    if perms & libc::PROT_WRITE != 0 {
        (perms & !libc::PROT_WRITE) | libc::PROT_READ
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
    }

    // Apply the intended protections to the scratch before committing: if
    // policy denies them here, the original mapping is still intact and we
    // abort instead of stranding a half-protected replacement.
    // SAFETY: `map`/`size` are ours from the `mmap` above.
    if unsafe { libc::mprotect(map, size, perms) } != 0 {
        let err = io::Error::last_os_error();
        if copy_prot != perms {
            // SAFETY: same range frozen above; best-effort repair of a partial apply.
            unsafe { libc::mprotect(address, size, perms) };
        }
        end_rebuild();
        // SAFETY: as above; best-effort cleanup, result deliberately ignored.
        unsafe { libc::munmap(map, size) };
        return Err(RelocateError::Restore(err));
    }

    // SAFETY: `map` is ours and `address`/`size` describe the live target;
    // FIXED transplants the already-correctly-protected scratch over it.
    unsafe {
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
    // Without parked faults a concurrent write reaches the app handler;
    // fail closed (visible but alive) instead of risking a crash.
    if !_retry.guards_active() {
        loge_fmt(format_args!(
            "remap: fault guard unavailable for {}; skipping",
            basename(query)
        ));
        return;
    }

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
    #[cfg_attr(miri, ignore)] // sigaction(2) has no Miri shim
    fn install_reports_active_guards() {
        let _state = lock_state();
        {
            let retry = install_fault_retry();
            assert!(retry.guards_active());
        }
    }

    #[test]
    fn previous_publish_is_single_atomic() {
        let _state = lock_state();
        let h = 0x1234 as *mut c_void;
        // Byte pattern instead of libc set ops (no Miri shims needed).
        let raw = [0b1010_0101u8; SIGSET_LEN];
        // SAFETY: any bit pattern stores fine; only round-tripped below.
        let mask: libc::sigset_t = unsafe { std::mem::transmute(raw) };
        publish_previous(0, h, 7, &mask);
        let (rh, rf, rmask) = load_previous(0).expect("published");
        assert_eq!((rh, rf), (h, 7));
        // SAFETY: reads our own stack copy as bytes.
        let back: [u8; SIGSET_LEN] = unsafe { std::mem::transmute(rmask) };
        assert_eq!(back, raw);
        // Odd version fails closed instead of returning a torn triple.
        PREVIOUS_VERSION[0].fetch_add(1, Ordering::Relaxed);
        assert!(load_previous(0).is_none());
        PREVIOUS_VERSION[0].fetch_add(1, Ordering::Release);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2)/raise(2); no Miri shims
    fn forward_applies_mask_and_reset() {
        use std::sync::atomic::AtomicBool;

        static RAN: AtomicBool = AtomicBool::new(false);
        static SAW_MASKED: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            // SAFETY: query-only mask read into our own stack slot.
            let mut cur: libc::sigset_t = unsafe { std::mem::zeroed() };
            // SAFETY: async-signal-safe query; pure membership test below.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur) };
            // SAFETY: as above.
            let masked = unsafe {
                libc::sigismember(&cur, libc::SIGUSR1) == 1
                    && libc::sigismember(&cur, libc::SIGSEGV) == 1
            };
            RAN.store(true, Ordering::Relaxed);
            SAW_MASKED.store(masked, Ordering::Relaxed);
        }

        let _state = lock_state();
        RAN.store(false, Ordering::Relaxed);
        SAW_MASKED.store(false, Ordering::Relaxed);

        // SAFETY: query-only mask read on this thread.
        let mut saved_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: scratch set for the unblock below.
        let mut unblock: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: this-thread mask and set ops only.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved_mask);
            libc::sigemptyset(&mut unblock);
            libc::sigaddset(&mut unblock, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
        }

        // SAFETY: query-only call below; the old action is restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );
        // SAFETY: fully initialised below; restored at the end of the test.
        let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
        probe_action.sa_sigaction = probe as *const () as usize;
        probe_action.sa_mask = unblock;
        probe_action.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        assert_eq!(
            // SAFETY: fully initialised action above; installed synchronously.
            unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
            0
        );

        {
            let _retry = install_fault_retry();
            // Kill-delivered fault skips parking (garbage si_addr) and forwards.
            // SAFETY: our handler is installed; the probe only records and returns.
            unsafe { libc::raise(libc::SIGSEGV) };
            assert!(RAN.load(Ordering::Relaxed));
            assert!(SAW_MASKED.load(Ordering::Relaxed));
            // Reset recorded atomically; the saved payload is untouched.
            assert!(RESETHAND_FIRED[0].load(Ordering::Relaxed));
            let (handler, _, _) = load_previous(0).expect("published");
            assert_ne!(handler.addr(), libc::SIG_DFL);
        }

        // Drop honored the reset: DFL installed, not the one-shot probe.
        // SAFETY: output buffer for the query below.
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction as usize, libc::SIG_DFL);
        assert!(!RESETHAND_FIRED[0].load(Ordering::Relaxed));

        // SAFETY: restores the pre-test disposition and thread mask.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
            libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2)/threads; no Miri shims
    fn wrapper_keeps_sa_restart() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        static RAN: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            RAN.store(true, Ordering::Relaxed);
        }

        let _state = lock_state();
        RAN.store(false, Ordering::Relaxed);

        // SAFETY: output buffers for the queries below.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut saved_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only calls.
            unsafe {
                libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action);
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved_mask)
            },
            0
        );

        // SAFETY: fully initialised below; restored at the end of the test.
        let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
        probe_action.sa_sigaction = probe as *const () as usize;
        probe_action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        assert_eq!(
            // SAFETY: fully initialised action above; installed synchronously.
            unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
            0
        );

        // SAFETY: test-owned pipe pair.
        let mut fds = [0; 2];
        // SAFETY: valid two-element output buffer.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: main thread id for the directed kill below.
        let main_tid = unsafe { libc::pthread_self() };
        let helper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            // SAFETY: directed kill at the blocked reader below.
            unsafe { libc::pthread_kill(main_tid, libc::SIGSEGV) };
            let deadline = Instant::now() + Duration::from_secs(5);
            while !RAN.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            // SAFETY: releases the reader either way; RAN pins the verdict.
            unsafe { libc::write(fds[1], [1u8].as_ptr().cast(), 1) };
        });

        {
            let _retry = install_fault_retry();
            // Kill-delivered fault forwards; with RESTART kept the read resumes.
            let mut byte = [0u8; 1];
            // SAFETY: blocking read on our own empty pipe end.
            let n = unsafe { libc::read(fds[0], byte.as_mut_ptr().cast(), 1) };
            assert!(RAN.load(Ordering::Relaxed));
            assert_eq!(n, 1, "interrupted read must restart, not EINTR");
            assert_eq!(byte, [1u8]);
        }
        helper.join().expect("helper thread died");

        // SAFETY: restores the pre-test disposition, mask, and pipe pair.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
            libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2); no Miri shims
    fn wrapper_inherits_mask_per_signal() {
        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {}

        let _state = lock_state();

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );

        for mask_usr1 in [false, true] {
            // SAFETY: fully initialised below; restored at the end of the test.
            let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
            probe_action.sa_sigaction = probe as *const () as usize;
            probe_action.sa_flags = libc::SA_SIGINFO;
            if mask_usr1 {
                // SAFETY: pure set op on our own stack set.
                unsafe {
                    libc::sigemptyset(&mut probe_action.sa_mask);
                    libc::sigaddset(&mut probe_action.sa_mask, libc::SIGUSR1);
                }
            }
            assert_eq!(
                // SAFETY: fully initialised action above.
                unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
                0
            );
            {
                let _retry = install_fault_retry();
                // SAFETY: output buffer for the query below.
                let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
                assert_eq!(
                    // SAFETY: query-only call (`act == NULL`).
                    unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut current) },
                    0
                );
                // SAFETY: read-only membership test on the queried mask.
                let has_usr1 = unsafe { libc::sigismember(&current.sa_mask, libc::SIGUSR1) } == 1;
                assert_eq!(
                    has_usr1, mask_usr1,
                    "wrapper must inherit sa_mask, not install empty"
                );
            }
        }

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2); no Miri shims
    fn wrapper_inherits_nodefer_per_signal() {
        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {}

        let _state = lock_state();

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );

        for (extra, expect_nodefer) in [(0, false), (libc::SA_NODEFER, true)] {
            // SAFETY: fully initialised below; restored at the end of the test.
            let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
            probe_action.sa_sigaction = probe as *const () as usize;
            probe_action.sa_flags = libc::SA_SIGINFO | extra;
            assert_eq!(
                // SAFETY: fully initialised action above.
                unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
                0
            );
            {
                let _retry = install_fault_retry();
                // SAFETY: output buffer for the query below.
                let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
                assert_eq!(
                    // SAFETY: query-only call (`act == NULL`).
                    unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut current) },
                    0
                );
                assert_eq!(
                    current.sa_flags & libc::SA_NODEFER != 0,
                    expect_nodefer,
                    "wrapper must inherit NODEFER, not drop it"
                );
            }
        }

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2); no Miri shims
    fn wrapper_inherits_onstack_per_signal() {
        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {}

        let _state = lock_state();

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );

        for (extra, expect_onstack) in [(0, false), (libc::SA_ONSTACK, true)] {
            // SAFETY: fully initialised below; restored at the end of the test.
            let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
            probe_action.sa_sigaction = probe as *const () as usize;
            probe_action.sa_flags = libc::SA_SIGINFO | extra;
            assert_eq!(
                // SAFETY: fully initialised action above.
                unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
                0
            );
            {
                let _retry = install_fault_retry();
                // SAFETY: output buffer for the query below.
                let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
                assert_eq!(
                    // SAFETY: query-only call (`act == NULL`).
                    unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut current) },
                    0
                );
                assert_eq!(
                    current.sa_flags & libc::SA_ONSTACK != 0,
                    expect_onstack,
                    "wrapper must inherit ONSTACK, not force it"
                );
                assert_ne!(current.sa_sigaction as usize, probe as *const () as usize);
            }
        }

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2)/raise(2); no Miri shims
    fn drop_clears_reset_when_app_replaces_handler() {
        use std::sync::atomic::AtomicBool;

        static RAN_A: AtomicBool = AtomicBool::new(false);
        static RAN_B: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn probe_a(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            RAN_A.store(true, Ordering::Relaxed);
        }

        unsafe extern "C" fn probe_b(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            RAN_B.store(true, Ordering::Relaxed);
        }

        let _state = lock_state();
        RAN_A.store(false, Ordering::Relaxed);
        RAN_B.store(false, Ordering::Relaxed);

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );
        // SAFETY: fully initialised below; superseded before the end of the test.
        let mut one_shot: libc::sigaction = unsafe { std::mem::zeroed() };
        one_shot.sa_sigaction = probe_a as *const () as usize;
        one_shot.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        // SAFETY: fully initialised replacement below; restored at the end.
        let mut replacement: libc::sigaction = unsafe { std::mem::zeroed() };
        replacement.sa_sigaction = probe_b as *const () as usize;
        replacement.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            // SAFETY: fully initialised one-shot above; superseded below.
            unsafe { libc::sigaction(libc::SIGSEGV, &one_shot, std::ptr::null_mut(),) },
            0
        );

        {
            let retry = install_fault_retry();
            // Kill-delivered fault forwards to the one-shot probe.
            // SAFETY: our handler is installed; the probe only records and returns.
            unsafe { libc::raise(libc::SIGSEGV) };
            assert!(RAN_A.load(Ordering::Relaxed));
            // The one-shot probe replaces itself, like a chaining runtime would.
            assert_eq!(
                // SAFETY: fully initialised replacement above.
                unsafe { libc::sigaction(libc::SIGSEGV, &replacement, std::ptr::null_mut()) },
                0
            );
            drop(retry);
            // The app action is preserved and no stale reset remains.
            // SAFETY: output buffer for the query below.
            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                // SAFETY: query-only call (`act == NULL`).
                unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut current) },
                0
            );
            assert_eq!(current.sa_sigaction as usize, probe_b as *const () as usize);
            assert!(!RESETHAND_FIRED[0].load(Ordering::Relaxed));
        }

        // A later remap still forwards to the replacement instead of DFL.
        RAN_B.store(false, Ordering::Relaxed);
        {
            let _retry = install_fault_retry();
            // SAFETY: our handler is installed; the probe only records and returns.
            unsafe { libc::raise(libc::SIGSEGV) };
            assert!(RAN_B.load(Ordering::Relaxed));
        }

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2); no Miri shims
    fn drop_installs_dfl_on_pending_reset() {
        let _state = lock_state();

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );

        {
            let _retry = install_fault_retry();
            // Simulates a claim that landed without a live forward.
            RESETHAND_FIRED[0].store(true, Ordering::Relaxed);
        }

        // Drop honored the pending reset and consumed it.
        // SAFETY: output buffer for the query below.
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction as usize, libc::SIG_DFL);
        assert!(!RESETHAND_FIRED[0].load(Ordering::Relaxed));

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2); no Miri shims
    fn install_clears_stale_reset() {
        let _state = lock_state();

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );

        {
            // A firing older than the publish below is obsolete.
            RESETHAND_FIRED[0].store(true, Ordering::Relaxed);
            let _retry = install_fault_retry();
            // The publish cleared it, so the Drop below takes the
            // restore path instead of wrongly leaving DFL.
            assert!(!RESETHAND_FIRED[0].load(Ordering::Relaxed));
        }

        // SAFETY: output buffer for the query below.
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(
            after.sa_sigaction as usize,
            saved_action.sa_sigaction as usize
        );

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // raw sigaction(2); no Miri shims
    fn post_teardown_claim_retires_handler() {
        use std::sync::atomic::AtomicBool;

        static RAN: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            RAN.store(true, Ordering::Relaxed);
        }

        let _state = lock_state();
        RAN.store(false, Ordering::Relaxed);

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );
        // SAFETY: fully initialised below; superseded before the end of the test.
        let mut one_shot: libc::sigaction = unsafe { std::mem::zeroed() };
        one_shot.sa_sigaction = probe as *const () as usize;
        one_shot.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        assert_eq!(
            // SAFETY: fully initialised one-shot above.
            unsafe { libc::sigaction(libc::SIGSEGV, &one_shot, std::ptr::null_mut(),) },
            0
        );

        {
            // A full window with no firing; Drop restores the one-shot.
            let _retry = install_fault_retry();
        }

        // Models a claim paused before its swap, resuming after teardown:
        // the kernel never resets (direct call), so the claimer retires it.
        // SAFETY: scratch info the probe ignores; context unused.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: models a post-teardown claim; installs nothing but DFL below.
        unsafe { forward_fault(libc::SIGSEGV, &mut info, std::ptr::null_mut()) };
        assert!(RAN.load(Ordering::Relaxed));
        // SAFETY: output buffer for the query below.
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction as usize, libc::SIG_DFL);
        assert!(!RESETHAND_FIRED[0].load(Ordering::Relaxed));

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // real sigaction(2)/threads; no Miri shims
    fn drop_drains_in_flight_forward() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        static ENTERED: AtomicBool = AtomicBool::new(false);
        static GO: AtomicBool = AtomicBool::new(false);

        unsafe extern "C" fn probe(_sig: c_int, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
            ENTERED.store(true, Ordering::Relaxed);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !GO.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let _state = lock_state();
        ENTERED.store(false, Ordering::Relaxed);
        GO.store(false, Ordering::Relaxed);

        // SAFETY: output buffer for the query below; restored at the end.
        let mut saved_action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut saved_action) },
            0
        );
        // SAFETY: fully initialised below; restored at the end of the test.
        let mut probe_action: libc::sigaction = unsafe { std::mem::zeroed() };
        probe_action.sa_sigaction = probe as *const () as usize;
        probe_action.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            // SAFETY: fully initialised action above.
            unsafe { libc::sigaction(libc::SIGSEGV, &probe_action, std::ptr::null_mut(),) },
            0
        );

        let retry = install_fault_retry();
        let helper = std::thread::spawn(|| {
            // SAFETY: directed at this thread; the probe above only gates.
            unsafe { libc::raise(libc::SIGSEGV) };
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while IN_FLIGHT_FORWARD[0].load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        // The helper is inside the wrapper; teardown must wait for it.
        assert_eq!(IN_FLIGHT_FORWARD[0].load(Ordering::Relaxed), 1);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(retry);
            let _ = done_tx.send(());
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            done_rx.try_recv().is_err(),
            "teardown must still be draining the in-flight forward"
        );
        GO.store(true, Ordering::Relaxed);
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("drained");
        helper.join().expect("helper thread died");
        assert_eq!(IN_FLIGHT_FORWARD[0].load(Ordering::Relaxed), 0);

        // SAFETY: output buffer for the query below.
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: query-only call (`act == NULL`).
            unsafe { libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction as usize, probe as *const () as usize);

        // SAFETY: restores the pre-test disposition.
        unsafe {
            libc::sigaction(libc::SIGSEGV, &saved_action, std::ptr::null_mut());
        }
    }

    #[test]
    fn flight_guard_never_underflows_reset_counter() {
        let _state = lock_state();
        // Models a fork from inside a forwarded handler: after_fork zeroes
        // the counter while this guard is still live on the stack.
        IN_FLIGHT_FORWARD[0].store(1, Ordering::Relaxed);
        after_fork();
        {
            let _flight = FlightGuard { index: 0 };
        }
        assert_eq!(IN_FLIGHT_FORWARD[0].load(Ordering::Relaxed), 0);

        // Balanced use still counts exactly.
        IN_FLIGHT_FORWARD[0].fetch_add(1, Ordering::Relaxed);
        {
            let _flight = FlightGuard { index: 0 };
        }
        assert_eq!(IN_FLIGHT_FORWARD[0].load(Ordering::Relaxed), 0);
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
    fn deleted_suffix_is_tried_raw_before_stripped() {
        // Genuine deletion markers still match the live path underneath.
        assert!(maps_path_matches(
            "/data/x/libfoo.so (deleted)",
            "/data/x/libfoo.so"
        ));
        // A literal ` (deleted)` filename matches itself, not just its stem.
        assert!(maps_path_matches(
            "/data/x/libfoo.so (deleted)",
            "/data/x/libfoo.so (deleted)"
        ));
        assert!(!maps_path_matches(
            "/data/x/other.so (deleted)",
            "/data/x/libfoo.so (deleted)"
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2) has no Miri shim
    fn literal_deleted_suffix_mapping_is_found() {
        use crate::test_support::TempDir;

        let dir = TempDir::new("deleted-name");
        let file = dir.join("libfoo.so (deleted)");
        std::fs::write(&file, vec![0u8; 4096]).unwrap();
        let path = file.to_str().unwrap().to_string();
        // SAFETY: fresh file mapping owned by this test.
        let address = unsafe {
            let fd = libc::open(crate::sys::cstring(&path).unwrap().as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            let address = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd,
                0,
            );
            assert_ne!(
                address,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            assert_eq!(libc::close(fd), 0);
            address as usize
        };
        let found = get_modules_by_name(&path);
        assert_eq!(
            found.iter().map(|info| info.start).collect::<Vec<_>>(),
            [address]
        );
        // SAFETY: cleanup our mapping.
        unsafe {
            assert_eq!(libc::munmap(address as *mut c_void, 4096), 0);
        }
    }

    #[test]
    fn dev_inode_parse_hex_device_and_decimal_inode() {
        let info = parse_maps_line(
            "762e1cc000-762e1cd000 rw-s 00000000 00:148 6171                          /tmp/seg.bin\n",
        )
        .expect("line");
        assert_eq!(
            (info.dev_major, info.dev_minor, info.inode),
            (0, 0x148, 6171)
        );
    }

    #[test]
    fn identity_matches_needs_ids_only_for_files() {
        let id = FileId {
            dev_major: 0,
            dev_minor: 1,
            inode: 2,
        };
        let same = ProcMapsInfo {
            start: 0,
            end: 0,
            perms: 0,
            private: true,
            path: String::new(),
            dev_major: 0,
            dev_minor: 1,
            inode: 2,
        };
        let other = ProcMapsInfo {
            inode: 3,
            ..same.clone()
        };
        assert!(identity_matches(&same, Some(id)));
        assert!(!identity_matches(&other, Some(id)));
        assert!(identity_matches(&other, None));
    }

    #[test]
    fn escaped_query_covers_newline_pathnames_only() {
        assert_eq!(escaped_maps_query("/data/x/libfoo.so"), None);
        assert_eq!(
            escaped_maps_query("/data/x/a\nb.so"),
            Some("/data/x/a\\012b.so".to_string())
        );
    }

    #[test]
    fn newline_path_matches_octal_escaped_maps_line() {
        let info =
            parse_maps_line("7ac49c2000-7ac4a26000 r--p 00000000 00:00 0 /data/x/a\\012b.so\n")
                .expect("line");
        assert_eq!(info.path, "/data/x/a\\012b.so");
        assert!(maps_path_matches(&info.path, "/data/x/a\nb.so"));
        assert!(!maps_path_matches(&info.path, "/data/x/a\nc.so"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2) has no Miri shim
    fn twin_newline_and_literal_names_resolve_to_own_mapping() {
        use crate::test_support::TempDir;

        let dir = TempDir::new("twin-map");
        let newline_file = dir.join("a\nb.so");
        let literal_file = dir.join("a\\012b.so");
        std::fs::write(&newline_file, vec![0u8; 4096]).unwrap();
        std::fs::write(&literal_file, vec![1u8; 4096]).unwrap();
        let newline_path = newline_file.to_str().unwrap().to_string();
        let literal_path = literal_file.to_str().unwrap().to_string();

        // SAFETY: fresh file mappings owned by this test.
        let (newline_addr, literal_addr) = unsafe {
            let map_one = |path: &str| {
                let fd = libc::open(crate::sys::cstring(path).unwrap().as_ptr(), libc::O_RDONLY);
                assert!(fd >= 0, "{}", std::io::Error::last_os_error());
                let address = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                );
                assert_ne!(
                    address,
                    libc::MAP_FAILED,
                    "{}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(libc::close(fd), 0);
                address as usize
            };
            (map_one(&newline_path), map_one(&literal_path))
        };

        // Both render identically in maps; identity must pick each file's own.
        let newline_hits = get_modules_by_name(&newline_path);
        assert_eq!(
            newline_hits
                .iter()
                .map(|info| info.start)
                .collect::<Vec<_>>(),
            [newline_addr]
        );
        let literal_hits = get_modules_by_name(&literal_path);
        assert_eq!(
            literal_hits
                .iter()
                .map(|info| info.start)
                .collect::<Vec<_>>(),
            [literal_addr]
        );

        // SAFETY: cleanup our mappings.
        unsafe {
            assert_eq!(libc::munmap(newline_addr as *mut c_void, 4096), 0);
            assert_eq!(libc::munmap(literal_addr as *mut c_void, 4096), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2) has no Miri shim
    fn newline_backed_mapping_is_found() {
        use crate::test_support::TempDir;

        let dir = TempDir::new("newline-map");
        let file = dir.join("n\nl.so");
        std::fs::write(&file, vec![0u8; 4096]).unwrap();
        let path = file.to_str().unwrap().to_string();
        // SAFETY: fresh file mapping owned by this test.
        let address = unsafe {
            let fd = libc::open(crate::sys::cstring(&path).unwrap().as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            let address = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd,
                0,
            );
            assert_ne!(
                address,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            assert_eq!(libc::close(fd), 0);
            address
        };
        let found = get_modules_by_name(&path);
        assert!(
            found.iter().any(|info| info.start == address as usize),
            "newline-backed mapping must be found"
        );
        // SAFETY: cleanup our mapping.
        unsafe {
            assert_eq!(libc::munmap(address, 4096), 0);
        }
    }

    #[test]
    fn maps_line_preserves_trailing_space_in_path() {
        let info =
            parse_maps_line("7ac49c2000-7ac4a26000 r--p 00000000 00:00 0 /data/x/libfoo.so \n")
                .expect("line");
        assert_eq!(info.path, "/data/x/libfoo.so ");

        let info =
            parse_maps_line("7ac49c2000-7ac4a26000 r--p 00000000 00:00 0 /data/x/libfoo.so\n")
                .expect("line");
        assert_eq!(info.path, "/data/x/libfoo.so");

        // Kernel-faithful padding between the inode column and the path.
        let info = parse_maps_line(
            "762e1cc000-762e1cd000 rw-s 00000000 00:148 6171                          /tmp/seg.bin\n",
        )
        .expect("line");
        assert_eq!(info.start, 0x762e1cc000);
        assert!(!info.private);
        assert_eq!(info.path, "/tmp/seg.bin");
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
        // Write without read is unreadable on ARM64: the copy source must
        // stay readable (PROT_NONE or --x would fault the rebuilder itself).
        assert_eq!(copy_prot_for(libc::PROT_WRITE), libc::PROT_READ);
        assert_eq!(
            copy_prot_for(libc::PROT_WRITE | libc::PROT_EXEC),
            libc::PROT_READ | libc::PROT_EXEC
        );
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
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2)/mremap(2) have no Miri shims
    fn relocate_aborted_before_commit_keeps_original() {
        use crate::test_support::TempDir;

        let _state = lock_state();
        const SIZE: usize = 4096;
        let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

        let _retry = install_fault_retry();

        // File-backed on purpose: only the pathname tells an aborted
        // rebuild (mapping intact) from a committed one (anon transplant).
        let dir = TempDir::new("relocate-abort");
        let file = dir.join("seg.bin");
        std::fs::write(&file, &expected).unwrap();
        // SAFETY: fresh file mapping owned by this test; failure asserted inside.
        unsafe {
            let fd = libc::open(
                crate::sys::cstring(file.to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                libc::O_RDWR,
            );
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            let address = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(address, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            assert_eq!(libc::close(fd), 0);

            // Bogus protections: the pre-commit mprotect must fail (EINVAL)
            // while the original file mapping is still intact.
            let err = relocate_segment(address, SIZE, 0x1000, "/test/libbogus.so").unwrap_err();
            assert!(
                matches!(err, RelocateError::Restore(_)),
                "unexpected error: {err:?}"
            );
            let after = std::slice::from_raw_parts(address as *const u8, SIZE);
            assert_eq!(after, &expected[..], "original bytes must survive");
            // Intactness here means identity, not protections: the request
            // itself is invalid, so the best-effort restore has nothing
            // valid to apply. Only the pathname tells an aborted rebuild
            // (file mapping intact) from a committed one (anon transplant).
            let mut seen_path = false;
            for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
                if let Some(info) = parse_maps_line(line)
                    && info.start == address as usize
                {
                    assert_eq!(info.path, file.to_str().unwrap());
                    seen_path = true;
                }
            }
            assert!(seen_path, "file mapping must still be mapped");

            assert_eq!(libc::munmap(address, SIZE), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2) have no Miri shims
    fn relocate_write_only_segment_stays_readable_for_the_copy() {
        let _state = lock_state();
        const SIZE: usize = 4096;
        let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

        let _retry = install_fault_retry();

        // SAFETY: fresh anonymous mapping owned by this test.
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

            assert_eq!(libc::mprotect(address, SIZE, libc::PROT_WRITE), 0);
            assert_eq!(prot_at(address as usize), (libc::PROT_WRITE, true));

            relocate_segment(address, SIZE, libc::PROT_WRITE, "/test/libwrite.so")
                .expect("relocate_segment failed");

            assert_eq!(
                prot_at(address as usize),
                (libc::PROT_WRITE, true),
                "write-only protections restored"
            );
            // Our own mapping: re-add read to verify the copied bytes below.
            assert_eq!(
                libc::mprotect(address, SIZE, libc::PROT_READ | libc::PROT_WRITE),
                0
            );
            let after = std::slice::from_raw_parts(address as *const u8, SIZE);
            assert_eq!(after, &expected[..], "segment contents must survive");

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
