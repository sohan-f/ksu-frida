use std::ffi::{CStr, c_char, c_int, c_void};

use crate::log::{basename, loge, loge_fmt, logi_fmt};
use crate::sys::{DlIterateCb, DlPhdrInfo, dl_iterate_phdr};

struct ScrubSearch {
    target: Vec<u8>,
    replacement: Vec<u8>,
    found: bool,
    soname: bool,
    symbols: usize,
    substring: bool,
}

/// # Safety
/// `buf` must point to a live NUL-terminated string with at least `len + 1`
/// writable bytes (i.e. `len == strlen(buf)` of a heap string we own the
/// reference to, like the linker's `dlpi_name` copy).
unsafe fn overwrite_in_place(buf: *mut c_char, len: usize, replacement: &[u8]) {
    // SAFETY: bounded by the caller's footprint contract; every write below
    // lands at `buf[..=len]`.
    unsafe {
        let take = replacement.len().min(len);
        std::ptr::copy_nonoverlapping(replacement.as_ptr().cast::<c_char>(), buf, take);
        buf.add(take).write(0);
    }
}

/// # Safety
/// Installed only via [`scrub_dlpi_name`]; `info` comes from the linker and
/// `data` is the live [`ScrubSearch`] below.
unsafe extern "C" fn scrub_callback(
    info: *mut DlPhdrInfo,
    _size: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the linker hands the callback a valid entry; `data` is our
    // search struct, alive for the whole synchronous walk.
    let (current, search) = unsafe {
        let name = CStr::from_ptr((*info).name);
        (name.to_bytes(), &mut *(data.cast::<ScrubSearch>()))
    };
    let matched = if search.substring {
        current
            .windows(search.target.len().max(1))
            .any(|w| w == search.target.as_slice())
    } else {
        current == search.target.as_slice()
    };
    if !matched {
        return 0;
    }
    // SAFETY: `info` is the matched live entry; the callee bounds every
    // read by the linker's own tables and truncates writes to measured
    // footprints.
    let (soname, symbols) = unsafe { scrub_elf_metadata(info, &search.replacement) };
    search.soname = soname;
    search.symbols = symbols;
    // SAFETY: `dlpi_name` is the linker's heap copy of the loaded path; its
    // known footprint is `current.len() + 1`, which is all we ever touch.
    unsafe {
        overwrite_in_place(
            (*info).name as *mut c_char,
            current.len(),
            &search.replacement,
        );
    }
    search.found = true;
    1
}

const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

const MAX_DYNAMIC: usize = 128;
const MAX_SYMBOLS: usize = 1_000_000;

#[cfg(target_pointer_width = "64")]
#[repr(C)]
struct Phdr64 {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
// Field order differs from 64-bit.
struct Phdr32 {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
struct Dyn64 {
    d_tag: i64,
    d_val: u64,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
struct Dyn32 {
    d_tag: i32,
    d_val: u32,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
struct Sym64 {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
// Field order differs from 64-bit.
struct Sym32 {
    st_name: u32,
    st_value: u32,
    st_size: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
}

#[cfg(target_pointer_width = "32")]
use self::{Dyn32 as Dyn, Phdr32 as Phdr, Sym32 as Sym};
#[cfg(target_pointer_width = "64")]
use self::{Dyn64 as Dyn, Phdr64 as Phdr, Sym64 as Sym};

/// # Safety
/// `ptr[..max]` must be readable.
unsafe fn bounded_strlen(ptr: *const u8, max: usize) -> Option<usize> {
    // SAFETY: the caller bounds the scan; each read lands inside `ptr[..max]`.
    unsafe {
        for i in 0..max {
            if ptr.add(i).read() == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn contains_frida(name: &[u8]) -> bool {
    name.windows(5)
        .any(|window| window.eq_ignore_ascii_case(b"frida"))
}

struct WritableWindow {
    start: usize,
    len: usize,
    label: &'static str,
}

impl WritableWindow {
    /// # Safety
    /// `[addr, addr + len)` must name readable memory we own (our own
    /// tables); flipping it writable is safe exactly then.
    unsafe fn open(addr: usize, len: usize, label: &'static str) -> Option<Self> {
        // SAFETY: `sysconf(3)` takes a constant and reports errors via -1.
        let page = unsafe {
            let ps = libc::sysconf(libc::_SC_PAGESIZE);
            if ps <= 0 { 4096 } else { ps as usize }
        };
        debug_assert!(page.is_power_of_two());
        if len == 0 {
            return None;
        }
        let end = addr.checked_add(len)?;
        let start = addr & !(page - 1);
        let end = (end + page - 1) & !(page - 1);
        // SAFETY: page-aligned range around caller-owned data; checked below.
        if unsafe {
            libc::mprotect(
                start as *mut c_void,
                end - start,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            loge_fmt(format_args!(
                "linkmap: cannot unprotect {label}: {}",
                std::io::Error::last_os_error()
            ));
            return None;
        }
        Some(Self {
            start,
            len: end - start,
            label,
        })
    }
}

impl Drop for WritableWindow {
    fn drop(&mut self) {
        // SAFETY: the range `open` flipped; best-effort restore.
        if unsafe { libc::mprotect(self.start as *mut c_void, self.len, libc::PROT_READ) } != 0 {
            loge_fmt(format_args!(
                "linkmap: cannot re-protect {}: {}",
                self.label,
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// # Safety
/// `strtab[..strsz]` must be readable and writable (the caller holds the
/// window); `symtab`/`nsyms`/`soname` come from our own validated tables
/// (`symtab == base` and `nsyms > MAX_SYMBOLS` disable the sweep, `soname`
/// outside the table is skipped); `replacement` is truncated to every
/// footprint touched.
unsafe fn scrub_tables(
    strtab: usize,
    strsz: usize,
    symtab: usize,
    base: usize,
    nsyms: usize,
    soname: Option<usize>,
    replacement: &[u8],
) -> (bool, usize) {
    let mut symbols = 0usize;
    if symtab != base && nsyms <= MAX_SYMBOLS {
        for i in 0..nsyms {
            // SAFETY: `i` is bounded by `nchain` from our own hash table
            // (capped above); each step lands inside our own table; unaligned copy.
            let sym: Sym =
                unsafe { ((symtab + i * size_of::<Sym>()) as *const Sym).read_unaligned() };
            let off = sym.st_name as usize;
            if off >= strsz {
                continue;
            }
            // SAFETY: `off` is inside the table; at most `strsz - off`
            // bytes are read.
            let len = unsafe {
                match bounded_strlen((strtab + off) as *const u8, strsz - off) {
                    Some(len) => len,
                    None => continue,
                }
            };
            // SAFETY: same bounded slice, read-only.
            let name = unsafe { std::slice::from_raw_parts((strtab + off) as *const u8, len) };
            if contains_frida(name) {
                // SAFETY: within the footprint just measured.
                unsafe {
                    overwrite_in_place((strtab + off) as *mut c_char, len, replacement);
                }
                symbols += 1;
            }
        }
    }
    let mut soname_done = false;
    if let Some(off) = soname
        && off < strsz
    {
        // SAFETY: bounded by the table size like every read above.
        if let Some(len) = unsafe { bounded_strlen((strtab + off) as *const u8, strsz - off) } {
            // SAFETY: same bounded footprint as every write above.
            unsafe {
                overwrite_in_place((strtab + off) as *mut c_char, len, replacement);
            }
            soname_done = true;
        }
    }
    (soname_done, symbols)
}

/// # Safety
/// `info` must be a live linker entry (only called from [`scrub_callback`]
/// on a match); `replacement` is truncated to every footprint it touches.
unsafe fn scrub_elf_metadata(info: *mut DlPhdrInfo, replacement: &[u8]) -> (bool, usize) {
    // SAFETY: `info` is the matched live entry; `phdr[..phnum]` is the
    // linker's own read-only table.
    let (base, phdr, phnum) = unsafe { ((*info).addr, (*info).phdr, (*info).phnum) };
    if phdr.is_null() {
        return (false, 0);
    }

    let mut dyn_addr = 0usize;
    for i in 0..phnum as usize {
        // SAFETY: `i` is bounded by the linker's `phnum`; each step lands
        // inside our own read-only table; unaligned copy, no alignment promise.
        let p: Phdr =
            unsafe { (phdr.byte_add(i * size_of::<Phdr>()) as *const Phdr).read_unaligned() };
        if p.p_type == PT_DYNAMIC {
            dyn_addr = base.wrapping_add(p.p_vaddr as usize);
            break;
        }
    }
    if dyn_addr == 0 {
        return (false, 0);
    }

    let (mut strtab, mut strsz, mut symtab, mut hash, mut gnu_hash, mut soname) =
        (0usize, 0usize, 0usize, 0usize, 0usize, None::<usize>);
    for i in 0..MAX_DYNAMIC {
        // SAFETY: bounded walk of the linker's dynamic array; each step
        // lands inside our own read-only table; unaligned copy.
        let d: Dyn = unsafe { ((dyn_addr + i * size_of::<Dyn>()) as *const Dyn).read_unaligned() };
        let tag = d.d_tag as i64;
        if tag == DT_NULL {
            break;
        }
        // SAFETY: none yet — values are only stored, resolved below.
        let val = d.d_val as usize;
        match tag {
            t if t == DT_STRTAB => strtab = val,
            t if t == DT_STRSZ => strsz = val,
            t if t == DT_SYMTAB => symtab = val,
            t if t == DT_HASH => hash = val,
            t if t == DT_GNU_HASH => gnu_hash = val,
            t if t == DT_SONAME => soname = Some(val),
            _ => {}
        }
    }
    if strtab == 0 || strsz == 0 {
        return (false, 0);
    }
    let strtab = base.wrapping_add(strtab);
    let symtab = base.wrapping_add(symtab);
    let hash = base.wrapping_add(hash);
    let gnu_hash = base.wrapping_add(gnu_hash);

    let nsyms = if hash != base {
        // SAFETY: `hash` names our own read-only table; unaligned-safe `u32` reads.
        unsafe { (hash as *const u32).add(1).read_unaligned() as usize }
    } else if gnu_hash != base {
        // SAFETY: `gnu_hash` names our own read-only table; the callee
        // bounds every read by the header counts below.
        unsafe { gnu_nsyms(gnu_hash) }
    } else {
        0
    };

    // SAFETY: `strtab[..strsz]` names our own read-only table (bounded
    // above); the window makes it writable, and the callee keeps every
    // write inside a measured footprint.
    let (soname_done, symbols) = unsafe {
        let Some(window) = WritableWindow::open(strtab, strsz, "dynstr") else {
            return (false, 0);
        };
        let result = scrub_tables(strtab, strsz, symtab, base, nsyms, soname, replacement);
        drop(window);
        result
    };
    (soname_done, symbols)
}

/// Upper bound on the symbol count from a GNU hash table.
///
/// # Safety
/// `table` must address a readable `DT_GNU_HASH` table of our own image;
/// every read below stays inside its header, buckets, and chains.
unsafe fn gnu_nsyms(table: usize) -> usize {
    // SAFETY: header of our own table; unaligned-safe `u32` reads.
    let (nbuckets, symoffset, bloom_words) = unsafe {
        let header = table as *const u32;
        (
            header.read_unaligned() as usize,
            header.add(1).read_unaligned() as usize,
            header.add(2).read_unaligned() as usize,
        )
    };
    if nbuckets == 0 || nbuckets > MAX_SYMBOLS {
        return 0;
    }
    let limit = symoffset.saturating_add(MAX_SYMBOLS);
    let Some(buckets) = bloom_words
        .checked_mul(size_of::<usize>())
        .and_then(|bloom| table.checked_add(16 + bloom))
    else {
        return 0;
    };
    let Some(chain) = nbuckets.checked_mul(4).and_then(|b| buckets.checked_add(b)) else {
        return 0;
    };
    // Chains of one bucket run contiguous until the LSB stop bit; total work
    // across buckets is bounded by the shared budget below.
    let mut budget = MAX_SYMBOLS;
    let mut highest = symoffset;
    for i in 0..nbuckets {
        // SAFETY: `i` bounded by the header count; one unaligned bucket read per step.
        let mut sym = unsafe { ((buckets as *const u32).add(i)).read_unaligned() as usize };
        if sym < symoffset || sym >= limit {
            continue;
        }
        while budget > 0 && sym < limit {
            // SAFETY: `sym` bounded above; one unaligned chain word per step.
            let word = unsafe { ((chain as *const u32).add(sym - symoffset)).read_unaligned() };
            budget -= 1;
            highest = highest.max(sym + 1);
            if word & 1 == 1 {
                break;
            }
            sym += 1;
        }
    }
    highest
}

fn run_scrub(search: &mut ScrubSearch) {
    // SAFETY: `scrub_callback` matches the `DlIterateCb` signature; `search`
    // outlives the synchronous walk; the return value (entries visited) is
    // informational only.
    unsafe {
        dl_iterate_phdr(
            scrub_callback as DlIterateCb,
            std::ptr::from_mut(search).cast::<c_void>(),
        );
    }
}

/// # Safety
/// Logs every dlpi name; `info` comes from the linker.
unsafe extern "C" fn log_names_callback(
    info: *mut DlPhdrInfo,
    _size: usize,
    _data: *mut c_void,
) -> c_int {
    // SAFETY: linker-provided entry, read-only copy for logging.
    unsafe {
        let name = CStr::from_ptr((*info).name).to_string_lossy();
        logi_fmt(format_args!("linkmap entry: {name}"));
    }
    0
}

fn log_all_names() {
    // SAFETY: logging-only walk, no mutation.
    unsafe { dl_iterate_phdr(log_names_callback as DlIterateCb, std::ptr::null_mut()) };
}

pub fn scrub_dlpi_name(staged_path: &str) {
    // SAFETY: `getpid(2)` cannot fail.
    let pid = unsafe { libc::getpid() };
    let mut search = ScrubSearch {
        target: staged_path.as_bytes().to_vec(),
        replacement: format!("libnative_{pid}.so").into_bytes(),
        found: false,
        soname: false,
        symbols: 0,
        substring: false,
    };

    run_scrub(&mut search);

    if search.found {
        logi_fmt(format_args!(
            "Scrubbed linker name for {} (soname {}, {} symbols)",
            basename(staged_path),
            if search.soname { "renamed" } else { "left" },
            search.symbols
        ));
    } else {
        loge_fmt(format_args!(
            "linkmap: no dl_iterate_phdr entry matched {}; name left visible",
            basename(staged_path)
        ));
        log_all_names();
    }
}

/// Scrub the memfd entry (`/memfd:jit-cache`) created by `try_memfd_inject`.
/// The linker does not use the source path for fd loads, so exact matching fails.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn scrub_memfd() {
    // SAFETY: `getpid(2)` cannot fail.
    let pid = unsafe { libc::getpid() };
    let mut search = ScrubSearch {
        target: crate::sys::MEMFD_NAME.as_bytes().to_vec(),
        replacement: format!("libnative_{pid}.so").into_bytes(),
        found: false,
        soname: false,
        symbols: 0,
        substring: true,
    };

    run_scrub(&mut search);

    if search.found {
        logi_fmt(format_args!(
            "Scrubbed linker name for memfd (soname {}, {} symbols)",
            if search.soname { "renamed" } else { "left" },
            search.symbols
        ));
    } else {
        loge("linkmap: no dl_iterate_phdr entry matched memfd; name left visible");
        log_all_names();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn raw_cstring(s: &str) -> *mut c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn entry(name: *const c_char) -> DlPhdrInfo {
        DlPhdrInfo {
            addr: 0,
            name,
            phdr: std::ptr::null(),
            phnum: 0,
        }
    }

    /// # Safety
    /// `ptr` came from `raw_cstring` with payload length `orig_len` (measured
    /// *before* any overwrite: the current strlen is shorter after one, and
    /// freeing by it would use the wrong layout — Miri catches this).
    unsafe fn free_cstring(ptr: *mut c_char, orig_len: usize) {
        // SAFETY: reconstructs the exact `into_raw` allocation above.
        unsafe {
            drop(Vec::from_raw_parts(
                ptr.cast::<u8>(),
                orig_len + 1,
                orig_len + 1,
            ));
        }
    }

    #[test]
    fn callback_scrubs_only_the_matching_entry() {
        let first = raw_cstring("/system/lib/libc.so");
        let second = raw_cstring("/data/data/com.a.b/.cache/1234/libsecmon.so");
        let mut first_entry = entry(first);
        let mut second_entry = entry(second);

        let mut search = ScrubSearch {
            target: b"/data/data/com.a.b/.cache/1234/libsecmon.so".to_vec(),
            replacement: b"libnative_1234.so".to_vec(),
            found: false,
            soname: false,
            symbols: 0,
            substring: false,
        };
        let data = (&raw mut search).cast::<c_void>();

        // SAFETY: both entries are live owned strings; `search` outlives them.
        unsafe {
            assert_eq!(scrub_callback(&raw mut first_entry, 0, data), 0);
            assert_eq!(scrub_callback(&raw mut second_entry, 0, data), 1);
        }

        assert!(search.found);
        // SAFETY: both strings still owned; read-only checks, then freed
        // with their original lengths.
        unsafe {
            assert_eq!(CStr::from_ptr(first).to_bytes(), b"/system/lib/libc.so");
            assert_eq!(CStr::from_ptr(second).to_bytes(), b"libnative_1234.so");
            free_cstring(first, 19);
            free_cstring(second, 43);
        }
    }

    #[test]
    fn overwrite_truncates_instead_of_overflowing() {
        let buf = raw_cstring("/a/b.so");
        // SAFETY: 7 payload bytes + NUL are ours; the replacement is longer.
        unsafe {
            overwrite_in_place(buf, 7, b"libnative_99999.so");
        }
        // SAFETY: read-only check of our own string, then freed by
        // original length.
        unsafe {
            assert_eq!(CStr::from_ptr(buf).to_bytes(), b"libnati");
            free_cstring(buf, 7);
        }
    }

    #[test]
    fn missing_entry_reports_not_found() {
        let only = raw_cstring("/system/lib/libc.so");
        let mut only_entry = entry(only);
        let mut search = ScrubSearch {
            target: b"/nope.so".to_vec(),
            replacement: b"libnative_1.so".to_vec(),
            found: false,
            soname: false,
            symbols: 0,
            substring: false,
        };
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                scrub_callback(&raw mut only_entry, 0, (&raw mut search).cast::<c_void>()),
                0
            );
        }
        assert!(!search.found);
        // SAFETY: frees our own string (never overwritten: 19 payload bytes).
        unsafe {
            free_cstring(only, 19);
        }
    }

    #[test]
    fn frida_match_is_case_insensitive_substring() {
        assert!(contains_frida(b"frida_agent_main"));
        assert!(contains_frida(b"libFRIDA-gadget.so"));
        assert!(contains_frida(b"xxFrIdAxx"));
        assert!(!contains_frida(b"puts"));
        assert!(!contains_frida(b"fri"));
        assert!(!contains_frida(b""));
    }

    #[test]
    fn substring_match_finds_memfd_entry() {
        let memfd = raw_cstring("/memfd:jit-cache (deleted)");
        let mut memfd_entry = entry(memfd);
        let mut search = ScrubSearch {
            target: b"jit-cache".to_vec(),
            replacement: b"libnative_1.so".to_vec(),
            found: false,
            soname: false,
            symbols: 0,
            substring: true,
        };
        // SAFETY: entry is a live owned string; `search` outlives the call.
        unsafe {
            assert_eq!(
                scrub_callback(&raw mut memfd_entry, 0, (&raw mut search).cast::<c_void>()),
                1
            );
        }
        assert!(search.found);
        // SAFETY: read-only check, then freed by original length (24).
        unsafe {
            assert_eq!(CStr::from_ptr(memfd).to_bytes(), b"libnative_1.so");
            free_cstring(memfd, 24);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg(target_pointer_width = "64")]
    fn elf_scrub_rewrites_soname_and_frida_symbols() {
        const SIZE: usize = 4096;
        // SAFETY: fresh anonymous page owned by this test.
        let page = unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(
                page,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            page as *mut u8
        };

        let soname_off = 1usize;
        let sym1_off = 20usize;
        let sym2_off = 37usize;
        let strtab_off = 256usize;
        let strtab: &[u8] = b"\0libfrida-gadget.so\0frida_agent_main\0puts\0";
        assert_eq!(strtab.len(), 42);
        let symtab_off = 512usize;
        let hash_off = 640usize;
        let dyn_off = 64usize;

        // SAFETY: all writes land inside our own page at the offsets above.
        unsafe {
            (page.add(0) as *mut Phdr64).write(Phdr64 {
                p_type: PT_DYNAMIC,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: dyn_off as u64,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0,
            });
            let dyn_entries: [(i64, u64); 6] = [
                (DT_STRTAB, strtab_off as u64),
                (DT_STRSZ, strtab.len() as u64),
                (DT_SYMTAB, symtab_off as u64),
                (DT_HASH, hash_off as u64),
                (DT_SONAME, soname_off as u64),
                (DT_NULL, 0),
            ];
            for (i, (tag, val)) in dyn_entries.iter().enumerate() {
                (page.add(dyn_off + i * size_of::<Dyn64>()) as *mut Dyn64).write(Dyn64 {
                    d_tag: *tag,
                    d_val: *val,
                });
            }
            std::ptr::copy_nonoverlapping(strtab.as_ptr(), page.add(strtab_off), strtab.len());
            let names = [0u32, sym1_off as u32, sym2_off as u32];
            for (i, name) in names.iter().enumerate() {
                (page.add(symtab_off + i * size_of::<Sym64>()) as *mut Sym64).write(Sym64 {
                    st_name: *name,
                    st_info: 0,
                    st_other: 0,
                    st_shndx: 0,
                    st_value: 0,
                    st_size: 0,
                });
            }
            let hash: [u32; 5] = [1, 3, 1, 0, 1];
            std::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                page.add(hash_off) as *mut u32,
                hash.len(),
            );
        }

        let mut info = DlPhdrInfo {
            addr: page as usize,
            name: c"fake.so".as_ptr(),
            phdr: page as *const c_void,
            phnum: 1,
        };
        // SAFETY: `info` describes the fake image above; the replacement
        // fits every footprint it can touch.
        let (soname_done, symbols) =
            unsafe { scrub_elf_metadata(&raw mut info, b"libnative_1.so") };
        // SAFETY: read-only checks of our own page (perms restored to R).
        // (Strings live at `strtab_off + off`, not bare `off`.)
        unsafe {
            let at =
                |off: usize| CStr::from_ptr(page.add(strtab_off + off) as *const c_char).to_bytes();
            assert!(soname_done);
            assert_eq!(symbols, 1);
            assert_eq!(at(soname_off), b"libnative_1.so");
            assert_eq!(at(sym1_off), b"libnative_1.so");
            assert_eq!(at(sym2_off), b"puts");
            assert_eq!(libc::munmap(page as *mut c_void, SIZE), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg(target_pointer_width = "64")]
    fn elf_scrub_falls_back_to_gnu_hash() {
        const SIZE: usize = 4096;
        // SAFETY: fresh anonymous page owned by this test.
        let page = unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            assert_ne!(
                page,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            page as *mut u8
        };

        let soname_off = 1usize;
        let sym1_off = 20usize;
        let sym2_off = 37usize;
        let strtab_off = 256usize;
        let strtab: &[u8] = b"\0libfrida-gadget.so\0frida_agent_main\0puts\0";
        assert_eq!(strtab.len(), 42);
        let symtab_off = 512usize;
        let gnu_off = 640usize;
        let dyn_off = 64usize;

        // SAFETY: all writes land inside our own page at the offsets above.
        unsafe {
            (page.add(0) as *mut Phdr64).write(Phdr64 {
                p_type: PT_DYNAMIC,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: dyn_off as u64,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0,
            });
            let dyn_entries: [(i64, u64); 6] = [
                (DT_STRTAB, strtab_off as u64),
                (DT_STRSZ, strtab.len() as u64),
                (DT_SYMTAB, symtab_off as u64),
                (DT_GNU_HASH, gnu_off as u64),
                (DT_SONAME, soname_off as u64),
                (DT_NULL, 0),
            ];
            for (i, (tag, val)) in dyn_entries.iter().enumerate() {
                (page.add(dyn_off + i * size_of::<Dyn64>()) as *mut Dyn64).write(Dyn64 {
                    d_tag: *tag,
                    d_val: *val,
                });
            }
            std::ptr::copy_nonoverlapping(strtab.as_ptr(), page.add(strtab_off), strtab.len());
            let names = [0u32, sym1_off as u32, sym2_off as u32];
            for (i, name) in names.iter().enumerate() {
                (page.add(symtab_off + i * size_of::<Sym64>()) as *mut Sym64).write(Sym64 {
                    st_name: *name,
                    st_info: 0,
                    st_other: 0,
                    st_shndx: 0,
                    st_value: 0,
                    st_size: 0,
                });
            }
            // One bucket fanning from symbol 1; chain stop bits end at symbol 2.
            let header: [u32; 4] = [1, 1, 1, 0];
            std::ptr::copy_nonoverlapping(
                header.as_ptr(),
                page.add(gnu_off) as *mut u32,
                header.len(),
            );
            (page.add(gnu_off + 16) as *mut u64).write(0);
            (page.add(gnu_off + 24) as *mut u32).write(1);
            let chain: [u32; 2] = [0, 1];
            std::ptr::copy_nonoverlapping(
                chain.as_ptr(),
                page.add(gnu_off + 28) as *mut u32,
                chain.len(),
            );
        }

        let mut info = DlPhdrInfo {
            addr: page as usize,
            name: c"fake.so".as_ptr(),
            phdr: page as *const c_void,
            phnum: 1,
        };
        // SAFETY: `info` describes the fake image above; the replacement
        // fits every footprint it can touch.
        let (soname_done, symbols) =
            unsafe { scrub_elf_metadata(&raw mut info, b"libnative_1.so") };
        // SAFETY: read-only checks of our own page (perms restored to R).
        unsafe {
            let at =
                |off: usize| CStr::from_ptr(page.add(strtab_off + off) as *const c_char).to_bytes();
            assert!(soname_done);
            assert_eq!(symbols, 1);
            assert_eq!(at(soname_off), b"libnative_1.so");
            assert_eq!(at(sym1_off), b"libnative_1.so");
            assert_eq!(at(sym2_off), b"puts");
            assert_eq!(libc::munmap(page as *mut c_void, SIZE), 0);
        }
    }
}
