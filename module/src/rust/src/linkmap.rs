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
#[inline(always)]
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
    size: usize,
    data: *mut c_void,
) -> c_int {
    // The linker may pass a larger struct as fields are added; the first
    // four (through `phnum`) are stable. A smaller `size` means even those
    // cannot be trusted.
    if size < size_of::<DlPhdrInfo>() {
        return 0;
    }
    // SAFETY: linker entry is valid for a field read; null precedes any string deref.
    if unsafe { (*info).name.is_null() } {
        return 0;
    }
    // SAFETY: the linker hands the callback a valid entry; `data` is our
    // search struct, alive for the whole synchronous walk.
    let (current, search) = unsafe {
        let name = CStr::from_ptr((*info).name);
        (name.to_bytes(), &mut *(data.cast::<ScrubSearch>()))
    };
    let matched = entry_matches(current, &search.target, search.substring);
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
    // Stop at the first match; each staged lib rescans, so later calls converge on later entries.
    1
}

#[inline(always)]
fn entry_matches(current: &[u8], target: &[u8], substring: bool) -> bool {
    if substring {
        if target.is_empty() {
            return false;
        }
        // First-byte skip: linker names share prefixes, a full memcmp is rare.
        let first = target[0];
        current
            .windows(target.len())
            .any(|w| w[0] == first && w == target)
    } else {
        current == target
    }
}

struct VisibleSearch {
    target: Vec<u8>,
    substring: bool,
    leaked: bool,
}

/// Read-only walk like [`scrub_callback`], but visits every entry: `scrub`
/// stops at the first match, so a later duplicate would survive it.
unsafe extern "C" fn verify_callback(
    info: *mut DlPhdrInfo,
    size: usize,
    data: *mut c_void,
) -> c_int {
    // Only `dlpi_name` is read; it predates every later field.
    if size < std::mem::offset_of!(DlPhdrInfo, name) + size_of::<*const c_char>() {
        return 0;
    }
    // SAFETY: linker entry is valid for a field read; null precedes any string deref.
    if unsafe { (*info).name.is_null() } {
        return 0;
    }
    // SAFETY: the linker hands the callback a valid entry; `data` is our
    // search struct, alive for the whole synchronous walk.
    let (current, search) = unsafe {
        let name = CStr::from_ptr((*info).name);
        (name.to_bytes(), &mut *(data.cast::<VisibleSearch>()))
    };
    if entry_matches(current, &search.target, search.substring) {
        search.leaked = true;
    }
    0
}

/// Reports whether any linker entry still shows `target`.
pub fn is_linker_visible(target: &str, substring: bool) -> bool {
    let mut search = VisibleSearch {
        target: target.as_bytes().to_vec(),
        substring,
        leaked: false,
    };
    // SAFETY: `verify_callback` matches the `DlIterateCb` signature; `search`
    // outlives the synchronous walk.
    unsafe {
        dl_iterate_phdr(
            verify_callback as DlIterateCb,
            std::ptr::from_mut(&mut search).cast::<c_void>(),
        );
    }
    search.leaked
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

/// Fuzz driver for [`scrub_elf_metadata`]: carves an adversarial but
/// container-consistent image out of one mapping and walks it.
///
/// Consistency contract: placements live in fixed disjoint arenas, so
/// tables can never collide; only table *values* are adversarial. Any
/// fault is therefore a real finding. The guards themselves get hostile
/// values: unbounded `strsz` (mprotect gate), oversized `nchain` (cap
/// skip), out-of-range name offsets (skips). Middle `nchain` values would
/// read past any fixed-size table by construction, so they fold to the
/// walked maximum; the cap boundary itself is pinned by unit test.
#[cfg(fuzzing)]
pub fn fuzz_scrub_elf(data: &[u8]) {
    const PAGE: usize = 65536;
    const HEADER: usize = 24;
    if data.len() < HEADER {
        return;
    }
    let u16le = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    let u32le =
        |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
    let pool = |k: usize| data.get(HEADER + k).copied().unwrap_or(0);

    // SAFETY: fresh anonymous mapping owned by this call; unmapped at return.
    let page = unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            return;
        }
        page as *mut u8
    };
    // SAFETY: every write below lands in its fixed disjoint arena inside
    // the mapping above; sizes are constants, values adversarial.
    unsafe {
        // Fixed disjoint arenas: placements never overlap (an earlier
        // revision masked offsets independently and the tables collided,
        // corrupting values the reader trusts). Only table *values* below
        // are adversarial; every computed read stays inside these rooms.
        let phdr_off = 64usize;
        let phnum = (data[2] % 4) as u16;
        let dyn_off = 256usize;
        let dyn_count = (data[5] % 8) as usize + 1;
        let strtab_off = 4096usize;
        let room_small = 4096usize;
        let strsz = u32le(8);
        let symtab_off = 12288usize;
        const SYMS_HELD: usize = 257;
        let nchain_raw = u32le(14);
        let nchain = if nchain_raw > MAX_SYMBOLS {
            nchain_raw
        } else {
            nchain_raw.min(SYMS_HELD - 1)
        };
        let hash_kind = data[18] % 3;
        let soname_off = u16le(19) % (room_small + 64);
        let hash_off = 18464usize;
        let gnu_off = 22560usize;

        for i in 0..room_small {
            page.add(strtab_off + i).write(pool(i));
        }
        for i in 0..SYMS_HELD {
            let name =
                u16::from_le_bytes([pool(2 * i), pool(2 * i + 1)]) as usize % (room_small + 64);
            (page.add(symtab_off + i * size_of::<Sym>()) as *mut Sym).write_unaligned(Sym {
                st_name: name as u32,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            });
        }
        (page.add(hash_off) as *mut u32).write_unaligned(pool(500) as u32 % 8);
        (page.add(hash_off + 4) as *mut u32).write_unaligned(nchain as u32);
        // Small symoffset walks the chains; huge symoffset skips them all.
        let symoffset = if pool(501) % 2 == 0 {
            (pool(502) % 64) as u32
        } else {
            0x8000_0000 + (pool(502) as u32 % 256)
        };
        let gbloom = pool(504) as u32 % 4;
        // Chain-prone bodies get stop bits first: the reader may land on any
        // of these words as buckets or chain links, and 0xFF either skips
        // (huge sym) or stops the walk on the first link. Headers and the
        // single live bucket below overwrite the words the reader uses.
        for &base in &[hash_off, gnu_off] {
            for i in 0..512usize {
                (page.add(base + 16 + i * 4) as *mut u32).write_unaligned(0xFFFF_FFFF);
            }
        }
        (page.add(hash_off + 8) as *mut u32).write_unaligned(0);
        (page.add(hash_off + 12) as *mut u32).write_unaligned(0);
        (page.add(hash_off + 16) as *mut u32).write_unaligned(nchain as u32);
        (page.add(gnu_off) as *mut u32).write_unaligned(pool(503) as u32 % 8);
        (page.add(gnu_off + 4) as *mut u32).write_unaligned(symoffset);
        (page.add(gnu_off + 8) as *mut u32).write_unaligned(gbloom);
        (page.add(gnu_off + 12) as *mut u32).write_unaligned(pool(505) as u32);
        (page.add(gnu_off + 16 + gbloom as usize * 8) as *mut u32).write_unaligned(symoffset);
        let tags = [
            DT_STRTAB,
            DT_STRSZ,
            DT_SYMTAB,
            hash_tag(hash_kind),
            DT_SONAME,
            1,
            0x6fff_fff1,
        ];
        let vals = [
            strtab_off as u64,
            strsz as u64,
            symtab_off as u64,
            (if hash_kind == 1 { hash_off } else { gnu_off }) as u64,
            soname_off as u64,
            pool(506) as u64,
            pool(507) as u64,
        ];
        for k in 0..dyn_count {
            let (tag, val) = if k + 1 == dyn_count && pool(508) % 4 != 0 {
                (DT_NULL, 0)
            } else {
                let pick = pool(510 + k) as usize % tags.len();
                (tags[pick], vals[pick])
            };
            (page.add(dyn_off + k * size_of::<Dyn>()) as *mut Dyn).write_unaligned(Dyn {
                d_tag: tag as _,
                d_val: val as _,
            });
        }
        for k in 0..phnum as usize {
            let p_type = if pool(520 + k) % 2 == 0 {
                PT_DYNAMIC
            } else {
                1
            };
            (page.add(phdr_off + k * size_of::<Phdr>()) as *mut Phdr).write_unaligned(Phdr {
                p_type,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: dyn_off as _,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0,
            });
        }

        let mut info = crate::sys::DlPhdrInfo {
            addr: page as usize,
            name: c"fake.so".as_ptr(),
            phdr: page.add(phdr_off) as *const c_void,
            phnum,
        };
        if std::env::var_os("KSUFRIDA_FUZZ_TRACE").is_some() {
            eprintln!(
                "page={page:p} phdr_off={phdr_off} phnum={phnum} dyn_off={dyn_off} \
                 strtab_off={strtab_off} strsz={strsz} symtab_off={symtab_off} \
                 nchain={nchain_raw} kind={hash_kind} soname={soname_off} \
                 hash={hash_off} gnu={gnu_off} end={:p}",
                (page as usize + PAGE) as *const u8,
            );
            for k in 0..dyn_count {
                // Slots just written above, all inside the mapping.
                let d = (page.add(dyn_off + k * size_of::<Dyn>()) as *const Dyn).read_unaligned();
                eprintln!("dyn[{k}]: tag={} val={}", d.d_tag as i64, d.d_val as u64);
            }
        }
        // SAFETY: the image above upholds the callee's container contract
        // (valid phdr/dyn tables in one live mapping); only table *values*
        // are adversarial, which is exactly what is under test.
        let _ = scrub_elf_metadata(&raw mut info, b"libnative_1.so");
        libc::munmap(page as *mut c_void, PAGE);
    }
}

#[cfg(fuzzing)]
fn hash_tag(kind: u8) -> i64 {
    if kind == 1 { DT_HASH } else { DT_GNU_HASH }
}

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
#[inline(always)]
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

#[inline(always)]
fn contains_frida(name: &[u8]) -> bool {
    if name.len() < 5 {
        return false;
    }
    name.windows(5)
        .any(|w| (w[0] | 32) == b'f' && w.eq_ignore_ascii_case(b"frida"))
}

struct WritableWindow {
    start: usize,
    len: usize,
    perms: c_int,
    label: &'static str,
}

impl WritableWindow {
    /// # Safety
    /// `[addr, addr + len)` must name readable memory we own (our own
    /// tables); flipping it writable is safe exactly then.
    unsafe fn open(addr: usize, len: usize, label: &'static str) -> Option<Self> {
        // Page size is fixed for the process lifetime; one syscall total.
        static PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        // SAFETY: `sysconf(3)` takes a constant and reports errors via -1.
        let page = *PAGE_SIZE.get_or_init(|| unsafe {
            let ps = libc::sysconf(libc::_SC_PAGESIZE);
            if ps <= 0 { 4096 } else { ps as usize }
        });
        debug_assert!(page.is_power_of_two());
        if len == 0 {
            return None;
        }
        let end = addr.checked_add(len)?;
        // The range must sit inside a single live mapping: a corrupt size
        // would otherwise widen onto neighbor mappings, and the restore
        // below would clobber their protections.
        let perms = crate::remap::mapped_perms(addr, end)?;
        let start = addr & !(page - 1);
        let end = end.checked_add(page - 1)? & !(page - 1);
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
            perms,
            label,
        })
    }
}

impl Drop for WritableWindow {
    fn drop(&mut self) {
        // SAFETY: the range `open` flipped; best-effort restore of the
        // protections it had (a blanket PROT_READ would strip neighbors
        // sharing the rounded pages).
        if unsafe { libc::mprotect(self.start as *mut c_void, self.len, self.perms) } != 0 {
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
            // Fail closed on wrap: a wrapped base would scrub the wrong object.
            let Some(addr) = base.checked_add(p.p_vaddr as usize) else {
                return (false, 0);
            };
            dyn_addr = addr;
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
    // Fail closed on wrap; zero offsets resolve to `base` (absent-table sentinel below).
    let (Some(strtab), Some(symtab), Some(hash), Some(gnu_hash)) = (
        base.checked_add(strtab),
        base.checked_add(symtab),
        base.checked_add(hash),
        base.checked_add(gnu_hash),
    ) else {
        return (false, 0);
    };

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
        // Spent budget cannot extend the count; later buckets read nothing new.
        if budget == 0 {
            break;
        }
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
#[cold]
unsafe extern "C" fn log_names_callback(
    info: *mut DlPhdrInfo,
    _size: usize,
    _data: *mut c_void,
) -> c_int {
    // SAFETY: linker entry is valid for a field read; null precedes any string deref.
    if unsafe { (*info).name.is_null() } {
        return 0;
    }
    // SAFETY: linker-provided entry, read-only copy for logging.
    unsafe {
        let name = CStr::from_ptr((*info).name).to_string_lossy();
        logi_fmt(format_args!("linkmap entry: {name}"));
    }
    0
}

#[cold]
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

/// Scrub the memfd entry (`/memfd:dalvik-jit-cache`) created by `try_memfd_inject`.
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

    fn entry_size() -> usize {
        size_of::<DlPhdrInfo>()
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
            assert_eq!(scrub_callback(&raw mut first_entry, entry_size(), data), 0);
            assert_eq!(scrub_callback(&raw mut second_entry, entry_size(), data), 1);
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
                scrub_callback(
                    &raw mut only_entry,
                    entry_size(),
                    (&raw mut search).cast::<c_void>()
                ),
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
    fn undersized_phdr_info_is_ignored() {
        let only = raw_cstring("/data/data/com.a.b/.cache/1234/libsecmon.so");
        let mut only_entry = entry(only);
        let mut search = ScrubSearch {
            target: b"/data/data/com.a.b/.cache/1234/libsecmon.so".to_vec(),
            replacement: b"libnative_1.so".to_vec(),
            found: false,
            soname: false,
            symbols: 0,
            substring: false,
        };
        // SAFETY: live owned string; undersized `size` must stop before touching it.
        unsafe {
            assert_eq!(
                scrub_callback(
                    &raw mut only_entry,
                    entry_size() - 1,
                    (&raw mut search).cast::<c_void>()
                ),
                0
            );
            assert_eq!(
                CStr::from_ptr(only).to_bytes(),
                b"/data/data/com.a.b/.cache/1234/libsecmon.so"
            );
            free_cstring(only, 43);
        }
        assert!(!search.found);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // dl_iterate_phdr(3) has no Miri shim
    fn null_dlpi_name_is_ignored() {
        let mut null_entry = entry(std::ptr::null());
        let mut search = ScrubSearch {
            target: b"/a.so".to_vec(),
            replacement: b"libnative_1.so".to_vec(),
            found: false,
            soname: false,
            symbols: 0,
            substring: false,
        };
        // SAFETY: null name must return before any string read.
        unsafe {
            assert_eq!(
                scrub_callback(
                    &raw mut null_entry,
                    entry_size(),
                    (&raw mut search).cast::<c_void>()
                ),
                0
            );
        }
        assert!(!search.found);
        assert!(!is_linker_visible(
            "definitely-absent-ksufrida-xyz-null",
            false
        ));
    }

    #[test]
    fn entry_match_covers_exact_and_substring() {
        assert!(entry_matches(b"/a/b.so", b"/a/b.so", false));
        assert!(!entry_matches(b"/a/b.so", b"/a/c.so", false));
        assert!(!entry_matches(b"/a/b.so", b"", false));
        assert!(entry_matches(
            b"/memfd:jit-cache (deleted)",
            b"jit-cache",
            true
        ));
        assert!(!entry_matches(b"/system/lib/libc.so", b"jit-cache", true));
        assert!(!entry_matches(b"abc", b"", true));
        assert!(!entry_matches(b"short", b"much longer needle", true));
        assert!(!entry_matches(b"short", b"much longer needle", false));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // dl_iterate_phdr(3) has no Miri shim
    fn verify_walk_finds_libc_and_misses_absent_names() {
        assert!(is_linker_visible("libc.so", true));
        assert!(!is_linker_visible(
            "definitely-absent-ksufrida-xyz.so",
            false
        ));
        assert!(!is_linker_visible("definitely-absent-ksufrida-xyz", true));
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
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2) have no Miri shims
    fn window_refuses_range_past_its_mapping() {
        const SIZE: usize = 4096;
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
            addr as *mut u8
        };
        // SAFETY: `addr` is live; no single VMA can span to usize::MAX, so
        // no window may open. A just-past-the-end range would work too, but
        // the kernel may merge our page into a larger neighbor VMA.
        unsafe {
            assert!(
                WritableWindow::open(addr as usize, usize::MAX - addr as usize, "test").is_none()
            );
            assert_eq!(libc::munmap(addr as *mut c_void, SIZE), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // mmap(2)/mprotect(2) have no Miri shims
    fn window_restore_keeps_original_protections() {
        const SIZE: usize = 4096;
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
            addr as *mut u8
        };
        {
            // SAFETY: `addr`/`SIZE` is our live mapping.
            let _window =
                unsafe { WritableWindow::open(addr as usize, SIZE, "test").expect("window") };
        }
        // SAFETY: still ours; a blanket PROT_READ restore would fault here.
        unsafe {
            addr.write_bytes(0x5A, SIZE);
            assert_eq!(libc::munmap(addr as *mut c_void, SIZE), 0);
        }
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
                scrub_callback(
                    &raw mut memfd_entry,
                    entry_size(),
                    (&raw mut search).cast::<c_void>()
                ),
                1
            );
        }
        assert!(search.found);
        // SAFETY: read-only check, then freed by original length (26).
        unsafe {
            assert_eq!(CStr::from_ptr(memfd).to_bytes(), b"libnative_1.so");
            free_cstring(memfd, 26);
        }
    }

    #[test]
    fn scrub_tables_rewrites_only_frida_names() {
        let strtab = b"\0frida_agent\0puts\0".to_vec();
        let syms = [
            Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Sym {
                st_name: 1,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Sym {
                st_name: 13,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
        ];
        // SAFETY: both buffers outlive the call; every access stays inside measured footprints.
        let (soname_done, symbols) = unsafe {
            scrub_tables(
                strtab.as_ptr() as usize,
                strtab.len(),
                syms.as_ptr() as usize,
                0,
                syms.len(),
                Some(1),
                b"X",
            )
        };
        assert!(soname_done);
        assert_eq!(symbols, 1);
        // SAFETY: read-only checks of our own buffer.
        unsafe {
            let at =
                |off: usize| CStr::from_ptr(strtab.as_ptr().add(off) as *const c_char).to_bytes();
            assert_eq!(at(1), b"X");
            assert_eq!(at(13), b"puts");
        }
    }

    #[test]
    fn scrub_tables_skips_overcapped_symbol_counts() {
        let strtab = b"\0frida_agent\0".to_vec();
        let syms = [Sym {
            st_name: 1,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        }];
        // SAFETY: both buffers outlive the call; the count exceeds the cap
        // so no symbol entry is read at all.
        let (soname_done, symbols) = unsafe {
            scrub_tables(
                strtab.as_ptr() as usize,
                strtab.len(),
                syms.as_ptr() as usize,
                0,
                MAX_SYMBOLS + 1,
                None,
                b"X",
            )
        };
        assert_eq!(symbols, 0);
        assert!(!soname_done);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn gnu_nsyms_counts_chained_symbols() {
        let mut blob = vec![1u32, 1, 1, 0];
        blob.extend([0u32, 0]);
        blob.extend([1u32]);
        blob.extend([0u32, 1]);
        // SAFETY: blob outlives the call; header counts bound every read.
        assert_eq!(unsafe { gnu_nsyms(blob.as_ptr() as usize) }, 3);

        let empty = [0u32, 1, 1, 0];
        // SAFETY: as above; zero buckets short-circuits.
        assert_eq!(unsafe { gnu_nsyms(empty.as_ptr() as usize) }, 0);
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

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg(target_pointer_width = "64")]
    fn elf_scrub_sysv_count_wins_and_skips_overcap() {
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
        let gnu_off = 768usize;
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
            let dyn_entries: [(i64, u64); 7] = [
                (DT_STRTAB, strtab_off as u64),
                (DT_STRSZ, strtab.len() as u64),
                (DT_SYMTAB, symtab_off as u64),
                (DT_HASH, hash_off as u64),
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
            // Oversized chain count: the SysV count is skipped outright.
            let hash: [u32; 2] = [1, (MAX_SYMBOLS + 5) as u32];
            std::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                page.add(hash_off) as *mut u32,
                hash.len(),
            );
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
        // fits every footprint it can touch. The oversized SysV count wins
        // over the live GNU table, so no symbol is walked or rewritten.
        let (soname_done, symbols) =
            unsafe { scrub_elf_metadata(&raw mut info, b"libnative_1.so") };
        // SAFETY: read-only checks of our own page (perms restored to R).
        unsafe {
            let at =
                |off: usize| CStr::from_ptr(page.add(strtab_off + off) as *const c_char).to_bytes();
            assert!(soname_done);
            assert_eq!(symbols, 0);
            assert_eq!(at(soname_off), b"libnative_1.so");
            assert_eq!(at(sym1_off), b"frida_agent_main");
            assert_eq!(at(sym2_off), b"puts");
            assert_eq!(libc::munmap(page as *mut c_void, SIZE), 0);
        }
    }
}
