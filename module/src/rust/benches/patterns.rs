//! Pattern benches for doc-grounded idiom decisions.
//!
//! Each pair does the same work on the same fixture and asserts identical
//! results in setup, so a faster median means a better idiom, not different
//! behavior. Patterns mirror `src/` (whose helpers are private); winners get
//! applied to `src/` with unit tests pinning the equality.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

use divan::black_box;

fn main() {
    divan::main();
}

// Stage copy: kernel-copy chunk size and the read/write fallback ----------

const STAGE_LEN: u64 = 8 << 20;

fn scratch_base() -> std::path::PathBuf {
    // adb shells usually lack TMPDIR and /tmp; the module's world-writable
    // tmp is the device fallback. Hosts without it use std's temp dir.
    for cand in [
        std::env::var_os("TMPDIR").map(std::path::PathBuf::from),
        Some(std::path::PathBuf::from("/data/local/tmp")),
    ] {
        if let Some(dir) = cand
            && fs::create_dir_all(&dir).is_ok()
        {
            return dir;
        }
    }
    std::env::temp_dir()
}

fn stage_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = scratch_base().join(format!("ksufrida-bench-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let payload: Vec<u8> = (0..STAGE_LEN).map(|i| (i % 251) as u8).collect();
    let src = dir.join("src.bin");
    fs::write(&src, &payload).unwrap();
    (src, dir.join("dst.bin"))
}

fn open_dst(dst: &std::path::Path) -> File {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .unwrap()
}

fn cfr_copy(input: &File, output: &File, len: u64, chunk: u64) -> u64 {
    let mut remaining = len;
    while remaining > 0 {
        let n = chunk.min(remaining) as usize;
        // SAFETY: two live fds, NULL offsets (file-offset form), flags 0.
        let r = unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                input.as_raw_fd(),
                std::ptr::null::<libc::c_void>(),
                output.as_raw_fd(),
                std::ptr::null::<libc::c_void>(),
                n,
                0 as libc::c_uint,
            )
        };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if r == 0 {
            break;
        }
        remaining -= r as u64;
    }
    len - remaining
}

fn rw_copy(input: &mut File, output: &mut File) -> u64 {
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                output.write_all(&buf[..n]).unwrap();
                total += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read: {e}"),
        }
    }
    total
}

#[divan::bench]
fn stage_cfr_1g_chunk(bencher: divan::Bencher) {
    let (src, dst) = stage_fixture("cfr1g");
    let expect = fs::read(&src).unwrap();
    let n = cfr_copy(
        &File::open(&src).unwrap(),
        &open_dst(&dst),
        STAGE_LEN,
        1 << 30,
    );
    assert_eq!(
        n, STAGE_LEN,
        "kernel copy unsupported on this fs; bench is void"
    );
    assert_eq!(fs::read(&dst).unwrap(), expect);
    bencher.bench(|| {
        let n = cfr_copy(
            &File::open(black_box(&src)).unwrap(),
            &open_dst(black_box(&dst)),
            STAGE_LEN,
            1 << 30,
        );
        black_box(n)
    });
    assert_eq!(fs::read(&dst).unwrap(), expect);
    fs::remove_dir_all(dst.parent().unwrap()).ok();
}

#[divan::bench]
fn stage_cfr_1m_chunks(bencher: divan::Bencher) {
    let (src, dst) = stage_fixture("cfr1m");
    let expect = fs::read(&src).unwrap();
    let n = cfr_copy(
        &File::open(&src).unwrap(),
        &open_dst(&dst),
        STAGE_LEN,
        1 << 20,
    );
    assert_eq!(
        n, STAGE_LEN,
        "kernel copy unsupported on this fs; bench is void"
    );
    assert_eq!(fs::read(&dst).unwrap(), expect);
    bencher.bench(|| {
        let n = cfr_copy(
            &File::open(black_box(&src)).unwrap(),
            &open_dst(black_box(&dst)),
            STAGE_LEN,
            1 << 20,
        );
        black_box(n)
    });
    assert_eq!(fs::read(&dst).unwrap(), expect);
    fs::remove_dir_all(dst.parent().unwrap()).ok();
}

#[divan::bench]
fn stage_rw_64k_loop(bencher: divan::Bencher) {
    let (src, dst) = stage_fixture("rw64k");
    let expect = fs::read(&src).unwrap();
    let n = rw_copy(&mut File::open(&src).unwrap(), &mut open_dst(&dst));
    assert_eq!(n, STAGE_LEN);
    assert_eq!(fs::read(&dst).unwrap(), expect);
    bencher.bench(|| {
        let n = rw_copy(
            &mut File::open(black_box(&src)).unwrap(),
            &mut open_dst(black_box(&dst)),
        );
        black_box(n)
    });
    assert_eq!(fs::read(&dst).unwrap(), expect);
    fs::remove_dir_all(dst.parent().unwrap()).ok();
}

// Maps parse: hand splitter chain vs split_whitespace ----------------------

fn next_field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

fn parse_next_field(lines: &[String]) -> (usize, usize) {
    let mut count = 0;
    let mut starts = 0usize;
    for line in lines {
        let Some((range, rest)) = next_field(line) else {
            continue;
        };
        let Some((_perms, _)) = next_field(rest) else {
            continue;
        };
        let Some((start_hex, _)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_hex, 16) else {
            continue;
        };
        count += 1;
        starts = starts.wrapping_add(start);
    }
    (count, starts)
}

fn parse_split_whitespace(lines: &[String]) -> (usize, usize) {
    let mut count = 0;
    let mut starts = 0usize;
    for line in lines {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(_)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some((start_hex, _)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_hex, 16) else {
            continue;
        };
        count += 1;
        starts = starts.wrapping_add(start);
    }
    (count, starts)
}

#[divan::bench]
fn maps_next_field_chain(bencher: divan::Bencher) {
    let lines: Vec<String> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(parse_next_field(&lines), parse_split_whitespace(&lines));
    bencher.bench(|| black_box(parse_next_field(black_box(&lines))));
}

#[divan::bench]
fn maps_split_whitespace(bencher: divan::Bencher) {
    let lines: Vec<String> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(parse_next_field(&lines), parse_split_whitespace(&lines));
    bencher.bench(|| black_box(parse_split_whitespace(black_box(&lines))));
}

// Relocate copy: memmove vs memcpy on anon mappings ------------------------

fn anon_pair(size: usize) -> (*mut u8, *mut u8) {
    // SAFETY: fresh anonymous mappings; failure aborts the bench setup.
    unsafe {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;
        let src = libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0);
        let dst = libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0);
        assert_ne!(src, libc::MAP_FAILED);
        assert_ne!(dst, libc::MAP_FAILED);
        let src = src as *mut u8;
        for i in 0..size {
            src.add(i).write((i % 251) as u8);
        }
        (src, dst as *mut u8)
    }
}

// SAFETY: both regions are live `size`-byte mappings from `anon_pair`.
unsafe fn region_eq(a: *const u8, b: *const u8, size: usize) -> bool {
    unsafe { std::slice::from_raw_parts(a, size) == std::slice::from_raw_parts(b, size) }
}

// SAFETY: both regions are live `size`-byte mappings from `anon_pair`.
unsafe fn unmap_pair(src: *mut u8, dst: *mut u8, size: usize) {
    unsafe {
        libc::munmap(src as *mut libc::c_void, size);
        libc::munmap(dst as *mut libc::c_void, size);
    }
}

#[divan::bench(args = [4096, 65536, 1048576, 8388608])]
fn relocate_ptr_copy(bencher: divan::Bencher, size: usize) {
    let (src, dst) = anon_pair(size);
    // SAFETY: scratch-to-live shape from `relocate_segment`; non-overlapping.
    unsafe { std::ptr::copy(src, dst, size) };
    assert!(unsafe { region_eq(src, dst, size) });
    bencher
        .bench_local(|| unsafe { std::ptr::copy(black_box(src), black_box(dst), black_box(size)) });
    assert!(unsafe { region_eq(src, dst, size) });
    unsafe { unmap_pair(src, dst, size) };
}

#[divan::bench(args = [4096, 65536, 1048576, 8388608])]
fn relocate_copy_nonoverlapping(bencher: divan::Bencher, size: usize) {
    let (src, dst) = anon_pair(size);
    // SAFETY: as above.
    unsafe { std::ptr::copy_nonoverlapping(src, dst, size) };
    assert!(unsafe { region_eq(src, dst, size) });
    bencher.bench_local(|| unsafe {
        std::ptr::copy_nonoverlapping(black_box(src), black_box(dst), black_box(size))
    });
    assert!(unsafe { region_eq(src, dst, size) });
    unsafe { unmap_pair(src, dst, size) };
}

// Scrub scan: windows + eq_ignore_ascii_case vs naive manual loop ----------

fn build_dynstr(nsyms: usize) -> (Vec<u8>, Vec<u32>) {
    let mut strtab = vec![0u8];
    let mut offs = Vec::with_capacity(nsyms);
    for i in 0..nsyms {
        let name = if i % 50 == 7 {
            format!("FrIdA_hook_{i}")
        } else {
            format!("sym_{i}")
        };
        offs.push(strtab.len() as u32);
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    (strtab, offs)
}

fn name_of(strtab: &[u8], off: u32) -> &[u8] {
    let rest = &strtab[off as usize..];
    let len = rest.iter().position(|&b| b == 0).unwrap();
    &rest[..len]
}

fn scan_windows(strtab: &[u8], offs: &[u32]) -> usize {
    offs.iter()
        .filter(|&&o| {
            let name = name_of(strtab, o);
            name.len() >= 5 && name.windows(5).any(|w| w.eq_ignore_ascii_case(b"frida"))
        })
        .count()
}

fn scan_naive(strtab: &[u8], offs: &[u32]) -> usize {
    const NEEDLE: &[u8; 5] = b"frida";
    offs.iter()
        .filter(|&&o| {
            let name = name_of(strtab, o);
            name.len() >= 5
                && (0..=name.len() - 5).any(|i| {
                    NEEDLE
                        .iter()
                        .enumerate()
                        .all(|(j, &n)| name[i + j].to_ascii_lowercase() == n)
                })
        })
        .count()
}

#[divan::bench(args = [512, 8192])]
fn scrub_scan_windows(bencher: divan::Bencher, nsyms: usize) {
    let (strtab, offs) = build_dynstr(nsyms);
    assert_eq!(scan_windows(&strtab, &offs), scan_naive(&strtab, &offs));
    bencher.bench(|| black_box(scan_windows(black_box(&strtab), black_box(&offs))));
}

#[divan::bench(args = [512, 8192])]
fn scrub_scan_naive(bencher: divan::Bencher, nsyms: usize) {
    let (strtab, offs) = build_dynstr(nsyms);
    assert_eq!(scan_windows(&strtab, &offs), scan_naive(&strtab, &offs));
    bencher.bench(|| black_box(scan_naive(black_box(&strtab), black_box(&offs))));
}

// Zero-cost proof for applied opts: old vs new on the same fixture ---------

fn prot_old(perms: &str) -> i32 {
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
    prot
}

fn prot_new(perms: &str) -> i32 {
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

const PERMS_FIXTURE: [&str; 8] = [
    "r--p", "rw-p", "r-xp", "rwxp", "---p", "r--s", "rw-s", "r-xs",
];

#[divan::bench]
fn prot_contains_old(bencher: divan::Bencher) {
    for p in PERMS_FIXTURE {
        assert_eq!(prot_old(p), prot_new(p));
    }
    bencher.bench(|| {
        let mut acc = 0;
        for p in PERMS_FIXTURE {
            acc += black_box(prot_old(black_box(p)));
        }
        black_box(acc)
    });
}

#[divan::bench]
fn prot_bytes_new(bencher: divan::Bencher) {
    for p in PERMS_FIXTURE {
        assert_eq!(prot_old(p), prot_new(p));
    }
    bencher.bench(|| {
        let mut acc = 0;
        for p in PERMS_FIXTURE {
            acc += black_box(prot_new(black_box(p)));
        }
        black_box(acc)
    });
}

fn parse_alloc_old(line: &str) -> Option<(usize, usize, i32)> {
    let mut parts = line.trim_start().splitn(6, ' ');
    let (range, perms, _, _, _, path) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    let (s, e) = range.split_once('-')?;
    let (Ok(start), Ok(end)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
        return None;
    };
    let _owned: String = path.trim().to_string();
    Some((start, end, prot_new(perms)))
}

fn parse_range_new(line: &str) -> Option<(usize, usize, i32)> {
    let mut parts = line.trim_start().splitn(6, ' ');
    let (range, perms) = (parts.next()?, parts.next()?);
    let (s, e) = range.split_once('-')?;
    let (Ok(start), Ok(end)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
        return None;
    };
    Some((start, end, prot_new(perms)))
}

#[divan::bench]
fn maps_parse_alloc_old(bencher: divan::Bencher) {
    let lines: Vec<String> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let old: Vec<_> = lines.iter().map(|l| parse_alloc_old(l)).collect();
    let new: Vec<_> = lines.iter().map(|l| parse_range_new(l)).collect();
    assert_eq!(old, new);
    bencher.bench(|| black_box(lines.iter().filter_map(|l| parse_alloc_old(l)).count()));
}

#[divan::bench]
fn maps_parse_range_new(bencher: divan::Bencher) {
    let lines: Vec<String> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let old: Vec<_> = lines.iter().map(|l| parse_alloc_old(l)).collect();
    let new: Vec<_> = lines.iter().map(|l| parse_range_new(l)).collect();
    assert_eq!(old, new);
    bencher.bench(|| black_box(lines.iter().filter_map(|l| parse_range_new(l)).count()));
}

fn cmdline_string_old(expected: &str) -> bool {
    let name: String = fs::read("/proc/self/cmdline")
        .ok()
        .and_then(|bytes| {
            bytes
                .split(|b| *b == 0)
                .next()
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
        })
        .unwrap_or_default();
    name == expected
}

fn cmdline_stack_new(expected: &str) -> bool {
    let Ok(f) = File::open("/proc/self/cmdline") else {
        return false;
    };
    if expected.len() > 256 {
        return cmdline_string_old(expected);
    }
    let mut buf = [0u8; 256];
    // SAFETY: `read` into our own stack buffer; return checked below.
    let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return false;
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    buf[..end] == *expected.as_bytes()
}

#[divan::bench]
fn cmdline_string_old_bench(bencher: divan::Bencher) {
    let expect = fs::read("/proc/self/cmdline").unwrap();
    let end = expect.iter().position(|&b| b == 0).unwrap_or(expect.len());
    let expect_str = String::from_utf8_lossy(&expect[..end]).into_owned();
    assert_eq!(
        cmdline_string_old(&expect_str),
        cmdline_stack_new(&expect_str)
    );
    bencher.bench(|| black_box(cmdline_string_old(black_box(&expect_str))));
}

#[divan::bench]
fn cmdline_stack_new_bench(bencher: divan::Bencher) {
    let expect = fs::read("/proc/self/cmdline").unwrap();
    let end = expect.iter().position(|&b| b == 0).unwrap_or(expect.len());
    let expect_str = String::from_utf8_lossy(&expect[..end]).into_owned();
    assert_eq!(
        cmdline_string_old(&expect_str),
        cmdline_stack_new(&expect_str)
    );
    bencher.bench(|| black_box(cmdline_stack_new(black_box(&expect_str))));
}

#[divan::bench]
fn memfd_cstring_alloc(bencher: divan::Bencher) {
    use std::ffi::CString;
    bencher.bench(|| black_box(CString::new(black_box("dalvik-jit-cache")).unwrap()));
}

#[divan::bench]
fn memfd_cstr_literal(bencher: divan::Bencher) {
    let lit: &std::ffi::CStr = c"dalvik-jit-cache";
    assert_eq!(lit.to_bytes(), b"dalvik-jit-cache");
    bencher.bench(|| black_box(lit.as_ptr()));
}
