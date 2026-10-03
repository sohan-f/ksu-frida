
use std::ffi::{CStr, c_char, c_int, c_void};

use crate::log::{loge, logi};
use crate::sys::{DlIterateCb, DlPhdrInfo, dl_iterate_phdr};

struct ScrubSearch {
    target: Vec<u8>,
    replacement: Vec<u8>,
    found: bool,
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
    if current != search.target.as_slice() {
        return 0;
    }
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

pub fn scrub_dlpi_name(staged_path: &str) {
    // SAFETY: `getpid(2)` cannot fail.
    let pid = unsafe { libc::getpid() };
    let mut search = ScrubSearch {
        target: staged_path.as_bytes().to_vec(),
        replacement: format!("libnative_{pid}.so").into_bytes(),
        found: false,
    };

    // SAFETY: `scrub_callback` matches the `DlIterateCb` signature; `search`
    // outlives the synchronous walk; the return value (entries visited) is
    // informational only.
    unsafe {
        dl_iterate_phdr(
            scrub_callback as DlIterateCb,
            (&mut search as *mut ScrubSearch).cast::<c_void>(),
        );
    }

    if search.found {
        logi(format!("Scrubbed linker name for {staged_path}"));
    } else {
        loge(format!(
            "linkmap: no dl_iterate_phdr entry matched {staged_path}; name left visible"
        ));
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

    /// SAFETY: `ptr` came from `raw_cstring` above and is freed exactly once
    unsafe fn free_cstring(ptr: *mut c_char, orig_len: usize) {
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
        };
        let data = (&mut search as *mut ScrubSearch).cast::<c_void>();

        // SAFETY: both entries are live owned strings; `search` outlives them.
        unsafe {
            assert_eq!(scrub_callback(&mut first_entry, 0, data), 0);
            assert_eq!(scrub_callback(&mut second_entry, 0, data), 1);
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
        };
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                scrub_callback(
                    &mut only_entry,
                    0,
                    (&mut search as *mut ScrubSearch).cast::<c_void>()
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
}
