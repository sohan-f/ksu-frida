
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

    fn entry(name: &str, entries: &mut Vec<CString>) -> DlPhdrInfo {
        entries.push(CString::new(name).unwrap());
        DlPhdrInfo {
            addr: 0,
            name: entries.last().unwrap().as_ptr(),
            phdr: std::ptr::null(),
            phnum: 0,
        }
    }

    #[test]
    fn callback_scrubs_only_the_matching_entry() {
        let mut owned = Vec::new();
        let mut first = entry("/system/lib/libc.so", &mut owned);
        let mut second = entry("/data/data/com.a.b/.cache/1234/libsecmon.so", &mut owned);

        let mut search = ScrubSearch {
            target: b"/data/data/com.a.b/.cache/1234/libsecmon.so".to_vec(),
            replacement: b"libnative_1234.so".to_vec(),
            found: false,
        };
        let data = (&mut search as *mut ScrubSearch).cast::<c_void>();

        // SAFETY: both entries are live `CString`s; `search` outlives the calls.
        unsafe {
            assert_eq!(scrub_callback(&mut first, 0, data), 0);
            assert_eq!(scrub_callback(&mut second, 0, data), 1);
        }

        assert!(search.found);
        // SAFETY: `owned` still owns both strings.
        unsafe {
            assert_eq!(
                CStr::from_ptr(first.name).to_bytes(),
                b"/system/lib/libc.so"
            );
            assert_eq!(CStr::from_ptr(second.name).to_bytes(), b"libnative_1234.so");
        }
    }

    #[test]
    fn overwrite_truncates_instead_of_overflowing() {
        let owned = CString::new("/a/b.so").unwrap();
        let ptr = owned.as_ptr() as *mut c_char;
        // SAFETY: 7 payload bytes + NUL are ours; the replacement is longer.
        unsafe {
            overwrite_in_place(ptr, 7, b"libnative_99999.so");
        }
        assert_eq!(owned.as_bytes(), b"libnati");
    }

    #[test]
    fn missing_entry_reports_not_found() {
        let mut owned = Vec::new();
        let mut only = entry("/system/lib/libc.so", &mut owned);
        let mut search = ScrubSearch {
            target: b"/nope.so".to_vec(),
            replacement: b"libnative_1.so".to_vec(),
            found: false,
        };
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                scrub_callback(
                    &mut only,
                    0,
                    (&mut search as *mut ScrubSearch).cast::<c_void>()
                ),
                0
            );
        }
        assert!(!search.found);
    }
}
