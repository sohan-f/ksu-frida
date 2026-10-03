
use std::ffi::c_void;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

use libc::{self, c_int};

use crate::log::{loge, logi};

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

pub fn remap_lib(lib_path: &str) {
    let lib_name = match lib_path.rfind('/') {
        Some(slash) => &lib_path[slash + 1..],
        None => lib_path,
    };

    let maps = get_modules_by_name(lib_name);
    if maps.is_empty() {
        return;
    }

    logi(format!("Remapping {lib_name}"));

    for info in &maps {
        let address = info.start as *mut c_void;
        let size = info.end - info.start;

        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if map == libc::MAP_FAILED {
            loge(format!(
                "Failed to Allocate Memory: {}",
                io::Error::last_os_error()
            ));
            return;
        }

        if info.perms & libc::PROT_READ == 0 {
            logi(format!("Removing memory protection: {}", info.path));
            unsafe {
                libc::mprotect(address, size, libc::PROT_READ);
            }
        }

        unsafe {
            std::ptr::copy(map as *const u8, info.start as *mut u8, size);
            let moved = crate::sys::mremap(
                map,
                size,
                size,
                crate::sys::MREMAP_MAYMOVE | crate::sys::MREMAP_FIXED,
                address,
            );
            if moved == libc::MAP_FAILED {
                loge(format!("mremap failed: {}", io::Error::last_os_error()));
            }
        }

        unsafe {
            libc::mprotect(address, size, info.perms);
        }
        logi(format!("Allocated at address {map:p} with size of {size}"));
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
}
