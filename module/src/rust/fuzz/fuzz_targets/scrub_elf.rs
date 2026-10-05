#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ksufrida_rust::fuzz_scrub_elf(data);
});
