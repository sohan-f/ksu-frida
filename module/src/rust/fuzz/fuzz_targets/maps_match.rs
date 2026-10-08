#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ksufrida_rust::fuzz_maps_match(data);
});
