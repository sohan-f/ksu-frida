#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Scratch dir for the fuzzed `config.json`, created once per worker: the
/// harness under test reads its config from a directory.
fn fuzz_dir() -> std::path::PathBuf {
    static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("ksufrida-fuzz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.clone()
    })
    .clone()
}

fuzz_target!(|data: &[u8]| {
    // App name: leading bytes up to the first NUL (capped, so the config
    // body below stays the bulk of the input). The config is the body after
    // the separator — or the whole input when no NUL is present — so a
    // resolving input (name match) is reachable; testing the whole data as
    // the config would make the match arm below dead (a NUL never parses).
    let split = data.iter().position(|&b| b == 0).unwrap_or(64.min(data.len()));
    let app = String::from_utf8_lossy(&data[..split]).into_owned();
    let body = if split < data.len() {
        &data[split + 1..]
    } else {
        data
    };

    let dir = fuzz_dir();
    if std::fs::write(dir.join("config.json"), body).is_err() {
        return;
    }
    // Property under test (audit A9): a resolved target must carry exactly
    // the requested name — and nothing may panic on any input.
    if let Some(name) = ksufrida_rust::fuzz_parse_config(dir.to_str().unwrap(), &app) {
        assert_eq!(name, app, "resolved target must match requested app exactly");
    }
});
