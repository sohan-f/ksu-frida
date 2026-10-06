#![forbid(unsafe_code)]

use std::fs;

use serde_json::Value;

use crate::log::{loge, loge_fmt};

/// Upper bound for per-launch injection delay.
pub const MAX_START_UP_DELAY_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChildMode {
    Kill,
    Freeze,
    Inject,
    #[default]
    Pass,
}

impl ChildMode {
    pub(crate) fn parse(mode: &str) -> Option<Self> {
        mode.parse().ok()
    }
}

impl std::str::FromStr for ChildMode {
    type Err = ();

    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            "kill" => Ok(Self::Kill),
            "freeze" => Ok(Self::Freeze),
            "inject" => Ok(Self::Inject),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChildGatingConfig {
    pub enabled: bool,
    pub mode: ChildMode,
    pub injected_libraries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConfig {
    pub enabled: bool,
    pub app_name: String,
    pub start_up_delay_ms: u64,
    pub kernel_assisted_evasion: bool,
    pub hide_maps: bool,
    pub scrub_elf_header: bool,
    pub injected_libraries: Vec<String>,
    pub child_gating: ChildGatingConfig,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_name: String::new(),
            start_up_delay_ms: 0,
            kernel_assisted_evasion: false,
            hide_maps: true,
            scrub_elf_header: false,
            injected_libraries: Vec::new(),
            child_gating: ChildGatingConfig::default(),
        }
    }
}

pub fn load_config(module_dir: &str, app_name: &str) -> Option<TargetConfig> {
    load_advanced_config(module_dir, app_name).or_else(|| load_simple_config(module_dir, app_name))
}

fn deserialize_libraries(value: &Value) -> Option<Vec<String>> {
    let Some(arr) = value.as_array() else {
        loge("invalid config: expected injected_libraries to be an array");
        return None;
    };

    let mut result = Vec::new();
    for library in arr {
        let Some(obj) = library.as_object() else {
            loge("invalid config: expected injected_libraries members to be objects");
            return None;
        };
        let Some(path) = obj.get("path").and_then(Value::as_str) else {
            loge("invalid config: expected injected_libraries.path to be a string");
            return None;
        };
        result.push(path.to_string());
    }

    Some(result)
}

fn deserialize_child_gating_config(value: &Value) -> Option<ChildGatingConfig> {
    let obj = value.as_object()?;

    let mut result = ChildGatingConfig::default();

    let Some(enabled) = obj.get("enabled").and_then(Value::as_bool) else {
        loge("invalid config: expected child_gating.enabled members to be a bool");
        return None;
    };
    result.enabled = enabled;

    let Some(mode) = obj.get("mode").and_then(Value::as_str) else {
        loge("invalid config: expected child_gating.mode members to be a string");
        return None;
    };
    let Some(mode) = ChildMode::parse(mode) else {
        loge("invalid config: unknown child_gating.mode; expected kill, freeze, or inject");
        return None;
    };
    result.mode = mode;

    if let Some(libraries) = obj.get("injected_libraries") {
        result.injected_libraries = deserialize_libraries(libraries)?;
    }

    Some(result)
}

// Optional field: missing keeps the default, wrong types reject the target.
fn opt_value<T>(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    kind: &str,
    convert: impl FnOnce(&Value) -> Option<T>,
) -> Option<Option<T>> {
    let value = match obj.get(key) {
        None => return Some(None),
        Some(value) => value,
    };
    let Some(v) = convert(value) else {
        loge_fmt(format_args!("invalid config: expected {key} to be {kind}"));
        return None;
    };
    Some(Some(v))
}

fn opt_bool(obj: &serde_json::Map<String, Value>, key: &str) -> Option<Option<bool>> {
    opt_value(obj, key, "a bool", Value::as_bool)
}

fn opt_u64(obj: &serde_json::Map<String, Value>, key: &str) -> Option<Option<u64>> {
    opt_value(obj, key, "an uint64", Value::as_u64)
}

fn deserialize_target_config(value: &Value) -> Option<TargetConfig> {
    let Some(obj) = value.as_object() else {
        loge("expected config targets array to contain objects");
        return None;
    };

    let mut result = TargetConfig::default();

    let Some(app_name) = obj.get("app_name").and_then(Value::as_str) else {
        loge("expected config target to have a valid app_name");
        return None;
    };
    result.app_name = app_name.to_string();

    // Optional fields default fail-closed; only wrong types reject the target.
    if let Some(enabled) = opt_bool(obj, "enabled")? {
        result.enabled = enabled;
    }

    if let Some(kernel_assisted_evasion) = opt_bool(obj, "kernel_assisted_evasion")? {
        result.kernel_assisted_evasion = kernel_assisted_evasion;
    }

    if let Some(start_up_delay_ms) = opt_u64(obj, "start_up_delay_ms")? {
        result.start_up_delay_ms = start_up_delay_ms.min(MAX_START_UP_DELAY_MS);
    }

    if let Some(hide_maps) = opt_bool(obj, "hide_maps")? {
        result.hide_maps = hide_maps;
    }

    if let Some(scrub_elf_header) = opt_bool(obj, "scrub_elf_header")? {
        result.scrub_elf_header = scrub_elf_header;
    }

    if let Some(libraries) = obj.get("injected_libraries") {
        result.injected_libraries = deserialize_libraries(libraries)?;
    }

    if let Some(child_gating) = obj.get("child_gating") {
        result.child_gating = deserialize_child_gating_config(child_gating)?;
    }

    Some(result)
}

fn load_simple_config(module_dir: &str, app_name: &str) -> Option<TargetConfig> {
    let content = fs::read_to_string(format!("{module_dir}/target_packages")).ok()?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split(',').map(str::trim);
        let Some(first) = fields.next() else { continue };
        if first != app_name {
            continue;
        }

        let mut cfg = TargetConfig {
            app_name: first.to_string(),
            enabled: true,
            kernel_assisted_evasion: true,
            ..Default::default()
        };

        if let Some(delay) = fields.next() {
            cfg.start_up_delay_ms = strtoul_base10(delay).min(MAX_START_UP_DELAY_MS);
        }
        cfg.injected_libraries = parse_injected_libraries(module_dir);

        return Some(cfg);
    }

    None
}

fn strtoul_base10(s: &str) -> u64 {
    let digits = s.trim_start().bytes().take_while(u8::is_ascii_digit);
    digits.fold(0u64, |acc, d| {
        acc.saturating_mul(10).saturating_add(u64::from(d - b'0'))
    })
}

fn parse_injected_libraries(module_dir: &str) -> Vec<String> {
    let Ok(content) = fs::read_to_string(format!("{module_dir}/injected_libraries")) else {
        return vec![format!("{module_dir}/libsecmon.so")];
    };

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    // `windows(0)` panics; longer needle yields empty iterator → false.
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

fn load_advanced_config(module_dir: &str, app_name: &str) -> Option<TargetConfig> {
    if app_name.is_empty() {
        return None;
    }
    let bytes = fs::read(format!("{module_dir}/config.json")).ok()?;

    // Byte precheck skips the parse for non-targets; package names are never JSON-escaped.
    if !contains_bytes(&bytes, app_name.as_bytes()) {
        return None;
    }

    let doc: Value = match serde_json::from_slice(&bytes) {
        Ok(doc) => doc,
        Err(err) => {
            loge_fmt(format_args!(
                "config is not a valid json file at line {} column {}: {}",
                err.line(),
                err.column(),
                err
            ));
            return None;
        }
    };

    if !doc.is_object() {
        loge("config expected a json root object");
        return None;
    }

    let Some(targets) = doc.get("targets").and_then(Value::as_array) else {
        loge("expected config targets to be an array");
        return None;
    };

    for target in targets {
        // Name match first: a malformed unrelated entry must stay silent.
        if target.get("app_name").and_then(Value::as_str) != Some(app_name) {
            continue;
        }
        if let Some(deserialized) = deserialize_target_config(target) {
            return Some(deserialized);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    const ADVANCED: &str = r#"{
        "targets": [
            {
                "app_name": "com.example.app",
                "enabled": true,
                "kernel_assisted_evasion": false,
                "start_up_delay_ms": 1500,
                "injected_libraries": [
                    { "path": "/data/local/tmp/libsec/libsecmon.so" },
                    { "path": "/data/local/tmp/libsec/libgadget.so" }
                ],
                "child_gating": {
                    "enabled": true,
                    "mode": "freeze",
                    "injected_libraries": [ { "path": "/data/local/tmp/libsec/libsecmon.so" } ]
                }
            },
            {
                "app_name": "org.other.app",
                "enabled": true,
                "kernel_assisted_evasion": true,
                "start_up_delay_ms": 0,
                "injected_libraries": [ { "path": "/other.so" } ]
            }
        ]
    }"#;

    #[test]
    fn advanced_config_parses_matching_target() {
        let dir = TempDir::new("advanced");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();

        let cfg = load_config(dir.to_str().unwrap(), "com.example.app").expect("config");
        assert!(cfg.enabled);
        assert!(!cfg.kernel_assisted_evasion);
        assert_eq!(cfg.start_up_delay_ms, 1500);
        assert_eq!(
            cfg.injected_libraries,
            [
                "/data/local/tmp/libsec/libsecmon.so".to_string(),
                "/data/local/tmp/libsec/libgadget.so".to_string()
            ]
        );
        assert!(cfg.child_gating.enabled);
        assert_eq!(cfg.child_gating.mode, ChildMode::Freeze);
        assert_eq!(cfg.child_gating.injected_libraries.len(), 1);

        let other = load_config(dir.to_str().unwrap(), "org.other.app").expect("other config");
        assert!(other.kernel_assisted_evasion);
        assert_eq!(other.start_up_delay_ms, 0);
        assert!(!other.child_gating.enabled);
        assert!(other.child_gating.injected_libraries.is_empty());
    }

    #[test]
    fn unknown_app_returns_none() {
        let dir = TempDir::new("unknown");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.unknown.app").is_none());
    }

    #[test]
    fn non_target_skips_parse_entirely() {
        let dir = TempDir::new("noparse");
        fs::write(dir.join("config.json"), "{ not json at all").unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.unknown.app").is_none());
    }

    #[test]
    fn substring_hit_falls_through_to_exact_match() {
        let dir = TempDir::new("substr");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"com.example.approx","enabled":true,
                "kernel_assisted_evasion":true,"start_up_delay_ms":0,
                "injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.example.app").is_none());
        assert!(load_config(dir.to_str().unwrap(), "com.example.approx").is_some());
    }

    #[test]
    fn empty_app_name_matches_nothing() {
        let dir = TempDir::new("empty");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "").is_none());
    }

    fn target_with_hide_maps(value: &str) -> String {
        format!(
            r#"{{"targets":[{{"app_name":"a.b","enabled":true,
                "kernel_assisted_evasion":false,"start_up_delay_ms":0,
                "hide_maps":{value},"injected_libraries":[]}}]}}"#,
        )
    }

    #[test]
    fn scrub_elf_header_defaults_to_disabled_and_parses_explicit_values() {
        let dir = TempDir::new("scrubhdr-default");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "com.example.app").expect("config");
        assert!(!cfg.scrub_elf_header);

        for (fragment, expected) in [
            ("\"scrub_elf_header\":true", true),
            ("\"scrub_elf_header\":false", false),
        ] {
            let dir = TempDir::new("scrubhdr-explicit");
            fs::write(
                dir.join("config.json"),
                format!(
                    r#"{{"targets":[{{"app_name":"a.b","enabled":true,
                        "kernel_assisted_evasion":false,"start_up_delay_ms":0,
                        {fragment},"injected_libraries":[]}}]}}"#,
                ),
            )
            .unwrap();
            let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("config");
            assert_eq!(cfg.scrub_elf_header, expected);
        }

        let dir = TempDir::new("scrubhdr-mistype");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":false,
                "start_up_delay_ms":0,"scrub_elf_header":"yes","injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());
    }

    #[test]
    fn hide_maps_defaults_to_true_and_parses_explicit_values() {
        let dir = TempDir::new("hidemaps-default");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "com.example.app").expect("config");
        assert!(cfg.hide_maps);

        for (value, expected) in [("true", true), ("false", false)] {
            let dir = TempDir::new("hidemaps-explicit");
            fs::write(dir.join("config.json"), target_with_hide_maps(value)).unwrap();
            let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("config");
            assert_eq!(cfg.hide_maps, expected);
        }

        let dir = TempDir::new("hidemaps-mistype");
        fs::write(dir.join("config.json"), target_with_hide_maps("\"yes\"")).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());
    }

    #[test]
    fn invalid_json_falls_back_to_simple_config() {
        let dir = TempDir::new("fallback");
        fs::write(dir.join("config.json"), "{ not json").unwrap();
        fs::write(
            dir.join("target_packages"),
            "com.simple.app,250\ncom.other.app\n",
        )
        .unwrap();

        let cfg = load_config(dir.to_str().unwrap(), "com.simple.app").expect("simple config");
        assert!(cfg.enabled);
        assert!(cfg.kernel_assisted_evasion);
        assert_eq!(cfg.start_up_delay_ms, 250);
        assert_eq!(
            cfg.injected_libraries,
            [format!("{}/libsecmon.so", dir.to_str().unwrap())]
        );

        let other = load_config(dir.to_str().unwrap(), "com.other.app").expect("no-delay config");
        assert_eq!(other.start_up_delay_ms, 0);
    }

    #[test]
    fn malformed_unrelated_entry_does_not_block_resolution() {
        let dir = TempDir::new("unrelated-broken");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"other.app","enabled":"yes"},
                {"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,"injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_some());
        assert!(load_config(dir.to_str().unwrap(), "other.app").is_none());
    }

    #[test]
    fn legacy_lines_are_trimmed() {
        let dir = TempDir::new("legacy-trim");
        fs::write(
            dir.join("target_packages"),
            "  com.simple.app , 250  \n\ncom.other.app\n",
        )
        .unwrap();
        fs::write(dir.join("injected_libraries"), "  /a.so  \n\n/b.so\n").unwrap();

        let cfg = load_config(dir.to_str().unwrap(), "com.simple.app").expect("simple config");
        assert_eq!(cfg.start_up_delay_ms, 250);
        assert_eq!(
            cfg.injected_libraries,
            ["/a.so".to_string(), "/b.so".to_string()]
        );
    }

    #[test]
    fn wrong_types_are_rejected() {
        let dir = TempDir::new("badtypes");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":"500","injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());

        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,"injected_libraries":"nope"}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());
    }

    #[test]
    fn missing_libraries_defaults_to_empty_for_gating_only() {
        let dir = TempDir::new("nolibs");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,
                "child_gating":{"enabled":true,"mode":"freeze"}}]}"#,
        )
        .unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("gating-only config");
        assert!(cfg.injected_libraries.is_empty());
        assert!(cfg.child_gating.enabled);
    }

    #[test]
    fn unknown_child_gating_mode_is_rejected() {
        let dir = TempDir::new("badmode");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,"injected_libraries":[],
                "child_gating":{"enabled":true,"mode":"kil"}}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());
    }

    #[test]
    fn start_up_delay_is_capped() {
        let dir = TempDir::new("bigdelay");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":999999999,"injected_libraries":[]}]}"#,
        )
        .unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("config");
        assert_eq!(cfg.start_up_delay_ms, MAX_START_UP_DELAY_MS);
    }

    #[test]
    fn missing_optionals_default_to_disabled_and_empty() {
        let dir = TempDir::new("defaults");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"a.b"}]}"#,
        )
        .unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("minimal config");
        assert!(!cfg.enabled);
        assert!(!cfg.kernel_assisted_evasion);
        assert_eq!(cfg.start_up_delay_ms, 0);
        assert!(cfg.hide_maps);
        assert!(!cfg.scrub_elf_header);
        assert!(cfg.injected_libraries.is_empty());
        assert!(!cfg.child_gating.enabled);
        assert_eq!(cfg.child_gating.mode, ChildMode::Pass);
    }

    #[test]
    fn broken_entry_does_not_disable_other_targets() {
        let dir = TempDir::new("skip-broken");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"broken","enabled":"yes"},
                {"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,"injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_some());
        assert!(load_config(dir.to_str().unwrap(), "broken").is_none());
    }

    #[test]
    fn strtoul_semantics_match_c() {
        assert_eq!(strtoul_base10("1500"), 1500);
        assert_eq!(strtoul_base10("  42"), 42);
        assert_eq!(strtoul_base10("12abc"), 12);
        assert_eq!(strtoul_base10("abc"), 0);
        assert_eq!(strtoul_base10(""), 0);
        assert_eq!(strtoul_base10("-5"), 0);
    }

    #[test]
    fn contains_bytes_matches_windows() {
        let hay = b"{\"app_name\":\"com.example.app\"}";
        assert!(contains_bytes(hay, b"com.example.app"));
        assert!(contains_bytes(hay, b""));
        assert!(!contains_bytes(hay, b"com.example.approx"));
        assert!(!contains_bytes(b"short", b"much longer needle"));
        assert!(!contains_bytes(b"", b"a"));
    }
}
