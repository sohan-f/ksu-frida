#![forbid(unsafe_code)]

use std::fs;

use serde_json::Value;

use crate::log::loge;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChildGatingConfig {
    pub enabled: bool,
    pub mode: String,
    pub injected_libraries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConfig {
    pub enabled: bool,
    pub app_name: String,
    pub start_up_delay_ms: u64,
    pub kernel_assisted_evasion: bool,
    pub hide_maps: bool,
    pub injected_libraries: Vec<String>,
    pub child_gating: ChildGatingConfig,
}

impl Default for TargetConfig {
    fn default() -> Self {
        TargetConfig {
            enabled: false,
            app_name: String::new(),
            start_up_delay_ms: 0,
            kernel_assisted_evasion: false,
            hide_maps: true,
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
    result.mode = mode.to_string();

    if let Some(libraries) = obj.get("injected_libraries") {
        result.injected_libraries = deserialize_libraries(libraries)?;
    }

    Some(result)
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

    let Some(enabled) = obj.get("enabled").and_then(Value::as_bool) else {
        loge("invalid config: expected targets.enabled members to be a bool");
        return None;
    };
    result.enabled = enabled;

    let Some(kernel_assisted_evasion) = obj.get("kernel_assisted_evasion").and_then(Value::as_bool)
    else {
        loge("invalid config: expected kernel_assisted_evasion members to be a bool");
        return None;
    };
    result.kernel_assisted_evasion = kernel_assisted_evasion;

    let Some(start_up_delay_ms) = obj.get("start_up_delay_ms").and_then(Value::as_u64) else {
        loge("expected config target start_up_delay_ms to be an uint64");
        return None;
    };
    result.start_up_delay_ms = start_up_delay_ms;

    if let Some(hide_maps) = obj.get("hide_maps") {
        let Some(hide_maps) = hide_maps.as_bool() else {
            loge("invalid config: expected targets.hide_maps to be a bool");
            return None;
        };
        result.hide_maps = hide_maps;
    }

    let null = Value::Null;
    let libraries = obj.get("injected_libraries").unwrap_or(&null);
    result.injected_libraries = deserialize_libraries(libraries)?;

    if let Some(child_gating) = obj.get("child_gating") {
        result.child_gating = deserialize_child_gating_config(child_gating)?;
    }

    Some(result)
}

fn load_simple_config(module_dir: &str, app_name: &str) -> Option<TargetConfig> {
    let content = fs::read_to_string(format!("{module_dir}/target_packages")).ok()?;

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split(',');
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
            cfg.start_up_delay_ms = strtoul_base10(delay);
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
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_advanced_config(module_dir: &str, app_name: &str) -> Option<TargetConfig> {
    if app_name.is_empty() {
        return None;
    }
    let bytes = fs::read(format!("{module_dir}/config.json")).ok()?;

    if !bytes
        .windows(app_name.len())
        .any(|window| window == app_name.as_bytes())
    {
        return None;
    }

    let content = String::from_utf8_lossy(&bytes);
    let doc: Value = match serde_json::from_str(&content) {
        Ok(doc) => doc,
        Err(err) => {
            loge(format!(
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
        let deserialized = deserialize_target_config(target)?;
        if deserialized.app_name == app_name {
            return Some(deserialized);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ksufrida_test_{name}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

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
        let dir = temp_dir("advanced");
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
        assert_eq!(cfg.child_gating.mode, "freeze");
        assert_eq!(cfg.child_gating.injected_libraries.len(), 1);

        let other = load_config(dir.to_str().unwrap(), "org.other.app").expect("other config");
        assert!(other.kernel_assisted_evasion);
        assert_eq!(other.start_up_delay_ms, 0);
        assert!(!other.child_gating.enabled);
        assert!(other.child_gating.injected_libraries.is_empty());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_app_returns_none() {
        let dir = temp_dir("unknown");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.unknown.app").is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_target_skips_parse_entirely() {
        let dir = temp_dir("noparse");
        fs::write(dir.join("config.json"), "{ not json at all").unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.unknown.app").is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn substring_hit_falls_through_to_exact_match() {
        let dir = temp_dir("substr");
        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"com.example.approx","enabled":true,
                "kernel_assisted_evasion":true,"start_up_delay_ms":0,
                "injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "com.example.app").is_none());
        assert!(load_config(dir.to_str().unwrap(), "com.example.approx").is_some());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_app_name_matches_nothing() {
        let dir = temp_dir("empty");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "").is_none());

        fs::remove_dir_all(&dir).ok();
    }

    fn target_with_hide_maps(value: &str) -> String {
        format!(
            r#"{{"targets":[{{"app_name":"a.b","enabled":true,
                "kernel_assisted_evasion":false,"start_up_delay_ms":0,
                "hide_maps":{value},"injected_libraries":[]}}]}}"#,
        )
    }

    #[test]
    fn hide_maps_defaults_to_true_and_parses_explicit_values() {
        let dir = temp_dir("hidemaps-default");
        fs::write(dir.join("config.json"), ADVANCED).unwrap();
        let cfg = load_config(dir.to_str().unwrap(), "com.example.app").expect("config");
        assert!(cfg.hide_maps);
        fs::remove_dir_all(&dir).ok();

        for (value, expected) in [("true", true), ("false", false)] {
            let dir = temp_dir("hidemaps-explicit");
            fs::write(dir.join("config.json"), target_with_hide_maps(value)).unwrap();
            let cfg = load_config(dir.to_str().unwrap(), "a.b").expect("config");
            assert_eq!(cfg.hide_maps, expected);
            fs::remove_dir_all(&dir).ok();
        }

        let dir = temp_dir("hidemaps-mistype");
        fs::write(dir.join("config.json"), target_with_hide_maps("\"yes\"")).unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_json_falls_back_to_simple_config() {
        let dir = temp_dir("fallback");
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

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_types_are_rejected() {
        let dir = temp_dir("badtypes");
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
                "start_up_delay_ms":0}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());

        fs::write(
            dir.join("config.json"),
            r#"{"targets":[{"app_name":"broken"},
                {"app_name":"a.b","enabled":true,"kernel_assisted_evasion":true,
                "start_up_delay_ms":0,"injected_libraries":[]}]}"#,
        )
        .unwrap();
        assert!(load_config(dir.to_str().unwrap(), "a.b").is_none());

        fs::remove_dir_all(&dir).ok();
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
}
