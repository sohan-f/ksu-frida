#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::log::loge_fmt;

pub const RECORD_LEN: usize = 256;
const MAX_BYTES: u64 = 64 * 1024;
const APP_CAP: usize = 128;
const LIB_CAP: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageSource {
    None,
    File,
    Memfd,
    Staged,
}

impl StageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::File => "file",
            Self::Memfd => "memfd",
            Self::Staged => "staged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HideOutcome {
    Disabled,
    Clean,
    LeakLinker,
    LeakMaps,
    LeakThreads,
}

pub fn load_result(loaded: bool, hide: HideOutcome) -> &'static str {
    if !loaded {
        return "failed";
    }
    match hide {
        HideOutcome::Disabled => "unverified",
        HideOutcome::Clean => "clean",
        HideOutcome::LeakLinker => "leak-linker",
        HideOutcome::LeakMaps => "leak-maps",
        HideOutcome::LeakThreads => "leak-threads",
    }
}

fn trunc(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// One `\x1f`-separated line per injection, space-padded to 255 bytes plus
// `\n`: fixed-size so the WebUI can `tail -c` whole records. App and lib
// come last and may hold spaces; only `\x1f` separates fields.
pub fn format_record(
    pid: u32,
    ts_secs: u64,
    src: StageSource,
    result: &str,
    app: &str,
    lib: &str,
) -> [u8; RECORD_LEN] {
    let line = format!(
        "1\x1f{pid}\x1f{ts_secs}\x1f{}\x1f{result}\x1f{}\x1f{}",
        src.as_str(),
        trunc(app, APP_CAP),
        trunc(lib, LIB_CAP),
    );
    let mut out = [b' '; RECORD_LEN];
    let body = trunc(&line, RECORD_LEN - 1);
    out[..body.len()].copy_from_slice(body.as_bytes());
    out[RECORD_LEN - 1] = b'\n';
    out
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct ParsedRecord {
    pub pid: u32,
    pub ts_secs: u64,
    pub src: String,
    pub result: String,
    pub app: String,
    pub lib: String,
}

#[cfg(test)]
pub fn parse_record(line: &str) -> Option<ParsedRecord> {
    let mut fields = line.trim_end().split('\x1f');
    let version = fields.next()?;
    let pid = fields.next()?.parse().ok()?;
    let ts_secs = fields.next()?.parse().ok()?;
    let record = ParsedRecord {
        pid,
        ts_secs,
        src: fields.next()?.to_string(),
        result: fields.next()?.to_string(),
        app: fields.next()?.to_string(),
        lib: fields.next()?.to_string(),
    };
    if version != "1" || fields.next().is_some() {
        return None;
    }
    Some(record)
}

// Best-effort `O_APPEND` write, verbose-gated like all logging (fork
// children stay silent through the same gate). Caps the file at 256
// records; a full file restarts rather than growing without bound.
// Concurrent appends may lose records but never corrupt them.
pub fn append_record(path: &str, record: &[u8; RECORD_LEN]) {
    if !crate::log::verbose() {
        return;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o666)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(err) => {
            loge_fmt(format_args!("history: open failed: {err}"));
            return;
        }
    };
    let full = file
        .metadata()
        .is_ok_and(|meta| meta.len() + RECORD_LEN as u64 > MAX_BYTES);
    if full {
        match fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o666)
            .open(path)
        {
            Ok(f) => file = f,
            Err(err) => {
                loge_fmt(format_args!("history: rotate failed: {err}"));
                return;
            }
        }
    }
    if let Err(err) = file.write_all(record) {
        loge_fmt(format_args!("history: write failed: {err}"));
    }
    // Creators own the file under their umask; stay world-appendable so
    // later app UIDs can add records. Non-owners fail here harmlessly.
    let _ = file.set_permissions(fs::Permissions::from_mode(0o666));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn records_are_fixed_size_newline_terminated() {
        let record = format_record(12, 34, StageSource::Memfd, "clean", "com.a", "lib.so");
        assert_eq!(record.len(), RECORD_LEN);
        assert_eq!(record[RECORD_LEN - 1], b'\n');
        assert!(record[..RECORD_LEN - 1].iter().all(|&b| b != b'\n'));
    }

    #[test]
    fn format_round_trips_through_parse() {
        let record = format_record(
            4242,
            1_700_000_000,
            StageSource::Staged,
            "leak-maps",
            "com.foo:push",
            "libsecmon_com.foo_push.so",
        );
        let parsed = parse_record(str::from_utf8(&record).unwrap()).expect("parse");
        assert_eq!(
            parsed,
            ParsedRecord {
                pid: 4242,
                ts_secs: 1_700_000_000,
                src: "staged".to_string(),
                result: "leak-maps".to_string(),
                app: "com.foo:push".to_string(),
                lib: "libsecmon_com.foo_push.so".to_string(),
            }
        );
    }

    #[test]
    fn overlong_fields_truncate_on_char_boundaries() {
        let record = format_record(
            1,
            2,
            StageSource::File,
            "clean",
            &"é".repeat(200),
            &"ü".repeat(200),
        );
        assert_eq!(record.len(), RECORD_LEN);
        let parsed = parse_record(str::from_utf8(&record).unwrap()).expect("parse");
        assert!(parsed.app.len() <= APP_CAP);
        assert!(parsed.lib.len() <= LIB_CAP);
        assert!(parsed.app.chars().all(|c| c == 'é'));
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse_record("").is_none());
        assert!(parse_record("1\x1f12\x1f34\x1fmemfd\x1fclean\x1fcom.a").is_none());
        assert!(parse_record("2\x1f12\x1f34\x1fmemfd\x1fclean\x1fcom.a\x1flib.so").is_none());
        assert!(parse_record("1\x1f12\x1f34\x1fmemfd\x1fclean\x1fcom.a\x1flib.so\x1fx").is_none());
        assert!(parse_record("1\x1fNaN\x1f34\x1fmemfd\x1fclean\x1fcom.a\x1flib.so").is_none());
    }

    #[test]
    fn load_result_names_every_outcome() {
        assert_eq!(load_result(false, HideOutcome::Clean), "failed");
        assert_eq!(load_result(true, HideOutcome::Disabled), "unverified");
        assert_eq!(load_result(true, HideOutcome::Clean), "clean");
        assert_eq!(load_result(true, HideOutcome::LeakLinker), "leak-linker");
        assert_eq!(load_result(true, HideOutcome::LeakMaps), "leak-maps");
        assert_eq!(load_result(true, HideOutcome::LeakThreads), "leak-threads");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // chmod has no Miri shim
    fn append_writes_and_rotates_a_full_file() {
        let dir = TempDir::new("history");
        let path = dir.join("history").to_str().unwrap().to_string();
        let record = format_record(7, 8, StageSource::Memfd, "clean", "com.a", "lib.so");
        append_record(&path, &record);
        append_record(&path, &record);
        let body = fs::read(&path).unwrap();
        assert_eq!(body.len(), 2 * RECORD_LEN);
        assert_eq!(&body[..RECORD_LEN], &record);

        fs::write(&path, vec![b'x'; MAX_BYTES as usize]).unwrap();
        append_record(&path, &record);
        let body = fs::read(&path).unwrap();
        assert_eq!(body.len(), RECORD_LEN);
        assert_eq!(&body, &record);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // chmod has no Miri shim
    fn quiet_children_write_nothing() {
        let dir = TempDir::new("history-quiet");
        let path = dir.join("history").to_str().unwrap().to_string();
        let record = format_record(1, 2, StageSource::File, "clean", "com.a", "lib.so");
        crate::log::set_fork_child_quiet(true);
        append_record(&path, &record);
        crate::log::set_fork_child_quiet(false);
        assert!(!dir.join("history").exists());
        append_record(&path, &record);
        assert_eq!(fs::read(&path).unwrap().len(), RECORD_LEN);
    }
}
