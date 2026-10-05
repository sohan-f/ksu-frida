use std::ffi::{CStr, c_char, c_void};

// Table slots from NDK 29 `jni.h` (`JNINativeInterface`, indices verified by
// enumeration; `GetStringUTFChars` lands on the well-known slot 169).
const IDX_EXCEPTION_CLEAR: usize = 17;
const IDX_GET_STRING_UTF_CHARS: usize = 169;
const IDX_RELEASE_STRING_UTF_CHARS: usize = 170;
const IDX_EXCEPTION_CHECK: usize = 228;

type JString = *mut c_void;
type JniEnv = *mut c_void;

#[repr(C)]
struct JniTable {
    _head: [*const c_void; IDX_EXCEPTION_CLEAR],
    exception_clear: unsafe extern "C" fn(JniEnv),
    _mid: [*const c_void; IDX_GET_STRING_UTF_CHARS - IDX_EXCEPTION_CLEAR - 1],
    get_string_utf_chars: unsafe extern "C" fn(JniEnv, JString, *mut u8) -> *const c_char,
    release_string_utf_chars: unsafe extern "C" fn(JniEnv, JString, *const c_char),
    _tail: [*const c_void; IDX_EXCEPTION_CHECK - IDX_RELEASE_STRING_UTF_CHARS - 1],
    _exception_check: unsafe extern "C" fn(JniEnv) -> u8,
}

/// Calls `GetStringUTFChars` and copies the result into an owned `String`.
///
/// Returns `None` (after clearing any pending JNI exception) when `env` or
/// `name` is null or the conversion call fails. The owned copy is made before
/// `ReleaseStringUTFChars`, so the caller never borrows JNI memory.
///
/// # Safety
/// `env` must be a valid `JNIEnv` for this thread or null; `name` must be a
/// valid `jstring` or null.
pub unsafe fn read_app_name(env: JniEnv, name: JString) -> Option<String> {
    if env.is_null() || name.is_null() {
        return None;
    }
    // SAFETY: `env` non-null per above; a `JNIEnv` is a table pointer by JNI layout.
    let table = unsafe { *(env as *mut *const JniTable) };
    if table.is_null() {
        return None;
    }
    // SAFETY: table from a live `JNIEnv`; raw string released below.
    let raw = unsafe { ((*table).get_string_utf_chars)(env, name, std::ptr::null_mut()) };
    if raw.is_null() {
        // SAFETY: same live table; clearing is a no-op without a pending exception.
        unsafe { ((*table).exception_clear)(env) };
        return None;
    }
    // SAFETY: `raw` is NUL-terminated per the JNI contract; copied before release.
    let owned = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `raw` came from the paired call above on the same string.
    unsafe { ((*table).release_string_utf_chars)(env, name, raw) };
    Some(owned)
}

/// Entry for the Zygisk module: resolves the app name and runs injection.
///
/// Returns true when the caller must keep the module loaded.
///
/// # Safety
/// Called only from `postAppSpecialize` with the framework-provided `JNIEnv`
/// and `nice_name` (either may be null on OOM); fail-closed on any error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ksufrida_handle_app(env: JniEnv, name: JString) -> bool {
    // Fail closed: a panic must never unwind into the Zygisk host.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `read_app_name` upholds its contract for the documented inputs.
        let Some(app_name) = (unsafe { read_app_name(env, name) }) else {
            return false;
        };
        crate::inject::check_and_inject(&app_name)
    }))
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    static RELEASED: AtomicBool = AtomicBool::new(false);
    static CLEARED: AtomicBool = AtomicBool::new(false);
    static MOCK_NAME: &[u8] = b"com.mock.app\0";

    unsafe extern "C" fn stub_get(_env: JniEnv, _s: JString, _copy: *mut u8) -> *const c_char {
        MOCK_NAME.as_ptr().cast()
    }

    unsafe extern "C" fn stub_get_oom(_env: JniEnv, _s: JString, _copy: *mut u8) -> *const c_char {
        std::ptr::null()
    }

    unsafe extern "C" fn stub_release(_env: JniEnv, _s: JString, _raw: *const c_char) {
        RELEASED.store(true, Ordering::Relaxed);
    }

    unsafe extern "C" fn stub_clear(_env: JniEnv) {
        CLEARED.store(true, Ordering::Relaxed);
    }

    unsafe extern "C" fn stub_check(_env: JniEnv) -> u8 {
        0
    }

    // Raw pointers pair into_raw with from_raw at each call site: reading the
    // tables through a live Box borrow and then dropping it is UB under Miri.
    fn mock_env(
        get: unsafe extern "C" fn(JniEnv, JString, *mut u8) -> *const c_char,
    ) -> (*mut JniTable, *mut *const JniTable, JString) {
        // JNIEnv is a pointer to a table pointer; into_raw hands out both addresses.
        let table = Box::into_raw(Box::new(JniTable {
            _head: [std::ptr::null(); IDX_EXCEPTION_CLEAR],
            exception_clear: stub_clear,
            _mid: [std::ptr::null(); IDX_GET_STRING_UTF_CHARS - IDX_EXCEPTION_CLEAR - 1],
            get_string_utf_chars: get,
            release_string_utf_chars: stub_release,
            _tail: [std::ptr::null(); IDX_EXCEPTION_CHECK - IDX_RELEASE_STRING_UTF_CHARS - 1],
            _exception_check: stub_check,
        }));
        let slot: *mut *const JniTable = Box::into_raw(Box::new(std::ptr::null()));
        // SAFETY: both are live into_raw outputs; the slot stores the table address.
        unsafe { *slot = table as *const JniTable };
        (table, slot, 0x1234 as JString)
    }

    // Reconstructs exactly one mock_env pair; both pointers must be its live outputs.
    unsafe fn free_mock_env(table: *mut JniTable, slot: *mut *const JniTable) {
        // SAFETY: into_raw outputs reconstructed exactly once each.
        unsafe {
            drop(Box::from_raw(table));
            drop(Box::from_raw(slot));
        }
    }

    #[test]
    fn jni_app_name_resolution() {
        // Null env/name fail closed without touching JNI.
        assert_eq!(
            // SAFETY: null inputs take the early return above; nothing dereferenced.
            unsafe { read_app_name(std::ptr::null_mut(), 0x1 as JString) },
            None
        );
        assert_eq!(
            // SAFETY: as above.
            unsafe { read_app_name(0x1 as JniEnv, std::ptr::null_mut()) },
            None
        );

        // OOM conversion clears the pending exception and releases nothing.
        let (table_oom, slot_oom, name) = mock_env(stub_get_oom);
        let env = slot_oom as JniEnv;
        RELEASED.store(false, Ordering::Relaxed);
        CLEARED.store(false, Ordering::Relaxed);
        // SAFETY: raw pair from mock_env, alive for the call; stubs only flip atomics.
        assert_eq!(unsafe { read_app_name(env, name) }, None);
        assert!(CLEARED.load(Ordering::Relaxed));
        assert!(!RELEASED.load(Ordering::Relaxed));
        // SAFETY: the pair above, reconstructed exactly once.
        unsafe { free_mock_env(table_oom, slot_oom) };

        // Valid string is copied, then released.
        let (table_ok, slot_ok, name) = mock_env(stub_get);
        let env = slot_ok as JniEnv;
        RELEASED.store(false, Ordering::Relaxed);
        assert_eq!(
            // SAFETY: as above; the mock string is a valid NUL-terminated static.
            unsafe { read_app_name(env, name) },
            Some("com.mock.app".to_string())
        );
        assert!(RELEASED.load(Ordering::Relaxed));
        // SAFETY: the pair above, reconstructed exactly once.
        unsafe { free_mock_env(table_ok, slot_ok) };

        // End to end stays fail-closed without a device config dir.
        assert!(!unsafe {
            // SAFETY: null inputs take the early return; nothing dereferenced.
            ksufrida_handle_app(std::ptr::null_mut(), std::ptr::null_mut())
        });
    }
}
