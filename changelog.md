# v1.9.39
- Fixed memfd linker scrub/remap miss (matched source path instead of memfd entry)
- Remap now skips shared mappings and dedupes by address; memfd renamed to blend with ART JIT
- Hides executable mappings without losing concurrent writes (write-freeze + fault parking)
- pidfd-based stale stage cleanup, sealed memfd, openat2-hardened staging, pthread_atfork state reset
- Lazy logging (no allocation when verbose off), faster config precheck, null-guarded fork/vfork hooks
- Silent fork-child inject reusing parent strings (no /proc re-read in child)

# v1.9.36
- Updated Zygisk API from v2 to v5 (requires a provider with API v5 support: ReZygisk or a recent Zygisk Next)
- KernelSU is now the only supported root solution
- Module libraries are now 16 KB page-size aligned

# v1.9.20
- Fixed WebUI-saved config file permissions so the target app can read them (thanks @limbang, #7)

# v1.9.4
- Frida gadget updated to 17.9.1
- Switched to own patched Frida fork
- Added auto-update workflow

# v1.9.3
- Auto-update support via KernelSU/Magisk Manager
- Updated docs to match current config schema
- Fixed child gating modes in WebUI
- Default gadget config set to listen mode

# v1.9.2
- Rebranded to KsuFrida
- Removed Riru support (Zygisk only)
- Rewrote WebUI with dark theme
- Fixed ksu.exec callback mechanism
- Added kernel_assisted_evasion toggle
- Added app labels in WebUI target list
- Fixed cpplint errors
