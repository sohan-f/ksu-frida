# KsuFrida

Frida gadget injection module for KernelSU via Zygisk (API v5).

- Gadget is not embedded into the APK — APK integrity/signature checks still pass
- No ptrace — avoids ptrace-based detection
- Library remapping hides injected libraries from /proc/self/maps
- Configurable injection delay, child gating, and multiple library injection
- WebUI for managing targets from KernelSU Manager

## Prerequisites

- KernelSU (KernelSU-Next supported; Magisk/APatch are not targeted)
- A Zygisk provider implementing **Zygisk API v5**: [ReZygisk](https://github.com/PerformanC/ReZygisk) or a recent Zygisk Next

## Quick Start

1. Download the latest release from the [Releases](https://github.com/sohan-f/ksu-frida/releases) page
2. Install the ZIP via KernelSU Manager
3. Reboot

### Option A: WebUI (KernelSU only)

Open KernelSU Manager → Modules → KsuFrida → WebUI. Add target apps, configure delay, toggle child
gating, watch module/gadget status, restart targets to apply changes, validate configs before
saving, copy the exact connect commands for the ports your gadgets picked, refresh the gadget
binary from the bundled payload, and check for gadget updates from the knox-frida-patcher
releases (the gadget ships separately from this module).

Each target can optionally have its own gadget port and Frida Gadget JSON config. Set a dedicated
port in that target's details to give it an isolated gadget config; edit the JSON there to use a
different script or interaction mode. Targets without a dedicated port keep using the shared
`libsecmon.so` gadget and its default config. Dedicated ports must be unique across targets.
Targets that inject the 32-bit gadget (`libsecmon32.so`) get a matching 32-bit pair on save.

### Option B: Manual config

```shell
adb shell su -c 'cp /data/local/tmp/libsec/config.json.example /data/local/tmp/libsec/config.json'
adb shell su -c "sed -i 's/com.example.package/your.target.app/' /data/local/tmp/libsec/config.json"
```

### Connecting

The default gadget config uses **listen mode** on port 27042. After opening the target app:

```shell
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l your_script.js
```

For a target with its own port, use the connect command shown in that target's details. Each app can
then run at the same time and listen on its own port.

## Configuration

Config files are stored at `/data/local/tmp/libsec/`:

| File | Purpose |
|------|---------|
| `config.json` | Target apps, delay, child gating settings |
| `libsecmon.config.so` | Frida gadget config (listen/script mode) |
| `libsecmon.so` | Frida gadget binary (auto-installed) |

Example `config.json`:
```json
{
    "targets": [
        {
            "app_name": "com.example.app",
            "enabled": true,
            "start_up_delay_ms": 0,
            "injected_libraries": [
                { "path": "/data/local/tmp/libsec/libsecmon.so" }
            ],
            "child_gating": {
                "enabled": false,
                "mode": "freeze",
                "injected_libraries": []
            }
        }
    ]
}
```

## Building

Prerequisites:

- Android SDK with NDK
- Rust stable toolchain with the Android targets and [cargo-ndk](https://crates.io/crates/cargo-ndk):

```shell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-ndk
```

```shell
./gradlew :module:assembleRelease
```

The Gradle build compiles the Rust core (`module/src/rust`: config parsing, injection
staging, remapping, child-gating policy) via cargo-ndk and links it into the C++
Zygisk shell (`module/src/jni`: Zygisk ABI entry + Dobby hook shim) automatically.

Output ZIP will be in the `out/` directory.

To build, install and reboot directly:
```shell
./gradlew :module:flashAndRebootZygiskRelease
```

### Gadget pins

The Frida gadget is fetched from the [knox-frida-patcher](https://github.com/sohan-f/knox-frida-patcher)
releases, but builds never follow "latest" silently: `gadget-pins.json` at the repo root pins the
exact version plus the SHA-256 of each arch asset. `fetchGadget` cross-checks the release metadata
against the pins and verifies every downloaded byte; any mismatch fails the build. The WebUI updater
on-device enforces the same hashes before installing.

To adopt a new gadget version, copy the version and digests from the release `gadget.json`
(or `SHA256SUMS` asset) into `gadget-pins.json` and rebuild.

## Credits

- [lico-n](https://github.com/lico-n) — Original author of [ZygiskFrida](https://github.com/lico-n/ZygiskFrida)
- [electrondefuser](https://github.com/electrondefuser) — Library remapper, child gating, advanced config system
- [xDL](https://github.com/hexhacking/xDL)
- Inspired by [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)
