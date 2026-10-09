<div align="center">

# KsuFrida

Frida gadget injection for KernelSU, via Zygisk.

[![Release](https://img.shields.io/github/v/release/sohan-f/ksu-frida)](https://github.com/sohan-f/ksu-frida/releases)
[![CI](https://github.com/sohan-f/ksu-frida/actions/workflows/ci.yml/badge.svg)](https://github.com/sohan-f/ksu-frida/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

Loads the gadget from disk at app start. App signatures stay intact. No ptrace. Injected libraries are hidden from `/proc/self/maps` and the linker tables.

**Contents**

- [Requirements](#requirements)
- [Install](#install)
- [Use](#use)
- [Files on device](#files-on-device)
- [Build](#build)
- [Troubleshoot](#troubleshoot)
- [Credits](#credits)

## Requirements

| Need | Notes |
|------|-------|
| KernelSU or KernelSU-Next | Magisk and APatch are not supported |
| Zygisk provider with API v5 | [ReZygisk](https://github.com/PerformanC/ReZygisk) or recent Zygisk Next |
| Android 12 or newer | API 31 minimum |

## Install

1. Get the ZIP from [Releases](https://github.com/sohan-f/ksu-frida/releases).
2. Install it in KernelSU Manager.
3. Reboot.

> [!NOTE]
> Zygisk loads at zygote start, so the module does nothing until reboot.

## Use

### WebUI

Open KernelSU Manager > Modules > KsuFrida > WebUI.

| Tab | What it does |
|-----|--------------|
| Targets | Add or remove apps, set delay and child gating |
| Status | Module state, gadget version, running targets |
| Gadget | Refresh the binary, check for updates |

A target can have its own port and gadget config. Set a port in the target details to give it a private config file. Targets with no port share `libsecmon.so` and the default config. Ports must be unique. 32-bit targets get a matching 32-bit pair on save.

### Connect

The default config listens on `127.0.0.1:27042`. Start the target app, then run:

```shell
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l your_script.js
```

For a target with its own port, use the command shown in its WebUI details.

### Manual setup

<details>
<summary>Set up <code>config.json</code> by hand</summary>

```shell
adb shell su -c 'cp /data/local/tmp/libsec/config.json.example /data/local/tmp/libsec/config.json'
adb shell su -c "sed -i 's/com.example.package/your.target.app/' /data/local/tmp/libsec/config.json"
```

Full field reference: [`docs/advanced_config.md`](docs/advanced_config.md). Legacy file-based setup: [`docs/simple_config.md`](docs/simple_config.md).

</details>

## Files on device

All state lives in `/data/local/tmp/libsec/`:

| File | Use |
|------|-----|
| `config.json` | Target apps, delay, child gating |
| `libsecmon.so` | Gadget binary, 64-bit |
| `libsecmon32.so` | Gadget binary, 32-bit |
| `libsecmon.config.so` | Shared gadget config (listen on 27042) |
| `libsecmon_<app>.so` | Per-target copy, only when a custom port is set |
| `verbose` | Touch this file to enable logcat output |

Example `config.json`:

```json
{
    "targets": [
        {
            "app_name": "com.example.app",
            "enabled": true,
            "hide_maps": true,
            "start_up_delay_ms": 100,
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

> [!TIP]
> Keep the delay at 100 ms or higher. Lower values can stall app startup.

## Build

<details>
<summary>Build steps and gadget pins</summary>

You need the Android SDK with NDK, plus Rust stable and `cargo-ndk`:

```shell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-ndk
```

Build the ZIP:

```shell
./gradlew :module:assembleRelease
```

The ZIP lands in `out/`. To build, flash, and reboot in one step:

```shell
./gradlew :module:flashAndRebootZygiskRelease
```

The Gradle build compiles `module/src/rust` with cargo-ndk and links it into the Zygisk library in `module/src/jni`.

**Gadget version.** The gadget comes from [knox-frida-patcher](https://github.com/sohan-f/knox-frida-patcher) releases. Version and SHA-256 per arch are pinned in `gadget-pins.json`. The build checks the hashes and stops on mismatch. The WebUI updater checks the same hashes on device. To move to a new gadget, copy the version and digests from the release `gadget.json` into `gadget-pins.json` and rebuild.

</details>

## Troubleshoot

The module stays silent in logcat unless verbose mode is on:

```shell
adb shell su -c 'touch /data/local/tmp/libsec/verbose'
adb logcat -s KsuFrida
```

Checklist:

- Rebooted after flash
- Target app restarted after config save
- Target package name spelled exactly as in the app manifest
- No port shared by two targets

## Credits

- [lico-n](https://github.com/lico-n): original [ZygiskFrida](https://github.com/lico-n/ZygiskFrida)
- [electrondefuser](https://github.com/electrondefuser): remapper, child gating, config system
- [xDL](https://github.com/hexhacking/xDL)
- [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper) for reference
