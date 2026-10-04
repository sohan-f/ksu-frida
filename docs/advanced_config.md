# Advanced Config

For the previous configuration method with various files, see [simple config](simple_config.md).
It remains a valid method of configuration but the structured configuration method specified here is the preferred
method and supports more features.

Both configurations are supported with the advanced config taking precedence in case an app appears in both.

## Config File

This module is configured via a json config located at `/data/local/tmp/libsec/config.json`.
To start off, you can copy the example config
```shell
adb shell su -c 'cp /data/local/tmp/libsec/config.json.example /data/local/tmp/libsec/config.json'
```

Example config
```json
{
    "targets": [
        {
            "app_name": "com.example.package",
            "enabled": true,
            "kernel_assisted_evasion": false,
            "hide_maps": true,
            "start_up_delay_ms": 0,
            "injected_libraries": [
                {
                    "path": "/data/local/tmp/libsec/libsecmon.so"
                }
            ],
            "child_gating": {
                "enabled": false,
                "mode": "freeze",
                "injected_libraries": [
                    {
                        "path": "/data/local/tmp/libsec/libsecmon-child.so"
                    }
                ]
            }
        }
    ]
}
```

The config contains an array of targets. A target contains the configuration for one application
you want to inject with frida.

In case things are not working as expected, enable Verbose logging in the
WebUI (off by default: the module stays silent in logcat otherwise — the
setting applies to newly started processes) and check `adb logcat -s
KsuFrida` to see if an error is logged.

## Target configuration

### app_name
The bundle id of the application you want to inject frida into.

### enabled
If set to false, then this module will ignore this configuration.
This is useful if you want to temporarily disable a target while maintaining the config.

### kernel_assisted_evasion
Enables kernel-assisted evasion for the target process (KSIE). Requires KernelSU with compatible kernel patches.

### hide_maps
Whether injected libraries are remapped out of `/proc/self/maps` after
loading (default `true`). Turning it off skips copying every segment, so the
whole gadget is never faulted resident at startup — at the price of leaving
the library paths visible to the target while it runs. Only disable this if
you do not need maps-hiding for the target.

### start_up_delay_ms
Injection of libraries is delayed by this amount in milliseconds.

There are times that you might want to delay the injection of the gadget. Some applications
might run checks at start up and delaying the injection can help avoid these.

### injected_libraries
These are the libraries that will be injected into the process. The libraries
specified here will be loaded in the order of the array.

The module includes a bundled frida gadget at `/data/local/tmp/libsec/libsecmon.so`.
`libsecmon.so` default architecture is always that of your device.

For convenience this module also installs a 32-bit gadget at `/data/local/tmp/libsec/libsecmon32.so` for injection into applications
with 32-bit only support on 64-bit devices.

You can adjust the gadget config according to the official [Gadget Doc](https://frida.re/docs/gadget/)

If you want to use a different frida version or an alternative version you can replace this
with the path to your own gadget.

Using this you can also inject arbitrary libraries alongside the gadget or without the gadget if
you remove it.
Make sure that the libraries you provide here have the correct file permissions set and are accessible
by the app itself.

The module will setup file permissions in the complete `libsec` directory on install. If you suspect
a file permission issue, an easy way to check is to place your libraries within the `libsec` directory
and install the module again (without uninstalling).


## Child gating configuration (experimental)
This is an experimental feature and has a lot of caveats! Please read carefully.

This module is able to intercept fork/vfork within the process to instrument child processes.
An application might fork a child process to run checks from there that you can't intercept
without child gating.

By enabling this feature by setting `enabled` to true, you can configure how to deal
with these child processes.

There are currently 3 modes in how child gating operates. You can determine by
setting the mode to either `freeze`, `kill` or `inject`.

Using any of the child gating mode can cause issues properly shutting down the application even with a force close.
This can cause issues restarting the app. Manually killing the app can resolve this.
```
adb shell su -c 'kill -9 $(pidof com.example.package)'
```

### freeze
The child process will not return from the fork. This means that no code will
run within the child process but the process itself stays alive.

### kill
The child process will be killed as soon as it is forked. No code will
run within the child process.

### inject
This mode will inject the `injected_libraries` into the child process similar to the target configuration.
After injection the child process will resume its normal code flow. You may fail to connect to the gadget
interactively if the child is only doing a quick check and exits.

Please be aware as the child is forked, it already contains all libraries loaded that the parent process had.
But as only a single thread returns from the fork the loaded frida gadget thread is not present in the child process.

The module automatically stages a copy of the gadget (plus its config) into the app's data
directory for each child process before injecting it. The same file cannot be loaded into the
process twice and a symbolic link won't work either — it must be a copy.

The default gadget configuration uses `"on_port_conflict": "pick-next"`, so the child's gadget
binds the next free port instead of failing on the parent's 27042.

If you want a dedicated gadget for child processes (different port or script), create its
configuration at `/data/local/tmp/libsec/libsecmon-child.config.so`.
See [Gadget Doc](https://frida.re/docs/gadget/) for reference.
```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27043,
    "on_port_conflict": "pick-next",
    "on_load": "wait"
  }
}
```

Please take note of the `on_port_conflict: pick-next` which is important in case the parent process forks
multiple children.

Check `adb logcat -s Frida` to see which ports the child gadget started on.

Then connect via
```shell
adb forward tcp:27043 tcp:27043
frida -H 127.0.0.1:27043 -n Gadget
```
