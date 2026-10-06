// Fake KernelSU WebUI bridge for desktop preview. Dev-only, never shipped:
// packaging only copies template/ plus the root config example, so this
// directory cannot end up on a device. Loaded before main.js by preview.html.
(function () {
    "use strict";

    // Keep in sync with src/util.ts + main.ts marker constants.
    var DONE_MARK = "@@__KSUFRIDA_DONE__";
    var CONFIG_MARK = "@@__KSUFRIDA_CONFIG__";
    var GADGET_MARK = "@@__KSUFRIDA_GADGET__";
    var SAVE_MARK = "__KSU_FRIDA_SAVED__";
    var GVER_MARK = "@@__KSUFRIDA_GVER__";
    var ABI_MARK = "@@__KSUFRIDA_ABI__";
    var META_MARK = "@@__KSUFRIDA_META__";
    var VERBOSE_PATH = "/data/local/tmp/libsec/verbose";

    var PKGS = ["com.example.app", "com.example.game", "com.example.notes"];
    var LABELS = {
        "com.example.app": "Example App",
        "com.example.game": "Example Game",
        "com.example.notes": "Example Notes"
    };

    var state = {
        verbose: false,
        bundled: "17.22.1",
        config: JSON.stringify({
            targets: [
                {
                    app_name: "com.example.app",
                    enabled: true,
                    hide_maps: true,
                    start_up_delay_ms: 500,
                    injected_libraries: [{ path: "/data/local/tmp/libsec/libsecmon.so" }],
                    child_gating: { enabled: false, mode: "freeze", injected_libraries: [] }
                },
                {
                    app_name: "com.example.game",
                    enabled: false,
                    hide_maps: true,
                    start_up_delay_ms: 0,
                    injected_libraries: [{ path: "/data/local/tmp/libsec/libsecmon.so" }],
                    child_gating: { enabled: true, mode: "freeze", injected_libraries: [] }
                }
            ]
        }),
        gadget: '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}'
    };

    function metaJson() {
        return JSON.stringify({
            version: "17.33.0",
            assets: {
                arm: "https://github.com/sohan-f/knox-frida-patcher/releases/download/17.33.0/frida-gadget-17.33.0-android-arm.so.xz",
                arm64: "https://github.com/sohan-f/knox-frida-patcher/releases/download/17.33.0/frida-gadget-17.33.0-android-arm64.so.xz"
            },
            sha256: { arm: "aa".repeat(32), arm64: "bb".repeat(32) }
        });
    }

    // Inverse of shQuote: reads one single-quoted shell token.
    function extractQuoted(cmd, at) {
        var out = "";
        var i = at + 1;
        while (i < cmd.length) {
            if (cmd[i] === "'") {
                if (cmd.substr(i, 4) === "'\\''") { out += "'"; i += 4; continue; }
                return out;
            }
            out += cmd[i];
            i += 1;
        }
        return out;
    }

    function route(cmd) {
        cmd = String(cmd);
        if (cmd === "echo __KSU_PROBE__") return "__KSU_PROBE__";
        if (/&\s*$/.test(cmd)) return "";
        if (cmd.indexOf("cat ") === 0) {
            if (cmd.indexOf(".webui-gadget-dl.tmp") !== -1) {
                return "STAGE:download\nSTAGE:verify\nSTAGE:install\nRESULT:ok\n" + DONE_MARK + "\n";
            }
            if (cmd.indexOf(".webui-labels.tmp") !== -1) {
                return PKGS.map(function (p) { return p + "|" + (LABELS[p] || p); }).join("\n") +
                    "\n" + DONE_MARK + "\n";
            }
            if (cmd.indexOf(".webui-scan.tmp") !== -1) return "17.22.1\n" + DONE_MARK + "\n";
            if (cmd.indexOf(".webui-packages.tmp") !== -1) {
                return PKGS.map(function (p) { return "package:" + p; }).join("\n") +
                    "\n" + DONE_MARK + "\n";
            }
            return "";
        }
        if (cmd.indexOf(CONFIG_MARK) !== -1) {
            return CONFIG_MARK + "\n" + state.config + "\n" + GADGET_MARK + "\n" + state.gadget + "\n";
        }
        if (cmd.indexOf("^version=") !== -1) {
            return "MOD:v1.9.39\nGADGETKEY:40711:1728000000\nVERBOSE:" +
                (state.verbose ? "on" : "off") + "\n";
        }
        if (cmd.indexOf(GVER_MARK) !== -1) {
            return GVER_MARK + "\n" + state.bundled + "\n" + ABI_MARK + "\narm64-v8a\n" +
                META_MARK + "\n" + metaJson() + "\n";
        }
        if (cmd.indexOf("tag_name") !== -1) return "";
        if (cmd.indexOf("GADGET_SRC_MISSING") !== -1) return "GADGET_OK\nGADGET32_OK\n" + SAVE_MARK + "\n";
        if (cmd.indexOf(SAVE_MARK) !== -1 && cmd.indexOf("printf ") !== -1) {
            var at = cmd.indexOf("printf '%s\\n' ");
            if (at !== -1) {
                try {
                    var body = extractQuoted(cmd, at + "printf '%s\\n' ".length);
                    JSON.parse(body);
                    if (cmd.indexOf("libsecmon.config.so") !== -1) state.gadget = body;
                    else state.config = body;
                } catch (_) {}
            }
            return SAVE_MARK + "\n";
        }
        if (cmd.indexOf("/proc/[0-9]*/cmdline") !== -1) return "com.example.app 1234\n";
        if (cmd.indexOf("/proc/net/tcp") !== -1) return "27042\n";
        if (cmd.indexOf("touch " + VERBOSE_PATH) === 0) { state.verbose = true; return ""; }
        if (cmd.indexOf("rm -f " + VERBOSE_PATH) === 0) { state.verbose = false; return ""; }
        if (cmd.indexOf("ls -a -p ") === 0) {
            var m = /'([^']*)'/.exec(cmd);
            var dir = m ? m[1] : "";
            if (dir === "/data/local/tmp/libsec") {
                return "libsecmon.so\nlibsecmon32.so\nlibsecmon.config.so\nold/\n";
            }
            if (dir === "/data/local/tmp/libsec/old") return "libsecmon.so.1\n";
            if (dir === "/data/local/tmp") return "libsec/\n";
            return "";
        }
        return "";
    }

    window.ksu = {
        exec: function (cmd, opts, callback) {
            if (typeof callback === "string") {
                var out = route(cmd);
                setTimeout(function () {
                    var fn = window[callback];
                    if (typeof fn === "function") fn(0, out, "");
                }, 5);
                return;
            }
            return route(cmd);
        },
        toast: function (m) { console.log("[preview toast]", m); },
        listPackages: function () { return JSON.stringify(PKGS); },
        getPackagesInfo: function (query) {
            var names = [];
            try { names = JSON.parse(String(query)); } catch (_) {}
            return JSON.stringify(names.map(function (p) {
                return { packageName: p, appLabel: LABELS[p] || p };
            }));
        }
    };

    var css = "margin:0;padding:6px 12px;background:#2a1412;color:#f08070;" +
        'font:12px/1.4 "Roboto",sans-serif;text-align:center;position:fixed;top:0;' +
        "left:0;right:0;z-index:3000;";
    var banner = document.createElement("div");
    banner.setAttribute("style", css);
    banner.textContent = "Preview mode: simulated root shell, nothing is real. " +
        "Save/Reload persist in memory until refresh.";
    document.body.style.paddingTop = "64px";
    document.body.appendChild(banner);
})();
