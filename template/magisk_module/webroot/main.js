const CONFIG_PATH = "/data/local/tmp/libsec/config.json";
const GADGET_CONFIG_PATH = "/data/local/tmp/libsec/libsecmon.config.so";
const MODULE_PROP = "/data/adb/modules/ksufrida/module.prop";
const GADGET_PATH = "/data/local/tmp/libsec/libsecmon.so";
const VERBOSE_PATH = "/data/local/tmp/libsec/verbose";
const DEFAULT_GADGET = '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}';

let config = { targets: [] };
let allApps = [];
let appLabels = {};
let callbackId = 0;
let missingPaths = {};
let targetStatus = {};
let pillEls = {};
let gadgetConfig = null;
let gadgetFileOk = false;
let dirtyConfig = false;
let dirtyGadget = false;
let searchQuery = "";
let connectKey = "";
let connectTimer = null;

const APPS_CACHE_KEY = "ksufrida.apps.v1";
const GADGET_VERSION_KEY = "ksufrida.gadgetver.v1";
const APP_BATCH = 50;
const LABEL_CHUNK = 100;
let appsLoading = false;
let labelsPending = false;
let labelsTried = false;
let appsLoadPromise = null;
let appListFiltered = [];
let appListRenderIndex = 0;
let appListObserver = null;
let appSearchTimer = null;
let nativeIcons = false;
let statusTimer = null;
let renderScheduled = false;
let targetStatusTimer = null;
let versionScanning = false;
let lastAppsSync = 0;
let lastInteraction = 0;
const APPS_SYNC_TTL = 60000;

// Bridge calls freeze JS; polls yield briefly after user input.
if (typeof document !== "undefined") {
    document.addEventListener("pointerdown", function () {
        lastInteraction = Date.now();
    }, { capture: true, passive: true });
}

async function awaitQuietWindow(ms) {
    var window_ = ms == null ? 500 : ms;
    while (Date.now() - lastInteraction < window_) await delay(120);
}

function delay(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
}

function parseJson(raw, fallback) {
    if (raw == null || raw === "") return fallback;
    if (typeof raw !== "string") return raw;
    try { return JSON.parse(raw); } catch (_) { return fallback; }
}

function escHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
}

function scheduleStatus() {
    if (statusTimer) return;
    statusTimer = setTimeout(function () { statusTimer = null; loadStatus(); }, 80);
}

function scheduleRenderTargets() {
    if (renderScheduled) return;
    renderScheduled = true;
    requestAnimationFrame(function () { renderScheduled = false; renderTargets(); });
}

function scheduleTargetStatus(ms) {
    clearTimeout(targetStatusTimer);
    targetStatusTimer = setTimeout(function () {
        targetStatusTimer = null;
        refreshTargetStatus();
    }, ms == null ? 150 : ms);
}

const EXEC_TIMEOUT_MS = 15000;
const PROBE_TIMEOUT_MS = 4000;
const SAVE_MARK = "__KSU_FRIDA_SAVED__";
let execMode = "auto";
let probePromise = null;

// Managers differ in exec overloads; probe once and fall back rather than hang.
function probeExec() {
    if (execMode !== "auto") return Promise.resolve(execMode);
    if (probePromise) return probePromise;

    probePromise = new Promise(function (resolve) {
        var name = "_ksu_probe_" + (++callbackId);
        var settled = false;
        var timer = null;

        function finish(mode) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            delete window[name];
            execMode = mode;
            resolve(mode);
        }

        timer = setTimeout(function () {
            var mode = syncProbe();
            finish(mode === "none" ? "async" : mode);
        }, PROBE_TIMEOUT_MS);

        window[name] = function (errno, stdout) {
            var text = stdout == null ? "" : String(stdout);
            finish(text.indexOf("__KSU_PROBE__") !== -1 ? "async" : syncProbe());
        };
        try {
            ksu.exec("echo __KSU_PROBE__", "{}", name);
        } catch (_) {
            finish(syncProbe());
        }
    });
    return probePromise;
}

function syncProbe() {
    try {
        var out = ksu.exec("echo __KSU_PROBE__");
        if (out != null && String(out).indexOf("__KSU_PROBE__") !== -1) return "sync";
    } catch (_) {}
    return "none";
}

function exec(cmd) {
    return probeExec().then(function (mode) {
        if (mode === "async") return asyncExec(cmd);
        if (mode === "sync") return syncExec(cmd);
        return { errno: -1, stdout: "", stderr: "KernelSU exec API unavailable" };
    });
}

function asyncExec(cmd) {
    return new Promise(function (resolve) {
        var name = "_ksu_cb_" + (++callbackId);
        var settled = false;

        var timer = setTimeout(function () {
            if (settled) return;
            settled = true;
            delete window[name];
            execMode = "sync";
            resolve(syncExec(cmd));
        }, EXEC_TIMEOUT_MS);

        window[name] = function (errno, stdout, stderr) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            delete window[name];
            var code = Number(errno);
            resolve({
                errno: isNaN(code) ? -1 : code,
                stdout: stdout == null ? "" : String(stdout),
                stderr: stderr == null ? "" : String(stderr)
            });
        };

        try {
            ksu.exec(cmd, "{}", name);
        } catch (_) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            delete window[name];
            execMode = "sync";
            resolve(syncExec(cmd));
        }
    });
}

function syncExec(cmd) {
    try {
        var out = ksu.exec(cmd);
        return { errno: 0, stdout: out == null ? "" : String(out), stderr: "" };
    } catch (e) {
        execMode = "none";
        return { errno: -1, stdout: "", stderr: String((e && e.message) || e) };
    }
}

// Single-quoted literals only; never let package names expand as globs or subshells.
function shQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

const DONE_MARK = "@@__KSUFRIDA_DONE__";
const LABEL_FILE = "/data/local/tmp/libsec/.webui-labels.tmp";
const SCAN_FILE = "/data/local/tmp/libsec/.webui-scan.tmp";
const PKGS_FILE = "/data/local/tmp/libsec/.webui-packages.tmp";
const POLL_INTERVAL_MS = 1000;

// Each exec spawns a fresh root shell; slow work runs detached and is polled.
async function runDetached(script, path, onBody, opts) {
    opts = opts || {};
    if (execMode === "none") return false;
    await exec("{ " + script + "; echo \"" + DONE_MARK + "\"; } > " + path +
        " </dev/null 2>/dev/null &");
    var deadline = Date.now() + (opts.timeout || 120000);
    var maxStale = opts.maxStale == null ? 8 : opts.maxStale;
    var lastLen = -1;
    var stale = 0;
    var done = false;
    while (Date.now() < deadline) {
        await delay(POLL_INTERVAL_MS);
        await awaitQuietWindow();
        var r = await exec("cat " + path + " 2>/dev/null");
        var text = (r.errno === 0 && r.stdout) || "";
        done = text.indexOf(DONE_MARK) !== -1;
        var body = done ? text : text.slice(0, text.lastIndexOf("\n") + 1);
        if (body && onBody) onBody(body, done);
        if (done) break;
        if (text.length === lastLen) {
            if (maxStale > 0 && ++stale >= maxStale) break;
        } else {
            stale = 0;
            lastLen = text.length;
        }
    }
    exec("rm -f " + path);
    return done;
}

function parseLabelLines(body) {
    var pairs = new Map();
    body.split("\n").forEach(function (line) {
        if (!line || line === DONE_MARK) return;
        var i = line.indexOf("|");
        if (i > 0) pairs.set(line.slice(0, i), line.slice(i + 1).trim());
    });
    return pairs;
}

function splitMarked(text, marks) {
    var parts = {};
    var cur = null;
    String(text || "").split("\n").forEach(function (line) {
        if (marks.indexOf(line) !== -1) { cur = line; parts[cur] = []; return; }
        if (cur) parts[cur].push(line);
    });
    return parts;
}

function markDirty(which) {
    if (which === "cfg") dirtyConfig = true;
    else if (which === "gadget") dirtyGadget = true;
    updateDirtyBadge();
}

function updateDirtyBadge() {
    var b = document.getElementById("dirty-badge");
    var any = dirtyConfig || dirtyGadget;
    b.style.display = any ? "block" : "none";
    if (any) {
        b.textContent = dirtyConfig && dirtyGadget
            ? "● Unsaved changes (targets + gadget)"
            : dirtyConfig ? "● Unsaved changes (targets)" : "● Unsaved changes (gadget config)";
    }
}

function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
            function () { ksu.toast("Copied"); },
            function () { ksu.toast("Copy failed — select the text manually"); }
        );
    } else {
        ksu.toast("Select the text and copy manually");
    }
}

const CONFIG_MARK = "@@__KSUFRIDA_CONFIG__";
const GADGET_MARK = "@@__KSUFRIDA_GADGET__";

async function loadConfigs() {
    var r = await exec(
        "echo " + CONFIG_MARK + ";" +
        "if [ -s " + CONFIG_PATH + " ]; then cat " + CONFIG_PATH + "; " +
        "else cat /data/local/tmp/libsec/config.json.example 2>/dev/null; fi;" +
        "echo;" +
        "echo " + GADGET_MARK + ";" +
        "cat " + GADGET_CONFIG_PATH + " 2>/dev/null"
    );
    var parts = {};
    var cur = null;
    (r.errno === 0 ? r.stdout : "").split("\n").forEach(function (line) {
        if (line === CONFIG_MARK) { cur = "cfg"; parts.cfg = []; return; }
        if (line === GADGET_MARK) { cur = "gadget"; parts.gadget = []; return; }
        if (cur) parts[cur].push(line);
    });
    applyConfigText((parts.cfg || []).join("\n"));
    applyGadgetText((parts.gadget || []).join("\n"));
}

function applyConfigText(text) {
    if (text && text.trim().length > 0) {
        try {
            config = JSON.parse(text);
        } catch (e) {
            ksu.toast("Config parse error: " + e.message);
            return;
        }
    }
    if (!config.targets || !Array.isArray(config.targets)) config.targets = [];
    dirtyConfig = false;
    updateDirtyBadge();
    renderTargets();
    scheduleTargetStatus();
    checkLibraries();
    resolveLabels(config.targets.map(function (t) { return t.app_name; }).filter(Boolean), true, false);
}

async function saveConfig() {
    var json = JSON.stringify(config, null, 4);
    var r = await exec("{ printf '%s\\n' " + shQuote(json) + " > " + CONFIG_PATH +
        " && chmod 644 " + CONFIG_PATH + " && echo " + SAVE_MARK + "; } 2>&1");
    if (String(r.stdout).indexOf(SAVE_MARK) !== -1) {
        ksu.toast("Config saved");
        dirtyConfig = false;
        updateDirtyBadge();
        checkLibraries();
    } else {
        ksu.toast("Save failed: " + (r.stderr || r.stdout || r.errno));
    }
}

async function checkLibraries() {
    var paths = [];
    var seen = {};
    config.targets.forEach(function (t) {
        function collect(libs) {
            (libs || []).forEach(function (l) {
                if (l && l.path && !seen[l.path]) {
                    seen[l.path] = 1;
                    paths.push(l.path);
                }
            });
        }
        collect(t.injected_libraries);
        collect(t.child_gating && t.child_gating.injected_libraries);
    });

    var before = JSON.stringify(Object.keys(missingPaths).sort());
    missingPaths = {};
    if (paths.length > 0) {
        var r = await exec("for f in " + paths.map(shQuote).join(" ") +
            "; do [ -f \"$f\" ] || echo \"MISSING:$f\"; done");
        if (r.errno === 0) {
            r.stdout.split("\n").forEach(function (line) {
                if (line.indexOf("MISSING:") === 0) missingPaths[line.slice(8)] = 1;
            });
        }
    }
    if (JSON.stringify(Object.keys(missingPaths).sort()) !== before) scheduleRenderTargets();
    scheduleStatus();
}

function applyGadgetText(text) {
    var editor = document.getElementById("gadget-editor");
    if (text && text.trim().length > 0) {
        gadgetFileOk = true;
        editor.value = text;
    } else {
        gadgetFileOk = false;
        editor.value = DEFAULT_GADGET;
    }
    validateGadget();
    dirtyGadget = false;
    updateDirtyBadge();
    scheduleStatus();
    refreshConnect();
}

function validateGadget() {
    var status = document.getElementById("gadget-status");
    var text = document.getElementById("gadget-editor").value;
    var obj = null;
    try { obj = JSON.parse(text); } catch (_) {}
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
        gadgetConfig = null;
        status.className = "status-err";
        status.textContent = "Invalid JSON";
        return null;
    }
    gadgetConfig = obj;
    var hasInteraction = !!obj.interaction && typeof obj.interaction === "object";
    if (!gadgetFileOk) {
        status.className = "status-warn";
        status.textContent = "Not found (default shown)";
    } else if (hasInteraction) {
        status.className = "status-ok";
        status.textContent = "Valid";
    } else {
        status.className = "status-warn";
        status.textContent = "No interaction";
    }
    return obj;
}

async function saveGadgetConfig() {
    var obj = validateGadget();
    if (!obj) {
        ksu.toast("Fix the JSON before saving");
        return;
    }
    var content = document.getElementById("gadget-editor").value;
    var r = await exec("{ printf '%s\\n' " + shQuote(content) + " > " + GADGET_CONFIG_PATH +
        " && chmod 644 " + GADGET_CONFIG_PATH + " && echo " + SAVE_MARK + "; } 2>&1");
    if (String(r.stdout).indexOf(SAVE_MARK) !== -1) {
        ksu.toast("Gadget config saved");
        gadgetFileOk = true;
        dirtyGadget = false;
        updateDirtyBadge();
        validateGadget();
        scheduleStatus();
        refreshConnect();
    } else {
        ksu.toast("Failed: " + (r.stderr || r.stdout || r.errno));
    }
}

function appendStatusRow(label, value, bad, valueId) {
    var el = document.getElementById("status-rows");
    var row = document.createElement("div");
    row.className = "status-row";
    var k = document.createElement("span");
    k.className = "kv";
    k.textContent = label;
    var v = document.createElement("span");
    if (valueId) v.id = valueId;
    v.textContent = value;
    if (bad) v.style.color = "var(--danger)";
    row.appendChild(k);
    row.appendChild(v);
    el.appendChild(row);
}

function setStatusValue(id, value, bad) {
    var v = document.getElementById(id);
    if (!v) return;
    v.textContent = value;
    v.style.color = bad ? "var(--danger)" : "";
}

function appendVerboseRow(on) {
    var el = document.getElementById("status-rows");
    var row = document.createElement("div");
    row.className = "status-row";
    var k = document.createElement("span");
    k.className = "kv";
    k.textContent = "Verbose logging";
    var label = document.createElement("label");
    label.className = "switch";
    var input = document.createElement("input");
    input.type = "checkbox";
    input.checked = !!on;
    input.title = "Off: silent in logcat. On: KsuFrida lines for troubleshooting (applies to newly started processes).";
    input.onchange = function () { setVerbose(input.checked); };
    var span = document.createElement("span");
    span.className = "slider";
    label.appendChild(input);
    label.appendChild(span);
    row.appendChild(k);
    row.appendChild(label);
    el.appendChild(row);
}

async function setVerbose(on) {
    if (on) {
        await exec("touch " + VERBOSE_PATH + " && chmod 644 " + VERBOSE_PATH);
    } else {
        await exec("rm -f " + VERBOSE_PATH);
    }
    loadStatus();
}

function readVersionCache(key) {
    if (!key) return null;
    try {
        var cached = JSON.parse(localStorage.getItem(GADGET_VERSION_KEY) || "null");
        if (cached && cached.k === key && cached.v) return cached.v;
    } catch (_) {}
    return null;
}

function startVersionScan(key) {
    if (versionScanning) return;
    versionScanning = true;
    var found = "";
    var script =
        "strings -a " + GADGET_PATH + " 2>/dev/null | " +
        "grep -E '^(1[6-9]|2[0-9])\\.[0-9]+\\.[0-9]+$' | head -1";
    runDetached(script, SCAN_FILE, function (body) {
        found = body.split("\n").filter(function (l) { return l && l !== DONE_MARK; })[0] || "";
    }, { timeout: 60000, maxStale: 40 })
        .then(function () {
            versionScanning = false;
            var v = found.trim() || "unknown";
            if (key) {
                try { localStorage.setItem(GADGET_VERSION_KEY, JSON.stringify({ k: key, v: v })); } catch (_) {}
            }
            setStatusValue("status-gadget", v, v === "unknown");
        });
}

async function loadStatus() {
    var el = document.getElementById("status-rows");
    var cmd =
        "v=$(grep -m1 '^version=' " + MODULE_PROP + " 2>/dev/null | cut -d= -f2); " +
        "[ -n \"$v\" ] && echo \"MOD:$v\" || echo 'MOD:not installed'; " +
        "if [ -f " + GADGET_PATH + " ]; then " +
        "echo \"GADGETKEY:$(stat -c '%s:%Y' " + GADGET_PATH + " 2>/dev/null)\"; " +
        "else echo 'GADGET:missing'; fi; " +
        "if [ -f " + VERBOSE_PATH + " ]; then echo 'VERBOSE:on'; else echo 'VERBOSE:off'; fi;";

    var rows = {};
    var r = await exec(cmd);
    if (execMode === "none") {
        el.innerHTML = "";
        el.className = "";
        appendStatusRow("Shell access", "unavailable (ksu.exec missing)", true);
        appendStatusRow("Targets", config.targets.length + " total", false);
        return;
    }
    if (r.errno === 0) {
        r.stdout.split("\n").forEach(function (line) {
            var i = line.indexOf(":");
            if (i > 0) rows[line.slice(0, i)] = line.slice(i + 1).trim();
        });
    }

    var gad = "unknown";
    if ("GADGET" in rows) {
        gad = rows.GADGET;
    } else {
        gad = readVersionCache(rows.GADGETKEY || "") || "…";
        if (gad === "…") startVersionScan(rows.GADGETKEY || "");
    }

    el.innerHTML = "";
    el.className = "";
    var mod = rows.MOD || "unknown";
    appendStatusRow("Module", mod, mod === "not installed" || mod === "unknown");
    appendStatusRow("Gadget", gad, gad === "missing" || gad === "unknown", "status-gadget");

    appendStatusRow("Gadget config", gadgetFileOk ? "saved" : "not found", !gadgetFileOk);
    appendVerboseRow(rows.VERBOSE === "on");
    var total = config.targets.length;
    var enabled = config.targets.filter(function (t) { return !!t.enabled; }).length;
    appendStatusRow("Targets", total + " total · " + enabled + " enabled", false);
    var missing = Object.keys(missingPaths);
    if (missing.length > 0) {
        appendStatusRow("Libraries", missing.length + (missing.length === 1 ? " file missing" : " files missing"), true);
    }
}

function targetNames() {
    return config.targets
        .map(function (t) { return t.app_name; })
        .filter(function (n) { return !!n; });
}

// One grep for candidates; forking tr per process costs seconds on every poll.
function targetStatusCmd(names) {
    return "for c in $(grep -a -l -F " +
        names.map(function (n) { return "-e " + shQuote(n); }).join(" ") +
        " /proc/[0-9]*/cmdline 2>/dev/null); do " +
        "n=$(tr '\\0' '\\n' 2>/dev/null < \"$c\" | head -1); " +
        "case \"$n\" in " + names.map(shQuote).join("|") + ") " +
        "p=${c#/proc/}; echo \"$n ${p%%/cmdline}\";; esac; done";
}

function applyTargetStatus(stdout, names) {
    targetStatus = {};
    if (stdout) {
        stdout.split("\n").forEach(function (line) {
            var parts = line.trim().split(/\s+/);
            if (parts.length === 2 && names.indexOf(parts[0]) !== -1) {
                (targetStatus[parts[0]] = targetStatus[parts[0]] || []).push(parts[1]);
            }
        });
    }
    updateStatusPills();
}

async function refreshTargetStatus() {
    var names = targetNames();
    if (names.length === 0) { applyTargetStatus("", names); return; }
    var r = await exec(targetStatusCmd(names));
    applyTargetStatus(r.stdout, names);
}

function updateStatusPills() {
    Object.keys(pillEls).forEach(function (name) {
        var pill = pillEls[name];
        if (!pill) return;
        var pids = targetStatus[name];
        if (pids && pids.length > 0) {
            pill.textContent = "running · pid " + pids[0] + (pids.length > 1 ? " +" + (pids.length - 1) : "");
            pill.className = "pill pill-on";
        } else {
            pill.textContent = "stopped";
            pill.className = "pill";
        }
    });
}

function stopApp(i) {
    var t = config.targets[i];
    if (!t) return;
    var pkg = t.app_name.split(":")[0];
    exec("am force-stop " + shQuote(pkg) + " </dev/null >/dev/null 2>&1 &")
        .then(function () {
            ksu.toast("Stopping " + pkg);
            setTimeout(refreshTargetStatus, 800);
            setTimeout(refreshConnect, 1500);
        });
}

function startApp(i) {
    var t = config.targets[i];
    if (!t) return;
    var pkg = t.app_name.split(":")[0];
    exec("monkey -p " + shQuote(pkg) + " -c android.intent.category.LAUNCHER 1 </dev/null >/dev/null 2>&1 &")
        .then(function () {
            ksu.toast("Starting " + pkg);
            setTimeout(refreshTargetStatus, 1500);
            setTimeout(refreshConnect, (t.start_up_delay_ms || 0) + 4000);
        });
}

function gadgetListenInfo() {
    var base = 27042;
    if (gadgetConfig) {
        var ic = gadgetConfig.interaction;
        if (!ic || typeof ic !== "object") return { listen: false, base: base };
        if (ic.type && ic.type !== "listen") return { listen: false, base: base };
        var p = parseInt(ic.port, 10);
        if (p > 0 && p < 65536) base = p;
        return { listen: true, base: base };
    }
    return { listen: true, base: base };
}

function scheduleConnectRefresh() {
    clearTimeout(connectTimer);
    connectTimer = setTimeout(function () { refreshConnect(); }, 700);
}

function connectScanCmd(info) {
    var end = Math.min(info.base + 64, 65535);
    return "for f in /proc/net/tcp /proc/net/tcp6; do awk 'NR>1 && $4==\"0A\"{print $2}' \"$f\"; done | " +
        "while read l; do p=$((0x${l##*:})); [ $p -ge " + info.base + " ] && [ $p -le " + end +
        " ] && echo $p; done | sort -nu";
}

function parsePorts(lines) {
    var ports = [];
    (lines || []).forEach(function (l) {
        var p = parseInt(l, 10);
        if (p) ports.push(p);
    });
    return ports;
}

function renderConnectNote() {
    if (connectKey === "nolisten") return;
    connectKey = "nolisten";
    var body = document.getElementById("connect-body");
    body.className = "";
    body.innerHTML = "";
    var note = document.createElement("div");
    note.className = "warn";
    note.textContent = "interaction.type is not \"listen\" — the gadget won't open a port.";
    body.appendChild(note);
}

function renderConnect(info, ports) {
    var body = document.getElementById("connect-body");
    var end = Math.min(info.base + 64, 65535);

    var key = info.base + "|" + ports.join(",");
    if (key === connectKey) return;
    connectKey = key;

    body.className = "";
    body.innerHTML = "";

    if (ports.length === 0) {
        var empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "Nothing listening on " + info.base + "–" + end +
            ". Start the target app and wait for its start-up delay.";
        body.appendChild(empty);
        return;
    }

    ports.slice(0, 4).forEach(function (p) {
        var text = "adb forward tcp:" + p + " tcp:" + p + "\n" +
            "frida -H 127.0.0.1:" + p + " -n Gadget -l your_script.js";
        var wrap = document.createElement("div");
        wrap.className = "connect-block";
        var block = document.createElement("div");
        block.className = "cmd";
        block.textContent = text;
        wrap.appendChild(block);
        var copy = document.createElement("button");
        copy.className = "btn btn-sm";
        copy.textContent = "Copy";
        copy.onclick = (function (t) { return function () { copyText(t); }; })(text);
        wrap.appendChild(copy);
        body.appendChild(wrap);
    });

    if (ports.length > 4) {
        var more = document.createElement("div");
        more.className = "sub";
        more.textContent = "+" + (ports.length - 4) + " more port(s)";
        body.appendChild(more);
    }
}

async function refreshConnect() {
    var info = gadgetListenInfo();
    if (!info.listen) { renderConnectNote(); return; }
    var r = await exec(connectScanCmd(info));
    renderConnect(info, parsePorts(r.stdout ? r.stdout.split("\n") : []));
}

const TARGET_MARK = "@@__KSUFRIDA_TARGET__";
const PORTS_MARK = "@@__KSUFRIDA_PORTS__";

async function poll() {
    if (document.hidden) return;
    var names = targetNames();
    var info = gadgetListenInfo();

    var sections = [];
    if (names.length > 0) sections.push("echo " + TARGET_MARK + "; " + targetStatusCmd(names));
    if (info.listen) sections.push("echo " + PORTS_MARK + "; " + connectScanCmd(info));

    if (sections.length === 0) {
        applyTargetStatus("", names);
        renderConnectNote();
        return;
    }

    await awaitQuietWindow();
    var r = await exec(sections.join("\n"));
    var parts = splitMarked(r.stdout, [TARGET_MARK, PORTS_MARK]);
    applyTargetStatus(parts[TARGET_MARK] ? parts[TARGET_MARK].join("\n") : "", names);
    if (info.listen) renderConnect(info, parsePorts(parts[PORTS_MARK]));
}

function readAppsCache() {
    try {
        var data = JSON.parse(localStorage.getItem(APPS_CACHE_KEY));
        if (!data || !Array.isArray(data.packages)) return null;
        return data;
    } catch (_) { return null; }
}

function writeAppsCache() {
    try {
        localStorage.setItem(APPS_CACHE_KEY, JSON.stringify({ packages: allApps, labels: appLabels }));
    } catch (_) {}
}

function sortApps() {
    allApps.sort(function (a, b) {
        var la = (appLabels[a] || a).toLowerCase();
        var lb = (appLabels[b] || b).toLowerCase();
        if (la !== lb) return la < lb ? -1 : 1;
        return a < b ? -1 : (a > b ? 1 : 0);
    });
}

function nativeListPackages() {
    if (typeof ksu === "undefined") return null;
    try {
        if (typeof ksu.listPackages === "function") return parseJson(ksu.listPackages("user"), null);
        if (typeof ksu.listUserPackages === "function") return parseJson(ksu.listUserPackages(), null);
    } catch (_) {}
    return null;
}

function nativeLabelsAvailable() {
    return typeof ksu !== "undefined" && typeof ksu.getPackagesInfo === "function";
}

async function listPackageNames() {
    var names = nativeListPackages();
    if (names === null) { await delay(250); names = nativeListPackages(); }
    if (Array.isArray(names) && names.length > 0) return names;

    var out = "";
    await runDetached("pm list packages -3", PKGS_FILE, function (body) { out = body; },
        { timeout: 30000, maxStale: 4 });
    return out.split("\n")
        .filter(function (l) { return l.indexOf("package:") === 0; })
        .map(function (l) { return l.replace("package:", "").trim(); });
}

function applyLabels(pairs) {
    var changed = false;
    var touchedTarget = false;
    pairs.forEach(function (label, pkg) {
        if (!pkg || !label || label === "null") return;
        if (appLabels[pkg] === label) return;
        appLabels[pkg] = label;
        changed = true;
        if (config.targets.some(function (t) { return t.app_name === pkg; })) touchedTarget = true;
    });
    if (changed) {
        sortApps();
        if (!labelsPending) writeAppsCache();
        if (touchedTarget) scheduleRenderTargets();
    }
    return changed;
}

let labelsChain = Promise.resolve();

function resolveLabels(pkgs, allowShell, fullSweep) {
    var run = function () {
        return resolveLabelsNow(pkgs, allowShell, fullSweep).catch(function () {
            labelsPending = false;
            updateAppHint();
        });
    };
    labelsChain = labelsChain.then(run, run);
    return labelsChain;
}

async function resolveLabelsNow(pkgs, allowShell, fullSweep) {
    var missing = pkgs.filter(function (p) { return p && !appLabels[p]; });
    if (missing.length === 0) return;

    if (nativeLabelsAvailable()) {
        labelsPending = true;
        updateAppHint();
        try {
            for (var i = 0; i < missing.length; i += LABEL_CHUNK) {
                var info = parseJson(ksu.getPackagesInfo(JSON.stringify(missing.slice(i, i + LABEL_CHUNK))), null);
                var pairs = new Map();
                if (Array.isArray(info)) {
                    info.forEach(function (it) {
                        if (it && it.packageName && !it.error) pairs.set(it.packageName, it.appLabel || it.packageName);
                    });
                }
                applyLabels(pairs);
                if (i + LABEL_CHUNK < missing.length) await delay(120);
            }
        } finally {
            labelsPending = false;
            writeAppsCache();
            updateAppHint();
            if (isAppModalOpen()) renderAppList();
        }
        return;
    }

    if (!allowShell) return;

    labelsPending = true;
    updateAppHint();
    var script = "for p in " + missing.map(shQuote).join(" ") + "; do " +
        "l=$(dumpsys package \"$p\" 2>/dev/null | grep -m1 'nonLocalizedLabel=' | " +
        "sed 's/.*nonLocalizedLabel=//;s/ .*//'); " +
        "echo \"$p|$l\"; done";
    var completed = false;
    try {
        completed = await runDetached(script, LABEL_FILE, function (body) {
            applyLabels(parseLabelLines(body));
            if (isAppModalOpen()) patchAppLabels();
        }, { timeout: missing.length * 500 + 30000 });
    } finally {
        labelsPending = false;
        writeAppsCache();
        updateAppHint();
        if (isAppModalOpen()) renderAppList();
    }
    if (fullSweep) labelsTried = completed;
}

async function fetchApps(force) {
    if (appsLoadPromise) return appsLoadPromise;
    appsLoadPromise = (async function () {
        try {
            var cached = readAppsCache();
            if (cached) {
                allApps = cached.packages;
                appLabels = cached.labels || {};
                sortApps();
                if (isAppModalOpen()) renderAppList();
            }

            var fresh = !force && lastAppsSync > 0 &&
                Date.now() - lastAppsSync < APPS_SYNC_TTL && allApps.length > 0;
            if (fresh) {
                appsLoading = false;
                updateAppHint();
                await resolveLabels(allApps, false);
                return;
            }

            appsLoading = allApps.length === 0;
            updateAppHint();

            var names = await listPackageNames();
            lastAppsSync = Date.now();
            if (names.length > 0) {
                var known = {};
                allApps.forEach(function (p) { known[p] = 1; });
                if (names.length !== allApps.length || names.some(function (p) { return !known[p]; })) {
                    allApps = names;
                    sortApps();
                    writeAppsCache();
                    if (isAppModalOpen()) renderAppList();
                }
            }
            appsLoading = false;
            updateAppHint();

            await resolveLabels(allApps, false);

            if (isAppModalOpen() && !nativeLabelsAvailable()) resolveLabels(allApps, true, true);
        } catch (e) {
            console.error("fetchApps failed", e);
        } finally {
            appsLoadPromise = null;
        }
    })();
    return appsLoadPromise;
}

function getAppLabel(pkg) {
    return appLabels[pkg] || pkg;
}

function isAppModalOpen() {
    return document.getElementById("app-modal").style.display === "flex";
}

function updateAppHint() {
    var hint = document.getElementById("app-list-hint");
    if (!hint) return;
    var text = appsLoading ? "Loading packages…" : (labelsPending ? "Loading labels…" : "");
    hint.textContent = text;
    hint.style.display = text ? "block" : "none";
}

function patchAppLabels() {
    var rows = document.querySelectorAll("#app-list .app-row");
    for (var i = 0; i < rows.length; i++) {
        var strong = rows[i].querySelector("strong");
        if (strong) strong.textContent = getAppLabel(rows[i].getAttribute("data-pkg"));
    }
}

function mkBtn(text, cls, onclick) {
    var b = document.createElement("button");
    b.className = cls;
    b.textContent = text;
    b.onclick = onclick;
    return b;
}

function makeSwitch(checked, field, idx) {
    var label = document.createElement("label");
    label.className = "switch";
    var input = document.createElement("input");
    input.type = "checkbox";
    input.checked = !!checked;
    input.onchange = function () { updateField(idx, field, input.checked); };
    var span = document.createElement("span");
    span.className = "slider";
    label.appendChild(input);
    label.appendChild(span);
    return label;
}

function fieldBlock(labelText, inputEl) {
    var f = document.createElement("div");
    f.className = "field";
    var l = document.createElement("label");
    l.textContent = labelText;
    f.appendChild(l);
    f.appendChild(inputEl);
    return f;
}

function libsToText(libs) {
    return (libs || []).map(function (l) { return l.path; }).join("\n");
}

function missingNote(libs) {
    var miss = (libs || [])
        .map(function (l) { return l.path; })
        .filter(function (p) { return missingPaths[p]; });
    if (miss.length === 0) return null;
    var d = document.createElement("div");
    d.className = "warn";
    d.textContent = "⚠ not found: " + miss.join(", ");
    return d;
}

function renderTargets() {
    var container = document.getElementById("targets");
    container.innerHTML = "";
    pillEls = {};

    if (config.targets.length === 0) {
        container.innerHTML = '<div class="empty">No targets configured. Tap + Add to start.</div>';
        return;
    }

    var list = config.targets.filter(function (t) {
        if (!searchQuery) return true;
        var label = (appLabels[t.app_name] || t.app_name).toLowerCase();
        return t.app_name.toLowerCase().indexOf(searchQuery) !== -1 || label.indexOf(searchQuery) !== -1;
    });

    if (list.length === 0) {
        container.innerHTML = '<div class="empty">No targets match the filter.</div>';
        return;
    }

    list.forEach(function (t) {
        var i = config.targets.indexOf(t);
        var div = document.createElement("div");
        div.className = "target";

        var head = document.createElement("div");
        head.className = "row";
        var left = document.createElement("div");
        var nameEl = document.createElement("strong");
        nameEl.textContent = getAppLabel(t.app_name);
        var pkgEl = document.createElement("div");
        pkgEl.className = "sub";
        pkgEl.textContent = t.app_name;
        left.appendChild(nameEl);
        left.appendChild(pkgEl);

        var right = document.createElement("div");
        right.className = "row row-gap";
        var pill = document.createElement("span");
        pill.className = "pill";
        pill.textContent = "…";
        pillEls[t.app_name] = pill;
        right.appendChild(pill);
        right.appendChild(makeSwitch(t.enabled, "enabled", i));
        var delBtn = mkBtn("X", "btn btn-danger btn-sm", function () { removeTarget(i); });
        right.appendChild(delBtn);
        head.appendChild(left);
        head.appendChild(right);
        div.appendChild(head);

        var bar = document.createElement("div");
        bar.className = "btnbar";
        bar.appendChild(mkBtn("Force stop", "btn btn-sm", function () { stopApp(i); }));
        bar.appendChild(mkBtn("Start", "btn btn-sm btn-primary", function () { startApp(i); }));
        var spacer = document.createElement("span");
        spacer.className = "spacer";
        bar.appendChild(spacer);
        var ksieLabel = document.createElement("span");
        ksieLabel.className = "sub";
        ksieLabel.textContent = "Kernel Evasion";
        bar.appendChild(ksieLabel);
        bar.appendChild(makeSwitch(t.kernel_assisted_evasion, "ksie", i));
        div.appendChild(bar);

        var delayInput = document.createElement("input");
        delayInput.type = "number";
        delayInput.min = "0";
        delayInput.value = t.start_up_delay_ms || 0;
        delayInput.onchange = function () { updateField(i, "delay", delayInput.value); };
        div.appendChild(fieldBlock("Delay (ms)", delayInput));

        var libsTa = document.createElement("textarea");
        libsTa.value = libsToText(t.injected_libraries);
        libsTa.onchange = function () {
            updateField(i, "libs", libsTa.value);
            checkLibraries();
        };
        div.appendChild(fieldBlock("Injected Libraries", libsTa));
        var note = missingNote(t.injected_libraries);
        if (note) div.appendChild(note);

        var panel = document.createElement("div");
        panel.className = "child-panel";
        var prow = document.createElement("div");
        prow.className = "row";
        var plabel = document.createElement("span");
        plabel.className = "sub";
        plabel.textContent = "Child Gating";
        prow.appendChild(plabel);
        prow.appendChild(makeSwitch(!!(t.child_gating && t.child_gating.enabled), "child_enabled", i));
        panel.appendChild(prow);

        if (t.child_gating && t.child_gating.enabled) {
            var modeSel = document.createElement("select");
            ["freeze", "kill", "inject"].forEach(function (m) {
                var opt = document.createElement("option");
                opt.value = m;
                opt.textContent = m.charAt(0).toUpperCase() + m.slice(1);
                if (t.child_gating.mode === m) opt.selected = true;
                modeSel.appendChild(opt);
            });
            modeSel.onchange = function () { updateField(i, "child_mode", modeSel.value); };
            panel.appendChild(fieldBlock("Mode", modeSel));

            var childTa = document.createElement("textarea");
            childTa.value = libsToText(t.child_gating.injected_libraries);
            childTa.onchange = function () {
                updateField(i, "child_libs", childTa.value);
                checkLibraries();
            };
            panel.appendChild(fieldBlock("Child Libraries", childTa));
            var cnote = missingNote(t.child_gating.injected_libraries);
            if (cnote) panel.appendChild(cnote);
        }
        div.appendChild(panel);

        container.appendChild(div);
    });

    updateStatusPills();
}

function textToLibs(v) {
    return String(v).split("\n")
        .filter(function (l) { return l.trim() !== ""; })
        .map(function (l) { return { path: l.trim() }; });
}

function updateField(i, field, value) {
    var t = config.targets[i];
    if (!t) return;
    switch (field) {
        case "enabled":
            t.enabled = value;
            break;
        case "ksie":
            t.kernel_assisted_evasion = value;
            break;
        case "delay":
            // Rust requires u64; a negative would disable every target.
            t.start_up_delay_ms = Math.max(0, parseInt(value, 10) || 0);
            break;
        case "libs":
            t.injected_libraries = textToLibs(value);
            break;
        case "child_enabled":
            if (!t.child_gating) {
                t.child_gating = { enabled: false, mode: "freeze", injected_libraries: [] };
            }
            t.child_gating.enabled = value;
            markDirty("cfg");
            scheduleRenderTargets();
            return;
        case "child_mode":
            if (t.child_gating) t.child_gating.mode = value;
            break;
        case "child_libs":
            if (t.child_gating) t.child_gating.injected_libraries = textToLibs(value);
            break;
        default:
            return;
    }
    markDirty("cfg");
}

function removeTarget(i) {
    config.targets.splice(i, 1);
    markDirty("cfg");
    scheduleRenderTargets();
    scheduleTargetStatus();
    scheduleStatus();
}

function addTarget(pkg) {
    if (config.targets.some(function (t) { return t.app_name === pkg; })) {
        ksu.toast("Already added");
        return;
    }
    config.targets.push({
        app_name: pkg,
        enabled: true,
        kernel_assisted_evasion: false,
        start_up_delay_ms: 0,
        injected_libraries: [{ path: "/data/local/tmp/libsec/libsecmon.so" }],
        child_gating: { enabled: false, mode: "freeze", injected_libraries: [] }
    });
    markDirty("cfg");
    scheduleRenderTargets();
    checkLibraries();
    scheduleTargetStatus();
    scheduleStatus();
}

function showAppList() {
    document.getElementById("app-modal").style.display = "flex";
    document.getElementById("app-search").value = "";
    fetchApps();
    renderAppList();
    if (!nativeLabelsAvailable() && !labelsTried && !labelsPending && allApps.length > 0) {
        resolveLabels(allApps, true, true);
    }
}

function closeAppModal() {
    document.getElementById("app-modal").style.display = "none";
    if (appListObserver) { appListObserver.disconnect(); appListObserver = null; }
}

function openAppFromRow(e) {
    var row = e.target && e.target.closest ? e.target.closest(".app-row") : null;
    if (!row) return;
    var pkg = row.getAttribute("data-pkg");
    if (!pkg) return;
    addTarget(pkg);
    closeAppModal();
}

function appRowHtml(pkg) {
    var icon = nativeIcons
        ? '<img class="app-icon" src="ksu://icon/' + escHtml(pkg) + '" alt="" loading="lazy" onerror="this.remove()">'
        : "";
    return '<div class="app-row" data-pkg="' + escHtml(pkg) + '">' + icon +
        '<div class="app-row-text"><strong>' + escHtml(getAppLabel(pkg)) + '</strong>' +
        '<div class="app-label">' + escHtml(pkg) + '</div></div></div>';
}

function renderAppBatch() {
    var list = document.getElementById("app-list");
    if (appListRenderIndex >= appListFiltered.length) {
        if (appListObserver) appListObserver.disconnect();
        return;
    }
    var batch = appListFiltered.slice(appListRenderIndex, appListRenderIndex + APP_BATCH);
    appListRenderIndex += batch.length;
    list.insertAdjacentHTML("beforeend", batch.map(appRowHtml).join(""));
    var last = list.lastElementChild;
    if (last && appListObserver) appListObserver.observe(last);
}

function renderAppList() {
    var list = document.getElementById("app-list");
    if (appListObserver) { appListObserver.disconnect(); appListObserver = null; }

    var q = document.getElementById("app-search").value.trim().toLowerCase();
    appListFiltered = allApps.filter(function (pkg) {
        if (!q) return true;
        return pkg.toLowerCase().indexOf(q) !== -1 || (appLabels[pkg] || "").toLowerCase().indexOf(q) !== -1;
    });

    list.innerHTML = "";
    appListRenderIndex = 0;

    if (appListFiltered.length === 0) {
        list.innerHTML = '<div class="empty">' +
            (appsLoading ? "Loading…" : "No apps found") + "</div>";
        updateAppHint();
        return;
    }

    appListObserver = new IntersectionObserver(function (entries) {
        if (entries[0] && entries[0].isIntersecting) renderAppBatch();
    }, { root: list, rootMargin: "300px" });

    renderAppBatch();
    updateAppHint();
}

function reloadAll() {
    loadConfigs();
    fetchApps(true);
}

window.onload = function () {
    if (typeof ksu === "undefined") {
        document.body.innerHTML = '<div style="text-align:center;padding:40px;color:#f44336;">' +
            'This page must be opened in KernelSU Manager.</div>';
        return;
    }

    nativeIcons = typeof ksu.listPackages === "function" ||
        typeof ksu.listUserPackages === "function";

    document.getElementById("btn-add").onclick = showAppList;
    document.getElementById("btn-save").onclick = saveConfig;
    document.getElementById("btn-reload").onclick = reloadAll;
    document.getElementById("btn-save-gadget").onclick = saveGadgetConfig;
    document.getElementById("btn-close-modal").onclick = closeAppModal;
    document.getElementById("app-list").onclick = openAppFromRow;
    document.getElementById("btn-status").onclick = loadStatus;
    document.getElementById("btn-connect").onclick = function () { refreshConnect(); };

    document.getElementById("app-search").oninput = function () {
        clearTimeout(appSearchTimer);
        appSearchTimer = setTimeout(renderAppList, 150);
    };
    var targetSearchTimer = null;
    document.getElementById("target-search").oninput = function () {
        searchQuery = this.value.trim().toLowerCase();
        clearTimeout(targetSearchTimer);
        targetSearchTimer = setTimeout(renderTargets, 150);
    };
    document.getElementById("gadget-editor").oninput = function () {
        markDirty("gadget");
        validateGadget();
        scheduleConnectRefresh();
    };

    loadConfigs();
    fetchApps();
    scheduleStatus();

    setInterval(poll, 10000);
    document.addEventListener("visibilitychange", function () {
        if (!document.hidden) poll();
    });
};
