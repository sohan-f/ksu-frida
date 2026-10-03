const CONFIG_PATH = "/data/local/tmp/libsec/config.json";
const GADGET_CONFIG_PATH = "/data/local/tmp/libsec/libsecmon.config.so";
const MODULE_PROP = "/data/adb/modules/ksufrida/module.prop";
const GADGET_PATH = "/data/local/tmp/libsec/libsecmon.so";
const DEFAULT_GADGET = '{"interaction":{"type":"listen","address":"0.0.0.0","port":27042,"on_port_conflict":"pick-next"}}';

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
const SHELL_LABEL_BATCH = 8;
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

function exec(cmd) {
    return new Promise(function (resolve) {
        var name = "_ksu_cb_" + (++callbackId);
        window[name] = function (errno, stdout, stderr) {
            delete window[name];
            resolve({ errno: errno, stdout: stdout, stderr: stderr });
        };
        ksu.exec(cmd, "{}", name);
    });
}

function shQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function patEsc(s) {
    return String(s).replace(/[\\.*?[\]()|!^$]/g, "\\$&");
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

async function loadConfig() {
    var r = await exec("cat " + CONFIG_PATH);
    if (r.errno === 0 && r.stdout.trim().length > 0) {
        try {
            config = JSON.parse(r.stdout);
        } catch (e) {
            ksu.toast("Config parse error: " + e.message);
            return;
        }
    } else {
        var ex = await exec("cat /data/local/tmp/libsec/config.json.example");
        if (ex.errno === 0) {
            try { config = JSON.parse(ex.stdout); } catch (_) {}
        }
    }
    if (!config.targets || !Array.isArray(config.targets)) config.targets = [];
    dirtyConfig = false;
    updateDirtyBadge();
    renderTargets();
    refreshTargetStatus();
    checkLibraries();
    resolveLabels(config.targets.map(function (t) { return t.app_name; }).filter(Boolean), true, false);
}

async function saveConfig() {
    var json = JSON.stringify(config, null, 4);
    var r = await exec("printf '%s\\n' " + shQuote(json) + " > " + CONFIG_PATH + " && chmod 644 " + CONFIG_PATH);
    if (r.errno === 0) {
        ksu.toast("Config saved");
        dirtyConfig = false;
        updateDirtyBadge();
        checkLibraries();
    } else {
        ksu.toast("Save failed: " + r.stderr);
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

async function loadGadgetConfig() {
    var editor = document.getElementById("gadget-editor");
    var r = await exec("cat " + GADGET_CONFIG_PATH);
    if (r.errno === 0 && r.stdout.trim().length > 0) {
        gadgetFileOk = true;
        editor.value = r.stdout;
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
    var r = await exec("printf '%s\\n' " + shQuote(content) + " > " + GADGET_CONFIG_PATH + " && chmod 644 " + GADGET_CONFIG_PATH);
    if (r.errno === 0) {
        ksu.toast("Gadget config saved");
        gadgetFileOk = true;
        dirtyGadget = false;
        updateDirtyBadge();
        validateGadget();
        scheduleStatus();
        refreshConnect();
    } else {
        ksu.toast("Failed: " + r.stderr);
    }
}

function appendStatusRow(label, value, bad) {
    var el = document.getElementById("status-rows");
    var row = document.createElement("div");
    row.className = "status-row";
    var k = document.createElement("span");
    k.className = "kv";
    k.textContent = label;
    var v = document.createElement("span");
    v.textContent = value;
    if (bad) v.style.color = "var(--danger)";
    row.appendChild(k);
    row.appendChild(v);
    el.appendChild(row);
}

async function gadgetVersion(key) {
    if (key) {
        var cached = null;
        try { cached = JSON.parse(localStorage.getItem(GADGET_VERSION_KEY) || "null"); } catch (_) {}
        if (cached && cached.k === key && cached.v) return cached.v;
    }
    var r = await exec(
        "strings -a " + GADGET_PATH + " 2>/dev/null | " +
        "grep -E '^(1[6-9]|2[0-9])\\.[0-9]+\\.[0-9]+$' | head -1"
    );
    var v = (r.errno === 0 && r.stdout.trim()) || "unknown";
    if (key) {
        try { localStorage.setItem(GADGET_VERSION_KEY, JSON.stringify({ k: key, v: v })); } catch (_) {}
    }
    return v;
}

async function loadStatus() {
    var el = document.getElementById("status-rows");
    var cmd =
        "v=$(grep -m1 '^version=' " + MODULE_PROP + " 2>/dev/null | cut -d= -f2); " +
        "[ -n \"$v\" ] && echo \"MOD:$v\" || echo 'MOD:not installed'; " +
        "if [ -f " + GADGET_PATH + " ]; then " +
        "echo \"GADGETKEY:$(stat -c '%s:%Y' " + GADGET_PATH + " 2>/dev/null)\"; " +
        "else echo 'GADGET:missing'; fi";

    var rows = {};
    var r = await exec(cmd);
    if (r.errno === 0) {
        r.stdout.split("\n").forEach(function (line) {
            var i = line.indexOf(":");
            if (i > 0) rows[line.slice(0, i)] = line.slice(i + 1).trim();
        });
    }

    if (!("GADGET" in rows)) {
        rows.GADGET = await gadgetVersion(rows.GADGETKEY || "");
    }

    el.innerHTML = "";
    el.className = "";
    var mod = rows.MOD || "unknown";
    appendStatusRow("Module", mod, mod === "not installed" || mod === "unknown");
    var gad = rows.GADGET || "unknown";
    appendStatusRow("Gadget", gad, gad === "missing" || gad === "unknown");
    appendStatusRow("Gadget config", gadgetFileOk ? "saved" : "not found", !gadgetFileOk);
    var total = config.targets.length;
    var enabled = config.targets.filter(function (t) { return !!t.enabled; }).length;
    appendStatusRow("Targets", total + " total · " + enabled + " enabled", false);
    var missing = Object.keys(missingPaths);
    if (missing.length > 0) {
        appendStatusRow("Libraries", missing.length + (missing.length === 1 ? " file missing" : " files missing"), true);
    }
}

async function refreshTargetStatus() {
    var names = config.targets
        .map(function (t) { return t.app_name; })
        .filter(function (n) { return !!n; });

    targetStatus = {};
    if (names.length > 0) {
        var pat = names.map(patEsc).join("|");
        var r = await exec(
            "for c in /proc/[0-9]*/cmdline; do set -- $(tr \"\\0\" \" \" 2>/dev/null < \"$c\"); " +
            "case \"$1\" in " + pat + ") p=${c#/proc/}; echo \"$1 ${p%%/cmdline}\";; esac; done"
        );
        if (r.errno === 0) {
            r.stdout.split("\n").forEach(function (line) {
                var parts = line.trim().split(/\s+/);
                if (parts.length === 2 && names.indexOf(parts[0]) !== -1) {
                    (targetStatus[parts[0]] = targetStatus[parts[0]] || []).push(parts[1]);
                }
            });
        }
    }
    updateStatusPills();
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
    exec("am force-stop " + shQuote(pkg)).then(function (r) {
        ksu.toast(r.errno === 0 ? "Stopped " + pkg : "force-stop failed: " + (r.stderr || r.errno));
        setTimeout(refreshTargetStatus, 800);
        setTimeout(refreshConnect, 1500);
    });
}

function startApp(i) {
    var t = config.targets[i];
    if (!t) return;
    var pkg = t.app_name.split(":")[0];
    exec("monkey -p " + shQuote(pkg) + " -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1").then(function (r) {
        ksu.toast(r.errno === 0 ? "Starting " + pkg : "start failed: " + (r.stderr || r.errno));
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

async function refreshConnect() {
    var body = document.getElementById("connect-body");
    var info = gadgetListenInfo();

    if (!info.listen) {
        if (connectKey === "nolisten") return;
        connectKey = "nolisten";
        body.className = "";
        body.innerHTML = "";
        var note = document.createElement("div");
        note.className = "warn";
        note.textContent = "interaction.type is not \"listen\" — the gadget won't open a port.";
        body.appendChild(note);
        return;
    }

    var end = Math.min(info.base + 64, 65535);
    var cmd =
        "for f in /proc/net/tcp /proc/net/tcp6; do awk 'NR>1 && $4==\"0A\"{print $2}' \"$f\"; done | " +
        "while read l; do p=$((0x${l##*:})); [ $p -ge " + info.base + " ] && [ $p -le " + end +
        " ] && echo $p; done | sort -nu";

    var r = await exec(cmd);
    var ports = [];
    if (r.errno === 0) {
        r.stdout.split("\n").forEach(function (l) {
            var p = parseInt(l, 10);
            if (p) ports.push(p);
        });
    }

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

    var r = await exec("pm list packages -3");
    if (r.errno !== 0) return [];
    return r.stdout.split("\n")
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
        writeAppsCache();
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
                if (i + LABEL_CHUNK < missing.length) await delay(15);
            }
        } finally {
            labelsPending = false;
            updateAppHint();
            if (isAppModalOpen()) renderAppList();
        }
        return;
    }

    if (!allowShell) return;
    if (fullSweep) labelsTried = true;

    labelsPending = true;
    updateAppHint();
    for (var j = 0; j < missing.length; j += SHELL_LABEL_BATCH) {
        var chunk = missing.slice(j, j + SHELL_LABEL_BATCH);
        var cmd = "for p in " + chunk.map(shQuote).join(" ") + "; do " +
            "l=$(dumpsys package \"$p\" 2>/dev/null | grep -m1 'nonLocalizedLabel=' | " +
            "sed 's/.*nonLocalizedLabel=//;s/ .*//'); " +
            "[ -n \"$l\" ] && [ \"$l\" != null ] && echo \"$p|$l\"; done";
        var r = await exec(cmd);
        var pairs2 = new Map();
        if (r.errno === 0) {
            r.stdout.split("\n").forEach(function (line) {
                var i = line.indexOf("|");
                if (i > 0) pairs2.set(line.slice(0, i), line.slice(i + 1).trim());
            });
        }
        applyLabels(pairs2);
        if (isAppModalOpen()) patchAppLabels();
        if (j + SHELL_LABEL_BATCH < missing.length) await delay(50);
    }
    labelsPending = false;
    updateAppHint();
    if (isAppModalOpen()) renderAppList();
}

async function fetchApps() {
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

            appsLoading = allApps.length === 0;
            updateAppHint();

            var names = await listPackageNames();
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
            t.start_up_delay_ms = parseInt(value, 10) || 0;
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
    refreshTargetStatus();
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
    refreshTargetStatus();
    scheduleStatus();
}

function showAppList() {
    document.getElementById("app-modal").style.display = "flex";
    document.getElementById("app-search").value = "";
    fetchApps();
    renderAppList();
    if (!nativeLabelsAvailable() && !labelsTried && allApps.length > 0) {
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
    loadConfig();
    loadGadgetConfig();
    fetchApps();
    refreshConnect();
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

    loadConfig();
    loadGadgetConfig();
    fetchApps();
    scheduleStatus();
    refreshConnect();
    refreshTargetStatus();

    var poll = function () {
        if (document.hidden) return;
        refreshTargetStatus();
        refreshConnect();
    };
    setInterval(poll, 10000);
    document.addEventListener("visibilitychange", function () {
        if (!document.hidden) poll();
    });
};
