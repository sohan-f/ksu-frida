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
    renderTargets();
    loadStatus();
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
    loadStatus();
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
        loadStatus();
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

async function loadStatus() {
    var el = document.getElementById("status-rows");
    var cmd =
        "v=$(grep -m1 '^version=' " + MODULE_PROP + " 2>/dev/null | cut -d= -f2); " +
        "[ -n \"$v\" ] && echo \"MOD:$v\" || echo 'MOD:not installed'; " +
        "if [ -f " + GADGET_PATH + " ]; then " +
        "gv=$(strings -a " + GADGET_PATH + " 2>/dev/null | grep -E '^(1[6-9]|2[0-9])\\.[0-9]+\\.[0-9]+$' | head -1); " +
        "echo \"GADGET:${gv:-unknown}\"; " +
        "else echo 'GADGET:missing'; fi";

    var rows = {};
    var r = await exec(cmd);
    if (r.errno === 0) {
        r.stdout.split("\n").forEach(function (line) {
            var i = line.indexOf(":");
            if (i > 0) rows[line.slice(0, i)] = line.slice(i + 1).trim();
        });
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

async function fetchApps() {
    var r = await exec(
        "for p in $(pm list packages -3 | sed 's/package://'); do " +
        "l=$(dumpsys package \"$p\" | grep -m1 'nonLocalizedLabel=' | sed 's/.*nonLocalizedLabel=//;s/ .*//'); " +
        "echo \"$p|${l:-$p}\"; done"
    );
    if (r.errno === 0 && r.stdout.trim().length > 0) {
        allApps = [];
        r.stdout.split("\n").forEach(function (line) {
            line = line.trim();
            if (!line) return;
            var parts = line.split("|");
            var pkg = parts[0];
            var label = parts[1] || pkg;
            allApps.push(pkg);
            appLabels[pkg] = label;
        });
        allApps.sort(function (a, b) {
            return (appLabels[a] || a).localeCompare(appLabels[b] || b);
        });
    }
    if (allApps.length === 0) {
        var r2 = await exec("pm list packages -3");
        if (r2.errno === 0 && r2.stdout.trim().length > 0) {
            allApps = r2.stdout.split("\n")
                .filter(function (l) { return l.indexOf("package:") === 0; })
                .map(function (l) { return l.replace("package:", "").trim(); })
                .sort();
        }
    }
}

function getAppLabel(pkg) {
    return appLabels[pkg] || pkg;
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
            renderTargets();
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
                renderTargets();
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
            renderTargets();
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
    renderTargets();
    refreshTargetStatus();
    loadStatus();
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
    renderTargets();
    checkLibraries();
    refreshTargetStatus();
    loadStatus();
}

function showAppList() {
    document.getElementById("app-modal").style.display = "flex";
    document.getElementById("app-search").value = "";
    renderAppList();
}

function closeAppModal() {
    document.getElementById("app-modal").style.display = "none";
}

function renderAppList() {
    var list = document.getElementById("app-list");
    var search = document.getElementById("app-search").value.toLowerCase();

    var filtered = allApps.filter(function (a) {
        var label = (appLabels[a] || "").toLowerCase();
        return a.toLowerCase().indexOf(search) !== -1 || label.indexOf(search) !== -1;
    });

    if (filtered.length === 0) {
        list.innerHTML = '<div class="empty">No apps found</div>';
        return;
    }

    list.innerHTML = "";
    filtered.forEach(function (app) {
        var row = document.createElement("div");
        row.className = "app-row";
        var labelEl = document.createElement("div");
        var strong = document.createElement("strong");
        strong.textContent = getAppLabel(app);
        labelEl.appendChild(strong);
        var pkgEl = document.createElement("div");
        pkgEl.className = "app-label";
        pkgEl.textContent = app;
        row.appendChild(labelEl);
        row.appendChild(pkgEl);
        row.onclick = function () {
            addTarget(app);
            closeAppModal();
        };
        list.appendChild(row);
    });
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

    document.getElementById("btn-add").onclick = showAppList;
    document.getElementById("btn-save").onclick = saveConfig;
    document.getElementById("btn-reload").onclick = reloadAll;
    document.getElementById("btn-save-gadget").onclick = saveGadgetConfig;
    document.getElementById("btn-close-modal").onclick = closeAppModal;
    document.getElementById("app-search").oninput = renderAppList;
    document.getElementById("btn-status").onclick = loadStatus;
    document.getElementById("btn-connect").onclick = function () { refreshConnect(); };
    document.getElementById("target-search").oninput = function () {
        searchQuery = this.value.trim().toLowerCase();
        renderTargets();
    };
    document.getElementById("gadget-editor").oninput = function () {
        markDirty("gadget");
        validateGadget();
        scheduleConnectRefresh();
    };

    loadConfig();
    loadGadgetConfig();
    fetchApps();
    loadStatus();
    refreshConnect();
    refreshTargetStatus();
    setInterval(function () {
        refreshTargetStatus();
        refreshConnect();
    }, 6000);
};
