const CONFIG_PATH = "/data/local/tmp/libsec/config.json";
const GADGET_CONFIG_PATH = "/data/local/tmp/libsec/libsecmon.config.so";
const MODULE_PROP = "/data/adb/modules/ksufrida/module.prop";
const MODDIR = "/data/adb/modules/ksufrida";
const GADGET_SRC = MODDIR + "/gadget/libsecmon.so.xz";
const GADGET32_SRC = MODDIR + "/gadget/libsecmon32.so.xz";
const BUSYBOX_BIN = "/data/adb/ksu/bin/busybox";
const GADGET_PATH = "/data/local/tmp/libsec/libsecmon.so";
const GADGET_VERSION_FILE = MODDIR + "/gadget/gadget.version";
const GADGET_META_URL = "https://github.com/sohan-f/knox-frida-patcher/releases/latest/download/gadget.json";
const GADGET_API_URL = "https://api.github.com/repos/sohan-f/knox-frida-patcher/releases/latest";
const GADGET_DL_DIR = "/data/local/tmp/libsec/.webui-gadget-dl";
const GADGET_DL_LOG = "/data/local/tmp/libsec/.webui-gadget-dl.tmp";
const VERBOSE_PATH = "/data/local/tmp/libsec/verbose";
const DEFAULT_GADGET = '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}';

// KernelSU WebUI bridge (injected by the manager app, absent in plain browsers).
import {
    AppConfig,
    ChildGating,
    ExecResult,
    GadgetMeta,
    GadgetUrls,
    Target,
    blockField,
    cmpVersions,
    escHtml,
    gadgetUrlsForAbi,
    hashCheckSnippet,
    parseGadgetMeta,
    parseJson,
    parseLabelLines,
    parsePorts,
    shQuote,
    splitMarked,
    targetStatusCmd,
    validReleaseUrl,
    validSha256,
    validVersion,
    DONE_MARK,
    LABEL_FILE,
    SCAN_FILE,
    PKGS_FILE,
    POLL_INTERVAL_MS,
} from "./src/util";

declare const ksu: {
    exec(cmd: string): unknown;
    exec(cmd: string, opts: string, callback: string): void;
    toast(message: string): void;
    listPackages?(scope: string): unknown;
    listUserPackages?(): unknown;
    getPackagesInfo?(query: unknown): unknown;
};













let config: AppConfig = { targets: [] };
let allApps: string[] = [];
let appLabels: Record<string, string> = {};
let callbackId = 0;
let missingPaths: Record<string, number> = {};
let targetStatus: Record<string, string[]> = {};
let pillEls: Record<string, HTMLElement> = {};
let gadgetConfig: unknown = null;
let gadgetFileOk = false;
let gadgetBundled: string | null = null;
let gadgetScanned: string | null = null;
let gadgetLatest: string | null = null;
let gadgetUpdateUrls: GadgetUrls = {};
let gadgetUpdateVerified = false;
let gadgetUpdating = false;
let dirtyConfig = false;
let dirtyGadget = false;
let reloadArmed = false;
let reloadArmTimer: ReturnType<typeof setTimeout> | null = null;
let searchQuery = "";
let connectKey = "";
let connectTimer: ReturnType<typeof setTimeout> | null = null;

const APPS_CACHE_KEY = "ksufrida.apps.v1";
const GADGET_VERSION_KEY = "ksufrida.gadgetver.v1";
const APP_BATCH = 50;
const LABEL_CHUNK = 100;
let appsLoading = false;
let labelsPending = false;
let labelsTried = false;
let appsLoadPromise: Promise<void> | null = null;
let appListFiltered: string[] = [];
let appListRenderIndex = 0;
let appListObserver: IntersectionObserver | null = null;
let appSearchTimer: ReturnType<typeof setTimeout> | null = null;
let nativeIcons = false;
let statusTimer: ReturnType<typeof setTimeout> | null = null;
let renderScheduled = false;
let targetStatusTimer: ReturnType<typeof setTimeout> | null = null;
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

async function awaitQuietWindow(ms?: number) {
    var window_ = ms == null ? 500 : ms;
    while (Date.now() - lastInteraction < window_) await delay(120);
}


function getEl(id: string): HTMLElement {
    const e = document.getElementById(id);
    if (!e) throw new Error("missing static element: " + id);
    return e;
}

function textEl(id: string): HTMLInputElement | HTMLTextAreaElement {
    const e = getEl(id);
    if (!(e instanceof HTMLInputElement) && !(e instanceof HTMLTextAreaElement)) {
        throw new Error("not a text field: " + id);
    }
    return e;
}

function delay(ms) {
    return new Promise<void>(function (r) { setTimeout(r, ms); });
}




function appendStatusRow(label: string, value: string, bad: boolean, valueId?: string) {
    var el = getEl("status-rows");
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

function setStatusValue(id: string, value: string, bad: boolean) {
    var v = getEl(id);
    if (!v) return;
    v.textContent = value;
    v.style.color = bad ? "var(--danger)" : "";
}

function appendVerboseRow(on) {
    var el = getEl("status-rows");
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
            gadgetScanned = v !== "unknown" ? v : null;
            setStatusValue("status-gadget", v, v === "unknown");
        });
}

async function loadStatus() {
    var el = getEl("status-rows");
    var cmd =
        "v=$(grep -m1 '^version=' " + MODULE_PROP + " 2>/dev/null | cut -d= -f2); " +
        "[ -n \"$v\" ] && echo \"MOD:$v\" || echo 'MOD:not installed'; " +
        "if [ -f " + GADGET_PATH + " ]; then " +
        "echo \"GADGETKEY:$(stat -c '%s:%Y' " + GADGET_PATH + " 2>/dev/null)\"; " +
        "else echo 'GADGET:missing'; fi; " +
        "if [ -f " + VERBOSE_PATH + " ]; then echo 'VERBOSE:on'; else echo 'VERBOSE:off'; fi;";

    var rows: Record<string, string> = {};
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
    if (gad !== "…" && gad !== "unknown" && gad !== "missing") gadgetScanned = gad;
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


function applyTargetStatus(stdout: string, names: string[]) {
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

const STATUS_CHUNK = 100;

async function execTargetStatus(names: string[]) {
    var out: string[] = [];
    for (var i = 0; i < names.length; i += STATUS_CHUNK) {
        var r = await exec(targetStatusCmd(names.slice(i, i + STATUS_CHUNK)));
        if (r.errno === 0 && r.stdout) out.push(r.stdout);
    }
    return out.join("\n");
}

async function refreshTargetStatus() {
    var names = targetNames();
    if (names.length === 0) { applyTargetStatus("", names); return; }
    applyTargetStatus(await execTargetStatus(names), names);
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
    // monkey(1) enables auto-rotate; resolve the launcher activity and use am instead.
    var script =
        "pkg=" + shQuote(pkg) + "; " +
        "act=$(cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \"$pkg\" 2>/dev/null | grep '/' | tail -n 1 | tr -d '\\r'); " +
        "if [ -n \"$act\" ]; then am start -n \"$act\"; fi </dev/null >/dev/null 2>&1 &";
    exec(script)
        .then(function () {
            ksu.toast("Starting " + pkg);
            setTimeout(refreshTargetStatus, 1500);
            setTimeout(refreshConnect, (t.start_up_delay_ms || 0) + 4000);
        });
}

interface GadgetListen {
    listen: boolean;
    base: number;
}

function gadgetListenInfo(): GadgetListen {
    var base = 27042;
    var ic: unknown = (gadgetConfig as { interaction?: unknown } | null)?.interaction;
    if (!ic || typeof ic !== "object") return { listen: false, base: base };
    var typed = ic as { type?: unknown; port?: unknown };
    if (typed.type && typed.type !== "listen") return { listen: false, base: base };
    var p = parseInt(String(typed.port ?? ""), 10);
    if (p > 0 && p < 65536) base = p;
    return { listen: true, base: base };
}

function scheduleConnectRefresh() {
    if (connectTimer !== null) clearTimeout(connectTimer);
    connectTimer = setTimeout(function () { refreshConnect(); }, 700);
}

function connectScanCmd(info: GadgetListen) {
    var end = Math.min(info.base + 64, 65535);
    return "for f in /proc/net/tcp /proc/net/tcp6; do awk 'NR>1 && $4==\"0A\"{print $2}' \"$f\"; done | " +
        "while read l; do p=$((0x${l##*:})); [ $p -ge " + info.base + " ] && [ $p -le " + end +
        " ] && echo $p; done | sort -nu";
}



function renderConnectNote() {
    if (connectKey === "nolisten") return;
    connectKey = "nolisten";
    var body = getEl("connect-body");
    body.className = "";
    body.innerHTML = "";
    var note = document.createElement("div");
    note.className = "warn";
    note.textContent = "interaction.type is not \"listen\" — the gadget won't open a port.";
    body.appendChild(note);
}

function renderConnect(info, ports) {
    var body = getEl("connect-body");
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

async function poll() {
    if (document.hidden) return;
    var names = targetNames();
    var info = gadgetListenInfo();

    await awaitQuietWindow();
    var targetOut = names.length > 0 ? await execTargetStatus(names) : "";
    applyTargetStatus(targetOut, names);

    if (!info.listen) { renderConnectNote(); return; }
    var r = await exec(connectScanCmd(info));
    renderConnect(info, parsePorts(r.stdout ? r.stdout.split("\n") : []));
}

interface AppsCache {
    packages: string[];
    labels: Record<string, string>;
}

function readAppsCache(): AppsCache | null {
    try {
        var raw = localStorage.getItem(APPS_CACHE_KEY);
        if (!raw) return null;
        var data = JSON.parse(raw);
        if (!data || !Array.isArray(data.packages)) return null;
        return data as AppsCache;
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

function nativeListPackages(): string[] | null {
    if (typeof ksu === "undefined") return null;
    try {
        if (typeof ksu.listPackages === "function") return parseJson<string[] | null>(ksu.listPackages("user"), null);
        if (typeof ksu.listUserPackages === "function") return parseJson<string[] | null>(ksu.listUserPackages(), null);
    } catch (_) {}
    return null;
}

function nativeLabelsAvailable() {
    return typeof ksu !== "undefined" && typeof ksu.getPackagesInfo === "function";
}

async function listPackageNames(): Promise<string[]> {
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

function applyLabels(pairs: Map<string, string>) {
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

async function resolveLabels(pkgs: string[], allowShell: boolean, fullSweep?: boolean) {
    var run = function () {
        return resolveLabelsNow(pkgs, allowShell, fullSweep).catch(function () {
            labelsPending = false;
            updateAppHint();
        });
    };
    labelsChain = labelsChain.then(run, run);
    return labelsChain;
}

async function resolveLabelsNow(pkgs: string[], allowShell: boolean, fullSweep?: boolean) {
    var missing = pkgs.filter(function (p) { return p && !appLabels[p]; });
    if (missing.length === 0) return;

    if (nativeLabelsAvailable()) {
        labelsPending = true;
        updateAppHint();
        try {
            for (var i = 0; i < missing.length; i += LABEL_CHUNK) {
                var getInfo = ksu.getPackagesInfo; var info = getInfo ? parseJson<Array<{ packageName?: string; appLabel?: string; error?: unknown }> | null>(getInfo(JSON.stringify(missing.slice(i, i + LABEL_CHUNK))), null) : null;
                var pairs = new Map<string, string>();
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

async function fetchApps(force?: boolean) {
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
                var known: Record<string, number> = {};
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
    return getEl("app-modal").style.display === "flex";
}

function updateAppHint() {
    var hint = getEl("app-list-hint");
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
    var container = getEl("targets");
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
        var hideLabel = document.createElement("span");
        hideLabel.className = "sub";
        hideLabel.textContent = "Hide maps";
        bar.appendChild(hideLabel);
        bar.appendChild(makeSwitch(t.hide_maps !== false, "hidemaps", i));
        div.appendChild(bar);

        var delayInput = document.createElement("input");
        delayInput.type = "number";
        delayInput.min = "0";
        delayInput.value = String(t.start_up_delay_ms || 0);
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
        const gating = t.child_gating;
        prow.appendChild(makeSwitch(!!(gating && gating.enabled), "child_enabled", i));
        panel.appendChild(prow);

        if (gating && gating.enabled) {
            var modeSel = document.createElement("select");
            ["freeze", "kill", "inject"].forEach(function (m) {
                var opt = document.createElement("option");
                opt.value = m;
                opt.textContent = m.charAt(0).toUpperCase() + m.slice(1);
                if (gating.mode === m) opt.selected = true;
                modeSel.appendChild(opt);
            });
            modeSel.onchange = function () { updateField(i, "child_mode", modeSel.value); };
            panel.appendChild(fieldBlock("Mode", modeSel));

            var childTa = document.createElement("textarea");
            childTa.value = libsToText(gating.injected_libraries);
            childTa.onchange = function () {
                updateField(i, "child_libs", childTa.value);
                checkLibraries();
            };
            panel.appendChild(fieldBlock("Child Libraries", childTa));
            var cnote = missingNote(gating.injected_libraries);
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
        case "hidemaps":
            t.hide_maps = value;
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
        hide_maps: true,
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
    getEl("app-modal").style.display = "flex";
    textEl("app-search").value = "";
    fetchApps();
    renderAppList();
    if (!nativeLabelsAvailable() && !labelsTried && !labelsPending && allApps.length > 0) {
        resolveLabels(allApps, true, true);
    }
}

function closeAppModal() {
    getEl("app-modal").style.display = "none";
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
        ? '<img class="app-icon" src="ksu://icon/' + escHtml(pkg) + '" alt="" loading="lazy">'
        : "";
    return '<div class="app-row" data-pkg="' + escHtml(pkg) + '">' + icon +
        '<div class="app-row-text"><strong>' + escHtml(getAppLabel(pkg)) + '</strong>' +
        '<div class="app-label">' + escHtml(pkg) + '</div></div></div>';
}

function renderAppBatch() {
    var list = getEl("app-list");
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
    var list = getEl("app-list");
    if (appListObserver) { appListObserver.disconnect(); appListObserver = null; }

    var q = textEl("app-search").value.trim().toLowerCase();
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
    if ((dirtyConfig || dirtyGadget) && !reloadArmed) {
        reloadArmed = true;
        ksu.toast("Unsaved changes — tap Reload again to discard");
        if (reloadArmTimer !== null) clearTimeout(reloadArmTimer);
        reloadArmTimer = setTimeout(function () { reloadArmed = false; }, 5000);
        return;
    }
    reloadArmed = false;
    if (reloadArmTimer !== null) clearTimeout(reloadArmTimer);
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

    getEl("btn-add").onclick = showAppList;
    getEl("btn-save").onclick = saveConfig;
    getEl("btn-reload").onclick = reloadAll;
    getEl("btn-save-gadget").onclick = saveGadgetConfig;
    getEl("btn-reset-gadget").onclick = resetGadgetConfig;
    getEl("btn-check-gadget").onclick = checkGadgetUpdate;
    getEl("btn-download-gadget").onclick = downloadGadgetUpdate;
    getEl("btn-refresh-gadget").onclick = refreshGadget;
    getEl("btn-close-modal").onclick = closeAppModal;
    getEl("app-list").onclick = openAppFromRow;
    getEl("app-list").addEventListener("error", function (e) {
        var img = e.target as HTMLElement | null;
        if (img && img.tagName === "IMG") img.remove();
    }, true);
    getEl("btn-status").onclick = loadStatus;
    getEl("btn-connect").onclick = function () { refreshConnect(); };

    getEl("app-search").oninput = function () {
        if (appSearchTimer !== null) clearTimeout(appSearchTimer);
        appSearchTimer = setTimeout(renderAppList, 150);
    };
    var targetSearchTimer: ReturnType<typeof setTimeout> | null = null;
    getEl("target-search").oninput = function () {
        searchQuery = textEl("target-search").value.trim().toLowerCase();
        if (targetSearchTimer !== null) clearTimeout(targetSearchTimer);
        targetSearchTimer = setTimeout(renderTargets, 150);
    };
    getEl("gadget-editor").oninput = function () {
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

function scheduleStatus() {
    if (statusTimer) return;
    statusTimer = setTimeout(function () { statusTimer = null; loadStatus(); }, 80);
}

function scheduleRenderTargets() {
    if (renderScheduled) return;
    renderScheduled = true;
    requestAnimationFrame(function () { renderScheduled = false; renderTargets(); });
}

function scheduleTargetStatus(ms?: number) {
    if (targetStatusTimer !== null) clearTimeout(targetStatusTimer);
    targetStatusTimer = setTimeout(function () {
        targetStatusTimer = null;
        refreshTargetStatus();
    }, ms == null ? 150 : ms);
}

const EXEC_TIMEOUT_MS = 15000;

const PROBE_TIMEOUT_MS = 4000;

const SAVE_MARK = "__KSU_FRIDA_SAVED__";

let execMode = "auto";

let probePromise: Promise<string> | null = null;

// Managers differ in exec overloads; probe once and fall back rather than hang.

function probeExec() {
    if (execMode !== "auto") return Promise.resolve(execMode);
    if (probePromise) return probePromise;

    probePromise = new Promise(function (resolve) {
        var name = "_ksu_probe_" + (++callbackId);
        var settled = false;
        var timer: ReturnType<typeof setTimeout> | null = null;

        function finish(mode) {
            if (settled) return;
            settled = true;
            if (timer !== null) clearTimeout(timer);
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

function exec(cmd: string): Promise<ExecResult> {
    return probeExec().then(function (mode): Promise<ExecResult> | ExecResult {
        if (mode === "async") return asyncExec(cmd);
        if (mode === "sync") return syncExec(cmd);
        return { errno: -1, stdout: "", stderr: "KernelSU exec API unavailable" };
    });
}

function asyncExec(cmd: string): Promise<ExecResult> {
    return new Promise<ExecResult>(function (resolve) {
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
            if (timer !== null) clearTimeout(timer);
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
            if (timer !== null) clearTimeout(timer);
            delete window[name];
            execMode = "sync";
            resolve(syncExec(cmd));
        }
    });
}

function syncExec(cmd: string): ExecResult {
    try {
        var out: unknown = ksu.exec(cmd);
        return { errno: 0, stdout: out == null ? "" : String(out), stderr: "" };
    } catch (e) {
        execMode = "none";
        return { errno: -1, stdout: "", stderr: String(e instanceof Error ? e.message : e) };
    }
}

// Each exec spawns a fresh root shell; slow work runs detached and is polled.

async function runDetached(script, path, onBody, opts) {
    opts = opts || {};
    if (execMode === "none") return false;
    await exec("rm -f " + shQuote(path) + "; { " + script + "; echo \"" + DONE_MARK + "\"; } > " + shQuote(path) +
        " </dev/null 2>/dev/null &");
    var deadline = Date.now() + (opts.timeout || 120000);
    var maxStale = opts.maxStale == null ? 8 : opts.maxStale;
    var lastLen = -1;
    var stale = 0;
    var done = false;
    while (Date.now() < deadline) {
        await delay(POLL_INTERVAL_MS);
        await awaitQuietWindow();
        var r = await exec("cat " + shQuote(path) + " 2>/dev/null");
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
    exec("rm -f " + shQuote(path));
    return done;
}

function markDirty(which) {
    if (which === "cfg") dirtyConfig = true;
    else if (which === "gadget") dirtyGadget = true;
    updateDirtyBadge();
}

function updateDirtyBadge() {
    var b = getEl("dirty-badge");
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
    var parts: Record<string, string[]> = {};
    var cur: string | null = null;
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
            ksu.toast("Config parse error: " + (e instanceof Error ? e.message : String(e)));
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
    var r = await exec("{ rm -f " + CONFIG_PATH + "; printf '%s\\n' " + shQuote(json) + " > " + CONFIG_PATH +
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
    var paths: string[] = [];
    var seen: Record<string, number> = {};
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
    var editor = textEl("gadget-editor");
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
    var status = getEl("gadget-status");
    var text = textEl("gadget-editor").value;
    var obj: unknown = null;
    try { obj = JSON.parse(text); } catch (_) {}
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
        gadgetConfig = null;
        status.className = "status-err";
        status.textContent = "Invalid JSON";
        return null;
    }
    gadgetConfig = obj;
    var shaped = obj as { interaction?: unknown };
    var ic: { type?: unknown } | null =
        !!shaped.interaction && typeof shaped.interaction === "object"
            ? shaped.interaction as { type?: unknown }
            : null;
    var hasInteraction = ic !== null;
    var itype: unknown = ic ? ic.type : null;
    if (!gadgetFileOk) {
        status.className = "status-warn";
        status.textContent = "Not found (default shown)";
    } else if (!hasInteraction) {
        status.className = "status-warn";
        status.textContent = "No interaction";
    } else if (itype !== "listen" && itype !== "script" && itype !== "connect") {
        status.className = "status-warn";
        status.textContent = "Unknown interaction type";
    } else {
        status.className = "status-ok";
        status.textContent = "Valid";
    }
    return obj;
}

async function saveGadgetConfig() {
    var obj = validateGadget();
    if (!obj) {
        ksu.toast("Fix the JSON before saving");
        return;
    }
    var content = textEl("gadget-editor").value;
    var r = await exec("{ rm -f " + GADGET_CONFIG_PATH + "; printf '%s\\n' " + shQuote(content) + " > " + GADGET_CONFIG_PATH +
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

function resetGadgetConfig() {
    textEl("gadget-editor").value = DEFAULT_GADGET;
    markDirty("gadget");
    validateGadget();
    scheduleConnectRefresh();
}

async function refreshGadget() {
    var dst = "/data/local/tmp/libsec";
    var r = await exec("mkdir -p " + dst + "; " +
        "if [ -f " + GADGET_SRC + " ]; then " +
        "rm -f " + dst + "/libsecmon.so.xz " + dst + "/libsecmon.so; " +
        "cp -f " + GADGET_SRC + " " + dst + "/libsecmon.so.xz && " +
        BUSYBOX_BIN + " unxz -f " + dst + "/libsecmon.so.xz && chmod 644 " + dst + "/libsecmon.so && echo GADGET_OK || echo GADGET_FAIL; " +
        "else echo GADGET_SRC_MISSING; fi; " +
        "if [ -f " + GADGET32_SRC + " ]; then " +
        "rm -f " + dst + "/libsecmon32.so.xz " + dst + "/libsecmon32.so; " +
        "cp -f " + GADGET32_SRC + " " + dst + "/libsecmon32.so.xz && " +
        BUSYBOX_BIN + " unxz -f " + dst + "/libsecmon32.so.xz && chmod 644 " + dst + "/libsecmon32.so && echo GADGET32_OK || echo GADGET32_FAIL; fi; " +
        "echo " + SAVE_MARK);
    var out = String(r.stdout || "");
    if (out.indexOf("GADGET_SRC_MISSING") !== -1) {
        ksu.toast("Bundled gadget missing — reinstall the module");
    } else if (out.indexOf("GADGET_OK") !== -1) {
        ksu.toast("Gadget updated");
        loadStatus();
    } else {
        ksu.toast("Update failed: " + (r.stderr || r.stdout || r.errno));
    }
}

// Builds a shell fragment that fails (||) unless the file at path hashes
// to the expected sha256. `sha256sum` may live in PATH or only as a
// busybox applet; the digest itself is hex-validated before embedding.
// path is a raw shell expression (caller-owned); only the hash is quoted.

async function downloadGadgetUpdate() {
    const stored = gadgetUpdateUrls;
    const primary = stored.primary;
    if (gadgetUpdating || !gadgetLatest || !primary) return;
    if (!gadgetUpdateVerified) {
        var proceed = false;
        try {
            proceed = confirm("No hash in update metadata — download " + gadgetLatest + " unverified?");
        } catch (_) {
            proceed = false;
        }
        if (!proceed) {
            setGadgetUpdateLine("Update cancelled (unverified)");
            return;
        }
    }
    gadgetUpdating = true;
    getEl("btn-download-gadget").style.display = "none";
    var v: string = gadgetLatest || "";
    var u1 = primary.url;
    var h1 = primary.sha256;
    var companion = stored.companion ?? null;
    var u2 = companion ? companion.url : null;
    var h2 = companion ? companion.sha256 : null;
    var script =
        "M=" + MODDIR + "/gadget; D=/data/local/tmp/libsec; S=" + GADGET_DL_DIR + "; B=" + BUSYBOX_BIN + "; V=" + shQuote(v) + "; " +
        "rm -rf \"$S\"; mkdir -p \"$S\" \"$D\" \"$M\"; " +
        "if command -v curl >/dev/null 2>&1; then GET=\"curl -sLf --max-time 600 -o\"; else GET=\"wget -q -O\"; fi; " +
        "echo STAGE:download; OK=1; " +
        "$GET \"$S/libsecmon.so.xz\" " + shQuote(u1) + " || OK=0; " +
        (u2 ? "$GET \"$S/libsecmon32.so.xz\" " + shQuote(u2) + " || OK=0; " : "") +
        "if [ \"$OK\" = 1 ]; then echo STAGE:verify; HOK=1; " +
        (h1 ? hashCheckSnippet('"$S/libsecmon.so.xz"', h1, BUSYBOX_BIN) + " || HOK=0; " : "") +
        ((u2 && h2) ? hashCheckSnippet('"$S/libsecmon32.so.xz"', h2, BUSYBOX_BIN) + " || HOK=0; " : "") +
        "if [ \"$HOK\" = 1 ] && \"$B\" unxz -t \"$S/libsecmon.so.xz\"" + (u2 ? " && \"$B\" unxz -t \"$S/libsecmon32.so.xz\"" : "") + "; then echo STAGE:install; OK2=1; " +
        "rm -f \"$M/libsecmon.so.xz\" \"$M/libsecmon.so.xz.sha256sum\" \"$D/libsecmon.so.xz\" \"$D/libsecmon.so\"; " +
        "cp -f \"$S/libsecmon.so.xz\" \"$M/libsecmon.so.xz\" || OK2=0; " +
        ((h1 && validSha256(h1)) ? "echo " + shQuote(h1.toLowerCase()) + " > \"$M/libsecmon.so.xz.sha256sum\" || OK2=0; " : "") +
        "cp -f \"$S/libsecmon.so.xz\" \"$D/libsecmon.so.xz\" || OK2=0; " +
        "$B unxz -f \"$D/libsecmon.so.xz\" || OK2=0; chmod 644 \"$D/libsecmon.so\" || OK2=0; " +
        (u2 ? "rm -f \"$M/libsecmon32.so.xz\" \"$M/libsecmon32.so.xz.sha256sum\" \"$D/libsecmon32.so.xz\" \"$D/libsecmon32.so\"; " +
        "cp -f \"$S/libsecmon32.so.xz\" \"$M/libsecmon32.so.xz\" || OK2=0; " +
        ((h2 && validSha256(h2)) ? "echo " + shQuote(h2.toLowerCase()) + " > \"$M/libsecmon32.so.xz.sha256sum\" || OK2=0; " : "") +
        "cp -f \"$S/libsecmon32.so.xz\" \"$D/libsecmon32.so.xz\" || OK2=0; $B unxz -f \"$D/libsecmon32.so.xz\" || OK2=0; chmod 644 \"$D/libsecmon32.so\" || OK2=0; " : "") +
        "if [ \"$OK2\" = 1 ]; then rm -f \"$M/gadget.version\"; echo \"$V\" > \"$M/gadget.version\"; chmod 644 \"$M/gadget.version\"; echo RESULT:ok; " +
        "else echo RESULT:install-fail; fi; " +
        "elif [ \"$HOK\" = 1 ]; then echo RESULT:verify-fail; " +
        "else echo RESULT:hash-fail; fi; " +
        "else echo RESULT:dl-fail; fi; " +
        "rm -rf \"$S\"";
    var result: string | null = null;
    function onUpdateBody(body: string) {
        body.split("\n").forEach(function (line) {
            if (line.indexOf("STAGE:") === 0) {
                var s = line.slice(6);
                setGadgetUpdateLine(s === "download" ? "Downloading " + v + "…" : s === "verify" ? "Verifying…" : "Installing…");
            } else if (line.indexOf("RESULT:") === 0) {
                result = line.slice(7);
            }
        });
    }
    await runDetached(script, GADGET_DL_LOG, onUpdateBody, { timeout: 660000, maxStale: 0 });
    gadgetUpdating = false;
    if (result === "ok") {
        gadgetBundled = v;
        ksu.toast(gadgetUpdateVerified ? "Gadget updated to " + v + " (verified)"
            : "Gadget updated to " + v + " (unverified)");
        setGadgetUpdateLine("Gadget " + v + " installed"
            + (gadgetUpdateVerified ? "" : " (unverified)"));
        loadStatus();
    } else {
        if (result === "dl-fail") {
            ksu.toast("Download failed — check network and retry");
            setGadgetUpdateLine("Download failed");
        } else if (result === "hash-fail") {
            ksu.toast("Hash mismatch — update aborted, nothing installed");
            setGadgetUpdateLine("Hash mismatch — nothing installed");
        } else if (result === "verify-fail") {
            ksu.toast("Downloaded file failed verification");
            setGadgetUpdateLine("Verification failed");
        } else if (result === "install-fail") {
            ksu.toast("Install failed — storage full?");
            setGadgetUpdateLine("Install failed — nothing changed");
        } else {
            ksu.toast("Update timed out — retry");
            setGadgetUpdateLine("Update timed out");
        }
        showDownloadButton(v);
    }
}

function setGadgetUpdateLine(text) {
    getEl("gadget-update").textContent = text;
}

function showDownloadButton(v) {
    var b = getEl("btn-download-gadget");
    b.textContent = "Update to " + v;
    b.style.display = "";
}

function currentGadgetVersion() {
    return gadgetBundled || gadgetScanned;
}

const GVER_MARK = "@@__KSUFRIDA_GVER__";

const ABI_MARK = "@@__KSUFRIDA_ABI__";

const META_MARK = "@@__KSUFRIDA_META__";

async function checkGadgetUpdate() {
    setGadgetUpdateLine("Checking…");
    getEl("btn-download-gadget").style.display = "none";
    gadgetLatest = null;
    gadgetUpdateUrls = {};
    gadgetUpdateVerified = false;
    var r = await exec(
        "echo " + GVER_MARK + "; cat " + GADGET_VERSION_FILE + " 2>/dev/null; echo; " +
        "echo " + ABI_MARK + "; getprop ro.product.cpu.abi; " +
        "echo " + META_MARK + "; curl -sL --max-time 20 " + GADGET_META_URL
    );
    var parts = splitMarked(r.stdout, [GVER_MARK, ABI_MARK, META_MARK]);
    var bundled = (parts[GVER_MARK] || []).join("").trim();
    if (bundled && validVersion(bundled)) gadgetBundled = bundled;
    var abi = (parts[ABI_MARK] || []).join("").trim();
    var meta = parseGadgetMeta((parts[META_MARK] || []).join("\n"));
    if (!meta) {
        var f = await exec("curl -sL --max-time 20 " + GADGET_API_URL + " | grep '\"tag_name\"'");
        var t = /"tag_name"\s*:\s*"([^"]+)"/.exec(f.stdout || "");
        if (t && validVersion(t[1])) {
            meta = {
                version: t[1],
                arm: "https://github.com/sohan-f/knox-frida-patcher/releases/download/" + t[1] + "/frida-gadget-" + t[1] + "-android-arm.so.xz",
                arm64: "https://github.com/sohan-f/knox-frida-patcher/releases/download/" + t[1] + "/frida-gadget-" + t[1] + "-android-arm64.so.xz",
                sha256: { arm: null, arm64: null }
            };
        }
    }
    if (!meta || !validVersion(meta.version)) {
        setGadgetUpdateLine("Update check failed — no network?");
        return;
    }
    // A published sha256 block with malformed digests is treated as
    // tampering, not as a legacy release: refuse rather than install blind.
    var metaHashes = meta.sha256 || {};
    if ((metaHashes.arm || metaHashes.arm64)
        && (!validSha256(metaHashes.arm || "") || !validSha256(metaHashes.arm64 || ""))) {
        setGadgetUpdateLine("Update metadata invalid — refusing to update");
        return;
    }
    gadgetLatest = meta.version;
    var urls = gadgetUrlsForAbi(abi, meta);
    if (!urls || !urls.primary || !validReleaseUrl(urls.primary.url)
        || (urls.companion && !validReleaseUrl(urls.companion.url))) {
        setGadgetUpdateLine("No build for this device (" + (abi || "unknown ABI") + ")");
        return;
    }
    gadgetUpdateUrls = urls;
    gadgetUpdateVerified = !!urls.primary.sha256
        && (!urls.companion || !!urls.companion.sha256);
    var suffix = gadgetUpdateVerified ? "" : " (unverified — no hash in metadata)";
    var cur = currentGadgetVersion();
    if (!cur) {
        setGadgetUpdateLine(meta.version + " available (installed version unknown)" + suffix);
        showDownloadButton(meta.version);
    } else if (cmpVersions(cur, meta.version) < 0) {
        setGadgetUpdateLine(cur + " installed · " + meta.version + " available" + suffix);
        showDownloadButton(meta.version);
    } else {
        setGadgetUpdateLine("Gadget " + cur + " is up to date");
    }
}

