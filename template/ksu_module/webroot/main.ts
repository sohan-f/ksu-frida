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
    GatingLib,
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
let checkingGadget = false;
let dirtyConfig = false;
let dirtyGadget = false;
let detailIndex: number | null = null;
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

// Buttons show a centered spinner while their shell roundtrip runs.
// Ref-counted so overlapping background refreshes cannot re-enable early.
// The label stays put (hidden while busy), so the box never changes size.
var busyCount: Record<string, number> = {};

function setBusy(id: string, busy: boolean) {
    var b = document.getElementById(id);
    if (!b || !(b instanceof HTMLButtonElement)) return;
    busyCount[id] = Math.max(0, (busyCount[id] || 0) + (busy ? 1 : -1));
    var on = busyCount[id] > 0;
    b.disabled = on;
    b.classList.toggle("busy", on);
}

var slotTimers: Record<string, ReturnType<typeof setTimeout> | null> = {};

function setSlotStatus(base: string, text: string, opts?: { cls?: UpdateTone; retry?: () => void; tag?: string; fade?: boolean }) {
    paintSlot(base, [{ text: text, cls: opts && opts.cls }], opts);
}

function paintSlot(base: string, spans: UpdateSegment[], opts?: { retry?: () => void; tag?: string; fade?: boolean }) {
    var el = getEl(base);
    el.innerHTML = "";
    el.className = "sub";
    var text = "";
    spans.forEach(function (s) {
        var span = document.createElement("span");
        span.textContent = s.text;
        if (s.cls) span.className = s.cls;
        el.appendChild(span);
        text += s.text;
    });
    var btn = getEl(base + "-retry");
    if (text && opts && opts.retry) {
        btn.style.display = "";
        btn.onclick = opts.retry;
    } else {
        btn.onclick = null;
        btn.style.display = "none";
    }
    var wrap = getEl(base + "-wrap");
    wrap.dataset.tag = (opts && opts.tag) || "";
    wrap.classList.toggle("show", text.length > 0);
    var pending = slotTimers[base];
    if (pending) clearTimeout(pending);
    slotTimers[base] = null;
    if (text && opts && opts.fade) {
        slotTimers[base] = setTimeout(function () { setSlotStatus(base, ""); }, 3000);
    }
}

function clearSlotIf(base: string, tag: string) {
    if (getEl(base + "-wrap").dataset.tag === tag) setSlotStatus(base, "");
}

// Brief result label on an idle button; skipped when a busy op is running.
function flashResult(id: string, label: string, ms?: number) {
    const el = document.getElementById(id);
    if (!el || !(el instanceof HTMLButtonElement)) return;
    if ((busyCount[id] || 0) > 0) return;
    flashEl(el, label, ms);
}

function flashEl(b: HTMLButtonElement, label: string, ms?: number) {
    var prev = b.innerHTML;
    if (b.offsetWidth > 0) b.style.minWidth = b.offsetWidth + "px";
    b.textContent = label;
    b.disabled = true;
    setTimeout(function () {
        b.innerHTML = prev;
        b.disabled = false;
        b.style.minWidth = "";
    }, ms == null ? 1200 : ms);
}

function delay(ms: number) {
    return new Promise<void>(function (r) { setTimeout(r, ms); });
}




function appendStatusRow(label: string, value: string, bad: boolean, valueId?: string, parent?: HTMLElement | DocumentFragment) {
    var el = parent || getEl("status-rows");
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

function appendVerboseRow(on: boolean, parent?: HTMLElement | DocumentFragment) {
    var el = parent || getEl("status-rows");
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

async function setVerbose(on: boolean) {
    if (on) {
        await exec("touch " + VERBOSE_PATH + " && chmod 644 " + VERBOSE_PATH);
    } else {
        await exec("rm -f " + VERBOSE_PATH);
    }
}

function readVersionCache(key: string) {
    if (!key) return null;
    try {
        var cached = JSON.parse(localStorage.getItem(GADGET_VERSION_KEY) || "null");
        if (cached && cached.k === key && cached.v) return cached.v;
    } catch (_) {}
    return null;
}

function startVersionScan(key: string) {
    if (versionScanning) return;
    versionScanning = true;
    var found = "";
    var script =
        "strings -a " + GADGET_PATH + " 2>/dev/null | " +
        "grep -E '^(1[6-9]|2[0-9])\\.[0-9]+\\.[0-9]+$' | head -1";
    runDetached(script, SCAN_FILE, function (body: string) {
        found = body.split("\n").filter(function (l: string) { return l && l !== DONE_MARK; })[0] || "";
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
    setBusy("btn-status", true);
    try {
        var frag = document.createDocumentFragment();
        await loadStatusNow(frag);
        var el = getEl("status-rows");
        el.replaceChildren(frag);
        el.className = "";
    } finally {
        setBusy("btn-status", false);
    }
}

async function loadStatusNow(frag: DocumentFragment) {
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
        appendStatusRow("Shell access", "unavailable (ksu.exec missing)", true, undefined, frag);
        appendStatusRow("Targets", config.targets.length + " total", false, undefined, frag);
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

    var mod = rows.MOD || "unknown";
    if (gad !== "…" && gad !== "unknown" && gad !== "missing") gadgetScanned = gad;
    appendStatusRow("Module", mod, mod === "not installed" || mod === "unknown", undefined, frag);
    appendStatusRow("Gadget", gad, gad === "missing" || gad === "unknown", "status-gadget", frag);
    var gadgetState = !gadgetFileOk ? "not found" : dirtyGadget ? "unsaved changes" : "saved";
    appendStatusRow("Gadget config", gadgetState, gadgetState !== "saved", undefined, frag);
    appendVerboseRow(rows.VERBOSE === "on", frag);
    var total = config.targets.length;
    var enabled = config.targets.filter(function (t) { return !!t.enabled; }).length;
    appendStatusRow("Targets", total + " total · " + enabled + " enabled", false, undefined, frag);
    var missing = Object.keys(missingPaths);
    if (missing.length > 0) {
        appendStatusRow("Libraries", missing.length + (missing.length === 1 ? " file missing" : " files missing"), true, undefined, frag);
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

function stopApp(i: number) {
    var t = config.targets[i];
    if (!t) return;
    var pkg = t.app_name.split(":")[0];
    if ((targetStatus[t.app_name] || []).length === 0) {
        setSlotStatus("detail-status", pkg + " is already stopped", { fade: true });
        return;
    }
    setSlotStatus("detail-status", "Stopping " + pkg, { fade: true });
    exec("am force-stop " + shQuote(pkg) + " </dev/null >/dev/null 2>&1 &")
        .then(function () {
            setTimeout(refreshTargetStatus, 800);
            setTimeout(refreshConnect, 1500);
        });
}

function startApp(i: number) {
    var t = config.targets[i];
    if (!t) return;
    var pkg = t.app_name.split(":")[0];
    if ((targetStatus[t.app_name] || []).length > 0) {
        setSlotStatus("detail-status", pkg + " is already running", { fade: true });
        return;
    }
    // monkey(1) enables auto-rotate; resolve the launcher activity and use am instead.
    var script =
        "pkg=" + shQuote(pkg) + "; " +
        "act=$(cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \"$pkg\" 2>/dev/null | grep '/' | tail -n 1 | tr -d '\\r'); " +
        "if [ -n \"$act\" ]; then am start -n \"$act\"; fi </dev/null >/dev/null 2>&1 &";
    setSlotStatus("detail-status", "Starting " + pkg, { fade: true });
    exec(script)
        .then(function () {
            setTimeout(refreshTargetStatus, 1500);
            setTimeout(refreshConnect, (t.start_up_delay_ms || 0) + 4000);
        });
}

interface GadgetListen {
    listen: boolean;
    base: number;
}

type UpdateTone = "status-ok" | "status-warn" | "status-err";

interface UpdateSegment {
    text: string;
    cls?: UpdateTone;
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
    note.textContent = "interaction.type is not \"listen\": the gadget won't open a port.";
    body.appendChild(note);
}

function renderConnect(info: GadgetListen, ports: number[]) {
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

    ports.slice(0, 4).forEach(function (p: number) {
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
        copy.onclick = (function (t, b) { return function () { copyText(t, b); }; })(text, copy);
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
    setBusy("btn-connect", true);
    try {
        var r = await exec(connectScanCmd(info));
        renderConnect(info, parsePorts(r.stdout ? r.stdout.split("\n") : []));
    } finally {
        setBusy("btn-connect", false);
    }
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
    await runDetached("pm list packages -3", PKGS_FILE, function (body: string) { out = body; },
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
        completed = await runDetached(script, LABEL_FILE, function (body: string) {
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

function getAppLabel(pkg: string) {
    return appLabels[pkg] || pkg;
}

function isAppModalOpen() {
    return getEl("app-modal").style.display === "flex";
}

function updateAppHint() {
    var text = appsLoading ? "Loading packages…" : (labelsPending ? "Loading labels…" : "");
    setSlotStatus("app-list-hint", text);
}

function patchAppLabels() {
    var rows = document.querySelectorAll("#app-list .app-row");
    for (var i = 0; i < rows.length; i++) {
        var strong = rows[i].querySelector("strong");
        if (strong) strong.textContent = getAppLabel(rows[i].getAttribute("data-pkg") || "");
    }
}

function mkBtn(text: string, cls: string, onclick: () => void) {
    var b = document.createElement("button");
    b.className = cls;
    b.textContent = text;
    b.onclick = onclick;
    return b;
}

function makeSwitch(checked: boolean, field: string, idx: number) {
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

function fieldBlock(labelText: string, inputEl: HTMLElement) {
    var f = document.createElement("div");
    f.className = "field";
    var l = document.createElement("label");
    l.textContent = labelText;
    f.appendChild(l);
    f.appendChild(inputEl);
    return f;
}

function getLibs(t: Target, field: LibField): GatingLib[] {
    if (field === "child_libs") return (t.child_gating && t.child_gating.injected_libraries) || [];
    return t.injected_libraries;
}

function ensureLibs(t: Target, field: LibField): GatingLib[] | null {
    if (field === "child_libs") {
        if (!t.child_gating) return null;
        if (!t.child_gating.injected_libraries) t.child_gating.injected_libraries = [];
        return t.child_gating.injected_libraries;
    }
    return t.injected_libraries;
}

function buildLibEditor(t: Target, i: number, field: LibField) {
    var wrap = document.createElement("div");
    wrap.className = "field";
    wrap.dataset.libeditor = field;
    var l = document.createElement("label");
    l.textContent = field === "libs" ? "Injected Libraries" : "Child Libraries";
    wrap.appendChild(l);
    var list = document.createElement("div");
    list.className = "lib-list";
    var libs = getLibs(t, field);
    if (libs.length === 0) {
        var empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No libraries yet";
        list.appendChild(empty);
    }
    libs.forEach(function (lib) {
        var row = document.createElement("div");
        row.className = "lib-row";
        var p = document.createElement("span");
        p.className = "mono lib-path";
        p.textContent = lib.path;
        p.title = lib.path;
        row.appendChild(p);
        row.appendChild(mkBtn("X", "btn btn-danger btn-sm", function () {
            removeLibPath(i, field, lib.path, row);
        }));
        list.appendChild(row);
    });
    wrap.appendChild(list);
    var note = missingNote(libs);
    if (note) wrap.appendChild(note);
    var addRow = document.createElement("div");
    addRow.className = "lib-add";
    var input = document.createElement("input");
    input.type = "text";
    input.placeholder = "/data/local/tmp/libsec/libsecmon.so";
    input.onkeydown = function (e) {
        if (e.key === "Enter") { e.preventDefault(); addManualLib(i, field, input); }
    };
    addRow.appendChild(input);
    addRow.appendChild(mkBtn("Add", "btn btn-sm btn-primary", function () { addManualLib(i, field, input); }));
    addRow.appendChild(mkBtn("Browse", "btn btn-sm", function () { openLibPicker(i, field); }));
    wrap.appendChild(addRow);
    return wrap;
}

function addManualLib(i: number, field: LibField, input: HTMLInputElement) {
    var p = input.value.trim();
    if (!p) { setSlotStatus("detail-status", "Type a library path first", { fade: true }); return; }
    var t = config.targets[i];
    if (!t) return;
    if (field === "child_libs" && !t.child_gating) {
        t.child_gating = { enabled: false, mode: "freeze", injected_libraries: [] };
    }
    var libs = ensureLibs(t, field);
    if (!libs) return;
    if (libs.some(function (l) { return l.path === p; })) {
        setSlotStatus("detail-status", "Already listed", { fade: true });
        return;
    }
    libs.push({ path: p });
    markDirty("cfg");
    checkLibraries();
    setSlotStatus("detail-status", "Added " + (p.split("/").pop() || p), { fade: true });
    input.value = "";
    refreshLibEditor(i, field);
}

function removeLibPath(i: number, field: LibField, path: string, row?: HTMLElement) {
    var t = config.targets[i];
    if (!t) return;
    var done = function () {
        var cur = config.targets[i];
        if (!cur) return;
        if (field === "child_libs") {
            if (!cur.child_gating || !cur.child_gating.injected_libraries) return;
            cur.child_gating.injected_libraries =
                cur.child_gating.injected_libraries.filter(function (l) { return l.path !== path; });
        } else {
            cur.injected_libraries = cur.injected_libraries.filter(function (l) { return l.path !== path; });
        }
        markDirty("cfg");
        checkLibraries();
        refreshLibEditor(i, field);
    };
    if (row && row.isConnected) {
        row.classList.add("leaving");
        setTimeout(done, 180);
    } else {
        done();
    }
}

function refreshLibEditor(i: number, field: LibField) {
    var t = config.targets[i];
    if (!t || detailIndex !== i) return;
    var slot = document.querySelector('#detail-body [data-libeditor="' + field + '"]');
    if (!slot) { renderDetail(); return; }
    var next = buildLibEditor(t, i, field);
    slot.replaceWith(next);
    var input = next.querySelector("input");
    if (input instanceof HTMLInputElement) input.focus();
}

function missingNote(libs: GatingLib[] | undefined) {
    var miss = (libs || [])
        .map(function (l) { return l.path; })
        .filter(function (p) { return missingPaths[p]; });
    if (miss.length === 0) return null;
    var d = document.createElement("div");
    d.className = "warn";
    d.textContent = "Missing: " + miss.join(", ");
    return d;
}

function renderTargets() {
    var container = getEl("targets");
    container.innerHTML = "";
    pillEls = {};

    if (config.targets.length === 0) {
        container.innerHTML = '<div class="empty">No targets configured. Tap Add to start.</div>';
    } else {
        var list = config.targets.filter(function (t) {
            if (!searchQuery) return true;
            var label = (appLabels[t.app_name] || t.app_name).toLowerCase();
            return t.app_name.toLowerCase().indexOf(searchQuery) !== -1 || label.indexOf(searchQuery) !== -1;
        });

        if (list.length === 0) {
            container.innerHTML = '<div class="empty">No targets match the filter.</div>';
        } else {
            list.forEach(function (t) {
                var i = config.targets.indexOf(t);
                var row = document.createElement("div");
                row.className = "target-row";
                row.insertAdjacentHTML("afterbegin", appIconHtml(t.app_name, false, true));
                var left = document.createElement("div");
                left.className = "grow";
                var nameEl = document.createElement("strong");
                nameEl.textContent = getAppLabel(t.app_name);
                var pkgEl = document.createElement("div");
                pkgEl.className = "sub";
                pkgEl.textContent = t.app_name;
                left.appendChild(nameEl);
                left.appendChild(pkgEl);
                var pill = document.createElement("span");
                pill.className = "pill";
                pill.textContent = "…";
                pillEls[t.app_name] = pill;
                row.appendChild(left);
                row.appendChild(pill);
                row.appendChild(makeSwitch(t.enabled, "enabled", i));
                row.onclick = function (e) {
                    var el = e.target as HTMLElement | null;
                    if (el && el.closest && el.closest(".switch")) return;
                    openDetail(i);
                };
                container.appendChild(row);
            });
        }
    }

    updateStatusPills();
    if (detailIndex !== null) {
        if (!config.targets[detailIndex]) closeDetail();
        else renderDetail();
    }
}

function openDetail(i: number) {
    detailIndex = i;
    renderDetail();
    getEl("target-modal").style.display = "flex";
}

function closeDetail() {
    detailIndex = null;
    getEl("target-modal").style.display = "none";
}

type LibField = "libs" | "child_libs";

let pickerTarget = -1;
let pickerField: LibField = "libs";
let pickerDir = "/data/local/tmp/libsec";

function openLibPicker(i: number, field: LibField) {
    pickerTarget = i;
    pickerField = field;
    pickerDir = "/data/local/tmp/libsec";
    getEl("lib-modal").style.display = "flex";
    browseLibDir();
}

function closeLibPicker() {
    getEl("lib-modal").style.display = "none";
    if (detailIndex !== null) renderDetail();
}

async function browseLibDir() {
    var list = getEl("lib-list");
    getEl("lib-path").textContent = pickerDir;
    list.innerHTML = '<div class="empty"><span class="spinner"></span>Loading…</div>';
    var r = await exec("ls -a -p " + shQuote(pickerDir) + " 2>/dev/null");
    list.innerHTML = "";
    if (r.errno !== 0) {
        list.innerHTML = '<div class="empty">Cannot list this folder</div>';
        return;
    }
    var dirs: string[] = [];
    var files: string[] = [];
    r.stdout.split("\n").forEach(function (line) {
        var name = line.trim();
        if (!name || name === "./" || name === "../") return;
        if (name[name.length - 1] === "/") dirs.push(name.slice(0, -1));
        else if (/\.so(\.|$)/.test(name) && !/\.config\.so$/.test(name)) files.push(name);
    });
    dirs.sort();
    files.sort();
    if (pickerDir !== "/") {
        list.appendChild(libRow("..", "Parent folder", function () {
            pickerDir = parentDir(pickerDir);
            browseLibDir();
        }));
    }
    dirs.forEach(function (d) {
        list.appendChild(libRow(d + "/", "Folder", function () {
            pickerDir = pickerDir === "/" ? "/" + d : pickerDir + "/" + d;
            browseLibDir();
        }));
    });
    files.forEach(function (f) {
        var full = pickerDir === "/" ? "/" + f : pickerDir + "/" + f;
        list.appendChild(libRow(f, full, function () { addLibPath(full); }));
    });
    if (!list.firstChild) list.innerHTML = '<div class="empty">No libraries here</div>';
}

function parentDir(dir: string) {
    if (dir === "/") return "/";
    var cut = dir.replace(/\/+$/, "").lastIndexOf("/");
    return cut <= 0 ? "/" : dir.slice(0, cut);
}

function libRow(name: string, sub: string, onclick: () => void) {
    var row = document.createElement("div");
    row.className = "app-row";
    var text = document.createElement("div");
    text.className = "app-row-text";
    var strong = document.createElement("strong");
    strong.textContent = name;
    var label = document.createElement("div");
    label.className = "app-label";
    label.textContent = sub;
    text.appendChild(strong);
    text.appendChild(label);
    row.appendChild(text);
    row.onclick = onclick;
    return row;
}

function addLibPath(p: string) {
    var t = config.targets[pickerTarget];
    if (!t) return;
    var libs = ensureLibs(t, pickerField);
    if (!libs) return;
    if (libs.some(function (l) { return l.path === p; })) {
        setSlotStatus("lib-status", "Already listed", { fade: true });
        return;
    }
    libs.push({ path: p });
    markDirty("cfg");
    checkLibraries();
    setSlotStatus("lib-status", "Added " + (p.split("/").pop() || p), { fade: true });
}

function renderDetail() {
    if (detailIndex === null) { closeDetail(); return; }
    var t = config.targets[detailIndex];
    if (!t) { closeDetail(); return; }
    var i = detailIndex;
    getEl("detail-title").textContent = getAppLabel(t.app_name);
    getEl("detail-sub").textContent = t.app_name;
    getEl("detail-icon").innerHTML = appIconHtml(t.app_name, true, true);
    var body = getEl("detail-body");
    var top = body.scrollTop;
    body.innerHTML = "";

    var bar = document.createElement("div");
    bar.className = "btnbar";
    bar.appendChild(mkBtn("Force stop", "btn btn-sm", function () { stopApp(i); }));
    bar.appendChild(mkBtn("Start", "btn btn-sm btn-primary", function () { startApp(i); }));
    body.appendChild(bar);

    var statusWrap = document.createElement("div");
    statusWrap.className = "collapse";
    statusWrap.id = "detail-status-wrap";
    var statusRow = document.createElement("div");
    statusRow.className = "slotrow";
    var statusText = document.createElement("span");
    statusText.className = "sub";
    statusText.id = "detail-status";
    var statusRetry = document.createElement("button");
    statusRetry.className = "btn btn-sm";
    statusRetry.id = "detail-status-retry";
    statusRetry.textContent = "Retry";
    statusRetry.style.display = "none";
    statusRow.appendChild(statusText);
    statusRow.appendChild(statusRetry);
    statusWrap.appendChild(statusRow);
    body.appendChild(statusWrap);

    var settings = document.createElement("div");
    settings.className = "settings";
    settings.appendChild(settingRow("Kernel Evasion", makeSwitch(t.kernel_assisted_evasion, "ksie", i)));
    settings.appendChild(settingRow("Hide maps", makeSwitch(t.hide_maps !== false, "hidemaps", i)));
    settings.appendChild(settingRow("Child Gating", makeSwitch(!!(t.child_gating && t.child_gating.enabled), "child_enabled", i)));
    body.appendChild(settings);

    body.appendChild(buildChildPanel(t, i));

    var delayInput = document.createElement("input");
    delayInput.type = "number";
    delayInput.min = "0";
    delayInput.value = String(t.start_up_delay_ms || 0);
    delayInput.onchange = function () { updateField(i, "delay", delayInput.value); };
    body.appendChild(fieldBlock("Delay (ms)", delayInput));

    body.appendChild(buildLibEditor(t, i, "libs"));
    body.scrollTop = top;
}

function settingRow(labelText: string, control: HTMLElement) {
    var r = document.createElement("div");
    r.className = "setting-row";
    var l = document.createElement("span");
    l.className = "sub";
    l.textContent = labelText;
    r.appendChild(l);
    r.appendChild(control);
    return r;
}

function buildModeSeg(t: Target, i: number) {
    var cur = (t.child_gating && t.child_gating.mode) || "freeze";
    var seg = document.createElement("div");
    seg.className = "seg";
    seg.setAttribute("role", "radiogroup");
    ["freeze", "kill", "inject"].forEach(function (m) {
        var b = document.createElement("button");
        b.className = "seg-btn" + (cur === m ? " seg-on" : "");
        b.textContent = m.charAt(0).toUpperCase() + m.slice(1);
        b.dataset.mode = m;
        b.setAttribute("role", "radio");
        b.setAttribute("aria-checked", cur === m ? "true" : "false");
        b.onclick = function () {
            updateField(i, "child_mode", m);
            Array.from(seg.children).forEach(function (c) {
                if (!(c instanceof HTMLElement)) return;
                var on = c.dataset.mode === m;
                c.classList.toggle("seg-on", on);
                c.setAttribute("aria-checked", on ? "true" : "false");
            });
        };
        seg.appendChild(b);
    });
    return seg;
}

function buildChildPanel(t: Target, i: number) {
    const gating = t.child_gating;
    var body = document.createElement("div");
    body.className = "collapse child-fields" + ((gating && gating.enabled) ? " show" : "");
    var inner = document.createElement("div");
    inner.appendChild(fieldBlock("Mode", buildModeSeg(t, i)));

    inner.appendChild(buildLibEditor(t, i, "child_libs"));
    body.appendChild(inner);
    return body;
}

// Child-toggle glides its own panel open or shut: the clicked switch is
// never replaced, so its slide plays like every other toggle.
function patchChildPanel(i: number) {
    var t = config.targets[i];
    if (!t || detailIndex !== i) return;
    var body = document.querySelector("#detail-body .child-fields");
    if (!body) { scheduleRenderTargets(); return; }
    body.classList.toggle("show", !!(t.child_gating && t.child_gating.enabled));
}

function updateField(i: number, field: string, value: any) {
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
        case "child_enabled":
            if (!t.child_gating) {
                t.child_gating = { enabled: false, mode: "freeze", injected_libraries: [] };
            }
            t.child_gating.enabled = value;
            markDirty("cfg");
            patchChildPanel(i);
            return;
        case "child_mode":
            if (t.child_gating) t.child_gating.mode = value;
            break;
        default:
            return;
    }
    markDirty("cfg");
}

function removeTarget(i: number) {
    config.targets.splice(i, 1);
    markDirty("cfg");
    closeDetail();
    scheduleRenderTargets();
    scheduleTargetStatus();
    scheduleStatus();
}

function addTarget(pkg: string) {
    if (config.targets.some(function (t) { return t.app_name === pkg; })) {
        setSlotStatus("app-list-hint", "Already added");
        return false;
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
    return true;
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

function openAppFromRow(e: MouseEvent) {
    var t = e.target as HTMLElement | null;
    var row = t && t.closest ? t.closest(".app-row") : null;
    if (!row) return;
    var pkg = row.getAttribute("data-pkg");
    if (!pkg) return;
    if (addTarget(pkg)) closeAppModal();
}

function appIconHtml(pkg: string, large?: boolean, eager?: boolean) {
    if (!nativeIcons) return "";
    return '<img class="app-icon' + (large ? " app-icon-lg" : "") +
        '" src="ksu://icon/' + escHtml(pkg) + '" alt=""' +
        (eager ? ' loading="eager" fetchpriority="high"' : ' loading="lazy"') +
        ' onerror="this.remove()">';
}

function appRowHtml(pkg: string) {
    return '<div class="app-row" data-pkg="' + escHtml(pkg) + '">' + appIconHtml(pkg) +
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

async function reloadAll() {
    if ((dirtyConfig || dirtyGadget) && !reloadArmed) {
        reloadArmed = true;
        setSlotStatus("targets-status", "Unsaved changes. Tap Reload again to discard", { fade: true });
        if (reloadArmTimer !== null) clearTimeout(reloadArmTimer);
        reloadArmTimer = setTimeout(function () { reloadArmed = false; }, 5000);
        return;
    }
    reloadArmed = false;
    if (reloadArmTimer !== null) clearTimeout(reloadArmTimer);
    setBusy("btn-reload", true);
    try {
        await loadConfigs();
        await fetchApps(true);
        setSlotStatus("targets-status", "Reloaded", { fade: true });
    } finally {
        setBusy("btn-reload", false);
    }
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
    getEl("btn-close-detail").onclick = closeDetail;
    getEl("btn-remove-detail").onclick = function () {
        if (detailIndex !== null) removeTarget(detailIndex);
    };
    getEl("target-modal").onclick = function (e) {
        var el = e.target as HTMLElement | null;
        if (el && el.id === "target-modal") closeDetail();
    };
    getEl("btn-close-lib").onclick = closeLibPicker;
    getEl("lib-modal").onclick = function (e) {
        var el = e.target as HTMLElement | null;
        if (el && el.id === "lib-modal") closeLibPicker();
    };
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

        function finish(mode: string) {
            if (settled) return;
            settled = true;
            if (timer !== null) clearTimeout(timer);
            delete (window as unknown as Record<string, unknown>)[name];
            execMode = mode;
            resolve(mode);
        }

        timer = setTimeout(function () {
            var mode = syncProbe();
            finish(mode === "none" ? "async" : mode);
        }, PROBE_TIMEOUT_MS);

(window as unknown as Record<string, unknown>)[name] = function (errno: unknown, stdout: unknown) {
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
            delete (window as unknown as Record<string, unknown>)[name];
            execMode = "sync";
            resolve(syncExec(cmd));
        }, EXEC_TIMEOUT_MS);

(window as unknown as Record<string, unknown>)[name] = function (errno: unknown, stdout: unknown, stderr: unknown) {
            if (settled) return;
            settled = true;
            if (timer !== null) clearTimeout(timer);
            delete (window as unknown as Record<string, unknown>)[name];
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
            delete (window as unknown as Record<string, unknown>)[name];
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

async function runDetached(script: string, path: string, onBody: (body: string, done: boolean) => void, opts?: { timeout?: number; maxStale?: number }): Promise<boolean> {
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

function markDirty(which: string) {
    if (which === "cfg") dirtyConfig = true;
    else if (which === "gadget") dirtyGadget = true;
    updateDirtyBadge();
    scheduleStatus();
}

function updateDirtyBadge() {
    var b = getEl("dirty-badge");
    getEl("dirty-wrap").classList.toggle("show", dirtyConfig);
    getEl("save-pill").classList.toggle("show", dirtyConfig);
    if (dirtyConfig) {
        b.textContent = "Unsaved changes (targets)";
    }
}

function copyText(text: string, btn?: HTMLButtonElement) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
            function () { if (btn) flashEl(btn, "Copied"); },
            function () { setSlotStatus("connect-status", "Copy failed. Select the text manually"); }
        );
    } else {
        setSlotStatus("connect-status", "Select the text and copy manually");
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

function applyConfigText(text: string) {
    if (text && text.trim().length > 0) {
        try {
            config = JSON.parse(text);
        } catch (e) {
            setSlotStatus("targets-status", "Config parse error: " + (e instanceof Error ? e.message : String(e)), { cls: "status-err", tag: "load", retry: function () { reloadAll(); } });
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
    setBusy("btn-save", true);
    var ok = false;
    var detail = "";
    try {
        var r = await exec("{ rm -f " + CONFIG_PATH + "; printf '%s\\n' " + shQuote(json) + " > " + CONFIG_PATH +
            " && chmod 644 " + CONFIG_PATH + " && echo " + SAVE_MARK + "; } 2>&1");
        if (String(r.stdout).indexOf(SAVE_MARK) !== -1) {
            ok = true;
            dirtyConfig = false;
            updateDirtyBadge();
            checkLibraries();
        } else {
            detail = String(r.stderr || r.stdout || r.errno);
        }
    } finally {
        setBusy("btn-save", false);
    }
    flashResult("btn-save", ok ? "Saved" : "Save failed");
    if (ok) clearSlotIf("targets-status", "save");
    else setSlotStatus("targets-status", "Save failed: " + detail, { cls: "status-err", tag: "save", retry: saveConfig });
}

async function checkLibraries() {
    var paths: string[] = [];
    var seen: Record<string, number> = {};
    config.targets.forEach(function (t) {
        function collect(libs: GatingLib[] | undefined) {
            (libs || []).forEach(function (l: GatingLib) {
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

function applyGadgetText(text: string) {
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
        return;
    }
    var content = textEl("gadget-editor").value;
    setBusy("btn-save-gadget", true);
    var ok = false;
    var detail = "";
    try {
        var r = await exec("{ rm -f " + GADGET_CONFIG_PATH + "; printf '%s\\n' " + shQuote(content) + " > " + GADGET_CONFIG_PATH +
            " && chmod 644 " + GADGET_CONFIG_PATH + " && echo " + SAVE_MARK + "; } 2>&1");
        if (String(r.stdout).indexOf(SAVE_MARK) !== -1) {
            ok = true;
            gadgetFileOk = true;
            dirtyGadget = false;
            updateDirtyBadge();
            validateGadget();
            scheduleStatus();
            refreshConnect();
        } else {
            detail = String(r.stderr || r.stdout || r.errno);
        }
    } finally {
        setBusy("btn-save-gadget", false);
    }
    flashResult("btn-save-gadget", ok ? "Saved" : "Save failed");
    if (ok) clearSlotIf("gadget-update", "gsave");
    else setSlotStatus("gadget-update", "Failed: " + detail, { cls: "status-err", tag: "gsave", retry: saveGadgetConfig });
}

function resetGadgetConfig() {
    var editor = textEl("gadget-editor");
    if (editor.value === DEFAULT_GADGET) {
        setSlotStatus("gadget-update", "Already showing defaults");
        return;
    }
    editor.value = DEFAULT_GADGET;
    markDirty("gadget");
    validateGadget();
    scheduleConnectRefresh();
}

async function refreshGadget() {
    var dst = "/data/local/tmp/libsec";
    setBusy("btn-refresh-gadget", true);
    var outcome = 0;
    var detail = "";
    try {
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
            outcome = 0;
        } else if (out.indexOf("GADGET_OK") !== -1) {
            outcome = 1;
            loadStatus();
        } else {
            outcome = 2;
            detail = String(r.stderr || r.stdout || r.errno);
        }
    } finally {
        setBusy("btn-refresh-gadget", false);
    }
    if (outcome === 1) {
        flashResult("btn-refresh-gadget", "Updated");
    } else if (outcome === 0) {
        setSlotStatus("gadget-update", "Bundled gadget missing. Reinstall the module", { cls: "status-warn" });
    } else {
        flashResult("btn-refresh-gadget", "Update failed");
        setSlotStatus("gadget-update", "Update failed: " + detail, { cls: "status-err", tag: "rgadget", retry: refreshGadget });
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
            proceed = confirm("No hash in update metadata. Download " + gadgetLatest + " unverified?");
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
    setBusy("btn-check-gadget", true);
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
    setBusy("btn-check-gadget", false);
    if (result === "ok") {
        gadgetBundled = v;
        setGadgetUpdateLineSeg([
            { text: "Gadget " },
            { text: v, cls: "status-ok" },
            { text: " installed" + (gadgetUpdateVerified ? "" : " (unverified)") }
        ]);
        loadStatus();
    } else {
        if (result === "dl-fail") {
            setSlotStatus("gadget-update", "Download failed. Check network and retry", { cls: "status-err", tag: "dl", retry: downloadGadgetUpdate });
        } else if (result === "hash-fail") {
            setSlotStatus("gadget-update", "Hash mismatch. Update aborted, nothing installed", { cls: "status-err", tag: "dl", retry: downloadGadgetUpdate });
        } else if (result === "verify-fail") {
            setSlotStatus("gadget-update", "Downloaded file failed verification", { cls: "status-err", tag: "dl", retry: downloadGadgetUpdate });
        } else if (result === "install-fail") {
            setSlotStatus("gadget-update", "Install failed. Storage full?", { cls: "status-err", tag: "dl", retry: downloadGadgetUpdate });
        } else {
            setSlotStatus("gadget-update", "Update timed out", { cls: "status-err", tag: "dl", retry: downloadGadgetUpdate });
        }
        showDownloadButton(v);
    }
}

function setGadgetUpdateLine(text: string, cls?: UpdateTone) {
    paintSlot("gadget-update", [{ text: text, cls: cls }]);
}

function setGadgetUpdateLineSeg(segs: UpdateSegment[]) {
    paintSlot("gadget-update", segs);
}

function showDownloadButton(v: string) {
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
    if (checkingGadget) return;
    checkingGadget = true;
    setBusy("btn-check-gadget", true);
    try {
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
            setGadgetUpdateLine("Update check failed. No network?", "status-err");
            return;
        }
        // A published sha256 block with malformed digests is treated as
        // tampering, not as a legacy release: refuse rather than install blind.
        var metaHashes = meta.sha256 || {};
        if ((metaHashes.arm || metaHashes.arm64)
            && (!validSha256(metaHashes.arm || "") || !validSha256(metaHashes.arm64 || ""))) {
            setGadgetUpdateLine("Update metadata invalid. Refusing to update", "status-err");
            return;
        }
        gadgetLatest = meta.version;
        var urls = gadgetUrlsForAbi(abi, meta);
        if (!urls || !urls.primary || !validReleaseUrl(urls.primary.url)
            || (urls.companion && !validReleaseUrl(urls.companion.url))) {
            setGadgetUpdateLine("No build for this device (" + (abi || "unknown ABI") + ")", "status-err");
            return;
        }
        gadgetUpdateUrls = urls;
        gadgetUpdateVerified = !!urls.primary.sha256
            && (!urls.companion || !!urls.companion.sha256);
        var suffix = gadgetUpdateVerified ? "" : " (unverified: no hash in metadata)";
        var cur = currentGadgetVersion();
        if (!cur) {
            setGadgetUpdateLineSeg([
                { text: meta.version, cls: "status-warn" },
                { text: " available (installed version unknown)" + suffix }
            ]);
            showDownloadButton(meta.version);
        } else if (cmpVersions(cur, meta.version) < 0) {
            setGadgetUpdateLineSeg([
                { text: cur + " installed · " },
                { text: meta.version, cls: "status-warn" },
                { text: " available" + suffix }
            ]);
            showDownloadButton(meta.version);
        } else {
            setGadgetUpdateLineSeg([
                { text: "Gadget " },
                { text: cur, cls: "status-ok" },
                { text: " is up to date" }
            ]);
        }
    } finally {
        checkingGadget = false;
        setBusy("btn-check-gadget", false);
    }
}

