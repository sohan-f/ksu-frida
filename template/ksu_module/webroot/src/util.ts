// Pure logic: no DOM, no bridge. Unit-tested via `npm test`.
export interface GatingLib {
    path: string;
}

export interface ChildGating {
    enabled: boolean;
    mode: string;
    injected_libraries?: GatingLib[];
}

export interface Target {
    app_name: string;
    enabled: boolean;
    start_up_delay_ms: number;
    hide_maps?: boolean;
    scrub_elf_header?: boolean;
    injected_libraries: GatingLib[];
    child_gating?: ChildGating;
}

export interface AppConfig {
    targets: Target[];
}

export interface GadgetUrl {
    url: string;
    sha256: string | null;
}

export interface GadgetUrls {
    primary?: GadgetUrl | null;
    companion?: GadgetUrl | null;
}

export function parseJson<T>(raw: unknown, fallback: T): T {
    if (raw == null || raw === "") return fallback;
    if (typeof raw !== "string") return raw as T;
    try { return JSON.parse(raw) as T; } catch (_) { return fallback; }
}

export function escHtml(s: unknown) {
    var entities: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(s).replace(/[&<>"']/g, function (c) { return entities[c]; });
}

export interface ExecResult {
    errno: number;
    stdout: string;
    stderr: string;
}

// Single-quoted literals only; never let package names expand as globs or subshells.
export function shQuote(s: unknown) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

export const DONE_MARK = "@@__KSUFRIDA_DONE__";
export const LABEL_FILE = "/data/local/tmp/libsec/.webui-labels.tmp";
export const SCAN_FILE = "/data/local/tmp/libsec/.webui-scan.tmp";
export const PKGS_FILE = "/data/local/tmp/libsec/.webui-packages.tmp";
export const POLL_INTERVAL_MS = 1000;

export function parseLabelLines(body: string) {
    var pairs = new Map<string, string>();
    body.split("\n").forEach(function (line: string) {
        if (!line || line === DONE_MARK) return;
        var i = line.indexOf("|");
        if (i > 0) pairs.set(line.slice(0, i), line.slice(i + 1).trim());
    });
    return pairs;
}

export interface PackagesInfoRow {
    packageName?: unknown;
    appLabel?: unknown;
    error?: unknown;
}

// Native getPackagesInfo rows to label pairs. Error rows stay missing
// so the caller retries them; labels fall back to the package name.
export function pairsFromPackagesInfo(info: unknown) {
    var pairs = new Map<string, string>();
    if (!Array.isArray(info)) return pairs;
    (info as PackagesInfoRow[]).forEach(function (it) {
        if (!it || typeof it !== "object" || it.error) return;
        if (typeof it.packageName !== "string" || !it.packageName) return;
        pairs.set(it.packageName,
            typeof it.appLabel === "string" && it.appLabel ? it.appLabel : it.packageName);
    });
    return pairs;
}

export function splitMarked(text: string, marks: string[]): Record<string, string[]> {
    var parts: Record<string, string[]> = {};
    var cur: string | null = null;
    String(text || "").split("\n").forEach(function (line) {
        if (marks.indexOf(line) !== -1) { cur = line; parts[cur] = []; return; }
        if (cur) parts[cur].push(line);
    });
    return parts;
}

export function cmpVersions(a: unknown, b: unknown) {
    var pa = String(a).split(".");
    var pb = String(b).split(".");
    for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
        var da = parseInt(pa[i] || "0", 10) || 0;
        var db = parseInt(pb[i] || "0", 10) || 0;
        if (da !== db) return da < db ? -1 : 1;
    }
    return 0;
}

export function blockField(text: string, block: string, field: string) {
    var b = new RegExp('"' + block + '"\\s*:\\s*\\{([^}]*)\\}').exec(text || "");
    if (!b) return null;
    var f = new RegExp('"' + field + '"\\s*:\\s*"([^"]+)"').exec(b[1]);
    return f && f[1];
}

export function parseGadgetMeta(text: string) {
    var v = /"version"\s*:\s*"([^"]+)"/.exec(text || "");
    if (!v) return null;
    return {
        version: v[1],
        arm: blockField(text, "assets", "arm"),
        arm64: blockField(text, "assets", "arm64"),
        sha256: {
            arm: blockField(text, "sha256", "arm"),
            arm64: blockField(text, "sha256", "arm64")
        }
    };
}

export interface GadgetMeta {
    version: string;
    arm?: string | null;
    arm64?: string | null;
    sha256?: { arm?: string | null; arm64?: string | null } | null;
}

export function gadgetUrlsForAbi(abi: string, meta: GadgetMeta | null): GadgetUrls | null {
    if (!meta) return null;
    function entry(url: string | null | undefined, hash: unknown): GadgetUrl | null {
        if (!url) return null;
        var e: GadgetUrl = { url: url, sha256: null };
        if (typeof hash === "string" && validSha256(hash)) e.sha256 = hash.toLowerCase();
        return e;
    }
    if (abi === "arm64-v8a" && meta.arm64) return {
        primary: entry(meta.arm64, meta.sha256 && meta.sha256.arm64),
        companion: meta.arm ? entry(meta.arm, meta.sha256 && meta.sha256.arm) : null
    };
    if (abi === "armeabi-v7a" && meta.arm) return {
        primary: entry(meta.arm, meta.sha256 && meta.sha256.arm),
        companion: null
    };
    return null;
}

export function validReleaseUrl(u: unknown) {
    return /^https:\/\/github\.com\/sohan-f\/knox-frida-patcher\/releases\/download\/[0-9.]+\/frida-gadget-[0-9.]+-android-(arm|arm64)\.so\.xz$/.test(typeof u === "string" ? u : "");
}

export function validVersion(v: unknown) {
    return /^[0-9]+\.[0-9]+\.[0-9]+$/.test(typeof v === "string" ? v : "");
}

export function validSha256(h: unknown) {
    return /^[0-9a-fA-F]{64}$/.test(typeof h === "string" ? h : "");
}

export function hashCheckSnippet(shellPath: string, hash: string, busyboxBin: string) {
    return "{ H=$(sha256sum " + shellPath + " 2>/dev/null | cut -d' ' -f1); " +
        "[ -n \"$H\" ] || H=$(" + busyboxBin + " sha256sum " + shellPath +
        " 2>/dev/null | cut -d' ' -f1); " +
        "[ \"$H\" = " + shQuote(hash.toLowerCase()) + " ]; }";
}

export function targetStatusCmd(names: string[]) {
    return "for c in $(grep -a -l -F " +
        names.map(function (n) { return "-e " + shQuote(n); }).join(" ") +
        " /proc/[0-9]*/cmdline 2>/dev/null); do " +
        "n=$(tr '\\0' '\\n' 2>/dev/null < \"$c\" | head -1); " +
        "case \"$n\" in " + names.map(shQuote).join("|") + ") " +
        "p=${c#/proc/}; echo \"$n ${p%%/cmdline}\";; esac; done";
}

export function parsePorts(lines: string[]) {
    var ports: number[] = [];
    (lines || []).forEach(function (l: string) {
        var p = parseInt(l, 10);
        if (p >= 1 && p <= 65535) ports.push(p);
    });
    return ports;
}

