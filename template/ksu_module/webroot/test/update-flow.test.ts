import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FakeDevice } from "./virtual";

const ROOT = path.join(__dirname, "..", "..");
const MAIN = fs.readFileSync(path.join(ROOT, "main.ts"), "utf8");

// Extracts the assembled download script from the real downloadGadgetUpdate
// source (string-aware scan, no duplication): from `var script =` to its
// terminating semicolon, evaluated with fixture-bound variables.
function extractInstallScript(vars: Record<string, unknown>): string {
    const startMark = '    var script =\n        "M=" + MODDIR';
    const start = MAIN.indexOf(startMark);
    assert.notEqual(start, -1, "script assembly moved; update this extractor");
    let i = MAIN.indexOf('"', start);
    let out = "";
    let quote: string | null = null;
    while (i < MAIN.length) {
        const c = MAIN[i];
        if (quote) {
            out += c;
            if (c === "\\") {
                out += MAIN[i + 1];
                i += 1;
            } else if (c === quote) {
                quote = null;
            }
        } else if (c === '"' || c === "'") {
            quote = c;
            out += c;
        } else if (c === ";") {
            break;
        } else {
            out += c;
        }
        i += 1;
    }
    const MODDIR = "/data/adb/modules/ksufrida";
    const GADGET_DL_DIR = "/data/local/tmp/libsec/.webui-gadget-dl";
    const BUSYBOX_BIN = "/data/adb/ksu/bin/busybox";
    const shQuote = (s: string) => "'" + String(s).replace(/'/g, "'\\''") + "'";
    const validSha256 = (h: unknown) =>
        /^[0-9a-fA-F]{64}$/.test(typeof h === "string" ? h : "");
    const hashCheckSnippet = (shellPath: string, hash: string, busyboxBin: string) =>
        `{ H=$(sha256sum ${shellPath} 2>/dev/null | cut -d' ' -f1); [ "$H" = ${shQuote(
            hash.toLowerCase(),
        )} ]; }`;
    const scope: Record<string, unknown> = { MODDIR, GADGET_DL_DIR, BUSYBOX_BIN, shQuote, validSha256, hashCheckSnippet, ...vars };
    const names = Object.keys(scope);
    const fn = new Function(...names, `return (${out});`);
    return String(fn(...names.map((n) => scope[n])));
}

function stubBin(dir: string): void {
    fs.writeFileSync(
        path.join(dir, "curl"),
        '#!/bin/sh\nout=""\nprev=""\nfor a in "$@"; do\n  if [ "$prev" = "-o" ] || [ "$prev" = "-O" ]; then out="$a"; fi\n  prev="$a"\ndone\ncat "$FIXTURE_XZ" > "$out"\n',
        { mode: 0o755 },
    );
}

function fixtureXz(root: string, body: string): { file: string; sha256: string } {
    const src = path.join(root, "gadget.bin");
    fs.writeFileSync(src, body);
    execFileSync("xz", ["-f", "-k", src]);
    const file = src + ".xz";
    const sha256 = execFileSync("sha256sum", [file], { encoding: "utf8" }).split(" ")[0];
    return { file, sha256 };
}

test("update flow installs on success and holds the version on disk-full", () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "ksufrida-update-"));
    const bin = path.join(work, "bin");
    fs.mkdirSync(bin);
    stubBin(bin);
    const dev = FakeDevice.create();
    try {
        const { file, sha256 } = fixtureXz(work, "fake-gadget-bytes");
        const run = (script: string) =>
            dev.exec(script, { PATH: bin + ":" + process.env.PATH, FIXTURE_XZ: file });

        // Success: version bumped, payload + hash land in both trees.
        const ok = run(
            extractInstallScript({ v: "9.9.9", u1: "https://x/y", h1: sha256, u2: null, h2: null }),
        );
        assert.match(ok.stdout, /RESULT:ok/);
        assert.equal(dev.readDevicePath("/data/adb/modules/ksufrida/gadget/gadget.version").trim(), "9.9.9");
        assert.ok(dev.existsDevicePath("/data/local/tmp/libsec/libsecmon.so"));
        assert.equal(
            dev.readDevicePath("/data/adb/modules/ksufrida/gadget/libsecmon.so.xz.sha256sum").trim(),
            sha256,
        );

        // Wrong digest: nothing installed, version untouched.
        const badHash = run(
            extractInstallScript({ v: "2.0.0", u1: "https://x/y", h1: "00".repeat(32), u2: null, h2: null }),
        );
        assert.match(badHash.stdout, /RESULT:hash-fail/);
        assert.doesNotMatch(badHash.stdout, /RESULT:ok/);
        assert.equal(dev.readDevicePath("/data/adb/modules/ksufrida/gadget/gadget.version").trim(), "9.9.9");
    } finally {
        dev.destroy();
        fs.rmSync(work, { recursive: true, force: true });
    }
});

test("install branch guards every mutating op and gates the version bump", () => {
    const src = fs.readFileSync(path.join(ROOT, "main.ts"), "utf8");
    const start = src.indexOf('"rm -f \\"$M/libsecmon.so.xz\\"');
    assert.notEqual(start, -1, "install branch moved; update this test");
    const end = src.indexOf('echo RESULT:ok;', start);
    const branch = src.slice(start, end).replace(/\\/g, "");
    for (const op of ["cp -f", "unxz -f", "chmod 644", "echo "]) {
        const at = branch.indexOf(op);
        assert.notEqual(at, -1, op + " missing from install branch");
        assert.ok(branch.slice(at).includes("|| OK2=0"), op + " must set OK2=0 on failure");
    }
    assert.ok(branch.includes('if [ "$OK2" = 1 ]'), "version bump must sit inside the OK2 gate");
});
