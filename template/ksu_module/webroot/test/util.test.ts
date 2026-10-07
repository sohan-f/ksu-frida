import test from "node:test";
import assert from "node:assert/strict";
import {
    blockField,
    cmpVersions,
    escHtml,
    gadgetUrlsForAbi,
    hashCheckSnippet,
    parseGadgetMeta,
    parseJson,
    parseLabelLines,
    parsePorts,
    pairsFromPackagesInfo,
    shQuote,
    splitMarked,
    targetStatusCmd,
    validReleaseUrl,
    validSha256,
    validVersion,
} from "../src/util";

const B = "/data/adb/ksu/bin/busybox";

test("shQuote neutralizes expansion and quoting", () => {
    assert.equal(shQuote("com.a.b"), "'com.a.b'");
    assert.equal(shQuote("a b"), "'a b'");
    assert.equal(shQuote("a'b"), "'a'\\''b'");
    assert.equal(shQuote("$(rm -rf /)"), "'$(rm -rf /)'");
    assert.equal(shQuote(""), "''");
});

test("parseJson falls back without throwing", () => {
    assert.deepEqual(parseJson('{"a":1}', {}), { a: 1 });
    assert.deepEqual(parseJson("nope", { d: 1 }), { d: 1 });
    assert.equal(parseJson("", "fb"), "fb");
    assert.equal(parseJson(null, "fb"), "fb");
});

test("escHtml escapes markup", () => {
    assert.equal(escHtml('<a href="x">&\'y'), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;y');
});

test("release metadata validators", () => {
    const good = "https://github.com/sohan-f/knox-frida-patcher/releases/download/17.2.0/frida-gadget-17.2.0-android-arm64.so.xz";
    assert.equal(validReleaseUrl(good), true);
    assert.equal(validReleaseUrl("https://evil.example/x.so.xz"), false);
    assert.equal(validReleaseUrl("https://github.com/sohan-f/knox-frida-patcher/releases/download/17.2.0/frida-gadget-17.2.0-android-x86.so.xz"), false);
    assert.equal(validVersion("17.2.0"), true);
    assert.equal(validVersion("17.2"), false);
    assert.equal(validVersion("v17.2.0"), false);
    assert.equal(validSha256("ab".repeat(32)), true);
    assert.equal(validSha256("xyz"), false);
    assert.equal(validSha256(null), false);
});

test("cmpVersions orders numerically", () => {
    assert.equal(cmpVersions("17.2.0", "17.10.0"), -1);
    assert.equal(cmpVersions("17.10.0", "17.2.0"), 1);
    assert.equal(cmpVersions("17.2.0", "17.2.0"), 0);
    assert.equal(cmpVersions("17.2", "17.2.0"), 0);
});

test("splitMarked sections output", () => {
    const out = splitMarked("A\n1\nB\n2\n3", ["A", "B"]);
    assert.deepEqual(out, { A: ["1"], B: ["2", "3"] });
    assert.deepEqual(splitMarked("x\ny", ["A"]), {});
});

test("parseLabelLines skips marks and malformed rows", () => {
    const m = parseLabelLines("com.a|Label A\n@@__KSUFRIDA_DONE__\nbroken\ncom.b|B");
    assert.equal(m.get("com.a"), "Label A");
    assert.equal(m.get("com.b"), "B");
    assert.equal(m.has("broken"), false);
});

test("pairsFromPackagesInfo skips errors, falls back to package", () => {
    const m = pairsFromPackagesInfo([
        { packageName: "com.a", appLabel: "A" },
        { packageName: "com.b" },
        { packageName: "com.c", appLabel: "", error: "x" },
        { packageName: "com.d", appLabel: "D", error: "x" },
        null,
        "junk",
    ]);
    assert.equal(m.get("com.a"), "A");
    assert.equal(m.get("com.b"), "com.b");
    assert.equal(m.has("com.c"), false);
    assert.equal(m.has("com.d"), false);
    assert.equal(pairsFromPackagesInfo(null).size, 0);
    assert.equal(pairsFromPackagesInfo("[]").size, 0);
});

test("parsePorts keeps valid ports only", () => {
    assert.deepEqual(parsePorts(["27042", "abc", "0", "65536", "-1"]), [27042]);
    assert.deepEqual(parsePorts(["1", "65535"]), [1, 65535]);
});

test("targetStatusCmd quotes names and matches exactly", () => {
    const cmd = targetStatusCmd(["com.a.b", "evil'x"]);
    assert.ok(cmd.includes("-e 'com.a.b'"));
    assert.ok(cmd.includes("-e 'evil'\\''x'"));
    assert.ok(cmd.includes("case \"$n\" in 'com.a.b'|'evil'\\''x')"));
});

test("hashCheckSnippet expands shell paths, quotes the digest", () => {
    const s = hashCheckSnippet('"$S/f.so.xz"', "AB".repeat(32), B);
    assert.ok(s.includes('sha256sum "$S/f.so.xz"'));
    assert.ok(!s.includes(`'"$S`));
    assert.ok(s.includes("ab".repeat(32)));
});

test("gadget metadata wiring", () => {
    const meta = parseGadgetMeta('{"version":"1.0.0","assets":{"arm64":"U64"},"sha256":{"arm64":"' + "ab".repeat(32) + '"}}');
    assert.equal(meta && meta.version, "1.0.0");
    const urls = gadgetUrlsForAbi("arm64-v8a", meta);
    assert.equal(urls && urls.primary && urls.primary.url, "U64");
    assert.equal(gadgetUrlsForAbi("x86", meta), null);
    assert.equal(gadgetUrlsForAbi("arm64-v8a", null), null);
    assert.equal(blockField('{"assets":{"arm":"U"}}', "assets", "arm"), "U");
});
