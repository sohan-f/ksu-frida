import test from "node:test";
import assert from "node:assert/strict";
import {
    blockField,
    cmpVersions,
    elfArch,
    escHtml,
    findDuplicateGadgetPorts,
    gadgetUrlsForAbi,
    hashCheckSnippet,
    isSafePairName,
    nextFreeGadgetPort,
    parseDoctorOutput,
    parseGadgetMeta,
    parseHistoryLine,
    parseJson,
    parseLabelLines,
    parsePorts,
    parseTargetStatus,
    pairsFromPackagesInfo,
    pairSweepCmd,
    sanitizeTargets,
    shQuote,
    splitMarked,
    targetStatusCmd,
    validReleaseUrl,
    validSha256,
    validVersion,
    wildcardPrefix,
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
    assert.deepEqual(parsePorts(["27042", "abc", "27042junk", "0", "65536", "-1"]), [27042]);
    assert.deepEqual(parsePorts(["1", "65535"]), [1, 65535]);
});

test("parseTargetStatus splits on the last blank, needs numeric pids", () => {
    assert.deepEqual(
        parseTargetStatus("com.a 12\ncom.a 34\n", ["com.a"]),
        { "com.a": ["12", "34"] },
    );
    assert.deepEqual(
        parseTargetStatus("com.a:my proc 99\n", ["com.a:my proc"]),
        { "com.a:my proc": ["99"] },
    );
    assert.deepEqual(parseTargetStatus("com.a nope\n", ["com.a"]), {});
    assert.deepEqual(parseTargetStatus("com.other 7\n", ["com.a"]), {});
    assert.deepEqual(parseTargetStatus("", ["com.a"]), {});
});

test("targetStatusCmd quotes names and matches exactly", () => {
    const cmd = targetStatusCmd(["com.a.b", "evil'x"]);
    assert.ok(cmd.includes("-e 'com.a.b'"));
    assert.ok(cmd.includes("-e 'evil'\\''x'"));
    assert.ok(cmd.includes("case \"$n\" in 'com.a.b'|'evil'\\''x')"));
});

test("wildcardPrefix accepts one trailing star only", () => {
    assert.equal(wildcardPrefix("com.foo*"), "com.foo");
    assert.equal(wildcardPrefix("*"), null);
    assert.equal(wildcardPrefix("com.foo"), null);
    assert.equal(wildcardPrefix("com.*foo"), null);
    assert.equal(wildcardPrefix("com.foo**"), null);
    assert.equal(wildcardPrefix("*com.foo"), null);
    assert.equal(wildcardPrefix(null), null);
});

test("targetStatusCmd expands wildcards to prefix patterns", () => {
    const cmd = targetStatusCmd(["com.foo*"]);
    assert.ok(cmd.includes("-e 'com.foo'"));
    assert.ok(!cmd.includes("-e 'com.foo*'"));
    assert.ok(cmd.includes("case \"$n\" in 'com.foo'*)"));
});

test("parseTargetStatus collects wildcard processes under the pattern", () => {
    assert.deepEqual(
        parseTargetStatus("com.foo 12\ncom.foo:push 34\ncom.bar 56\n", ["com.foo*"]),
        { "com.foo*": ["12", "34"] },
    );
    assert.deepEqual(
        parseTargetStatus("com.foo 12\n", ["com.foo", "com.foo*"]),
        { "com.foo": ["12"], "com.foo*": ["12"] },
    );
    assert.deepEqual(parseTargetStatus("com.foobar 7\n", ["com.foo"]), {});
});

test("nextFreeGadgetPort fills the lowest gap from the base", () => {
    assert.equal(nextFreeGadgetPort([]), 27042);
    assert.equal(nextFreeGadgetPort([{ gadget_port: 27042 }]), 27043);
    assert.equal(nextFreeGadgetPort([{ gadget_port: 27043 }]), 27042);
    assert.equal(
        nextFreeGadgetPort([{ gadget_port: 27042 }, { gadget_port: 27043 }], 27043),
        27044,
    );
    assert.equal(nextFreeGadgetPort([{ gadget_port: "99junk" }]), 27042);
    assert.deepEqual(findDuplicateGadgetPorts([{ gadget_port: 1 }, { gadget_port: 1 }]), [1]);
});

test("elfArch reads little-endian machine bytes", () => {
    assert.equal(elfArch("b700"), "arm64");
    assert.equal(elfArch("2800"), "arm");
    assert.equal(elfArch(" B700 "), "arm64");
    assert.equal(elfArch("0300"), null);
    assert.equal(elfArch(""), null);
    assert.equal(elfArch("MISSING"), null);
    assert.equal(elfArch(null), null);
});

test("parseHistoryLine keeps spaced names, rejects fragments", () => {    const sep = "";
    const line = ["1", "4242", "1700000000", "memfd", "clean", "com.foo:my proc", "libsecmon.so"].join(sep);
    assert.deepEqual(parseHistoryLine(line + "   "), {
        pid: "4242", ts: 1700000000, src: "memfd", result: "clean", app: "com.foo:my proc", lib: "libsecmon.so",
    });
    assert.equal(parseHistoryLine("1" + sep + "42"), null);
    assert.equal(parseHistoryLine(["2", "42", "1", "a", "b", "c", "d"].join(sep)), null);
    assert.equal(parseHistoryLine(["1", "NaN", "1", "a", "b", "c", "d"].join(sep)), null);
    assert.equal(parseHistoryLine(""), null);
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

test("sanitizeTargets drops nameless junk and normalizes types", () => {
    const raw: any[] = [
        { app_name: "com.a", enabled: 1 as any, start_up_delay_ms: "500", injected_libraries: [{ path: "/x.so" }, { path: 7 }, null] },
        { app_name: "", enabled: true },
        null,
        "junk",
        { app_name: "com.b", gadget_port: "99junk", child_gating: "yes" as any },
        { app_name: "com.c", gadget_port: 27043 },
    ];
    const clean = sanitizeTargets(raw as any);
    assert.equal(clean.length, 3);
    assert.equal(clean[0].app_name, "com.a");
    assert.equal(clean[0].enabled, true);
    assert.equal(clean[0].start_up_delay_ms, 500);
    assert.deepEqual(clean[0].injected_libraries, [{ path: "/x.so" }]);
    assert.equal((clean[1] as any).gadget_port, undefined);
    assert.equal((clean[1] as any).gadget_config, undefined);
    assert.equal(clean[2].gadget_port, 27043);
    assert.ok(typeof clean[2].gadget_config === "string" && (clean[2].gadget_config as string).includes("27043"));
});

test("pair sweep keeps only charset-safe basenames", () => {
    assert.equal(isSafePairName("libsecmon_a.so"), true);
    assert.equal(isSafePairName(""), false);
    assert.equal(isSafePairName("a b"), false);
    assert.equal(isSafePairName("a\"; rm -rf /; echo \""), false);
    const cmd = pairSweepCmd("/d", ['libsecmon_a.so', 'evil"; rm -rf /; echo "'], ["libsecmon_a.config.so", "a b"]);
    assert.ok(cmd.includes("libsecmon_a.so"));
    assert.ok(!cmd.includes("evil"));
    assert.ok(!cmd.includes("a b"));
});

test("parseDoctorOutput splits abi, libs, and cfg bodies", () => {
    const d = parseDoctorOutput(
        "ABI:arm64-v8a\n" +
        "LIB|/a/lib.so|b700\n" +
        "LIB|/b/missing.so|MISSING\n" +
        "CFG|shared|/d/libsecmon.config.so\n" +
        '{"a":1}\n' +
        "CFG|27043|/d/libsecmon_x.config.so\n" +
        "{\n" +
        '"port": 1\n' +
        "}\n",
    );
    assert.equal(d.abi, "arm64-v8a");
    assert.deepEqual(d.libs, [
        { path: "/a/lib.so", mach: "b700" },
        { path: "/b/missing.so", mach: "MISSING" },
    ]);
    assert.equal(d.cfgs.length, 2);
    assert.equal(d.cfgs[0].port, "shared");
    assert.equal(d.cfgs[0].body, '{"a":1}');
    assert.equal(d.cfgs[1].body, '{\n"port": 1\n}');
    assert.deepEqual(parseDoctorOutput(""), { abi: "", libs: [], cfgs: [] });
});
