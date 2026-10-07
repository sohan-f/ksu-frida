import test from "node:test";
import assert from "node:assert/strict";
import {
    findDuplicateGadgetPorts,
    pairManifestCmd,
    pairSetupCmd,
    pairStemCollisions,
    pairSweepCmd,
    parseGadgetPort,
    shQuote,
    targetGadgetCfg,
    targetGadgetSo,
    validateTargetGadgetJson,
} from "../src/util";
import { FakeDevice } from "./virtual";

const DIR = "/data/local/tmp/libsec";
const PAIRS = "/data/local/tmp/libsec/gadget-pairs";

test("pair basenames isolate processes and sanitize hostile input", () => {
    assert.equal(targetGadgetSo("com.foo"), "libsecmon_com.foo.so");
    assert.equal(targetGadgetSo("com.foo:push"), "libsecmon_com.foo_push.so");
    assert.notEqual(targetGadgetSo("com.foo"), targetGadgetSo("com.foo:push"));
    assert.equal(targetGadgetSo("com.foo", true), "libsecmon_com.foo32.so");
    assert.equal(targetGadgetSo("a/b;rm"), "libsecmon_a_b_rm.so");
    assert.equal(targetGadgetCfg("libsecmon_a.so"), "libsecmon_a.config.so");
    assert.equal(targetGadgetCfg("libsecmon_a32.so"), "libsecmon_a32.config.so");
});

test("parseGadgetPort accepts only the Frida range", () => {
    assert.equal(parseGadgetPort(27042), 27042);
    assert.equal(parseGadgetPort("27042"), 27042);
    assert.equal(parseGadgetPort(1), 1);
    assert.equal(parseGadgetPort(65535), 65535);
    assert.equal(parseGadgetPort(0), null);
    assert.equal(parseGadgetPort(65536), null);
    assert.equal(parseGadgetPort(-1), null);
    assert.equal(parseGadgetPort(27.5), null);
    assert.equal(parseGadgetPort("abc"), null);
    assert.equal(parseGadgetPort(""), null);
    assert.equal(parseGadgetPort(null), null);
    assert.equal(parseGadgetPort(undefined), null);
});

test("validateTargetGadgetJson pins the listen port, passes other modes", () => {
    const listen = (port: number) =>
        JSON.stringify({ interaction: { type: "listen", address: "127.0.0.1", port } });
    assert.equal(validateTargetGadgetJson(listen(27043), 27043), null);
    assert.ok((validateTargetGadgetJson(listen(27044), 27043) || "").includes("27043"));
    assert.ok(validateTargetGadgetJson("nope", 27043) !== null);
    assert.ok((validateTargetGadgetJson("[1]", 27043) || "").includes("object"));
    assert.ok((validateTargetGadgetJson("{}", 27043) || "").includes("27043"));
    assert.equal(
        validateTargetGadgetJson(JSON.stringify({ interaction: { type: "script", path: "/x.js" } }), 27043),
        null,
    );
});

test("duplicate ports and stem collisions are reported", () => {
    assert.deepEqual(
        findDuplicateGadgetPorts([{ gadget_port: 1 }, { gadget_port: 2 }, { gadget_port: 1 }]),
        [1],
    );
    assert.deepEqual(findDuplicateGadgetPorts([{ gadget_port: 1 }, { gadget_port: 2 }]), []);
    assert.deepEqual(findDuplicateGadgetPorts([{ gadget_port: "9" }, { gadget_port: 9 }]), [9]);
    assert.deepEqual(
        pairStemCollisions([{ app_name: "a:b", gadget_port: 1 }, { app_name: "a_b", gadget_port: 2 }]).length > 0
            ? ["clash"]
            : [],
        ["clash"],
    );
    assert.deepEqual(
        pairStemCollisions([{ app_name: "com.foo", gadget_port: 1 }, { app_name: "com.foo:push", gadget_port: 2 }]),
        [],
    );
    assert.deepEqual(pairStemCollisions([{ app_name: "com.foo" }, { app_name: "com.foo:push" }]), []);
});

test("pair shell uses rm-before-write plus tmp+rename and quotes payloads", () => {
    const evil = "x'; rm -rf /; echo '";
    const setup = pairSetupCmd(DIR, { so: "libsecmon_a.so", src: "libsecmon.so", cfg: "libsecmon_a.config.so", content: evil });
    assert.ok(setup.includes("rm -f " + shQuote(DIR + "/libsecmon_a.so")));
    assert.ok(setup.includes("rm -f " + shQuote(DIR + "/libsecmon_a.config.so.tmp")));
    assert.ok(setup.includes("mv -f " + shQuote(DIR + "/libsecmon_a.config.so.tmp")));
    assert.ok(setup.includes(shQuote(evil)));
    assert.ok(setup.includes("|| OK=0"));
    // No bare redirect onto a live path: every `>` targets a `.tmp` file
    // (`2>/dev/null` is stderr plumbing, not a file write).
    const redirects = setup.split("2>/dev/null").join("").match(/>[^;|&]+/g) || [];
    assert.ok(redirects.length > 0);
    redirects.forEach(function (tail) {
        assert.ok(tail.trim().endsWith(".tmp'"), tail);
    });

    const sweep = pairSweepCmd(DIR, ["libsecmon_a.so"], ["libsecmon_a.config.so"]);
    assert.ok(sweep.includes(shQuote(DIR + "/libsecmon.so")));
    assert.ok(sweep.includes(shQuote(DIR + "/libsecmon32.so")));
    assert.ok(sweep.includes("libsecmon_a.so"));
    assert.ok(sweep.includes("*.config.so) continue"), "binary sweep must skip sibling configs");

    const manifest = pairManifestCmd(PAIRS, [{ so: "libsecmon_a.so", src: "libsecmon.so" }]);
    assert.ok(manifest.includes("libsecmon_a.so libsecmon.so"));
    assert.ok(manifest.includes(".tmp"));
    assert.ok(pairManifestCmd(PAIRS, []).startsWith("rm -f " + shQuote(PAIRS)));
});

function device(testBody: (dev: FakeDevice) => void): () => void {
    return () => {
        const dev = FakeDevice.create();
        try {
            testBody(dev);
        } finally {
            dev.destroy();
        }
    };
}

test(
    "pair setup writes binaries, configs, manifest; sweep clears orphans only",
    device((dev) => {
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon.so", "gadget-64");
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon32.so", "gadget-32");
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon_stale.so", "old");
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon_stale.config.so", "{}");
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon_nocfg.config.so", "{}");

        const cfgA = JSON.stringify({ interaction: { type: "listen", port: 27043 } });
        const run = (cmd: string) => {
            const out = dev.exec("{ OK=1; " + cmd + "; if [ \"$OK\" = 1 ]; then echo SAVED; fi; } 2>&1");
            assert.match(out.stdout, /SAVED/);
        };
        run(pairSetupCmd(DIR, { so: "libsecmon_a.so", src: "libsecmon.so", cfg: "libsecmon_a.config.so", content: cfgA }));
        run(pairSetupCmd(DIR, { so: "libsecmon_a32.so", src: "libsecmon32.so", cfg: "libsecmon_a32.config.so", content: cfgA }));
        run(pairSweepCmd(DIR, ["libsecmon_a.so", "libsecmon_a32.so"], ["libsecmon_a.config.so", "libsecmon_a32.config.so"]));
        run(pairManifestCmd(PAIRS, [
            { so: "libsecmon_a.so", src: "libsecmon.so" },
            { so: "libsecmon_a32.so", src: "libsecmon32.so" },
        ]));

        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon_a.so"), "gadget-64");
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon_a32.so"), "gadget-32");
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon_a.config.so").trim(), cfgA);
        assert.equal(
            dev.readDevicePath(PAIRS),
            "libsecmon_a.so libsecmon.so\nlibsecmon_a32.so libsecmon32.so\n",
        );
        assert.equal(dev.existsDevicePath("/data/local/tmp/libsec/libsecmon_stale.so"), false);
        assert.equal(dev.existsDevicePath("/data/local/tmp/libsec/libsecmon_stale.config.so"), false);
        assert.equal(dev.existsDevicePath("/data/local/tmp/libsec/libsecmon_nocfg.config.so"), false);
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon.so"), "gadget-64");
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon32.so"), "gadget-32");
    }),
);

test(
    "pair setup replaces a planted config symlink and spares its target",
    device((dev) => {
        dev.writeDevicePath("/data/local/tmp/libsec/libsecmon.so", "gadget-64");
        dev.writeDevicePath("/data/local/tmp/libsec/victim.txt", "untouched");
        const plant = dev.exec("ln -s /data/local/tmp/libsec/victim.txt /data/local/tmp/libsec/libsecmon_v.config.so");
        assert.equal(plant.code, 0);

        const cfg = JSON.stringify({ interaction: { type: "listen", port: 27044 } });
        const out = dev.exec(
            "{ OK=1; " + pairSetupCmd(DIR, { so: "libsecmon_v.so", src: "libsecmon.so", cfg: "libsecmon_v.config.so", content: cfg }) +
            "; if [ \"$OK\" = 1 ]; then echo SAVED; fi; } 2>&1",
        );
        assert.match(out.stdout, /SAVED/);
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/victim.txt"), "untouched");
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/libsecmon_v.config.so").trim(), cfg);
    }),
);
