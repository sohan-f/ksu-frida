import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { hashCheckSnippet, parsePorts, shQuote, targetStatusCmd } from "../src/util";
import { FakeDevice } from "./virtual";

const B = "/data/adb/ksu/bin/busybox";

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
    "targetStatusCmd finds fixture processes by exact name",
    device((dev) => {
        dev.writeDevicePath("/proc/4242/cmdline", Buffer.from("com.a.b:push\0arg\0"));
        dev.writeDevicePath("/proc/9999/cmdline", Buffer.from("com.foobar\0"));
        const out = dev.exec(targetStatusCmd(["com.a.b:push"]));
        assert.equal(out.code, 0);
        assert.match(out.stdout, /com\.a\.b:push 4242/);
        assert.doesNotMatch(out.stdout, /9999/);
    }),
);

test(
    "hashCheckSnippet verifies a real digest and rejects a wrong one",
    device((dev) => {
        dev.writeDevicePath("/data/local/tmp/libsec/stage.bin", "payload-bytes");
        const digest = createHash("sha256").update("payload-bytes").digest("hex");
        const good = dev.exec(
            `H=$(sha256sum "$S" 2>/dev/null | cut -d' ' -f1); [ "$H" = ${shQuote(digest)} ]`
                .replaceAll("$S", "/data/local/tmp/libsec/stage.bin"),
        );
        assert.equal(good.code, 0);
        const bad = dev.exec(hashCheckSnippet('"$S"', "00".repeat(32), B).replaceAll("$S", "/data/local/tmp/libsec/stage.bin"));
        assert.notEqual(bad.code, 0);
    }),
);

test(
    "save pipeline writes and re-reads through the virtual fs",
    device((dev) => {
        const body = '{"targets":[]}';
        const out = dev.exec(
            `{ rm -f /data/local/tmp/libsec/config.json; printf '%s\\n' ${shQuote(body)} > /data/local/tmp/libsec/config.json && chmod 644 /data/local/tmp/libsec/config.json && echo SAVED; } 2>&1`,
        );
        assert.equal(out.code, 0);
        assert.match(out.stdout, /SAVED/);
        assert.equal(dev.readDevicePath("/data/local/tmp/libsec/config.json").trim(), body);
    }),
);

test(
    "parsePorts reads ports listed by a fixture scan",
    device((dev) => {
        dev.writeDevicePath("/data/local/tmp/libsec/ports.txt", "27042\nabc\n");
        const out = dev.exec("cat /data/local/tmp/libsec/ports.txt");
        assert.deepEqual(parsePorts(out.stdout.split("\n")), [27042]);
    }),
);
