import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Virtual device: a fixture root standing in for device-absolute paths,
// executed with the real local shell. No flashing, no adb.
const TRANSLATIONS: Array<{ from: string; to: string; rooted: boolean }> = [
    { from: "/data/local/tmp/libsec", to: "libsec", rooted: true },
    { from: "/data/adb/modules/ksufrida", to: "mod", rooted: true },
    // `$BUSYBOX_BIN applet args` → `env applet args`: same binaries, local PATH.
    { from: "/data/adb/ksu/bin/busybox", to: "env", rooted: false },
    { from: "/proc", to: "proc", rooted: true },
];

export interface ExecOut {
    code: number;
    stdout: string;
}

export class FakeDevice {
    readonly root: string;

    private constructor(root: string) {
        this.root = root;
    }

    static create(): FakeDevice {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), "ksufrida-vdev-"));
        fs.mkdirSync(path.join(root, "libsec"), { recursive: true });
        fs.mkdirSync(path.join(root, "mod", "gadget"), { recursive: true });
        fs.mkdirSync(path.join(root, "proc", "4242"), { recursive: true });
        return new FakeDevice(root);
    }

    writeDevicePath(devicePath: string, content: string | Buffer): void {
        const local = this.translate(devicePath);
        fs.mkdirSync(path.dirname(local), { recursive: true });
        fs.writeFileSync(local, content);
    }

    readDevicePath(devicePath: string): string {
        return fs.readFileSync(this.translate(devicePath), "utf8");
    }

    existsDevicePath(devicePath: string): boolean {
        return fs.existsSync(this.translate(devicePath));
    }

    exec(cmd: string, extraEnv: Record<string, string> = {}): ExecOut {
        let local = cmd;
        for (const t of TRANSLATIONS) {
            const to = t.rooted ? path.join(this.root, t.to) : t.to;
            local = local.split(t.from).join(to);
        }
        try {
            const stdout = execFileSync("sh", ["-c", local], {
                encoding: "utf8",
                timeout: 15000,
                env: { ...process.env, ...extraEnv },
            });
            return { code: 0, stdout };
        } catch (e) {
            const err = e as { status?: unknown; stdout?: unknown };
            return {
                code: typeof err.status === "number" ? err.status : 1,
                stdout: typeof err.stdout === "string" ? err.stdout : "",
            };
        }
    }

    destroy(): void {
        fs.rmSync(this.root, { recursive: true, force: true });
    }

    private translate(devicePath: string): string {
        for (const t of TRANSLATIONS) {
            if (!t.rooted) continue;
            if (devicePath.startsWith(t.from)) {
                return path.join(this.root, t.to, devicePath.slice(t.from.length));
            }
        }
        throw new Error("untranslatable device path: " + devicePath);
    }
}
