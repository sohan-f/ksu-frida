// Static preview server for the KsuFrida WebUI. Dev-only, never shipped:
// packaging only copies template/ plus the root config example.
// Serves template/ksu_module/webroot; `/` injects /mock.js before main.js.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const webroot = path.resolve(here, "../template/ksu_module/webroot");
const mockJs = path.join(here, "mock.js");
const port = Number(process.argv[2] || process.env.PORT || 8090);

const mime = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf"
};

function send(res, code, type, body) {
    res.writeHead(code, { "content-type": type });
    res.end(body);
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://localhost");
    if (url.pathname === "/mock.js") {
        send(res, 200, mime[".js"], fs.readFileSync(mockJs, "utf8"));
        return;
    }
    const file = path.normalize(path.join(
        webroot, url.pathname === "/" ? "index.html" : url.pathname.slice(1)));
    if (!file.startsWith(webroot) || !fs.existsSync(file) ||
        fs.statSync(file).isDirectory()) {
        send(res, 404, "text/plain; charset=utf-8", "not found");
        return;
    }
    const type = mime[path.extname(file)] || "application/octet-stream";
    if (url.pathname === "/" || url.pathname === "/index.html") {
        let body = fs.readFileSync(file, "utf8");
        body = body.replace('<script src="main.js">',
            '<script src="/mock.js"></script>\n    <script src="main.js"></script>');
        send(res, 200, type, body);
        return;
    }
    send(res, 200, type, fs.readFileSync(file));
});

server.listen(port, () => {
    console.log("KsuFrida WebUI preview at http://localhost:" + port + "/");
});
