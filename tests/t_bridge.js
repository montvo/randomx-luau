// Test HTTP vrstvy bridge: routovani (dashboard, stats, cache) a cache round trip.
// Spusti bridge na nahodnem portu s docasnym CACHE_DIR, pak overi odpovedi.
// usage: node tests/t_bridge.js
const { spawn } = require("node:child_process");
const net = require("node:net");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const assert = require("node:assert");

const PORT = 18000 + Math.floor(Math.random() * 1000);
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), "rxb-"));
const PART = 16 * 1024 * 1024;

function request(method, p, body) {
	return new Promise((resolve, reject) => {
		const s = net.connect(PORT, "127.0.0.1", () => {
			let head = `${method} ${p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n`;
			if (body) head += `Content-Length: ${body.length}\r\n`;
			s.write(head + "\r\n");
			if (body) s.write(body);
		});
		const chunks = [];
		s.on("data", (c) => chunks.push(c));
		s.on("error", reject);
		s.on("end", () => {
			const buf = Buffer.concat(chunks);
			const cut = buf.indexOf("\r\n\r\n");
			const status = Number(/^HTTP\/1\.1 (\d+)/.exec(buf.subarray(0, cut).toString())?.[1] || 0);
			resolve({ status, body: buf.subarray(cut + 4) });
		});
	});
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
	const child = spawn(process.execPath, [path.join(__dirname, "..", "bridge", "stratum-bridge.js"),
		"--bind", "127.0.0.1", "--port", String(PORT), "--cache-dir", DIR,
		"--pool", "127.0.0.1:1", "--wallet", "4test"], { stdio: ["ignore", "pipe", "pipe"] });
	let log = "";
	child.stdout.on("data", (c) => { log += c; });
	child.stderr.on("data", (c) => { log += c; });
	let failed = null;
	try {
		for (let i = 0; i < 50; i++) {
			try { await request("GET", "/"); break } catch { await wait(100) }
		}
		const seed = "ab".repeat(32);

		let r = await request("GET", "/");
		assert.equal(r.status, 200, "dashboard musi byt 200");
		assert.match(r.body.toString(), /<html/i, "dashboard ma vratit HTML");

		r = await request("GET", "/api/stats");
		assert.equal(r.status, 200, "/api/stats musi byt 200");
		assert.ok(JSON.parse(r.body.toString()).clients !== undefined, "stats ma mit clients");

		r = await request("GET", "/cache/" + seed + "/meta");
		assert.equal(r.status, 200, "meta musi byt 200");
		const meta = JSON.parse(r.body.toString());
		assert.equal(meta.parts, 16);
		assert.equal(meta.complete, false);

		r = await request("GET", "/cache/nesmysl");
		assert.equal(r.status, 404, "spatny tvar cache cesty je 404");

		r = await request("GET", "/cache/" + seed + "/16");
		assert.equal(r.status, 400, "index mimo rozsah je 400");

		r = await request("GET", "/cache/" + seed + "/0");
		assert.equal(r.status, 404, "chybejici dil je 404");

		const data = Buffer.alloc(PART, 7);
		for (let i = 0; i < 64; i++) data.writeUInt32LE(i, i * 4);
		r = await request("PUT", "/cache/" + seed + "/0", data);
		assert.equal(r.status, 200, "PUT dilu musi projit");

		r = await request("GET", "/cache/" + seed + "/0");
		assert.equal(r.status, 200);
		assert.equal(r.body.length, PART, "delka dilu musi sedet");
		assert.ok(r.body.equals(data), "dil musi vratit stejne bajty");

		r = await request("GET", "/cache/" + seed + "/meta");
		assert.deepEqual(JSON.parse(r.body.toString()).have, [0], "meta vi o nahranem dilu");

		r = await request("PUT", "/cache/" + seed + "/1", Buffer.alloc(1024));
		assert.equal(r.status, 400, "kratke telo je 400");

		r = await request("PUT", "/cache/" + seed + "/1", Buffer.alloc(PART + 5000));
		assert.equal(r.status, 413, "moc dlouhe telo je 413");

		console.log("PASS: routovani i cache round trip");
	} catch (e) {
		failed = e;
	} finally {
		child.kill();
		fs.rmSync(DIR, { recursive: true, force: true });
	}
	if (failed) {
		console.error("FAIL:", failed.message);
		console.error(log.split("\n").slice(-15).join("\n"));
		process.exit(1);
	}
})();
