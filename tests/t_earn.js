// Test vypoctu vydelku: falosny pool + falosny STATS_API + WS klient.
// overuje XMR/share, rozdeleni podle prijatych shares a Kc prevod.
// usage: node tests/t_earn.js
const { spawn } = require("node:child_process");
const net = require("node:net");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert");

const PORT = 19000 + Math.floor(Math.random() * 500);
const POOL_PORT = PORT + 600;
const STATS_PORT = PORT + 1200;
const WALLET = "4testwallet";
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), "rxe-"));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ── falosny pool: login vrati job, submit OK ────────────────────────────────
const poolSrv = net.createServer((sock) => {
	sock.on("error", () => {});
	let buf = "";
	sock.on("data", (c) => {
		buf += c.toString();
		let i;
		while ((i = buf.indexOf("\n")) >= 0) {
			const line = buf.slice(0, i);
			buf = buf.slice(i + 1);
			let m = null;
			try { m = JSON.parse(line) } catch { continue }
			if (m.method === "login") {
				sock.write(JSON.stringify({ id: m.id, jsonrpc: "2.0", error: null, result: { id: "sess-1", job: { blob: "00".repeat(76), job_id: "j1", target: "ffffffff", seed_hash: "00".repeat(32), height: 1 } } }) + "\n");
			} else if (m.method === "submit") {
				sock.write(JSON.stringify({ id: m.id, jsonrpc: "2.0", error: null, result: { status: "OK" } }) + "\n");
			} else if (m.id != null) {
				sock.write(JSON.stringify({ id: m.id, jsonrpc: "2.0", error: null, result: { status: "KEEPALIVED" } }) + "\n");
			}
		}
	});
});

// ── falosny STATS_API: 10 XMR za 20000 valid shares = 0.0005 XMR/share ─────
const PICO = 1e12;
const statsSrv = http.createServer((req, res) => {
	if (req.url.includes("/miner/") && req.url.endsWith("/stats")) {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ hash: 12345, amtDue: 1 * PICO, amtPaid: 9 * PICO, validShares: 20000, invalidShares: 7 }));
		return;
	}
	res.writeHead(404); res.end();
});

// ── minimalni WS klient ─────────────────────────────────────────────────────
function wsClient() {
	return new Promise((resolve, reject) => {
		const sock = net.connect(PORT, "127.0.0.1", () => {
			sock.write("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + crypto.randomBytes(16).toString("base64") + "\r\nSec-WebSocket-Version: 13\r\n\r\n");
		});
		let opened = false;
		let buf = Buffer.alloc(0);
		sock.on("error", reject);
		sock.on("data", (c) => {
			if (!opened) {
				buf = Buffer.concat([buf, c]);
				const end = buf.indexOf("\r\n\r\n");
				if (end < 0) return;
				assert.match(buf.subarray(0, end).toString(), /^HTTP\/1\.1 101/);
				buf = buf.subarray(end + 4);
				opened = true;
				sock.on("data", () => {});
				return;
			}
		});
		const send = (obj) => {
			const data = Buffer.from(JSON.stringify(obj));
			const mask = crypto.randomBytes(4);
			const head = data.length < 126
				? Buffer.from([0x81, 0x80 | data.length])
				: Buffer.from([0x81, 0x80 | 126, data.length >> 8, data.length & 0xff]);
			const body = Buffer.from(data);
			for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4];
			sock.write(Buffer.concat([head, mask, body]));
		};
		const opened2 = setInterval(() => { if (opened) { clearInterval(opened2); resolve({ sock, send }) } }, 20);
	});
}

(async () => {
	await new Promise((r) => poolSrv.listen(POOL_PORT, "127.0.0.1", r));
	await new Promise((r) => statsSrv.listen(STATS_PORT, "127.0.0.1", r));
	const child = spawn(process.execPath, [path.join(__dirname, "..", "bridge", "stratum-bridge.js"),
		"--bind", "127.0.0.1", "--port", String(PORT), "--cache-dir", DIR,
		"--pool", `127.0.0.1:${POOL_PORT}`, "--wallet", WALLET, "--stats-api", `http://127.0.0.1:${STATS_PORT}`],
		{ stdio: ["ignore", "pipe", "pipe"] });
	let log = "";
	console.error("bridge spusten, cekam na port");
	child.stdout.on("data", (c) => { log += c; });
	child.stderr.on("data", (c) => { log += c; });

	let failed = null;
	const c1 = await (async () => { for (let i = 0; i < 60; i++) { try { return await wsClient() } catch { await wait(100) } } })();
	const c2 = await wsClient();
	try {
		c1.send({ id: 1, jsonrpc: "2.0", method: "login", params: { login: WALLET, pass: "x", agent: "a" } });
		c2.send({ id: 1, jsonrpc: "2.0", method: "login", params: { login: WALLET, pass: "x", agent: "b" } });
		await wait(600);
		for (const c of [c1, c1, c1, c2]) {
			c.send({ id: 2, jsonrpc: "2.0", method: "submit", params: { id: "sess-1", job_id: "j1", nonce: "00000000", result: "00".repeat(32) } });
			await wait(120);
		}
		await wait(800);

		const d = await (await fetch(`http://127.0.0.1:${PORT}/api/stats`)).json();
		assert.equal(d.earn.acc24, 4, "4 prijate shares za 24 h");
		assert.ok(Math.abs(d.earn.xmrPerShare - 0.0005) < 1e-12, "XMR/share = (vyplaceno+nevyplaceno)/validShares");
		const byAgent = Object.fromEntries(d.clients.map((c) => [c.agent, c]));
		assert.equal(byAgent.a.acc24, 3);
		assert.equal(byAgent.b.acc24, 1);
		assert.equal(byAgent.b.rejected, 0);

		if (d.earn.czkPerShare != null && d.price != null && d.earn.usdCzk != null) {
			const cekane = byAgent.a.acc24 * d.earn.czkPerShare;
			assert.ok(Math.abs(byAgent.a.czk24 - cekane) < 1e-12, "Kc/24h = shares × Kc/share");
			assert.ok(Math.abs(d.earn.walletCzk24 - 4 * d.earn.czkPerShare) < 1e-12, "soucet za bridge");
			assert.ok(d.earn.czkPerShare > 0, "Kc/share je kladne");
		} else {
			console.log("pozn.: chybi zive kurzy, overena jen cast XMR/share (site)");
		}

		const html = await (await fetch(`http://127.0.0.1:${PORT}/`)).text();
		assert.match(html, /Kč\/24 h/, "dashboard ma sloupec s vydelkem");
		console.log("PASS: XMR/share, rozdeleni podle shares, Kč přepočet");
	} catch (e) {
		failed = e;
	} finally {
		try { c1.sock.destroy() } catch {}
		try { c2.sock.destroy() } catch {}
		child.kill();
		poolSrv.close();
		statsSrv.close();
		fs.rmSync(DIR, { recursive: true, force: true });
	}
	if (failed) {
		console.error("FAIL:", failed.message);
		console.error(log.split("\n").slice(-20).join("\n"));
		process.exit(1);
	}
	process.exit(0);
})();
