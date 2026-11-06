// stratum <-> websocket bridge pro Roblox miner (bez zavislosti, jen Node builtiny)
// usage: node bridge/stratum-bridge.js [--port 8790] [--pool gulf.moneroocean.stream:10128] [--bind 127.0.0.1]
const crypto = require("node:crypto");
const net = require("node:net");

const args = process.argv.slice(2);
const getArg = (name, def) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : def;
};
const LISTEN = Number(getArg("--port", "8790"));
const BIND = getArg("--bind", "127.0.0.1");
const POOL = getArg("--pool", "gulf.moneroocean.stream:10128");
const POOL_HOST = POOL.slice(0, POOL.lastIndexOf(":"));
const POOL_PORT = Number(POOL.slice(POOL.lastIndexOf(":") + 1));

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ── minimalni websocket ────────────────────────────────────────────────────────
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

// vraci pole payloadu; pri chybe/close null
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
			if (opcode === 0x9) onMessage(null, payload); // ping -> pong resime u klienta
			else if (fin) onMessage(payload.toString("utf8"));
		}
	};
}

function onConnection(socket) {
	socket.on("error", (e) => log("ws error", e.message));
	let head = Buffer.alloc(0);
	let open = false;

	const send = (text) => {
		try {
			socket.write(encodeFrame(text));
		} catch {}
	};

	let tcp = null;
	const parse = createParser(
		(text) => {
			if (text === null) return; // ping
			log("ws->pool:", text.slice(0, 200));
			if (tcp && tcp.writable) tcp.write(text.replace(/\n*$/, "\n"));
		},
		() => {
			log("ws client gone");
			if (tcp) tcp.end();
			socket.destroy();
		},
	);

	socket.on("data", (chunk) => {
		if (open) return parse(chunk);
		head = Buffer.concat([head, chunk]);
		const end = head.indexOf("\r\n\r\n");
		if (end < 0) return;
		const request = head.subarray(0, end).toString("latin1");
		const rest = head.subarray(end + 4);
		const key = /sec-websocket-key:\s*(\S+)/i.exec(request)?.[1];
		log("ws client connected" + (key ? "" : " (bez key)"));
		if (!key) log("handshake:", request.split("\r\n")[0]);
		const accept = crypto.createHash("sha1").update((key || "") + WS_GUID).digest("base64");
		socket.write(
			"HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			`Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
		);
		open = true;

		tcp = net.connect(POOL_PORT, POOL_HOST);
		tcp.setNoDelay(true);
		let tcpBuf = "";
		tcp.on("connect", () => log("tcp up ->", POOL));
		tcp.on("data", (d) => {
			tcpBuf += d.toString("utf8");
			let idx;
			while ((idx = tcpBuf.indexOf("\n")) >= 0) {
				const line = tcpBuf.slice(0, idx);
				tcpBuf = tcpBuf.slice(idx + 1);
				if (line.trim()) {
					log("pool:", line.slice(0, 200));
					send(line);
				}
			}
		});
		tcp.on("error", (e) => {
			log("tcp error", e.message);
			send(JSON.stringify({ __bridge: "tcp_error", message: e.message }));
		});
		tcp.on("close", () => {
			log("tcp closed");
			try {
				socket.end();
			} catch {}
		});

		if (rest.length) parse(rest);
	});

	socket.on("close", () => {
		if (open) log("ws client gone");
		if (tcp) tcp.end();
	});
}

const server = net.createServer(onConnection);

server.listen(LISTEN, BIND, () => log(`bridge listening on ws://${BIND}:${LISTEN} ->`, POOL));
