// stratum <-> websocket bridge for the Roblox miner
// usage: node stratum-bridge.js [--port 8790] [--pool pool.moneroocean.stream:10001]
// `ws` musi byt nainstalovany: npm i ws (nebo pouzij existujici instalaci)
const { WebSocketServer } = (() => {
	for (const id of ["ws", "/Users/adamcejpa/Documents/GitHub/roblox-executor-mcp/node_modules/ws"]) {
		try {
			return require(id);
		} catch {}
	}
	console.error("chybi modul 'ws' — spust 'npm i ws' v tomhle adresari");
	process.exit(1);
})();
const net = require("node:net");

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};
const LISTEN = Number(getArg("--port", "8790"));
const POOL = getArg("--pool", "pool.moneroocean.stream:10001");
const [POOL_HOST, POOL_PORT] = POOL.split(":");

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

const wss = new WebSocketServer({ port: LISTEN, host: "127.0.0.1" });

wss.on("connection", (ws) => {
  log("ws client connected");
  const tcp = net.connect(Number(POOL_PORT), POOL_HOST);
  tcp.setNoDelay(true);
  let tcpBuf = "";

  tcp.on("connect", () => log("tcp up ->", POOL));
  tcp.on("data", (chunk) => {
    tcpBuf += chunk.toString("utf8");
    let idx;
    while ((idx = tcpBuf.indexOf("\n")) >= 0) {
      const line = tcpBuf.slice(0, idx);
      tcpBuf = tcpBuf.slice(idx + 1);
      if (line.trim()) {
        log("pool:", line.slice(0, 200));
        if (ws.readyState === 1) ws.send(line);
      }
    }
  });
  tcp.on("error", (e) => {
    log("tcp error", e.message);
    if (ws.readyState === 1) ws.send(JSON.stringify({ __bridge: "tcp_error", message: e.message }));
  });
  tcp.on("close", () => {
    log("tcp closed");
    try { ws.close(); } catch {}
  });

  ws.on("message", (raw) => {
    const text = raw.toString("utf8");
    log("ws->pool:", text.slice(0, 200));
    if (tcp.writable) tcp.write(text.replace(/\n*$/, "\n"));
  });
  ws.on("close", () => {
    log("ws client gone");
    try { tcp.end(); } catch {}
  });
  ws.on("error", (e) => log("ws error", e.message));
});

log("bridge listening on ws://127.0.0.1:" + LISTEN, "->", POOL);
