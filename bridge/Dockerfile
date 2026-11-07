# Bridge pro Roblox miner — kontejner pro verejny server.
# build:  docker build -t rx-bridge bridge/
# run:    docker run -d --restart=always -p 127.0.0.1:8790:8790 --name rx-bridge rx-bridge
# TLS/wss pred to postav Caddy (viz Caddyfile) nebo cloudflared tunelem.
FROM node:22-alpine

WORKDIR /app
COPY stratum-bridge.js ./

EXPOSE 8790
# sdilena cache (256 MB na seed) — dej sem volume, at prezije restart
ENV CACHE_DIR=/cache
VOLUME ["/cache"]
# pool se da prebit pres --pool (env WALLET/STATS_API); druhy --pool je zalozni
ENTRYPOINT ["node", "stratum-bridge.js", "--bind", "0.0.0.0", "--port", "8790", "--cache-dir", "/cache", \
            "--pool", "gulf.moneroocean.stream:10128", "--pool", "xmr-eu1.nanopool.org:14444"]
