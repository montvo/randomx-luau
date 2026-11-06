# Bridge pro Roblox miner — kontejner pro verejny server.
# build:  docker build -t rx-bridge bridge/
# run:    docker run -d --restart=always -p 127.0.0.1:8790:8790 --name rx-bridge rx-bridge
# TLS/wss pred to postav Caddy (viz Caddyfile) nebo cloudflared tunelem.
FROM node:22-alpine

WORKDIR /app
COPY stratum-bridge.js ./

EXPOSE 8790
ENTRYPOINT ["node", "stratum-bridge.js", "--bind", "0.0.0.0", "--port", "8790"]
