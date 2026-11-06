# Bridge

WebSocket -> TCP most do poolu. Executor Robloxu neumi TCP, takze pres nej tece
prihlaseni, joby i shares. Nema zadne zavislosti (jen Node builtiny).

## Lokalne

```sh
node stratum-bridge.js                      # ws://127.0.0.1:8790
node stratum-bridge.js --port 9000 --pool gulf.moneroocean.stream:10128
node stratum-bridge.js --bind 0.0.0.0       # za reverzni proxy
```

## Verejne (jeden loadstring, uzivatel nic nema)

Potrebuje `wss://`. Dve cesty:

- **Cloudflare tunnel** (bez uctu, ale URL se meni pri restartu):

  ```sh
  cloudflared tunnel --url http://127.0.0.1:8790
  ```

  Vypisane `https://…trycloudflare.com` se v loaderu pouzije jako
  `wss://…trycloudflare.com/`.

- **Vlastni server s TLS** (stabilni URL): `docker build -t rx-bridge .` a
  `docker run -d --restart=always -p 127.0.0.1:8790:8790 rx-bridge`, pred tim
  Caddy s `Caddyfile` (doplnit domenu). Do loaderu patří `wss://<domena>/`.

Aktualne to bezi na Dokploy (152.53.160.54) jako `wss://rx-bridge.152.53.160.54.sslip.io/`.

## Provoz

- Jeden uzivatel = jedno WS spojeni = jedno TCP do poolu. Pool ma limity na IP.
- Kdo zna URL, muze most pouzit (tezi ale na svou penizenku).
- `getCache` nikam necachuje, kazdy klient si stavi vlastni cache.
