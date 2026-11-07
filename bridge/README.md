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

## Dashboard

Na `/` bezi prehled: kdo je pripojeny (`id`, IP, agent, vyska jobu, shares),
souhrn za vsechny klienty a cisla z pool API pro penizenku
(`--wallet`/`WALLET`, `--stats-api`/`STATS_API`). JSON je na `/api/stats`.

S `--wallet` (nebo env `WALLET`) bridge prepsise `login` kazdeho klienta, takze
vsechno tezi na jednu adresu; puvodni adresa klienta zustava v dashboardu.

### Odhad vydelku (Kc / 24 h)

Karty „vydělek 24 h (Kč)“, „výdělek 24 h / uživatel“ a sloupec „Kč/24 h“ v tabulce
pocitaji z pool API:

```
Kc/24h(klient) = prijate shares klienta za 24 h × XMR/share × XMR/USD × USD/CZK
XMR/share      = (amtPaid + amtDue) / validShares      (prumer za celou peněženku)
```

Proc se deli podle shares a ne podle hashrate: bridge od poolu dostava jen
`OK`/`Error` bez obtiznosti, takze per-share hashrate nema z ceho spocitat. Vsechno
ale jde pres jednu pool session, takze vardiff je pro vsechny klienty stejny a share
ma stejnou vahu. Kurz USD/CZK je z `api.frankfurter.app` (ECB, 10 min), XMR/USD
z CoinGecko (5 min), pool stats z `--stats-api` (1 min); kdyz neco chybi, dashboard
to vypise a Kč neukaze. Cislo je odhad, ne vyplata — meni se s kurzem i s tim, jak
pool zrovna prepocitava obtiznost.

## Provoz

- Jeden uzivatel = jedno WS spojeni = jedno TCP do poolu. Pool ma limity na IP.
- Kdo zna URL, muze most pouzit (tezi ale na svou penizenku).


## Sdilena cache (`/cache/<seed>/…`)

RandomX cache je 256 MB a je cista funkce seedu bloku — pocitat ji v kazdem
klientu je 83 % veskere prace klienta a 30 klientu tak dela 30× totéž. Bridge ji
proto drzi na disku a rozdalava:

| cesta | metoda | vysledek |
|---|---|---|
| `/cache/<seed>/meta` | GET | `{parts, partBytes, have[], complete}` |
| `/cache/<seed>/<0-15>` | GET | dil, `application/octet-stream` |
| `/cache/<seed>/<0-15>` | PUT | prijme dil (telo = presne 16 MB) |

Miner zkusi `/meta` jako prvni; kdyz je cache kompletni, stahne ji a Argon2
vubec nepusti. Kdyz ji ma z disku nebo ji postavi, chybejici dily nahraje zpet.

- `--cache-dir` (env `CACHE_DIR`), default `os.tmpdir()/rx-cache` — v kontejneru
  dej volume, jinak cache zmizi pri restartu.
- `--cache-keep N` (default 2) — kolik poslednich seedu drzet; starsi se maze.
  Jeden seed = 256 MB, takze pri 2 seedech pocitej s 512 MB disku.
- `--no-cache` — endpointy vypne, klienti budou pocitat sami.
- Klient cache nahrava jen kdyz ji bridge jeste nema; pozdejsi klienti preskoci.
- Pozadavky pres Caddy prochazi bez zmeny (`reverse_proxy` prenasi i PUT).
- Bez limitu na velikost tela to neni verejna sluzba: kdokoliv muze poslat 16 MB.
