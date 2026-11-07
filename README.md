# randomx-luau

Port [RandomX](https://github.com/tevador/RandomX) v1 (`rx/0`) do Luau, aby se v Roblox
executoru dalo těžit Monero bez nativní knihovny.

Stav: **hash se shoduje s C referencí bit po bitu** — všech 8 chainů × 2048 iterací
(`rg` srovnání stavu po každé iteraci) i oba oficiální vektory (`test key 000` /
`This is a test`) dávají `PASS`. Metodika, nálezy a seznam opravených bugů:
[`docs/RANDOMX-LUAU.md`](docs/RANDOMX-LUAU.md).

## Struktura

- `src/` — `rx.lua` (VM: decode, exec, hash) a kryptoprimitivy (`blake2b`, `aes`, `argon2`, `superscalar`)
- `tests/` — vektory a per-primitiva testy (`t_rx`, `t_trace`, `t_mul`, `t_rcp`, `t_add`, `t_sq`)
- `diagnostics/` — hash stavu po iteraci, trace a zkracování běhu (`t_rg`, `t_rg2`, `t_rg8`, `t_rf`, `t_sp`, `t_blob`, `t_pc`, `t_dbg`)
- `c-ref/` — `trace.cpp`, protistrana pro `tevador/RandomX` (`librandomx.a`)
- `bridge/` — `stratum-bridge.js`, WebSocket → pool TCP pro reálné shares
- `miner/` — `main.lua` (miner logika) + `entry.lua`; `tools/bundle.py` z toho staví
  jednosouborový `miner.lua` pro executor

## Tezba

Nejjednodussi cesta: bridge bezet na serveru s `wss://` (viz `bridge/README.md`),
do loaderu dat jeho URL a uzivateli poslat jen jeden loadstring. Nic lokalne
stahovat nemusi.

Pro sebe i pro druhe lidi je pripraveny `miner/loader.lua`: stahne aktualni miner,
nastavi penizenku a spusti ho. Potrebuje ale lokalne bezici bridge, protoze
executor neumi TCP.

1. Bridge (jednou, na stroji s Node.js):

   - macOS: dvojklik na `bridge/install.command`
   - Linux: `sh bridge/install.sh`
   - Windows: `bridge/install.cmd`
   - nebo rucne: `node bridge/stratum-bridge.js`

   Bridge nema zavislosti (jen Node builtiny), stahne se sam a bezi na
   `ws://127.0.0.1:8790`. Okno nechat otevrene.

2. Do executoru vlozit `miner/loader.lua`, nebo jen odkaz:

   ```lua
   loadstring(game:HttpGet("https://files.catbox.moe/kiz8k0.lua"))()
   ```

3. Zastavit: `_G.MINER_STOP = true`. Vlastni penizenka:
   `MINER_CFG = { wallet = "..." }` pred loaderem.

### Sdilena cache

Nejdriv se stavi 256 MB Argon2 cache z seedu bloku — a to je 83 % veskere prace
klienta. Je to cista funkce seedu, takze ji pocitat v kazdem klientu je 30x ta
sama prace. Bridge ji proto drzi a rozdalava pres `/cache/<seed>/…`: kdo ji ma,
stahne 16 dilu nativnim HTTP (nezere Luau CPU), kdo ji postavi, chybejici dily
nahraje. Pri 10 % duty to je rozdil mezi "cache se nikdy nestihne" a "hash bezi
skoro hned" — a bridge pri 30 klientech usetri ~17 minut CPU na blok.

Vypnout se to da na klientu (`MINER_CFG = { uploadCache = false }` nebo
`cacheUrl = false`) i na bridge (`--no-cache`). Dve instance bez sdilene cache
maji kazda svou.

Zatez CPU ridi jediny knob `duty` (default `0.10` = 10 % jadra):

```lua
MINER_CFG = { duty = 0.10 } -- 0.02 .. 1
```

nebo `_G.RX_DUTY = 0.10`. Pacing je token bucket: prace stoji budget, spanek ho
doplnuje, takze CPU drzi na cili i pri vypadcich frameratu; kazdych 20 s se do
logu pise dosazene `duty` a H/s, aby se dalo overit, ze to opravdu sedi.

Kolik to realne vynese: pool posila target `00022f3`, tedy share padne v prumeru
na ~480 000 hashu. Pri ~18 s/hash to je radove 100 dni na plny vykon a ~2,7 roku
na 10 %. Na 10 % miner bezi, ale share v rozumne dobe neuvidis -- 10 % je "nic
nepoznat pri hre", ne vydelek. Chces-li share, jdi na duty 0.5 nebo 1; chces-li
60 FPS bez skubani, nech 0.10 nebo uber.

Cena za 10 %: hash ~18 s -> ~180 s, stavba cache ~130 s (jen kdyz ji nema bridge
ani disk) a share skoro vzdy dorazi po dalsim bloku, takze ho pool zahodi jako
`Block outdated`.

Pozor: jeden hash trva pri 10 % ~180 s, blok chodi ~40 s —
share proto casto skonci jako `Block outdated`. `MINER_STOP` se vyhodnocuje i
behem hashe, ale hash se nedá přerušit — při 10 % to tedy trvá až ~3 min, než se
miner zastavi (loader na to ceka, dokud nedobehne). Executor ma taky maly limit
soucasnych websocketu: kdyz zustanou viset stare instance, dalsi pripojeni se
nevrati — pomuze rejoin.

je generovaný — upravuj `miner/main.lua` nebo `src/`, pak `python3
tools/bundle.py` (staví i `miner.test.lua` pro `tests/t_miner.lua`).

## Spuštění

```sh
cd tests
luau t_rx.lua -a 00 00000000000000000000000000000000 19041669a22e3d48a25741aa92fdc5289204170ec778edb8d42c31a4b42c04d7
luau t_trace.lua -a 00 00000000000000000000000000000000
luau t_miner.lua   # integrace: login, job, hash, submit
luau t_pace.lua    # duty throttle: cil 10 %, clamping, duty=1 nespi
luau t_cache.lua   # sdilena cache: stazeni z bridge, upload po vlastni stavbe
```

C strana:

```sh
git clone https://github.com/tevador/RandomX && cd RandomX
cp ../c-ref/trace.cpp .
sed -i '' '/xmmintrin.h/d' trace.cpp   # arm64 macOS
mkdir build && cd build && cmake .. && make randomx
cd .. && clang++ -O2 -std=c++17 -I src trace.cpp build/librandomx.a -o trace
./trace 00 00000000000000000000000000000000 1 8
```

## Poznámky k nástrojům

Pro trace build raději `clang++ -O0 -g` (binárka `trace_dbg`): `-O2` build padá na
`SIGBUS` při tisku `double`/`e` hodnot (nealignované 16bajtové vektory na stacku),
`-O0` je deterministický a dojde do konce.

`luau` CLI nemá `io` ani `writefile`; `blake2b(data, n)` s jiným `n` vrací jiný prefix
(délka je součástí parametrů), takže srovnání s C `blake2b(h, 4, …)` vyžaduje `n = 4`.
