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

2. Do executoru vlozit `miner/loader.lua` (nebo jen
   `loadstring(game:HttpGet("<url>"))()`).

3. Zastavit: `_G.MINER_STOP = true`. Vlastni penizenka:
   `MINER_CFG = { wallet = "..." }` pred loaderem.

Pozor: jeden hash trva v Robloxu ~18 s (plus ~130 s init cache), blok chodi ~40 s —
share proto casto skonci jako `Block outdated`. Executor ma taky maly limit
soucasnych websocketu: kdyz zustanou viset stare instance, dalsi pripojeni se
nevrati — pomuze rejoin.

je generovaný — upravuj `miner/main.lua` nebo `src/`, pak `python3
tools/bundle.py` (staví i `miner.test.lua` pro `tests/t_miner.lua`).

## Spuštění

```sh
cd tests
luau t_rx.lua -a 00 00000000000000000000000000000000 19041669a22e3d48a25741aa92fdc5289204170ec778edb8d42c31a4b42c04d7
luau t_trace.lua -a 00 00000000000000000000000000000000
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
