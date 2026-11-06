# randomx-luau

Port [RandomX](https://github.com/tevador/RandomX) v1 (`rx/0`) do Luau, aby se v Roblox
executoru dalo těžit Monero bez nativní knihovny.

Stav: primitivy ověřené proti Pythonu a C referenci, prvních 8 iterací VM chainu bit po
bitu shodných s C, finální hash oficiálního vektoru ještě `FAIL`. Podrobnosti, metodika
a seznam opravených bugů: [`docs/RANDOMX-LUAU.md`](docs/RANDOMX-LUAU.md).

## Struktura

- `src/` — `rx.lua` (VM: decode, exec, hash) a kryptoprimitivy (`blake2b`, `aes`, `argon2`, `superscalar`)
- `tests/` — vektory a per-primitiva testy (`t_rx`, `t_trace`, `t_mul`, `t_rcp`, `t_add`, `t_sq`)
- `diagnostics/` — hash stavu po iteraci, trace a zkracování běhu (`t_rg`, `t_rf`, `t_sp`, `t_dbg`)
- `c-ref/` — `trace.cpp`, protistrana pro `tevador/RandomX` (`librandomx.a`)
- `bridge/` — `stratum-bridge.js`, WebSocket → pool TCP pro reálné shares

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

`luau` CLI nemá `io` ani `writefile`; `blake2b(data, n)` s jiným `n` vrací jiný prefix
(délka je součástí parametrů), takže srovnání s C `blake2b(h, 4, …)` vyžaduje `n = 4`.
