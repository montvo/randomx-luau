# RandomX v1 (rx/0) v Luau — port a stav práce

Stav k **2026-11-06**. Dokument popisuje, co je hotové, jak se to testovalo, co ještě
chybí a jak navázat. Kód je v `scratch/randomx-luau/` (pracovní kopie `/tmp/rx/luau`).

## 1. Proč to existuje

Cíl: miner v Roblox executoru, který posílá **reálné shares** do XMR poolu.

- Executor (`OpiumwareMac`, `XxSkullyMaxX`) **neumí TCP**, umí ale `WebSocket`.
  → share komunikace jde přes lokální node bridge (`ws://127.0.0.1:8790` → pool TCP).
- MoneroOcean už cn-pico nenabízí, `gulf.moneroocean.stream:10001/10002/10004/10008/10016/10128`
  i `pool.supportxmr.com:3333` a `70.34.214.138:3333` vrací `algo=rx/0` a 76bajtový blob.
  → **RandomX musí běžet v Luau.**

Port je proto rozdělený na dvě vrstvy: nejdřív ověřit každou primitivu proti Pythonu/C,
teprve pak skládat VM. Postup je zdokumentovaný níže (sekce 6) a je to jediná cesta,
jak v 1bitové divergenci najít bug.

## 2. Co je hotové (zelené)

| Modul | Test | Výsledek |
|---|---|---|
| `blake2b.lua` | 164 vektorů z reference + 300 fuzz | vše prošlo |
| `aes.lua` (AES-128 / gen1R / gen4R / hash1R) | FIPS-197 + spec vektor | ALL TESTS PASSED |
| `argon2.lua` (cache init, 2 MiB) | 16/16 proti `cache_ref.txt` | PASS |
| `superscalar.lua` (generátor programů) | 10/10 program hashů | 12 passed, 0 failed |
| 64bit aritmetika (`mul64lo`, `mul64hi`, `smulh`, `add64`, `shl64`, `rotr`) | vs Python big-int | 0 neshod |
| `reciprocal()` | 60 náhodných dělitelů vs Python | 0 neshod |
| FADD/FSUB/FMUL/FDIV/FSQRT vč. softwarového zaokrouhlení | trace vs C | shoda bit po bitu |
| `decodeWords` (překlad 256 instrukcí) | trace vs C bytecode | shoda |
| `execProgram` (celý program, 256 pc) | trace r/f/e per-pc vs C | shoda |
| Scratchpad fill, sp0/sp1 odvození, dataset read, store zpět | hash scratchpadu vs C | shoda |
| Iterace 1–8 jednoho chainu | per-iter hash scratchpadu vs C | shoda |
| Celý chain 1–8 × 2048 iterací | `rg:` hash registrového souboru po každé iteraci vs C | **16 384/16 384 shod** |
| `t_rx.lua` na obou oficiálních vektorech | `test key 000`/`This is a test`, `key=00`/16 nul | **PASS** |

Naměřeno: nativní `luau` CLI ~167 kH/s (8 vláken), v Robloxu ~9 600 H/s se 2 workery,
cache fill 36 s, jeden celý hash (8 × 2048 iterací + finále) 7,2 s.

## 3. Co zbývá

Hash je hotový: `t_rx.lua` vrací `PASS` na obou oficiálních vektorech a celý běh
(8 chainů × 2048 iterací) má po každé iteraci shodný registrový soubor s C referencí.
Zbývá:

1. Napojení na executor skript (login přes bridge, nonce scan, submit) a otestování
   proti poolu.
2. Výkon: 7,2 s/hash znamená ~0,5 kH/s na vlákno — potřeba worker pool, time-slicing
   a UI.
3. `tests/t_mul.lua` spadne bez argumentů (`attempt to index nil with 'sub'`),
   `t_rcp`/`t_add`/`t_sq` jen vypisují hodnoty bez PASS/FAIL.

### Jak se divergence hledala (postup zůstává použitelný)

`t_rg.lua` + `rg:` tisk v `trace.cpp` tisknou raw 256 bajtů stavu po každé iteraci.
`t_rg2`/`t_rg8` jsou totéž s pevným počtem chainů/iterací, `t_blob.lua` porovnává
program chainu, `t_pc.lua` + `M.tracePC` dělá per-pc trace srovnání:

```sh
cd /tmp/rx/rxsrc && ./trace_dbg 00 00000000000000000000000000000000 8 2048 | grep "^rg:" > /tmp/crg.txt
cd diagnostics && luau t_rg8.lua 2>&1 | grep "^rg:" > /tmp/lrg.txt
python3 -c '
c=[l.strip() for l in open("/tmp/crg.txt")]; l=[l.strip() for l in open("/tmp/lrg.txt")]
bad=[i for i,(a,b) in enumerate(zip(c,l)) if a!=b]
print("first diff", bad[0]+1 if bad else None, "count", len(bad))
'
```

Pak tutéž iteraci rozebrat per-pc trace (sekce 6.3).

## 4. Architektura portu

`rx.lua` (605 řádků) má v sobě:

- 64bitové hodnoty jako dvojice 32bit `lo`/`hi` (bez `bit64` knihovny).
- `mulLimbs` — 8×16bit násobení, jediný zdroj pravdy pro `mul64lo`, `mul64hi`, `smulh`.
- `decodeWords(words)` → `K, D, S, MU, ILO, IHI, TGT, MASK, ZEROBASE`, 1-based indexy,
  masky L1/L2/L3, `zeroBase`, CBRANCH imm/mask, `StoreL3Condition = 14`.
- `runSuperscalar`, `datasetItem` (`DST_CONST`, reciproké násobení).
- `execProgram` — celý interpreter vč. per-instruction `hook` pro trace.
- `hash(blake, aes, ss, cache, key, input)` — hlavička, chain loop, finální AES+blake2b.
- Debug háčky: `M.traceSp` (hash scratchpadu), `M.traceReg`, `M.traceRF`,
  `M._chains` / `M._iters` (zkrácení běhu).

Klíčové konstanty a tvary převzaté z reference (bez nich se port neshoduje):

- `InstructionType`: IMUL_RCP 10, FSWAP_R 17, FADD_R 18, FADD_M 19, FSUB_R 20, FSUB_M 21,
  FSCAL_R 22, FMUL_R 23, FDIV_M 24, FSQRT_R 25, CBRANCH 26, CFROUND 27, ISTORE 28, NOP 29.
- `RegisterNeedsDisplacement = 5` (v 1-based Luau `d == 6`) pro IADD_RS.
- CBRANCH: `b = rshift(mod,4) + ConditionOffset`,
  `imm = band(bor(ilo, lshift(1,b)), bnot(lshift(1, b-1)))`,
  cíl `pc = TGT[pc]` (loop si `pc` sám inkrementuje), skok jen když `band(r[dst], MASK) == 0`.
- `registerUsage` (zdroj `TGT`): zapisuje jen skutečný zápis registru. Nezapisují
  FSWAP_R..FSQRT_R, CFROUND, ISTORE ani NOP; ISWAP_R zapisuje oba registry jen když
  `s ~= d`; IMUL_RCP jen když dělitel není mocnina dvou.
- `CacheLineAlignMask = (DATASET_BASE_SIZE - 1) & ~63 = 0x7FFFFFC0`.
- `nreg.r` se nuluje **na začátku každého chainu**, ne jednou pro celý hash.
- FSWAP přehazuje **lane v registru** (`_mm_shuffle_pd(a,a,1)`), ne registry.
- FSCAL xoruje masku `0x80F0000000000000` do obou lane.
- `eMask` = `getStaticExponent`: `expo = bor(0x300, lshift(band(rshift(hi,28),0xF),4))`
  (`staticExponentBits = 64 - 32 - dynamicExponentBits`, `constExponentBits = 0x300`,
  žádný clamp na 2047).
- Načtení `e`/`f`/`FMUL_M`/`FDIV_M`: dvakrát `int32 → double` (po 4 bajtech), pak
  maska exponentu/mantisy pro `e`. Načíst `int64` je špatně.
- `smulh`: negovat vstupy, `mulLimbs`, low/high 128 bitů, +1 do `q` jen když `p != 0`,
  negovat výsledek.

## 5. Transport a pool

- `scratch/randomx-luau/stratum-bridge.js` — node (`ws` z `roblox-executor-mcp/node_modules`),
  poslouchá `ws://127.0.0.1:8790`, řádky přeposílá do pool TCP.
- Login: `{"id":N,"jsonrpc":"2.0","method":"login","params":{"login":WALLET,"pass":"x","agent":"…"}}`
  → `result.job.{blob,seed_hash,target,height,job_id}`, `result.id`.
- Submit: `method:"submit"`, `params:{id, job_id, nonce, result}`.
- Target je 4bajtový; pro porovnání se rozšiřuje
  `target64 = 0xFFFFFFFFFFFFFFFF / (0xFFFFFFFF / t32)` a hash se čte jako LE u64.
- Peněženka: `42ypgDkEvE1VQSLfXwQffKBF7L5vETygtfvaynG9nW8W7crvsrGv4ziAAmTppDkedKSdz9iAKM7f5gBwZpnNviY81ACgjhw`.
- Naměřeno v executoru (XxSkullyMaxX): login, keepalived i submit projdou; pool na
  submit odpovídá a při `Block outdated` spojení zavře.
- `pool.moneroocean.stream` občas padá na DNS (`ENOTFOUND`), `gulf.moneroocean.stream`
  funguje; po reconnect stormu pool na chvíli přestane odpovídat → v mineru je
  exponenciální backoff (5 s → 60 s).
- Blok sem chodí ~40 s, takže share spočítaný o 3 bloky později skončí jako
  `Block outdated`. Proto je potřeba zrychlit cache init (v Robloxu 130 s) i hash
  (~18 s) — to je hlavní další práce.

## 6. Metodika ladění (jak se to dělalo a jak pokračovat)

1. Každou primitivu nejdřív proti Pythonu (`t_mul.lua`, `t_rcp.lua`, `t_sq.lua`).
   Odhalilo to chybu v `mul64lo` (carry) i v `reciprocal` (shift 64 → 32).
2. C reference: `tevador/RandomX` v `/tmp/rx/rxsrc`, `librandomx.a`, `trace.cpp` dědí
   z `InterpretedVm` a vypisuje stav po každé instrukci.
3. Spuštění: `luau t_trace.lua -a 00 0000…` vs `./trace 00 0000… 1 1`, diff po polích
   (`pc`, `r`, `f`, `e`). Dokud se jedna iterace neshoduje, nic dalšího nemá smysl.
4. Pomocné dumpy: `sp:` (blake2b celého scratchpadu před store zpět), `CH<n>` (hash
   64KiB bloku), `POSTIT`, `FILL0`, `FSTORE`, `SPB`.
5. Pozor na pozorovací body: C tiskne `sp:` a `f2/e2` **před** dataset readem a store zpět,
   takže Luau musí tisknout na stejných místech, jinak se porovnávají různé stavy.

## 7. Odchylky nástrojů (šetří čas)

- `luau` CLI nemá `io` ani `writefile`; `require` potřebuje `./`.
- `blake2b(data, n)` s jiným `n` dá jiný prefix (délka je v parametrech) — pro srovnání
  s C `blake2b(h, 4, …)` je potřeba `blake2b(str, 4)`, ne prvních 4 bajtů z 32.
- `clang++` na arm64 Macu: `xmmintrin.h` v `trace.cpp` odstranit.
- `sed -i ''`, žádné GNU `sed`.
- `string.format("%x", f2b(x))` neexpanduje vícenásobný return, pokud není poslední.

## 8. Bugy nalezené a opravené v poslední fázi

1. `trace` harness: `tostring(K[pc])` (nil concat) — trace se vůbec nespustil.
2. IADD_RS displacement: `d == 5` → `d == 6`.
3. `smulh`: chybná post-negace s `h2 + 1` → korektní negace vstupů a `q += (p != 0)`.
4. `reciprocal`: `shift = 64` → `32`.
5. `b2f`: zápis `hi` na offset 8 → 4.
6. FADD/FSUB zaokrouhlení: `stepUp`/`stepDown` s normalizací `hi >= W` / `hi < 0`.
7. FSQRT/nezaokrouhlené zbytky: `err` počítaný jako `x - s*s` (katastrofální krácení)
   → `TwoProd` (`prodErr`) a `err = (x - p) - prodErr`.
8. FSWAP zpět na přehození lane v registru.
9. `eMask` na reálný `getStaticExponent` tvar.
10. CBRANCH: maska imm, `rshift(mod,4)`, cíl `+1`.
11. Loady `e`: přes `f2b`/`b2f` + masky.
12. `MASK` u ISTORE: `kind == 29` omylem v integer větvi → vlastní pravidlo
    (`StoreL3Condition`), plus správné `L3Mask`.
13. Store zpět XORuje `f` s `e` jen v nízké lane → doplněna i vysoká lane
    (`fhi[i] = b2f(...)`), předtím se zahazovala.
14. Chybějící zápis `regFile` v `trace.cpp` (chain přechod).
15. Špatná místa tisků v harnessech (`sp:`, `rg:` před vs. po store zpět).
16. `CacheLineAlignMask = 0xFFFFFFC0` → `0x7FFFFFC0` (light VM maskuje jen base size).
17. `eMask` se odvozoval z `hi >> 27 & 0x1F` a clampoval na 2047 → `hi >> 28 & 0xF`
    bez clampu (viz sekce 4).
18. CBRANCH skákal na `TGT[pc] + 1` (o instrukci dál) → `TGT[pc]`.
19. `nreg.r` se nulovalo jen před prvním chainem → nuluje se v každém chainu.
20. `registerUsage` se aktualizoval i pro CFROUND, ISTORE a NOP → vyřazeny
    (CFROUND `28`, ISTORE `29`, NOP `30`).

## 9. Soubory

`scratch/randomx-luau/`

- moduly: `rx.lua`, `blake2b.lua`, `aes.lua`, `argon2.lua`, `superscalar.lua`
- testy: `t_rx.lua` (oficiální vektory), `t_trace.lua` (per-pc diff), `t_mul.lua`,
  `t_rcp.lua`, `t_add.lua`, `t_sq.lua`
- hash/chain diagnostika: `t_rg.lua`, `t_rg2.lua`, `t_rg8.lua`, `t_rf.lua`, `t_sp.lua`,
  `t_blob.lua`, `t_pc.lua`, `t_dbg.lua`
- C strana: `trace.cpp` (do klonu `tevador/RandomX`, build `librandomx.a`)
- transport: `stratum-bridge.js`

## 10. Navazující kroky

1. Napojit `rx.hash` do executor skriptu: login přes bridge, nonce scan, submit;
   znovu otestovat throttling poolu.
2. Výkon: worker pool, time-slicing, UI (7,2 s/hash je na reálné těžení pomalé).
3. Dočistit testy (`t_mul` bez argumentů, PASS/FAIL u primitivních testů).

## 11. Distribuce (loader + bridge)

- `miner/loader.lua` stahuje `miner.lua` z catboxu a predava `MINER_CFG`; po kazdem
  rebuildu je potreba `miner.lua` znovu nahrat a URL prebakedovat.
- `bridge/install.sh|.command|.cmd` stahnou bridge do `~/.rx-bridge` a spusti ho.
- Bridge je bez zavislosti (vlastni WS handshake nad `node:net`); modul `ws` je
  nahrazen, protoze na cizich strojich neni.
- Handshake musi byt vlastni: Opiumware na prvni spojeni neposle nic, co by
  proslo `ws` serverem, a `syn.websocket.connect` blokuje do dokonceni handshake.
- Executor ma maly limit soucasnych websocketu; kdyz zustanou viset stare
  instance, dalsi `syn.websocket.connect` se uz nevrati. Reseni: rejoin.

## 12. Hosting bridge na serveru (Dokploy)

Bridge bezi na `152.53.160.54` v Dokploy (projekt `rx-bridge`, aplikace `bridge`,
zdroj = git `montvo/randomx-luau` branch `master`, Dockerfile `bridge/Dockerfile`,
context `bridge`). Verejna adresa je
`wss://rx-bridge.152.53.160.54.sslip.io/` (sslip.io resolvuje na IP, certifikat
resi Traefik/Let's Encrypt, port 8790 zustava jen ve vnitrni siti).

Redeploy = push do `master` a `POST /api/application.deploy` s hlavickou
`x-api-key` (nebo zapnout autoDeploy). Loader ma tuhle URL zapečenou jako primarni.

Bridge multiplexuje vsechny klienty do jednoho pool spojeni (pool vidi 1 IP,
`--pool` lze zadat vicekrat jako zalozni seznam). Na `/` je dashboard (pripojeni klienti, souhrn shares, cisla z pool API
pro vynucenou penizenku) a `/api/stats` s JSONem. Penizenka se vynucuje pres env
`WALLET` (login klienta se prepise). Bezny GET vraci dashboard/200, WS handshake
jde jen po `Upgrade: websocket`.
