-- RandomX (rx/0) miner pro Roblox executor — stahovaci obal.
-- Vloz do executoru; stahne a spusti aktualni miner.
-- Zastaveni: _G.MINER_STOP = true

local WALLET = "42ypgDkEvE1VQSLfXwQffKBF7L5vETygtfvaynG9nW8W7crvsrGv4ziAAmTppDkedKSdz9iAKM7f5gBwZpnNviY81ACgjhw"
local MINER_URL = "https://files.catbox.moe/48icr5.lua"
local BRIDGE = "ws://127.0.0.1:8790"

local function fetch(url)
	local req = request or http_request or syn and syn.request
	if req then
		local ok, res = pcall(req, { Url = url, Method = "GET" })
		if ok and res and (res.StatusCode == 200 or res.status == 200) then
			return res.Body or res.body
		end
	end
	return game:HttpGet(url)
end

local function log(...)
	print("[loader]", ...)
end

if rawget(_G, "MINER_RUNNING") then
	log("miner uz bezi, ukoncuji ho a startuji znovu")
	_G.MINER_STOP = true
	task.wait(2)
end

log("stahuji miner…")
local src = fetch(MINER_URL)
if type(src) ~= "string" or #src < 100000 then
	error("miner se nestahl (odpoved " .. tostring(src and #src) .. " B)")
end
log(string.format("stazeno %d B", #src))

local env = getgenv and getgenv() or _G
-- cizi nastaveni (MINER_CFG = {...} pred timhle skriptem) ma prednost
local cfg = rawget(env, "MINER_CFG") or {}
cfg.wallet = cfg.wallet or rawget(env, "RX_WALLET") or WALLET
cfg.bridge = cfg.bridge or BRIDGE
cfg.slicePcs = cfg.slicePcs or 1024
env.MINER_CFG = cfg
env.MINER_RUNNING = true

local fn = assert((loadstring or env.loadstring)(src), "miner se nepodarilo zkompilovat")
local ok, err = pcall(fn)
env.MINER_RUNNING = false
if not ok then
	log("koncim s chybou: " .. tostring(err))
else
	log("miner dobehl")
end
