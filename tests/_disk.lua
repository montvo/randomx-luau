--!nocheck
-- docasny test: cesta pres souborovou cache (in-memory stubs)
local files = {}
local M = require("../miner.test")

local BLOB = "1010ef88b9d70612bedf6dd26440e34db153641376b2ca477abe933089476383faa665c6ac2ef1000000008a69bf09bb51105c089aedc53b531327822ba847b3d70daa3bc257ade8e2085123"
local SEED = "3c84566822d6a64abefa07e2980e99299f24440643e8a77201adb196604b1832"
local sent = {}
local ws
ws = {
	OnMessage = { Connect = function(self, fn) ws._onmsg = fn end },
	OnClose = { Connect = function(self, fn) ws._onclose = fn end },
	Send = function(self, p) table.insert(sent, p) end,
	Close = function() end,
}
local function decode(s)
	local t = {}
	t.method = s:match('"method":"([%w_.]+)"')
	local p = s:match('"params":(%b{})')
	if p then
		t.params = {}
		for k, v in p:gmatch('"([%w_]+)":"([^"]*)"') do t.params[k] = v end
		for k, v in p:gmatch('"([%w_]+)":(%d+)') do t.params[k] = tonumber(v) end
	end
	return t
end

local logins = 0
local cfg = {
	bridge = "ws://mock", chains = 1, iters = 4, maxHashes = 1, testShares = true,
	connect = function() return ws end,
	decode = decode,
	wait = function()
		if logins < 2 and #sent > 0 and sent[#sent]:find('"method":"login"') then
			logins = logins + 1
			ws._onmsg('{"jsonrpc":"2.0","method":"job","params":{' ..
				string.format('"blob":"%s","algo":"rx/0","height":1,"seed_hash":"%s","job_id":"j1","target":"ffffffff"}', BLOB, SEED) .. '}}')
		end
	end,
	readFile = function(p) return files[p] end,
	writeFile = function(p, d) files[p] = d end,
	fileExists = function(p) return files[p] ~= nil end,
	listFiles = function() local t = {} for k in pairs(files) do t[#t + 1] = k end return t end,
	deleteFile = function(p) files[p] = nil end,
}

-- 1. bez cache: postavi se a ulozi
math.randomseed(1)
print("--- bez cache")
local r1 = M.run(cfg)
local n = 0
for k in pairs(files) do if k:find("^rx_cache_") then n = n + 1 end end
print("casti cache:", n)
assert(n == 16, "cache se neulozila")

-- 2. s cache na "disku"
print("--- s cache")
table.clear(sent)
logins = 0
local r2 = M.run(cfg)
assert(r2.shares >= 1, "druhy beh nic neposlal")
print("PASS: cache ulozena i nactena")
