--!nocheck
-- Sdilena cache pres bridge: klient ma stahnout hotovou cache misto pocitani
-- a po vlastnim postaveni ji nabidnout zpet. Testy jedou na fake HTTP.

local BLOB = "1010ef88b9d70612bedf6dd26440e34db153641376b2ca477abe933089476383faa665c6ac2ef1000000008a69bf09bb51105c089aedc53b531327822ba847b3d70daa3bc257ade8e2085123"
local SEED = "3c84566822d6a64abefa07e2980e99299f24440643e8a77201adb196604b1832"
local PART = string.rep("\170", 16 * 1048576)
local SEED_KEY = SEED:sub(1, 16)

------------------------------------------------------------------------- mock

local sent = {}
local ws
ws = {
	OnMessage = { Connect = function(self, fn) ws._onmsg = fn end },
	OnClose = { Connect = function(self, fn) ws._onclose = fn end },
	Send = function(self, payload) table.insert(sent, payload) end,
	Close = function() end,
}

local gets, puts = {}, {}
local complete = true -- co predstira bridge v /meta

-- CONFIG.http vraci rovnou telo odpovedi (nebo nil), jako httpReq
local function fakeHttp(method, url, body)
	local idx = url:match("/(%d+)$")
	if url:match("/meta$") then
		return complete and '{"complete":true,"have":[]}' or '{"complete":false,"have":[]}'
	end
	if method == "GET" then
		table.insert(gets, tonumber(idx))
		return PART
	end
	if method == "PUT" then
		table.insert(puts, { idx = tonumber(idx), len = #tostring(body) })
		return "ok"
	end
	return nil
end

local function decode(s)
	if s:find('"complete"', 1, true) then
		return { complete = s:find('"complete":true', 1, true) ~= nil, have = {} }
	end
	local t = {}
	t.method = s:match('"method":"([%w_.]+)"')
	local p = s:match('"params":(%b{})')
	if p then
		t.params = {}
		for k, v in p:gmatch('"([%w_]+)":"([^"]*)"') do t.params[k] = v end
		for k, v in p:gmatch('"([%w_]+)":(%d+)') do t.params[k] = v end
	end
	return t
end

local function mock()
	local function pumpLogin()
		local payload = sent[#sent]
		assert(payload and payload:find('"method":"login"'), "login neodeslan")
		ws._onmsg('{"jsonrpc":"2.0","method":"job","params":{' ..
			string.format('"blob":"%s","algo":"rx/0","height":1,"seed_hash":"%s","job_id":"j1","target":"ffffffff"',
				BLOB, SEED) .. '}}')
	end
	local logins = 0
	local base = function() end
	return function()
		base()
		if logins == 0 and #sent > 0 and sent[#sent]:find('"method":"login"') then
			logins = logins + 1
			pumpLogin()
		end
	end
end

local function cfg(over)
	local c = {
		bridge = "ws://mock", cacheUrl = "http://mock", chains = 1, iters = 4,
		duty = 1, maxHashes = 1, connect = function() return ws end,
		decode = decode, wait = mock(), http = fakeHttp,
	}
	for k, v in pairs(over or {}) do c[k] = v end
	return c
end

------------------------------------------------------------------------- test

local M = require("../miner.test")
math.randomseed(1)

-- 1) bridge ma kompletni cache -> klient stahne vsech 16 dilu a sam nic nenahrava
local res = M.run(cfg())
assert(res.hashes == 1, "hash nedobehl: " .. tostring(res.hashes))
assert(#gets == 16, "cekáno 16 GET dilu, je " .. #gets)
for i = 0, 15 do assert(gets[i + 1] == i, "dily nešly poporade, pozice " .. i .. " = " .. tostring(gets[i + 1])) end
assert(#puts == 0, "pri kompletni cache se nemá nic nahrávat, PUTu " .. #puts)
print("PASS: kompletni cache stazena (16 dilu), 0 PUTu")

-- 2) bridge cache nema -> hash nesmi spadnout, cache se postavi lokalne
--    a nabidne zpet vsemi 16 dily
complete = false
local res2 = M.run(cfg{ maxHashes = res.hashes + 1 })
assert(res2.hashes == res.hashes + 1, "druhy beh nedobehl")
assert(#gets == 16, "pri neuplne cache se nema stahovat, GETu " .. #gets)
assert(#puts == 16, "cekáno 16 PUT dilu, je " .. #puts)
for i = 0, 15 do
	assert(puts[i + 1].idx == i, "dily nešly poporade, pozice " .. i)
	assert(puts[i + 1].len == 16 * 1048576, "dil " .. i .. " ma " .. puts[i + 1].len .. " B")
end
print("PASS: neuplna cache -> lokalni stavba, 16 dilu nahrano")
