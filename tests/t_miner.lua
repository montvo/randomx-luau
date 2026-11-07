--!nocheck
-- Integracni test mineru: mock WebSocket misto bridge, fake pool s realnym jobem.
-- Overuje login, prijem jobu, tezbu, target compare a format submitu.

------------------------------------------------------------------------- mock

-- realny 76bajtovy blob z gulf.moneroocean.stream (nonce na hex offsetu 78)
local BLOB = "1010ef88b9d70612bedf6dd26440e34db153641376b2ca477abe933089476383faa665c6ac2ef1000000008a69bf09bb51105c089aedc53b531327822ba847b3d70daa3bc257ade8e2085123"
local SEED = "3c84566822d6a64abefa07e2980e99299f24440643e8a77201adb196604b1832"

local sent = {}
local ws -- deklarace napred: funkce nize potrebuji upvalue, ne global
ws = {
	OnMessage = { Connect = function(self, fn) ws._onmsg = fn end },
	OnClose = { Connect = function(self, fn) ws._onclose = fn end },
	Send = function(self, payload) table.insert(sent, payload) end,
	Close = function() end,
}

local job2 = { blob = BLOB, seed_hash = SEED, target = "ffffffff", job_id = "j1", height = 1 }

local function fromHex(h)
	return (h:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end))
end

local function leU32(str, off)
	local a, b, c, d = string.byte(str, off + 1, off + 4)
	return a + b * 256 + c * 65536 + d * 16777216
end

local function decode(s)
	-- minimalni decoder: staci nam "method" a ploche "params" (job i submit)
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

-- cfg se predava do run(): require() v luau CLI ma vlastni globalni prostredi,
-- takze globalni `syn`/`task` z tohoto souboru tam nejsou videt.
local cfg = {
	bridge = "ws://mock", chains = 1, iters = 8, maxHashes = 2, duty = 0.10,
	connect = function() return ws end,
	decode = decode,
}
math.randomseed(1)

-- login -> odpoved s jobem
local function pumpLogin()
	local payload = sent[#sent]
	assert(payload:find('"method":"login"'), "login neodeslan")
	local job = job2
	ws._onmsg('{"jsonrpc":"2.0","method":"job","params":{' ..
		string.format('"blob":"%s","algo":"rx/0","height":%d,"seed_hash":"%s","job_id":"%s","target":"%s"',
			job.blob, job.height, job.seed_hash, job.job_id, job.target) .. '}}')
end

------------------------------------------------------------------------- test

local M = require("../miner.test")

-- login posle run(), odpoved s jobem dodame az v jeho prvnim wait()
local logins = 0
cfg.wait = function()
	if logins == 0 and #sent > 0 and sent[#sent]:find('"method":"login"') then
		logins = logins + 1
		pumpLogin()
	end
end

local res = M.run(cfg)

assert(res.hashes == 2, "cekano 2 hashe, je " .. tostring(res.hashes))
assert(res.shares == 2, "s target ffffffff musi projit vsechno, shares " .. tostring(res.shares))

local submits = {}
for _, p in ipairs(sent) do
	if p:find('"method":"submit"') then table.insert(submits, p) end
end
assert(#submits == 2, "cekano 2 submity, je " .. #submits)

for _, p in ipairs(submits) do
	local nonce = assert(p:match('"nonce":"(%x+)"'), "chybi nonce")
	local result = assert(p:match('"result":"(%x+)"'), "chybi result")
	assert(#nonce == 8, "nonce nema 4 bajty: " .. nonce)
	assert(#result == 64, "result nema 32 bajtů: " .. #result)
end

local r1 = submits[1]:match('"result":"(%x+)"')
local r2 = submits[2]:match('"result":"(%x+)"')
assert(r1 ~= r2, "stejny result pro dva ruzne nonce")
-- nonce je v submitu little-endian, proto prevod po bajtech
local function nonceValue(n) return leU32(fromHex(n), 0) end
local n1 = nonceValue(submits[1]:match('"nonce":"(%x+)"'))
local n2 = nonceValue(submits[2]:match('"nonce":"(%x+)"'))
-- nonce musi sedet presne na blob offset 39 (nonce region je "00000000")
local function patched(nonceHex)
	return BLOB:sub(1, 78) .. nonceHex .. BLOB:sub(87)
end
assert(#patched(string.format("%08x", n1)) == 152, "patch blobu meni delku")
assert(n2 == n1 + 1, string.format("nonce se neinkrementuje: %x -> %x", n1, n2))

-- job_id musi sedet
for _, p in ipairs(submits) do
	assert(p:find('"job_id":"j1"'), "chybi job_id")
end

print("PASS: login, job, 2 hashe, 2 shares, nonce++, job_id")
