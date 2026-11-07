--!nocheck
-- Test duty-cycle throttlu: fake CPU + fake wall clock, kontrola ze se skutecne
-- spi podle `duty`, ze duty=1 nespi vubec a ze se duty klampuje zdola.
-- Mining samotny musi dobehnout (2 hashe, 2 shares jako v t_miner).

local BLOB = "1010ef88b9d70612bedf6dd26440e34db153641376b2ca477abe933089476383faa665c6ac2ef1000000008a69bf09bb51105c089aedc53b531327822ba847b3d70daa3bc257ade8e2085123"
local SEED = "3c84566822d6a64abefa07e2980e99299f24440643e8a77201adb196604b1832"

------------------------------------------------------------------------- mock

local sent = {}
local ws -- deklarace napred: Connect nize potrebuje upvalue, ne global
ws = {
	OnMessage = { Connect = function(self, fn) ws._onmsg = fn end },
	OnClose = { Connect = function(self, fn) ws._onclose = fn end },
	Send = function(self, payload) table.insert(sent, payload) end,
	Close = function() end,
}

local function decode(s)
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

-- falesne hodiny: `t` je jediny zdroj casu, `clock()` ho posouva po 20 us
-- (simuluje spotrebovany CPU), `wall()` ho jen cte -> behem prace jdou oba
-- stejne rychle, behem spanku tece jen wall.
local t = 0
local cost = 0.00002
local slept, sleeps = 0, 0
local paceMax = 0.05 -- vyssi wait = neni to pacing (0,2 s idle, reconnect 5 s)

local function fakeClock()
	t = t + cost
	return t
end

local function fakeWall() return t end

local function fakeWait(s)
	if s > paceMax then return end -- idle/reconnect wait, nepace
	sleeps = sleeps + 1
	slept = slept + s
	t = t + s
end

local function installPump()
	local function pumpLogin()
		local payload = sent[#sent]
		assert(payload and payload:find('"method":"login"'), "login neodeslan")
		ws._onmsg('{"jsonrpc":"2.0","method":"job","params":{' ..
			string.format('"blob":"%s","algo":"rx/0","height":1,"seed_hash":"%s","job_id":"j1","target":"ffffffff"',
				BLOB, SEED) .. '}}')
	end
	local logins = 0
	return function()
		if logins == 0 and #sent > 0 and sent[#sent]:find('"method":"login"') then
			logins = logins + 1
			pumpLogin()
		end
	end
end

------------------------------------------------------------------------- test

local M = require("../miner.test")
math.randomseed(1)

local function run(duty, hashes)
	t, slept, sleeps = 0, 0, 0
	local cfg = {
		bridge = "ws://mock", chains = 1, iters = 8, duty = duty,
		workS = 0.0005, minSleepS = 0.0005, maxSleepS = paceMax,
		connect = function() return ws end, decode = decode,
		clock = fakeClock, wall = fakeWall, wait = fakeWait,
		maxHashes = hashes,
	}
	return cfg
end

-- cfg.wait musi umet oboji: pacing spanek i podstrceni jobu pri prvnim volani
local function start(duty, hashes)
	local cfg = run(duty, hashes)
	local pump = installPump()
	local inner = cfg.wait
	cfg.wait = function(s)
		inner(s)
		pump()
	end
	return M.run(cfg)
end

-- 1) cil 10 %
local res = start(0.10, 2)
assert(res.hashes == 2, "cekano 2 hashe, je " .. tostring(res.hashes))
assert(res.shares == 2, "cekano 2 shares, je " .. tostring(res.shares))
assert(sleeps > 0, "pri duty 10 % se nikdy nespalo")
local duty = (t - slept) / t
assert(duty > 0.06 and duty < 0.15, string.format("duty mimo pásmo: %.1f %%", duty * 100))
print(string.format("PASS: duty %.1f %% (cil 10 %%), %d spanku", duty * 100, sleeps))

-- 2) duty 1 = zadny spanek, jen hashovani
local res2 = start(1, res.hashes + 1)
assert(res2.hashes == res.hashes + 1, "druhy beh nedoběhl")
assert(sleeps == 0, "pri duty 1 se spalo " .. sleeps .. "x")

-- 3) nesmyslne nizke duty se klampuje na 2 %
local before = res2.hashes
start(0.0001, before + 1)
local duty3 = (t - slept) / t
assert(duty3 > 0.015 and duty3 < 0.05, string.format("clamp nefunguje: %.2f %%", duty3 * 100))
print(string.format("PASS: clamp 0,01 %% -> %.1f %%", duty3 * 100))
