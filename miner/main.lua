--!nocheck
-- Executor skript: pripoji se na lokalni bridge (WS -> pool TCP), prijme job a tezi.
-- Bundluje se do jednosouboroveho miner.lua (viz tools/bundle.py); moduly blake, aes,
-- argon2, ss a rx jsou vlozene nad timto kodem jako lokaly.
--
-- `M.run(over)` spusti tezbu, `over` prepise CONFIG (pouziva se i v testech).

local M = {}

local CONFIG = {
	wallet = "42ypgDkEvE1VQSLfXwQffKBF7L5vETygtfvaynG9nW8W7crvsrGv4ziAAmTppDkedKSdz9iAKM7f5gBwZpnNviY81ACgjhw",
	worker = "rx-luau",
	bridge = "ws://127.0.0.1:8790",
	bridgeFallback = nil, -- druha adresa, zkusi se po selhani prvni
	pass = "x",
	-- yield kazdych N instrukci VM (0 = bez yieldovani, cely hash najednou ~8 s)
	slicePcs = 1024,
	reconnectDelay = 5, -- zaklad backoffu, zdvojnasobi se az do 60 s
	-- 8 x 2048 = plny RandomX; nizsi hodnoty jen pro test
	chains = nil,
	iters = nil,
	maxHashes = nil, -- test: po N hashech skoncit
	testShares = nil, -- test: submitovat kazdy hash (pool vraci low difficulty)
	-- host API se da podstrcit (testy); defaultne executor
	connect = nil,
	wait = nil,
	decode = nil,
}

local NONCE_OFFSET = 39 -- kde v 76bajtovem blobu lezi 4bajtovy nonce

--------------------------------------------------------------------------- util

local function decode(s)
	if CONFIG.decode then return CONFIG.decode(s) end
	if syn and syn.json then return syn.json.decode(s) end
	return game:GetService("HttpService"):JSONDecode(s)
end

local function wait(s)
	if CONFIG.wait then return CONFIG.wait(s) end
	return task.wait(s)
end

local function hex(s)
	return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function fromHex(s)
	return (s:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
end

local function leU32(s, off)
	local b1, b2, b3, b4 = string.byte(s, off + 1, off + 4)
	return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

-- presne floor deleni 64bit / 32bit (64 kroku, jen pri prijmu jobu)
local function divU64(d)
	local nhi, nlo = 0xFFFFFFFF, 0xFFFFFFFF
	local qhi, qlo, rem = 0, 0, 0
	for i = 63, 0, -1 do
		local nb = (i >= 32) and (math.floor(nhi / 2 ^ (i - 32)) % 2) or (math.floor(nlo / 2 ^ i) % 2)
		rem = rem * 2 + nb
		if rem >= d then
			rem = rem - d
			if i >= 32 then
				qhi = qhi + 2 ^ (i - 32)
			else
				qlo = qlo + 2 ^ i
			end
		end
	end
	return qhi, qlo
end

local function targetFromJob(t32)
	local d = math.floor(0xFFFFFFFF / t32)
	if d < 1 then d = 1 end
	return divU64(d)
end

-- hash <= target ?
local function meets(hash, thi, tlo)
	local lo = leU32(hash, 0)
	local hi = leU32(hash, 4)
	if hi ~= thi then return hi < thi end
	return lo <= tlo
end

local function connect(url)
	if CONFIG.connect then return CONFIG.connect(url) end
	if syn and syn.websocket then
		return syn.websocket.connect(url)
	elseif WebSocket and WebSocket.connect then
		return WebSocket.connect(url)
	end
	error("executor neumi WebSocket")
end

-- primarni bridge, pri selhani se zkusi zalozni (napr. lokalni); primarni se
-- po par neuspesech zkusi znovu, aby se po restartu serveru vratil
local useFallback = false
local fallbackFails = 0
local function bridgeUrl()
	if useFallback and CONFIG.bridgeFallback then return CONFIG.bridgeFallback end
	return CONFIG.bridge
end

local function log(...)
	print("[miner]", ...)
end

-------------------------------------------------------------------------- stav

local ws
local msgId = 0
local queue = {}
local job -- { blob, seed, thi, tlo, id, height }
local cacheKey, cache
local done, submitted = 0, 0
local stop = false
local sessionId, lastKeep, sessionStart = nil, 0, nil
local attempt = 0

-- `_G.MINER_STOP = true` v libovolnem jinem skriptu tezbu ukonci
local function stopRequested()
	return rawget(_G, "MINER_STOP") == true
end

-- paramsById(id) vraci hotovy JSON objekt s "id"
local function send(method, paramsById)
	msgId = msgId + 1
	ws:Send(table.concat({
		'{"id":', tostring(msgId), ',"jsonrpc":"2.0","method":"', method,
		'","params":', paramsById(msgId), "}",
	}))
end

local function submit(nonceHex, resultHex)
	send("submit", function(id)
		return string.format('{"id":%d,"job_id":"%s","nonce":"%s","result":"%s"}', id, job.id, nonceHex, resultHex)
	end)
end

local function keepalive()
	if not sessionId or os.clock() - lastKeep < 30 then return end
	lastKeep = os.clock()
	send("keepalived", function(id) return string.format('{"id":%d}', id) end)
end

local function login()
	msgId = msgId + 1
	ws:Send(string.format(
		'{"id":%d,"jsonrpc":"2.0","method":"login","params":{"login":"%s","pass":"%s","agent":"%s"}}',
		msgId, CONFIG.wallet, CONFIG.pass, CONFIG.worker))
end

local function getCache(seed)
	if cacheKey == seed then return cache end
	log("stavim cache (~36 s)…")
	local n, t, pct = 0, os.clock(), 0
	cache = argon2.initCache(blake, seed, nil, nil, function()
		n = n + 1
		if n % 8 == 0 then
			local now = math.min(99, math.floor(n * 100 / 192))
			if now > pct then
				pct = now
				log(string.format("cache %d%%", now))
			end
			wait()
		end
	end)
	cacheKey = seed
	log(string.format("cache hotova za %.1f s", os.clock() - t))
	return cache
end

local function onJob(p)
	-- pool posila blob/seed/target jako hex
	local blob = type(p.blob) == "string" and fromHex(p.blob)
	local seed = type(p.seed_hash) == "string" and fromHex(p.seed_hash)
	if not blob or #blob < 44 or not seed then return end
	local t32 = type(p.target) == "string" and leU32(fromHex(p.target), 0) or 0
	if t32 == 0 then t32 = 0xFFFFFFFF end
	if job and job.seed == seed and job.blob == blob then return end -- stejny job
	local thi, tlo = targetFromJob(t32)
	job = {
		blob = blob:sub(1, 35) .. blob:sub(36),
		seed = seed,
		id = p.job_id,
		height = p.height,
		thi = thi,
		tlo = tlo,
	}
	log(string.format("job %s height %s target %08x", tostring(job.id), tostring(job.height or "?"), t32))
end

local function handle(line)
	local ok, msg = pcall(decode, line)
	if not ok or type(msg) ~= "table" then return end
	if msg.__bridge == "tcp_error" then
		log("bridge chyba: " .. tostring(msg.message))
		return
	end
	if msg.method == "job" then
		onJob(msg.params or {})
	elseif msg.method == "client.reconnect" then
		log("pool pozaduje reconnect")
		stop = true
	elseif type(msg.result) == "table" and msg.result.job then
		sessionId = msg.result.id
		log("prihlasen do poolu")
		onJob(msg.result.job)
	elseif msg.error then
		log("pool error: " .. tostring(msg.error.message or msg.error))
	end
end

local function pump()
	while queue[1] do
		local l = table.remove(queue, 1)
		handle(l)
	end
end

------------------------------------------------------------------------ tezba

local function mine()
	local seed = job.seed
	local c = getCache(seed)
	local nonce = math.random(0, 0x7FFFFFFF)
	local blob = job.blob
	local thi, tlo, height = job.thi, job.tlo, job.height
	local t0 = os.clock()

	while job and job.seed == seed and not stop do
		local n = string.char(
			nonce % 256, math.floor(nonce / 256) % 256,
			math.floor(nonce / 65536) % 256, math.floor(nonce / 16777216) % 256)
		local h = rx.hash(blake, aes, ss, c, seed, blob:sub(1, NONCE_OFFSET) .. n .. blob:sub(NONCE_OFFSET + 5))
		done = done + 1
		if CONFIG.testShares or meets(h, thi, tlo) then
			submitted = submitted + 1
			log(string.format("SHARE height %s nonce %s hash %s", tostring(height or "?"), hex(n), hex(h)))
			submit(hex(n), hex(h))
		end
		if done % 5 == 0 then
			log(string.format("%d hashu, %.2f H/s", done, done / math.max(os.clock() - t0, 0.001)))
		end
		nonce = nonce + 1
		if nonce > 0xFFFFFFFF then nonce = 0 end
		if CONFIG.maxHashes and done >= CONFIG.maxHashes then stop = true end
		if stopRequested() then stop = true end
		keepalive()
		pump() -- novy job / keepalive behem tezby
	end
end

-------------------------------------------------------------------------- main

function M.run(over)
	for k, v in pairs(over or {}) do CONFIG[k] = v end
	rx.slicePcs = CONFIG.slicePcs
	if CONFIG.chains then rx._chains = CONFIG.chains end
	if CONFIG.iters then rx._iters = CONFIG.iters end
	math.randomseed(os.time() % 100000)
	log("bridge " .. bridgeUrl() .. " wallet " .. CONFIG.wallet:sub(1, 12) .. "…")

	while true do
		stop = false
		job = nil
		cache = nil
		cacheKey = nil
		local ok, err = pcall(function()
			sessionStart = os.clock()
			ws = connect(bridgeUrl())
			ws.OnMessage:Connect(function(data)
				local s = tostring(data)
				if #s > 0 then table.insert(queue, s) end
			end)
			ws.OnClose:Connect(function()
				log("spojeni zavreno")
				stop = true
			end)
			login()
			while not stop do
				if job then
					mine()
				else
					pump()
					if stopRequested() then stop = true end
					keepalive()
					wait(0.2)
				end
			end
		end)
		if not ok then
			log("chyba: " .. tostring(err))
			if CONFIG.bridgeFallback then
				if useFallback then
					fallbackFails = fallbackFails + 1
					if fallbackFails >= 3 then
						fallbackFails = 0
						useFallback = false
						log("zkousim znovu primarni bridge")
					end
				else
					useFallback = true
					log("zkousim zalozni bridge " .. CONFIG.bridgeFallback)
				end
			end
		end
		pcall(function() ws:Close() end)
		if CONFIG.maxHashes and done >= CONFIG.maxHashes then
			log(string.format("konec: %d hashu, %d shares", done, submitted))
			return { hashes = done, shares = submitted }
		end
		-- pool (MoneroOcean) pri opakovanych reconnectech chvili neodpovida -> backoff
		if sessionStart and os.clock() - sessionStart > 60 then attempt = 0 end
		attempt = attempt + 1
		local delay = math.min(60, CONFIG.reconnectDelay * 2 ^ (attempt - 1))
		log(string.format("reconnect za %d s (odeslano %d shares)", delay, submitted))
		wait(delay)
	end
end

return M
