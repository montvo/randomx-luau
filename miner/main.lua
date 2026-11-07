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
	-- jemna davka pro plynulost + konzervativni vynos
	slicePcs = 256,
	duty = 0.10, -- podil CPU, ktery smi miner zit; jediny knob plynulosti
	workS = nil, -- kvantum prace v s; nil = odvozene z duty a ramce (1/60 s)
	frameS = nil, -- delka ramce pro odvozeni workS (nil = 1/60)
	maxSleepS = nil, -- strop jednoho spanku (nil = 0.1), aby GC spika nezamrzla hru
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
	clock = nil, -- zdroj CPU casu (testy)
	wall = nil, -- zdroj skutecneho casu (testy)
}

local NONCE_OFFSET = 39 -- kde v 76bajtovem blobu lezi 4bajtovy nonce

--------------------------------------------------------------------------- util

-- souborove API (executor ho ma globalne, testy si ho podstrci pres CONFIG)
local FS = {}
local function initFs()
	FS.read = CONFIG.readFile or (type(readfile) == "function" and readfile or nil)
	FS.write = CONFIG.writeFile or (type(writefile) == "function" and writefile or nil)
	FS.exists = CONFIG.fileExists or (type(isfile) == "function" and isfile or nil)
	FS.list = CONFIG.listFiles or (type(listfiles) == "function" and listfiles or nil)
	FS.delete = CONFIG.deleteFile or (type(delfile) == "function" and delfile or nil)
	FS.gc = collectgarbage
end

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

-- log jde na konzoli a kdyz to executor umi i do rx_log.txt;
-- konzole byva zahlcena vlastnimi zpravami, ze souboru se tocti spolehliveji
local logLines = {}
initFs()
local function log(...)
	local parts = {}
	for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
	local line = table.concat(parts, " ")
	print("[miner]", line)
	if FS.write then
		table.insert(logLines, string.format("%.1f %s", os.clock(), line))
		if #logLines > 300 then table.remove(logLines, 1) end
		pcall(FS.write, "rx_log.txt", table.concat(logLines, "\n"))
	end
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

------------------------------------------------------------------------ pacing

-- Jeden knob: `duty` = podil CPU, ktery smi miner zit (0.10 = 10 %).
-- Token bucket: prace budget spotrebovava, spanek ho doplnuje. Kvantum prace se
-- odvozuje z duty a ramce, takze pri nizkem duty vyjde jeden maly kousek na
-- ramec a zbytek ramce se spi -- CPU zustava na cili i tam, kde je `task.wait`
-- uzamceny po ramcich (60 Hz).
local duty = 0.10
local frameS = 1 / 60
local workS = duty * frameS -- ~1,7 ms pri 10 %
local minSleepS = frameS    -- kratsi spanek stejne skonci na ramci
local maxSleepS = 0.1       -- strop, aby GC spika nezpusobila dlouhy freeze
local sliceLen = 256        -- instrukci mezi kontrolami casu
local budget = 0            -- sekundy prace, ktere si muzeme dovolit
local qCpu, qWall = 0, 0    -- referencni body kvanta
local statCpu, statWall = 0, 0
local statSleep, statSlices = 0, 0
local hashFrom -- cas prvniho hashe, pro H/s v tepu
local pumpHook = function() end -- naplni se pump() nize; drzi WS zivy i behem hashe

local function cpuNow()
	if CONFIG.clock then return CONFIG.clock() end
	return os.clock()
end

-- skutecny cas: tick() v Robloxu, DateTime jako zaloha, os.clock az nakonec
local wallNow
if type(tick) == "function" then
	wallNow = tick
elseif type(DateTime) == "table" or type(DateTime) == "userdata" then
	local ok = pcall(function() return DateTime.now().UnixTimestampMillis end)
	wallNow = ok and function() return DateTime.now().UnixTimestampMillis / 1000 end or os.clock
else
	wallNow = os.clock
end

local function wall()
	if CONFIG.wall then return CONFIG.wall() end
	return wallNow()
end

local function resetPace()
	budget = 0
	statCpu, statWall, statSleep, statSlices = 0, 0, 0, 0
	qCpu, qWall = cpuNow(), wall()
end

-- jeden radek o prubehu tezke casti (cache): jak dlouho, jak dlouho se spalo
local function pacelog(what, wall0, sleep0)
	local wallD = math.max(wall() - wall0, 0.001)
	local slept = statSleep - sleep0
	log(string.format("%s %.1f s, spanku %.1f s, prumerna davka %.1f ms",
		what, wallD, slept, 1000 * math.max(wallD - slept, 0) / math.max(statSlices, 1)))
	statSleep, statSlices = 0, 0
end

-- vola se z rx po kazdem `sliceLen` instrukci; vraci delku dalsiho useku.
-- Kvantum jeste nedobehlo -> makame dal. Budget vycerpany -> spime presne tak
-- dlouho, aby se doplnil, a tim drzime cilove duty.
local function sliceDue()
	local c, w = cpuNow(), wall()
	local cpu, wallD = c - qCpu, w - qWall
	if cpu < workS then return sliceLen end -- jeste mame kvantum
	if wallD <= 0 then wallD = cpu end -- rozbity zdroj casu: ucetni aspon CPU
	if cpu > wallD then cpu = wallD end -- CPU nemuze presiahnout skutecny cas
	qCpu, qWall = c, w
	budget = math.min(budget + wallD * duty - cpu, maxSleepS * duty)

	statCpu, statWall = statCpu + cpu, statWall + wallD
	if stopRequested() then stop = true end
	pumpHook() -- vybav frontu (novy job, keepalive) i uprostred hashe

	if budget >= 0 then return sliceLen end
	local s = -budget / duty
	if s < minSleepS then s = minSleepS elseif s > maxSleepS then s = maxSleepS end
	local s0 = wall()
	wait(s)
	local slept = wall() - s0
	statSleep = statSleep + slept
	statSlices = statSlices + 1
	-- spanek patri do stejneho okna jako prace, jinak vyjde duty 100 %
	statWall = statWall + slept
	budget = budget + s * duty
	if budget < -maxSleepS * duty then budget = -maxSleepS * duty end
	qCpu, qWall = cpuNow(), wall()

	-- tep: po 20 s rekni, ze to zije a jak daleko od cile jsme
	if statWall > 20 then
		log(string.format("duty %.1f %% (cil %.0f %%), %d hashu, %.4f H/s",
			100 * statCpu / statWall, duty * 100, done, done / math.max(wall() - (hashFrom or wall()), 1)))
		statCpu, statWall = 0, 0
	end
	return sliceLen
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
	if not sessionId or wall() - lastKeep < 30 then return end
	lastKeep = wall()
	send("keepalived", function(id) return string.format('{"id":%d}', id) end)
end

local function login()
	msgId = msgId + 1
	ws:Send(string.format(
		'{"id":%d,"jsonrpc":"2.0","method":"login","params":{"login":"%s","pass":"%s","agent":"%s"}}',
		msgId, CONFIG.wallet, CONFIG.pass, CONFIG.worker))
end

local CACHE_BYTES = 262144 * 1024
local CACHE_CHUNK = 16 * 1048576 -- po kouscich, aby 256 MB string nezabil pamet
local CACHE_PARTS = CACHE_BYTES // CACHE_CHUNK

local function cachePart(seed, i)
	return string.format("rx_cache_%s_%02d.bin", hex(seed):sub(1, 16), i)
end

local function loadCache(seed)
	if not FS.read then return nil end
	local wall0 = wall()
	local sleep0 = statSleep
	for i = 0, CACHE_PARTS - 1 do
		local ok, has = pcall(FS.exists, cachePart(seed, i))
		if not ok or not has then return nil end
	end
	local okc, buf = pcall(buffer.create, CACHE_BYTES)
	if not okc then return nil end
	for i = 0, CACHE_PARTS - 1 do
		local okr, data = pcall(FS.read, cachePart(seed, i))
		if not okr or type(data) ~= "string" or #data ~= CACHE_CHUNK then return nil end
		local oks, src = pcall(buffer.fromstring, data)
		if not oks then return nil end
		buffer.copy(buf, i * CACHE_CHUNK, src, 0, #data)
		src, data = nil, nil -- nechame GC uvolnit docasne retezce
		if i % 4 == 3 then pcall(FS.gc, "collect") end
		sliceDue() -- i cteni z disku zere CPU -> drz duty
	end
	pcall(FS.gc, "collect")
	pacelog("nacteni cache", wall0, sleep0)
	return buf
end

local function saveCache(seed, buf)
	if not FS.write then return end
	local tmp = buffer.create(CACHE_CHUNK)
	for i = 0, CACHE_PARTS - 1 do
		buffer.copy(tmp, 0, buf, i * CACHE_CHUNK, CACHE_CHUNK)
		pcall(FS.write, cachePart(seed, i), buffer.tostring(tmp))
		if i % 4 == 3 then pcall(FS.gc, "collect") end
		sliceDue() -- zapis 16 MB je CPU spika jako kazda jina
	end
	pcall(FS.gc, "collect")
	if FS.list and FS.delete then
		local prefix = string.format("rx_cache_%s_", hex(seed):sub(1, 16))
		local okf, files = pcall(FS.list, "")
		if okf and type(files) == "table" then
			for _, f in ipairs(files) do
				if type(f) == "string" and f:find("^rx_cache_") and f:sub(1, #prefix) ~= prefix then
					pcall(FS.delete, f)
				end
			end
		end
	end
end

local function getCache(seed)
	if cacheKey == seed then return cache end
	local wall0 = wall()
	local fromDisk = loadCache(seed)
	if fromDisk then
		cache, cacheKey = fromDisk, seed
		return cache
	end
	log(string.format("stavim cache (pri %.0f %% duty ~%.1fx dele nez na plny vykon)…", duty * 100, 1 / duty))
	local n, t, pct, sleep0 = 0, wall(), 0, statSleep
	cache = argon2.initCache(blake, seed, nil, nil, function()
		n = n + 1
		if n % 8 == 0 then
			local now = math.min(99, math.floor(n * 100 / 983))
			if now > pct then
				pct = now
				log(string.format("cache %d%%", now))
			end
		end
		sliceDue() -- budget pryc -> spi; jinak makame dal
	end)
	cacheKey = seed
	pacelog("stavba cache", t, sleep0)
	local ts = wall()
	saveCache(seed, cache)
	log(string.format("cache ulozena za %.1f s (%d MB)", wall() - ts, CACHE_BYTES // 1048576))
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
pumpHook = pump

------------------------------------------------------------------------ tezba

local function mine()
	local seed = job.seed
	local c = getCache(seed)
	local nonce = math.random(0, 0x7FFFFFFF)
	local t0 = wall()
	hashFrom = hashFrom or t0

	while job and job.seed == seed and not stop do
		-- blob/target cti z aktualniho jobu, aby share neodchazely na stary blok
		local blob = job.blob
		local n = string.char(
			nonce % 256, math.floor(nonce / 256) % 256,
			math.floor(nonce / 65536) % 256, math.floor(nonce / 16777216) % 256)
		local h = rx.hash(blake, aes, ss, c, seed, blob:sub(1, NONCE_OFFSET) .. n .. blob:sub(NONCE_OFFSET + 5))
		done = done + 1
		if CONFIG.testShares or meets(h, job.thi, job.tlo) then
			submitted = submitted + 1
			log(string.format("SHARE height %s nonce %s hash %s", tostring(job.height or "?"), hex(n), hex(h)))
			submit(hex(n), hex(h))
		end
		if done % 5 == 0 then
			log(string.format("%d hashu, %.2f H/s", done, done / math.max(wall() - t0, 0.001)))
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
	initFs()
	-- jeden knob: duty. workS/minSleep se odvodi, dokud je nekdo nepretlaci.
	local d = tonumber(CONFIG.duty) or duty
	if d < 0.02 then d = 0.02 elseif d > 1 then d = 1 end
	duty = d
	frameS = tonumber(CONFIG.frameS) or frameS
	if frameS <= 0 then frameS = 1 / 60 end
	workS = tonumber(CONFIG.workS)
	if not workS then
		-- prilis kratke kvantum = prilis mnoho yieldu (kazdy task.wait neco stoji)
		workS = math.max(duty * frameS, 0.003)
	end
	if workS < 0.0005 then workS = 0.0005 end
	minSleepS = CONFIG.minSleepS or math.min(frameS, workS)
	maxSleepS = CONFIG.maxSleepS or math.max(0.1, workS * 4)
	sliceLen = math.max(1, math.floor(tonumber(CONFIG.slicePcs) or sliceLen))
	rx.slicePcs = sliceLen
	rx.slice = sliceDue
	if CONFIG.chains then rx._chains = CONFIG.chains end
	if CONFIG.iters then rx._iters = CONFIG.iters end
	math.randomseed(os.time() % 100000)
	log(string.format("bridge %s wallet %s… duty %.0f %% (kvantum %.1f ms, spanek ~%.0f ms)",
		bridgeUrl(), CONFIG.wallet:sub(1, 12), duty * 100, workS * 1000, workS * (1 / duty - 1) * 1000))

	while true do
		stop = false
		job = nil
		cache = nil
		cacheKey = nil
		resetPace()
		local ok, err = pcall(function()
			sessionStart = wall()
			lastKeep = wall()
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
		if sessionStart and wall() - sessionStart > 60 then attempt = 0 end
		attempt = attempt + 1
		local delay = math.min(60, CONFIG.reconnectDelay * 2 ^ (attempt - 1))
		log(string.format("reconnect za %d s (odeslano %d shares)", delay, submitted))
		wait(delay)
	end
end

return M
