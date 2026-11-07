--!nocheck
-- mul64lo proti referenci (16bitove limby, plny produkt) a hranove kombinace.
-- Hlavni riziko 22bitovych limbu je presnost double (53 bitu) — test to hlida.

local rx = require("../src/rx")
local mullo = rx._mullo

local W = 4294967296
local function ref(alo, ahi, blo, bhi)
	local a0 = alo % 65536 local a1 = (alo - a0) / 65536 local a2 = ahi % 65536 local a3 = (ahi - a2) / 65536
	local b0 = blo % 65536 local b1 = (blo - b0) / 65536 local b2 = bhi % 65536 local b3 = (bhi - b2) / 65536
	local t = a0 * b0 local o0 = t % 65536
	t = a0 * b1 + a1 * b0 + (t - o0) / 65536 local o1 = t % 65536
	t = a0 * b2 + a1 * b1 + a2 * b0 + (t - o1) / 65536 local o2 = t % 65536
	t = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + (t - o2) / 65536 local o3 = t % 65536
	return o0 + o1 * 65536, o2 + o3 * 65536
end

local bad, n = 0, 0
local function check(alo, ahi, blo, bhi, popis)
	n = n + 1
	local p0, p1 = ref(alo, ahi, blo, bhi)
	local q0, q1 = mullo(alo, ahi, blo, bhi)
	if p0 ~= q0 or p1 ~= q1 then
		bad = bad + 1
		if bad <= 5 then
			print(string.format("FAIL %s %08x %08x * %08x %08x -> %08x %08x, cekano %08x %08x",
				popis, alo, ahi, blo, bhi, q0, q1, p0, p1))
		end
	end
end

-- hrany: vsechny kombinace nul, jednicek, all-ones a krajnich mantisovych bitu
local E = { 0, 1, 2, 4095, 4096, 65535, 65536, 4194303, 4194304, 0x7FFFFF, 0x800000, 0xFFFFF000, 0xFFFFFFFF }
for _, alo in ipairs(E) do
	for _, ahi in ipairs(E) do
		for _, blo in ipairs(E) do
			for _, bhi in ipairs(E) do check(alo, ahi, blo, bhi, "hrana") end
		end
	end
end
print(string.format("hran: %d kombinaci", n))

-- nahodne, vcetne shodnych operandu a maxima
math.randomseed(1234)
local rnd = math.random
local N = 40000
for i = 1, N do
	local alo, ahi = rnd(0, 4294967295), rnd(0, 4294967295)
	local blo, bhi = rnd(0, 4294967295), rnd(0, 4294967295)
	if i % 5 == 0 then blo, bhi = alo, ahi end
	if i % 11 == 0 then alo, ahi = 4294967295, 4294967295 end
	if i % 13 == 0 then blo, bhi = 0, 0 end
	if i % 17 == 0 then alo, ahi = 0, 4294967295 end
	if i % 19 == 0 then ahi, bhi = 0, 4294967295 end
	if i % 23 == 0 then alo, blo = 4194303, 4194304 end
	check(alo, ahi, blo, bhi, "nahoda")
end

assert(bad == 0, bad .. " neshod z " .. n)
print(string.format("PASS: %d pripadu bez neshody", n))
