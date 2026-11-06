local args = { ... }
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
local band, bor, bxor, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local _fb = buffer.create(16)
local function f2b(x) buffer.writef64(_fb, 0, x) return buffer.readu32(_fb, 0), buffer.readu32(_fb, 4) end
local function b2f(lo, hi) buffer.writeu32(_fb, 0, lo) buffer.writeu32(_fb, 4, hi) return buffer.readf64(_fb, 0) end
local function i64ToD(lo, hi)
	if hi >= 0x80000000 then return lo + (hi - 4294967296) * 4294967296 end
	return lo + hi * 4294967296
end
local function unhex(h) local t={} for i=1,#h,2 do t[#t+1]=string.char(tonumber(h:sub(i,i+1),16)) end return table.concat(t) end
local function hex(n) return string.format("%08x", n) end
local function h64(lo,hi) return string.format("%08x%08x", hi, lo) end
local function hx(s) local t={} for i=1,#s do t[i]=string.format("%02x",string.byte(s,i)) end return table.concat(t) end
local key = unhex(args[1])
local input = unhex(args[2])
local cache = argon.initCache(blake, key)
local sgen = ss.newGen(blake, key)
local progs = {}
for i = 1, 8 do progs[i] = ss.generate(sgen) end
local datasetItem = rx.datasetItem
local CacheLineAlignMask = 0x7FFFFFC0
-- replicate internals by re-running the same steps as rx.hash but with prints
local M = rx
-- patch: reimplement the header part of hash
local seed = blake.blake2b(input, 64)
local scratch = buffer.create(2097152)
local g1 = aes.gen1R(seed)
for i = 0, 2097151/64 do buffer.writestring(scratch, i*64, g1:next()) end
print("FILLCHK:"..hx(buffer.readstring(scratch, 0x12ecc0, 64)))
print("chain 0")
local parts = {}
local g4 = aes.gen4R(g1.state)
for i = 1, 34 do parts[#parts+1] = g4:next() end
local blob = table.concat(parts)
print(hx(blob))
local full = buffer.fromstring(blob)
local cfg = full
local ent = {}
for i = 0, 15 do ent[i] = { buffer.readu32(cfg, i*8), buffer.readu32(cfg, i*8+4) } end
local function b2f(lo,hi) local b=buffer.create(8) buffer.writeu32(b,0,lo) buffer.writeu32(b,4,hi) return buffer.readf64(b,0) end
local function small(lo,hi) local e = band(rshift(hi,27)+1023, 2047) return b2f(lo, bor(band(hi,0xFFFFF), lshift(e,20))) end
local alo, ahi = {}, {}
for i = 0, 3 do alo[i+1] = small(ent[i*2][1], ent[i*2][2]) ahi[i+1] = small(ent[i*2+1][1], ent[i*2+1][2]) end
local ma = band(ent[8][1], CacheLineAlignMask)
local mx = ent[10][1]
local ar = ent[12][1]
local rr = { band(ar,1)+1, band(rshift(ar,1),1)+3, band(rshift(ar,2),1)+5, band(rshift(ar,3),1)+7 }
local off = (ent[13][1] % 524288) * 64
local eM = {}
for k=1,2 do local lo,hi = ent[13+k][1], ent[13+k][2] eM[k] = { band(lo,0x3FFFFF), bor(0x30000000, band(rshift(hi,28),0xF)*0x1000000) } end
print(string.format("ma=%08x mx=%08x eMask=%08x%08x %08x%08x rr=%d,%d,%d,%d off=%d", ma, mx, eM[1][2], eM[1][1], eM[2][2], eM[2][1], rr[1]-1, rr[2]-1, rr[3]-1, rr[4]-1, off))
local function vec(t) local o = {} for i=1,4 do local b=buffer.create(8) buffer.writef64(b,0,t[i]) o[#o+1]=hx(buffer.readstring(b,0,8)) end return table.concat(o," ") end
print("a: "..vec(alo).." | "..vec(ahi))
local words, K, D, S, MU, ILO, IHI, TGT, MASK, ZB
do
	words = {}
	for i=1,256 do local o = 128+(i-1)*8 words[i] = { buffer.readu8(cfg,o), buffer.readu8(cfg,o+1), buffer.readu8(cfg,o+2), buffer.readu8(cfg,o+3), buffer.readu32(cfg,o+4) } end
	local dec = rx.decodeWords
	K, D, S, MU, ILO, IHI, TGT, MASK, ZB = dec(words)
	local usage = {} for i=1,8 do usage[i]=0 end
	for pc=1,256 do
		local k = K[pc]
		if k == 27 then TGT[pc] = usage[D[pc]] for j=1,8 do usage[j]=pc end
		elseif k == 17 then if S[pc] ~= D[pc] then usage[D[pc]]=pc usage[S[pc]]=pc end
		elseif k == 11 then if band(words[pc][5], words[pc][5]-1) ~= 0 then usage[D[pc]]=pc end
		elseif k ~= 18 and k ~= 19 and k ~= 20 and k ~= 21 and k ~= 22 and k ~= 23 and k ~= 24 and k ~= 25 and k ~= 26 and k ~= 28 and k ~= 29 and k ~= 30 then usage[D[pc]]=pc end
	end
end
rx.debug = function(m) print(m) end
local rlo, rhi = {}, {}
for i=1,8 do rlo[i]=0 rhi[i]=0 end
local flo, fhi, elo, ehi = {}, {}, {}, {}
local spAddr0, spAddr1 = mx, ma
for ic = 1, (tonumber(args[3]) or 2) do
	spAddr0 = bit32.band(bit32.bxor(spAddr0, bit32.bxor(rlo[rr[1]], rlo[rr[2]])), 0x1FFFC0)
	spAddr1 = bit32.band(bit32.bxor(spAddr1, bit32.bxor(rhi[rr[1]], rhi[rr[2]])), 0x1FFFC0)
	for i=1,8 do local o = spAddr0+(i-1)*8 rlo[i]=bxor(rlo[i],buffer.readu32(scratch,o)) rhi[i]=bxor(rhi[i],buffer.readu32(scratch,o+4)) end
	for i=1,4 do
		local o = spAddr1+(i-1)*8
		flo[i] = buffer.readi32(scratch, o) fhi[i] = buffer.readi32(scratch, o + 4)
		local o2 = spAddr1+(i+3)*8
		local x1, x2 = f2b(buffer.readi32(scratch, o2))
		elo[i] = b2f(bor(x1, eM[1][1]), bor(band(x2,0xFFFFFF), eM[1][2]))
		x1, x2 = f2b(buffer.readi32(scratch, o2 + 4))
		ehi[i] = b2f(bor(x1, eM[2][1]), bor(band(x2,0xFFFFFF), eM[2][2]))
	end
	local t = {}
	for i=1,8 do t[#t+1] = h64(rlo[i], rhi[i]) end
	print(string.format("sp %08x %08x", spAddr0, spAddr1))
	print("it"..(ic-1).." r: "..table.concat(t," "))
	print("f: "..vec(flo).." | "..vec(fhi))
	print("e: "..vec(elo).." | "..vec(ehi))
	-- exec inline via rx? reuse the same code path: call a helper
	rx._exec(K, D, S, MU, ILO, IHI, TGT, MASK, ZB, words, scratch, rlo, rhi, flo, fhi, elo, ehi, alo, ahi, eM, spAddr0, spAddr1, function(pc)
		local o = "pc"..(pc-1).." k"..tostring(K[pc]).." d"..tostring(D[pc]).." s"..tostring(S[pc]).." ilo"..tostring(K[pc]==27 and string.format("%08x",ILO[pc]) or nil).." tgt"..tostring(K[pc]==27 and TGT[pc] or nil).." r:"
		for i=1,8 do o = o.." "..h64(rlo[i], rhi[i]) end
		o = o.." f:"
		for i=1,4 do local b=buffer.create(16) buffer.writef64(b,0,flo[i]) buffer.writef64(b,8,fhi[i]) o=o..hx(buffer.readstring(b,0,16)) end
		o = o.." e:"
		for i=1,4 do local b=buffer.create(16) buffer.writef64(b,0,elo[i]) buffer.writef64(b,8,ehi[i]) o=o..hx(buffer.readstring(b,0,16)) end
		print(o)
		if pc-1 == 6 then print("HOOKDBG fhi1="..tostring(fhi[1]).." flo1="..tostring(flo[1])) end
	end)
	local t2 = {}
	for i=1,8 do t2[#t2+1] = h64(rlo[i], rhi[i]) end
	print("after r: "..table.concat(t2," "))
	print("f2: "..vec(flo).." | "..vec(fhi))
	print("e2: "..vec(elo).." | "..vec(ehi))
	local sp = blake.blake2b(buffer.readstring(scratch,0,2097152), 32)
	print("sp:"..hx(sp:sub(1,4)))
	print("FILL0:"..hx(buffer.readstring(scratch,0,64)))
	for c=0,31 do print("CH"..c.." "..hx(blake.blake2b(buffer.readstring(scratch,c*65536,65536),4))) end
	local irlo, irhi = {}, {}
			local readPtr = off + band(ma, CacheLineAlignMask)
			mx = bxor(mx, bxor(rlo[rr[3]], rlo[rr[4]]))
			datasetItem(cache, progs, rshift(readPtr, 6), irlo, irhi)
			for i = 1, 8 do rlo[i] = bxor(rlo[i], irlo[i]) rhi[i] = bxor(rhi[i], irhi[i]) end
			ma, mx = mx, ma
			for i = 1, 8 do
				local o = spAddr1 + (i-1)*8
				buffer.writeu32(scratch, o, rlo[i]) buffer.writeu32(scratch, o+4, rhi[i])
			end
			for i = 1, 4 do
				local lo, hi = f2b(flo[i]) local l2, h2 = f2b(elo[i])
				local lo3, hi3 = f2b(fhi[i]) local l4, h4 = f2b(ehi[i])
				flo[i] = b2f(bxor(lo, l2), bxor(hi, h2)) fhi[i] = b2f(bxor(lo3, l4), bxor(hi3, h4))
			end
			for i = 1, 4 do
				buffer.writef64(scratch, spAddr0 + (i-1)*16, flo[i])
				buffer.writef64(scratch, spAddr0 + (i-1)*16 + 8, fhi[i])
			end
			print("POSTIT:"..hx(buffer.readstring(scratch, 0x12ecc0, 96)))
			print("POSTIT2:"..hx(buffer.readstring(scratch, 0x14b940, 96)))
			local t3 = {}
			for i=1,8 do t3[#t3+1] = h64(rlo[i], rhi[i]) end
			print("r3: "..table.concat(t3," "))
			spAddr0, spAddr1 = 0, 0
end
