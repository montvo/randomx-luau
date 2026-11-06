-- RandomX v1 (rx/0) light-mode hash, pure Luau.
local M = {}

local bit32 = bit32
local band, bor, bxor, bnot, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.lshift, bit32.rshift
local sqrt = math.sqrt
local W = 4294967296

local ScratchpadSize = 2097152
local CacheLineSize = 64
local CacheLineAlignMask = 0x7FFFFFC0
local DatasetExtraItems = 524287
local L1Mask = 0x3FF8
local L2Mask = 0x3FFF8
local L3Mask = 0x1FFFF8
local L3Mask64 = 0x1FFFC0
local ConditionMask = 0xFF
local ConditionOffset = 8
local StoreL3Condition = 14
local ProgramSize = 256
local ProgramIterations = 2048
local ProgramCount = 8
local CacheItemsMask = 0x3FFFFF

local fbuf = buffer.create(16)
local function f2b(x) buffer.writef64(fbuf, 0, x) return buffer.readu32(fbuf, 0), buffer.readu32(fbuf, 4) end
local function i64ToD(lo, hi)
	if hi >= 0x80000000 then return lo + (hi - 4294967296) * 4294967296 end
	return lo + hi * 4294967296
end
local function b2f(lo, hi) buffer.writeu32(fbuf, 0, lo) buffer.writeu32(fbuf, 4, hi) return buffer.readf64(fbuf, 0) end

local function stepUp(x)
	local lo, hi = f2b(x)
	if x >= 0 then
		lo = lo + 1
		if lo >= W then lo = 0 hi = hi + 1 if hi >= W then hi = hi - W end end
	else
		if lo == 0 then hi = hi - 1 if hi < 0 then hi = hi + W end lo = 0xFFFFFFFF else lo = lo - 1 end
	end
	return b2f(lo, hi)
end

local function stepDown(x)
	local lo, hi = f2b(x)
	if x > 0 then
		if lo == 0 then hi = hi - 1 if hi < 0 then hi = hi + W end lo = 0xFFFFFFFF else lo = lo - 1 end
	else
		lo = lo + 1
		if lo >= W then lo = 0 hi = hi + 1 if hi >= W then hi = hi - W end end
	end
	return b2f(lo, hi)
end

local fprc = 0
local function applyRound(hi, err)
	if err == 0 or fprc == 0 then return hi end
	if fprc == 3 then
		if (hi > 0 and err > 0) or (hi < 0 and err < 0) then return hi end
		if hi > 0 then return stepDown(hi) end
		return stepUp(hi)
	elseif fprc == 2 then
		if err > 0 then return stepUp(hi) end
		return hi
	else
		if err > 0 then return hi end
		return stepDown(hi)
	end
end

local function fadd(a, b)
	local s = a + b
	local bb = s - a
	return applyRound(s, (a - (s - bb)) + (b - bb))
end
local function fsub(a, b) return fadd(a, -b) end
local C = 134217729
local function prodErr(a, b, p)
	local ah = C * a local ahi = ah - (ah - a) local alo = a - ahi
	local bh = C * b local bhi = bh - (bh - b) local blo = b - bhi
	return ((ahi * bhi - p) + ahi * blo + alo * bhi) + alo * blo
end
local function fprod(a, b)
	local p = a * b
	return applyRound(p, prodErr(a, b, p))
end
local function fdiv(a, b)
	local q = a / b
	local p = q * b
	return applyRound(q, (a - p) - prodErr(q, b, p))
end
local function fsqrt(x)
	local s = sqrt(x)
	local p = s * s
	return applyRound(s, (x - p) - prodErr(s, s, p))
end

local function ad64(alo, ahi, blo, bhi)
	local lo = alo + blo
	local carry = 0
	if lo >= W then lo = lo - W carry = 1 end
	local hi = ahi + bhi + carry
	return lo, (hi >= W and hi - W or hi)
end
local function sb64(alo, ahi, blo, bhi)
	local lo = alo - blo
	local borrow = 0
	if lo < 0 then lo = lo + W borrow = 1 end
	local hi = ahi - bhi - borrow
	return lo, (hi < 0 and hi + W or hi)
end
local function mulLimbs(alo, ahi, blo, bhi)
	local a0 = alo % 65536 local a1 = (alo - a0) / 65536
	local a2 = ahi % 65536 local a3 = (ahi - a2) / 65536
	local b0 = blo % 65536 local b1 = (blo - b0) / 65536
	local b2 = bhi % 65536 local b3 = (bhi - b2) / 65536
	local c0 = a0 * b0
	local c1 = a0 * b1 + a1 * b0
	local c2 = a0 * b2 + a1 * b1 + a2 * b0
	local c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
	local c4 = a1 * b3 + a2 * b2 + a3 * b1
	local c5 = a2 * b3 + a3 * b2
	local c6 = a3 * b3
	local t = c0
	local o0 = t % 65536
	t = c1 + (t - o0) / 65536
	local o1 = t % 65536
	t = c2 + (t - o1) / 65536
	local o2 = t % 65536
	t = c3 + (t - o2) / 65536
	local o3 = t % 65536
	t = c4 + (t - o3) / 65536
	local o4 = t % 65536
	t = c5 + (t - o4) / 65536
	local o5 = t % 65536
	t = c6 + (t - o5) / 65536
	local o6 = t % 65536
	local o7 = (t - o6) / 65536
	return o0, o1, o2, o3, o4, o5, o6, o7
end

local function mul64lo(alo, ahi, blo, bhi)
	local o0, o1, o2, o3, o4, o5 = mulLimbs(alo, ahi, blo, bhi)
	return o0 + o1 * 65536, o2 + o3 * 65536
end

local function mul64hi(alo, ahi, blo, bhi)
	local _, _, _, _, o4, o5, o6, o7 = mulLimbs(alo, ahi, blo, bhi)
	return o4 + o5 * 65536, o6 + o7 * 65536
end

local function isNeg(hi) return hi >= 2147483648 end
local function neg64(lo, hi) return sb64(0, 0, lo, hi) end
local function smulh(alo, ahi, blo, bhi)
	local na, nb = isNeg(ahi), isNeg(bhi)
	if na then alo, ahi = neg64(alo, ahi) end
	if nb then blo, bhi = neg64(blo, bhi) end
	local o0, o1, o2, o3, o4, o5, o6, o7 = mulLimbs(alo, ahi, blo, bhi)
	local p0, p1 = o0 + o1 * 65536, o2 + o3 * 65536
	local q0, q1 = o4 + o5 * 65536, o6 + o7 * 65536
	if na ~= nb then
		if p0 ~= 0 or p1 ~= 0 then
			q0 = q0 + 1
			if q0 >= W then
				q0 = q0 - W
				q1 = q1 + 1
				if q1 >= W then q1 = q1 - W end
			end
		end
		return neg64(q0, q1)
	end
	return q0, q1
end

local function rotr64(lo, hi, n)
	n = n % 64
	if n == 0 then return lo, hi end
	if n >= 32 then lo, hi = hi, lo n = n - 32 end
	if n == 0 then return lo, hi end
	return bor(rshift(lo, n), lshift(hi, 32 - n)), bor(rshift(hi, n), lshift(lo, 32 - n))
end
local function rotl64(lo, hi, n) n = n % 64 if n == 0 then return lo, hi end return rotr64(lo, hi, 64 - n) end
local function shl64(lo, hi, n)
	if n == 0 then return lo, hi end
	if n >= 32 then return 0, lshift(lo, n - 32) end
	return lshift(lo, n), bor(lshift(hi, n), rshift(lo, 32 - n))
end

local function divmod64(dlo, dhi, d)
	local qlo, qhi, rlo, rhi = 0, 0, 0, 0
	for i = 63, 0, -1 do
		local lo1, hi1 = shl64(rlo, rhi, 1)
		local bit
		if i >= 32 then bit = band(rshift(dhi, i - 32), 1) else bit = band(rshift(dlo, i), 1) end
		rlo, rhi = lo1, hi1
		rlo = bor(rlo, bit)
		if rhi > 0 or rlo >= d then
			rlo, rhi = sb64(rlo, rhi, d, 0)
			if i >= 32 then qhi = bor(qhi, lshift(1, i - 32)) else qlo = bor(qlo, lshift(1, i)) end
		end
	end
	return qlo, qhi, rlo, rhi
end
local rcpCache = {}
local function reciprocal(d)
	local c = rcpCache[d]
	if c then return c[1], c[2] end
	local qlo, qhi, rlo, rhi = divmod64(0, 2147483648, d)
	local shift = 32
	local k = 2147483648
	while k > 0 do
		if band(k, d) ~= 0 then break end
		k = rshift(k, 1)
		shift = shift - 1
	end
	local slo, shi = shl64(qlo, qhi, shift)
	local tlo, thi = shl64(rlo, rhi, shift)
	local dlo, dhi = divmod64(tlo, thi, d)
	local r1, r2 = ad64(slo, shi, dlo, dhi)
	rcpCache[d] = { r1, r2 }
	return r1, r2
end

local function signExt(imm) if imm >= 2147483648 then return imm, 0xFFFFFFFF end return imm, 0 end
local function isZeroOrPow2(x) return band(x, x - 1) == 0 end

local function decodeWords(words)
	local n = #words
	local K, D, S, M, ILO, IHI, TGT, MASK, ZEROBASE = {}, {}, {}, {}, {}, {}, {}, {}, {}
	for pc = 1, n do
		local w = words[pc]
		local op, dst, src, mod, imm = w[1], w[2], w[3], w[4], w[5]
		local kind = (op < 16 and 1) or (op < 23 and 2) or (op < 39 and 3) or (op < 46 and 4) or (op < 62 and 5)
			or (op < 66 and 6) or (op < 70 and 7) or (op < 71 and 8) or (op < 75 and 9) or (op < 76 and 10)
			or (op < 84 and 11) or (op < 86 and 12) or (op < 101 and 13) or (op < 106 and 14) or (op < 114 and 15)
			or (op < 116 and 16) or (op < 120 and 17) or (op < 124 and 18) or (op < 140 and 19) or (op < 145 and 20)
			or (op < 161 and 21) or (op < 166 and 22) or (op < 172 and 23) or (op < 204 and 24) or (op < 208 and 25)
			or (op < 214 and 26) or (op < 239 and 27) or (op < 240 and 28) or 29
		local rd, rs = dst % 8, src % 8
		local d, s
		if kind == 18 then d = rd
		elseif kind == 19 or kind == 21 then d, s = dst % 4 + 1, src % 4 + 1
		elseif kind == 20 or kind == 22 then d, s = dst % 4 + 1, rs + 1
		elseif kind == 23 then d = dst % 4 + 1
		elseif kind == 24 then d, s = dst % 4 + 1, src % 4 + 1
		elseif kind == 25 or kind == 26 then d, s = dst % 4 + 1, rs + 1
		elseif kind == 27 then d, s = rd + 1, rs + 1
		else d, s = rd + 1, rs + 1 end
		local ilo, ihi = signExt(imm)
		if kind == 27 then
			local b = rshift(mod, 4) + ConditionOffset
			local mask = band(bor(ilo, lshift(1, b)), bnot(lshift(1, b - 1)))
			ilo, ihi = mask, ihi
		end
		K[pc], D[pc], S[pc], M[pc], ILO[pc], IHI[pc] = kind, d, s, mod, ilo, ihi
		TGT[pc] = 0
		local memMask = L3Mask
		local zeroBase = (rd == rs)
		if kind == 2 or kind == 4 or kind == 6 or kind == 8 or kind == 10 or kind == 14 then
			if rd ~= rs then memMask = (band(mod, 3) ~= 0) and L1Mask or L2Mask end
		elseif kind == 20 or kind == 22 or kind == 25 then
			memMask = (band(mod, 3) ~= 0) and L1Mask or L2Mask
		elseif kind == 29 then
			memMask = (rshift(mod, 4) < StoreL3Condition) and ((band(mod, 3) ~= 0) and L1Mask or L2Mask) or L3Mask
		end
		MASK[pc] = memMask
		ZEROBASE[pc] = zeroBase
	end
	return K, D, S, M, ILO, IHI, TGT, MASK, ZEROBASE
end

local function runSuperscalar(prog, rlo, rhi)
	local ins = prog.ins
	for j = 1, prog.size do
		local i2 = ins[j]
		local op = i2.op
		local d = i2.dst + 1
		local s = i2.src + 1
		if op == 0 then
			rlo[d], rhi[d] = sb64(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif op == 1 then
			rlo[d] = bxor(rlo[d], rlo[s]) rhi[d] = bxor(rhi[d], rhi[s])
		elseif op == 2 then
			local slo, shi = shl64(rlo[s], rhi[s], rshift(i2.mod, 2) % 4)
			rlo[d], rhi[d] = ad64(rlo[d], rhi[d], slo, shi)
		elseif op == 3 then
			rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif op == 4 then
			rlo[d], rhi[d] = rotr64(rlo[d], rhi[d], i2.imm)
		elseif op == 5 or op == 7 or op == 9 then
			local alo, ahi = signExt(i2.imm)
			rlo[d], rhi[d] = ad64(rlo[d], rhi[d], alo, ahi)
		elseif op == 6 or op == 10 then
			local alo, ahi = signExt(i2.imm)
			rlo[d] = bxor(rlo[d], alo) rhi[d] = bxor(rhi[d], ahi)
		elseif op == 8 then
			local alo, ahi = signExt(i2.imm)
			rlo[d] = bxor(rlo[d], alo) rhi[d] = bxor(rhi[d], ahi)
		elseif op == 11 then
			rlo[d], rhi[d] = mul64hi(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif op == 12 then
			rlo[d], rhi[d] = smulh(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif op == 13 then
			local xlo, xhi = reciprocal(i2.imm)
			rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], xlo, xhi)
		end
	end
end

local DST_CONST = {
	[2] = { 0x59F5A1FC, 0x810A978A }, [3] = { 0x38C2D846, 0xA77099DF }, [4] = { 0xBF22495C, 0x8126B91C },
	[5] = { 0x179F8A62, 0x494D2597 }, [6] = { 0xCEAAEC0C, 0x9237EFB9 }, [7] = { 0x6CE62D78, 0x2F2A5674 },
	[8] = { 0xB62CE54E, 0x84853BF7 },
}

local function datasetItem(cache, progs, itemNumber, rlo, rhi)
	local baseLo, baseHi = mul64lo(itemNumber + 1, 0, 0x4C957F2D, 0x5851F42D)
	rlo[1], rhi[1] = baseLo, baseHi
	for i = 2, 8 do
		rlo[i] = bxor(baseLo, DST_CONST[i][1])
		rhi[i] = bxor(baseHi, DST_CONST[i][2])
	end
	local cacheIndex = itemNumber
	for i = 1, 8 do
		local prog = progs[i]
		runSuperscalar(prog, rlo, rhi)
		local off = band(cacheIndex, CacheItemsMask) * 64
		for w = 0, 7 do
			rlo[w + 1] = bxor(rlo[w + 1], buffer.readu32(cache, off + w * 8))
			rhi[w + 1] = bxor(rhi[w + 1], buffer.readu32(cache, off + w * 8 + 4))
		end
		cacheIndex = rlo[prog.addrReg + 1]
	end
end


local function execProgram(K, D, S, MU, ILO, IHI, TGT, MASK, ZEROBASE, words, scratch, rlo, rhi, flo, fhi, elo, ehi, alo, ahi, eMask, spAddr0, spAddr1, hook)
	local pc = 1
	while pc <= ProgramSize do
		local k = K[pc]
		local d = D[pc]
		local s = S[pc]
		local mod = MU[pc]
		
		if k == 1 then
			local slo, shi = shl64(rlo[s], rhi[s], rshift(mod, 2) % 4)
			if d == 6 then slo, shi = ad64(slo, shi, ILO[pc], IHI[pc]) end
			rlo[d], rhi[d] = ad64(rlo[d], rhi[d], slo, shi)
		elseif k == 2 or k == 4 or k == 6 or k == 8 or k == 10 or k == 14 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			if k == 2 then rlo[d], rhi[d] = ad64(rlo[d], rhi[d], mlo, mhi)
			elseif k == 4 then rlo[d], rhi[d] = sb64(rlo[d], rhi[d], mlo, mhi)
			elseif k == 6 then rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], mlo, mhi)
			elseif k == 8 then rlo[d], rhi[d] = mul64hi(rlo[d], rhi[d], mlo, mhi)
			elseif k == 10 then rlo[d], rhi[d] = smulh(rlo[d], rhi[d], mlo, mhi)
			else rlo[d] = bxor(rlo[d], mlo) rhi[d] = bxor(rhi[d], mhi) end
		elseif k == 3 then
			if s ~= d then rlo[d], rhi[d] = sb64(rlo[d], rhi[d], rlo[s], rhi[s])
			else rlo[d], rhi[d] = sb64(rlo[d], rhi[d], ILO[pc], IHI[pc]) end
		elseif k == 5 then
			if s ~= d then rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], rlo[s], rhi[s])
			else rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], ILO[pc], IHI[pc]) end
		elseif k == 7 then rlo[d], rhi[d] = mul64hi(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif k == 9 then rlo[d], rhi[d] = smulh(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif k == 11 then
			local xlo, xhi = reciprocal(words[pc][5])
			rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], xlo, xhi)
		elseif k == 12 then rlo[d], rhi[d] = neg64(rlo[d], rhi[d])
		elseif k == 13 then
			if s ~= d then rlo[d] = bxor(rlo[d], rlo[s]) rhi[d] = bxor(rhi[d], rhi[s])
			else rlo[d] = bxor(rlo[d], ILO[pc]) rhi[d] = bxor(rhi[d], IHI[pc]) end
		elseif k == 15 then
			if s ~= d then rlo[d], rhi[d] = rotr64(rlo[d], rhi[d], rlo[s] % 64)
			else rlo[d], rhi[d] = rotr64(rlo[d], rhi[d], words[pc][5] % 64) end
		elseif k == 16 then
			if s ~= d then rlo[d], rhi[d] = rotl64(rlo[d], rhi[d], rlo[s] % 64)
			else rlo[d], rhi[d] = rotl64(rlo[d], rhi[d], words[pc][5] % 64) end
		elseif k == 17 then
			if s ~= d then rlo[d], rhi[d], rlo[s], rhi[s] = rlo[s], rhi[s], rlo[d], rhi[d] end
		elseif k == 18 then
			if d < 4 then flo[d + 1], fhi[d + 1] = fhi[d + 1], flo[d + 1] else elo[d - 3], ehi[d - 3] = ehi[d - 3], elo[d - 3] end
		elseif k == 19 then
			flo[d] = fadd(flo[d], alo[s]) fhi[d] = fadd(fhi[d], ahi[s])
		elseif k == 20 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			if M.debug then M.debug(string.format("faddm pc=%d d=%d addr=%x p0=%d p1=%d", pc, d, addr, flo[d], fhi[d])) end
			flo[d] = fadd(flo[d], buffer.readi32(scratch, addr))
			fhi[d] = fadd(fhi[d], buffer.readi32(scratch, addr + 4))
			if M.debug then M.debug(string.format("after d=%d lo=%d hi=%d", d, flo[d], fhi[d])) end
		elseif k == 21 then
			flo[d] = fsub(flo[d], alo[s]) fhi[d] = fsub(fhi[d], ahi[s])
		elseif k == 22 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			flo[d] = fsub(flo[d], buffer.readi32(scratch, addr))
			fhi[d] = fsub(fhi[d], buffer.readi32(scratch, addr + 4))
		elseif k == 23 then
			local lo, hi = f2b(flo[d]) flo[d] = b2f(lo, bxor(hi, 0x80F00000))
			lo, hi = f2b(fhi[d]) fhi[d] = b2f(lo, bxor(hi, 0x80F00000))
		elseif k == 24 then
			elo[d] = fprod(elo[d], alo[s]) ehi[d] = fprod(ehi[d], ahi[s])
		elseif k == 25 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			local m1, m2 = eMask[1][1], eMask[1][2]
			local x1, x2 = f2b(buffer.readi32(scratch, addr))
			local d1 = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			m1, m2 = eMask[2][1], eMask[2][2]
			x1, x2 = f2b(buffer.readi32(scratch, addr + 4))
			local d2 = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			elo[d] = fdiv(elo[d], d1) ehi[d] = fdiv(ehi[d], d2)
		elseif k == 26 then
			if M.debug then M.debug(string.format("fsqrt pc=%d fprc=%d x0=%d x1=%d", pc, fprc, elo[d], ehi[d])) end
			elo[d] = fsqrt(elo[d]) ehi[d] = fsqrt(ehi[d])
		elseif k == 27 then
			rlo[d], rhi[d] = ad64(rlo[d], rhi[d], ILO[pc], IHI[pc])
			if M.debug then M.debug(string.format('cb d=%d ilo=%08x pc=%d tgt=%d', d, ILO[pc], pc, TGT[pc])) end
			if band(rlo[d], lshift(ConditionMask, rshift(mod, 4) + ConditionOffset)) == 0 then pc = TGT[pc] end
		elseif k == 28 then
			local r1 = rotr64(rlo[s], rhi[s], words[pc][5] % 64)
			fprc = band(r1, 3)
		elseif k == 29 then
			local addr = band(rlo[d] + ILO[pc], MASK[pc])
			buffer.writeu32(scratch, addr, rlo[s])
			buffer.writeu32(scratch, addr + 4, rhi[s])
		end
		if hook then hook(pc) end
		pc = pc + 1
	end

end
M._exec = execProgram
M.datasetItem = datasetItem
M.decodeWords = decodeWords

function M.hash(blake, aes, ss, cache, key, input)
	local scratch = buffer.create(ScratchpadSize)
	local seed = blake.blake2b(input, 64)
	local gen1 = aes.gen1R(seed)
	for i = 0, ScratchpadSize / 64 - 1 do
		buffer.writestring(scratch, i * 64, gen1:next())
	end
	local gen4 = aes.gen4R(gen1.state)

	local sgen = ss.newGen(blake, key)
	local progs = {}
	for i = 1, 8 do progs[i] = ss.generate(sgen) end

	local rlo, rhi, flo, fhi, elo, ehi, alo, ahi = {}, {}, {}, {}, {}, {}, {}, {}
	local words, tgt = {}, {}

	for chain = 1, (M._chains or ProgramCount) do
		-- referencni execute() ma nreg.r zero-inicializovane pri kazdem chainu
		for i = 1, 8 do rlo[i] = 0 rhi[i] = 0 end
		local parts = {}
		for i = 1, 34 do parts[i] = gen4:next() end
		local blob = buffer.fromstring(table.concat(parts))
		if M.traceBlob then print("BLOB:" .. (blob and (buffer.readstring(blob, 0, 8):gsub('.', function(c) return string.format('%02x', string.byte(c)) end)))) end
		local ent = {}
		for i = 0, 15 do ent[i] = { buffer.readu32(blob, i * 8), buffer.readu32(blob, i * 8 + 4) } end
		local function small(lo, hi)
			local exp = band(rshift(hi, 27) + 1023, 2047)
			return b2f(lo, bor(band(hi, 0xFFFFF), lshift(exp, 20)))
		end
		for i = 0, 3 do
			alo[i + 1] = small(ent[i * 2][1], ent[i * 2][2])
			ahi[i + 1] = small(ent[i * 2 + 1][1], ent[i * 2 + 1][2])
		end
		local ma = band(ent[8][1], CacheLineAlignMask)
		local mx = ent[10][1]
		local ar = ent[12][1]
		local readReg0 = band(ar, 1) + 1 ar = rshift(ar, 1)
		local readReg1 = band(ar, 1) + 3 ar = rshift(ar, 1)
		local readReg2 = band(ar, 1) + 5 ar = rshift(ar, 1)
		local readReg3 = band(ar, 1) + 7
		local datasetOffset = (ent[13][1] % (DatasetExtraItems + 1)) * CacheLineSize
		local eMask = {}
		for k = 1, 2 do
			local lo, hi = ent[13 + k][1], ent[13 + k][2]
			local expo = bor(0x300, lshift(band(rshift(hi, 28), 0xF), 4))
			eMask[k] = { band(lo, 0x3FFFFF), lshift(expo, 20) }
		end

		for i = 1, ProgramSize do
			local o = 128 + (i - 1) * 8
			words[i] = { buffer.readu8(blob, o), buffer.readu8(blob, o + 1), buffer.readu8(blob, o + 2), buffer.readu8(blob, o + 3), buffer.readu32(blob, o + 4) }
		end
		local K, D, S, MU, ILO, IHI, TGT, MASK, ZEROBASE = decodeWords(words)
		local usage = {}
		for i = 1, 8 do usage[i] = 0 end
		for pc = 1, ProgramSize do
			local k = K[pc]
			if k == 27 then
				TGT[pc] = usage[D[pc]]
				for j = 1, 8 do usage[j] = pc end
			elseif k == 17 then
				if S[pc] ~= D[pc] then usage[D[pc]] = pc usage[S[pc]] = pc end
			elseif k == 11 then
				if not isZeroOrPow2(words[pc][5]) then usage[D[pc]] = pc end
			elseif k ~= 18 and k ~= 19 and k ~= 20 and k ~= 21 and k ~= 22 and k ~= 23 and k ~= 24 and k ~= 25 and k ~= 26 and k ~= 28 and k ~= 29 and k ~= 30 then
				usage[D[pc]] = pc
			end
		end

		local spAddr0, spAddr1 = mx, ma
		for ic = 1, (M._iters or ProgramIterations) do
			spAddr0 = band(bxor(spAddr0, bxor(rlo[readReg0], rlo[readReg1])), L3Mask64)
			spAddr1 = band(bxor(spAddr1, bxor(rhi[readReg0], rhi[readReg1])), L3Mask64)
			for i = 1, 8 do
				local o = spAddr0 + (i - 1) * 8
				rlo[i] = bxor(rlo[i], buffer.readu32(scratch, o))
				rhi[i] = bxor(rhi[i], buffer.readu32(scratch, o + 4))
			end
			if M.traceSp and ic == 2 then
				local t = {}
				for i = 1, 8 do t[i] = string.format("%08x%08x", rhi[i], rlo[i]) end
				print("RAW " .. string.format("%08x %08x", buffer.readu32(scratch, spAddr1), buffer.readu32(scratch, spAddr1+4)))
				print("DBG sp0=" .. string.format("%x", spAddr0) .. " sp1=" .. string.format("%x", spAddr1) .. " r=" .. table.concat(t, " "))
			end
			for i = 1, 4 do
				local o = spAddr1 + (i - 1) * 8
				flo[i] = buffer.readi32(scratch, o)
				fhi[i] = buffer.readi32(scratch, o + 4)
				local o2 = spAddr1 + (i + 3) * 8
				local m1, m2 = eMask[1][1], eMask[1][2]
				local x1, x2 = f2b(buffer.readi32(scratch, o2))
				elo[i] = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
				m1, m2 = eMask[2][1], eMask[2][2]
				x1, x2 = f2b(buffer.readi32(scratch, o2 + 4))
				ehi[i] = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			end

				local fb = {}
				for i = 1, 4 do local a1, a2 = f2b(flo[i]) local b1, b2 = f2b(fhi[i]) fb[i] = string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
				print("DBGFE f:" .. table.concat(fb))
				local eb = {}
				for i = 1, 4 do local a1, a2 = f2b(elo[i]) local b1, b2 = f2b(ehi[i]) eb[i] = string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
				print("DBGFE e:" .. table.concat(eb))
				print("DBGFN " .. tostring(flo[1]) .. " direct=" .. tostring(buffer.readi32(scratch, spAddr1)))
			local hook
			if M.tracePC and chain == (M.traceChain or 1) and ic == (M.traceIt or 1) then
				hook = function(pc)
					local o = "pc" .. (pc - 1) .. " k" .. tostring(K[pc]) .. " d" .. tostring(D[pc]) .. " s" .. tostring(S[pc]) .. " r:"
					for i = 1, 8 do o = o .. " " .. string.format("%08x%08x", rhi[i], rlo[i]) end
					o = o .. " f:"
					for i = 1, 4 do local a1, a2 = f2b(flo[i]) local b1, b2 = f2b(fhi[i]) o = o .. string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
					o = o .. " e:"
					for i = 1, 4 do local a1, a2 = f2b(elo[i]) local b1, b2 = f2b(ehi[i]) o = o .. string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
					print(o)
				end
			end
			execProgram(K, D, S, MU, ILO, IHI, TGT, MASK, ZEROBASE, words, scratch, rlo, rhi, flo, fhi, elo, ehi, alo, ahi, eMask, spAddr0, spAddr1, hook)
			if M.traceReg then
				local rb = buffer.create(256)
				for i = 1, 8 do buffer.writeu32(rb, (i-1)*8, rlo[i]) buffer.writeu32(rb, (i-1)*8+4, rhi[i]) end
				for i = 1, 4 do
					buffer.writef64(rb, 64+(i-1)*8, flo[i]) buffer.writef64(rb, 96+(i-1)*8, fhi[i])
					buffer.writef64(rb, 128+(i-1)*8, elo[i]) buffer.writef64(rb, 160+(i-1)*8, ehi[i])
				end
				print("rg:" .. (buffer.readstring(rb,0,256):gsub(".", function(c) return string.format("%02x", string.byte(c)) end)))
			end
			if M.traceSp then print(("sp:" .. string.format("%02x%02x%02x%02x", string.byte(blake.blake2b(buffer.readstring(scratch, 0, 2097152), 32), 1, 4)))) end
			local mt = ma
			local readPtr = datasetOffset + band(ma, CacheLineAlignMask)
			mx = bxor(mx, bxor(rlo[readReg2], rlo[readReg3]))
			do
				local irlo, irhi = {}, {}
				datasetItem(cache, progs, rshift(readPtr, 6), irlo, irhi)
				for i = 1, 8 do
					rlo[i] = bxor(rlo[i], irlo[i])
					rhi[i] = bxor(rhi[i], irhi[i])
				end
			end
			ma, mx = mx, ma
			for i = 1, 8 do
				local o = spAddr1 + (i - 1) * 8
				buffer.writeu32(scratch, o, rlo[i])
				buffer.writeu32(scratch, o + 4, rhi[i])
			end
			for i = 1, 4 do
				local lo, hi = f2b(flo[i]) local l2, h2 = f2b(elo[i])
				local lo3, hi3 = f2b(fhi[i]) local l4, h4 = f2b(ehi[i])
				flo[i] = b2f(bxor(lo, l2), bxor(hi, h2)) fhi[i] = b2f(bxor(lo3, l4), bxor(hi3, h4))
			end
			if M.traceSp and ic == 1 then print(string.format("FSTORE sp0=%x sp1=%x", spAddr0, spAddr1)) end
			for i = 1, 4 do
				buffer.writef64(scratch, spAddr0 + (i - 1) * 16, flo[i])
				buffer.writef64(scratch, spAddr0 + (i - 1) * 16 + 8, fhi[i])
			end
			spAddr0, spAddr1 = 0, 0
		end

		if chain < ProgramCount then
			local rf = buffer.create(256)
			for i = 1, 8 do
				buffer.writeu32(rf, (i - 1) * 8, rlo[i])
				buffer.writeu32(rf, (i - 1) * 8 + 4, rhi[i])
			end
			for i = 1, 4 do
				buffer.writef64(rf, 64 + (i - 1) * 16, flo[i]) buffer.writef64(rf, 64 + (i - 1) * 16 + 8, fhi[i])
				buffer.writef64(rf, 128 + (i - 1) * 16, elo[i]) buffer.writef64(rf, 128 + (i - 1) * 16 + 8, ehi[i])
				buffer.writef64(rf, 192 + (i - 1) * 16, alo[i]) buffer.writef64(rf, 192 + (i - 1) * 16 + 8, ahi[i])
			end
			if M.traceRF then print("RF:" .. (buffer.readstring(rf, 0, 256):gsub('.', function(ch) return string.format('%02x', string.byte(ch)) end))) end
			gen4.state = blake.blake2b(buffer.readstring(rf, 0, 256), 64)
		end
	end

	local rf = buffer.create(256)
	for i = 1, 8 do
		buffer.writeu32(rf, (i - 1) * 8, rlo[i])
		buffer.writeu32(rf, (i - 1) * 8 + 4, rhi[i])
	end
	for i = 1, 4 do
		buffer.writef64(rf, 64 + (i - 1) * 16, flo[i]) buffer.writef64(rf, 64 + (i - 1) * 16 + 8, fhi[i])
		buffer.writef64(rf, 128 + (i - 1) * 16, elo[i]) buffer.writef64(rf, 128 + (i - 1) * 16 + 8, ehi[i])
		buffer.writef64(rf, 192 + (i - 1) * 16, alo[i]) buffer.writef64(rf, 192 + (i - 1) * 16 + 8, ahi[i])
	end
	buffer.writestring(rf, 192, aes.hash1R(scratch))
	return blake.blake2b(buffer.readstring(rf, 0, 256), 32)
end

return M
