local bit32 = bit32
local band, bor, bxor, bnot, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.lshift, bit32.rshift
local sqrt = math.sqrt
local W = 4294967296

local ScratchpadSize = 2097152
local CacheLineSize = 64
local CacheLineAlignMask = 0xFFFFFFC0
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
local function fprod(a, b)
	local p = a * b
	local ah = C * a local ahi = ah - (ah - a) local alo = a - ahi
	local bh = C * b local bhi = bh - (bh - b) local blo = b - bhi
	return applyRound(p, ((ahi * bhi - p) + ahi * blo + alo * bhi) + alo * blo)
end
local function fdiv(a, b) local q = a / b return applyRound(q, a - q * b) end
local function fsqrt(x) local s = sqrt(x) return applyRound(s, x - s * s) end

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


local x = 9223372036854775807
local s = sqrt(x)
print("sqrt", s)
for _, mode in ipairs({0,1,2,3}) do fprc = mode print(mode, fsqrt(x)) end
