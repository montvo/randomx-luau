-- BLAKE2b (RFC 7693) in pure Luau.
-- 64-bit words are represented as {lo, hi} pairs of 32-bit numbers.
-- Supports optional key (0..64 bytes) and output length 1..64 bytes.
-- Also provides blakeLong (RFC 9106 H', Argon2 variable-length hash).

local bor, bxor, lshift, rshift = bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift

local M = {}

local IV = {
	{ 0xF3BCC908, 0x6A09E667 },
	{ 0x84CAA73B, 0xBB67AE85 },
	{ 0xFE94F82B, 0x3C6EF372 },
	{ 0x5F1D36F1, 0xA54FF53A },
	{ 0xADE682D1, 0x510E527F },
	{ 0x2B3E6C1F, 0x9B05688C },
	{ 0xFB41BD6B, 0x1F83D9AB },
	{ 0x137E2179, 0x5BE0CD19 },
}

local SIGMA = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
}

-- 64-bit helpers -----------------------------------------------------------

local function add64(a, b)
	local lo = a[1] + b[1]
	local hi = a[2] + b[2] + (lo >= 0x100000000 and 1 or 0)
	return { lo % 0x100000000, hi % 0x100000000 }
end

local function xor64(a, b)
	return { bxor(a[1], b[1]), bxor(a[2], b[2]) }
end

local function rotr64(x, n)
	n = n % 64
	local lo, hi = x[1], x[2]
	if n >= 32 then
		lo, hi = hi, lo
		n = n - 32
	end
	if n == 0 then
		return { lo, hi }
	end
	return {
		bor(rshift(lo, n), lshift(hi, 32 - n)),
		bor(rshift(hi, n), lshift(lo, 32 - n)),
	}
end

-- Compression function on a flat 16-word vector.
local function G(v, a, b, c, d, x, y)
	v[a] = add64(add64(v[a], v[b]), x)
	v[d] = rotr64(xor64(v[d], v[a]), 32)
	v[c] = add64(v[c], v[d])
	v[b] = rotr64(xor64(v[b], v[c]), 24)
	v[a] = add64(add64(v[a], v[b]), y)
	v[d] = rotr64(xor64(v[d], v[a]), 16)
	v[c] = add64(v[c], v[d])
	v[b] = rotr64(xor64(v[b], v[c]), 63)
end

local function compress(h, m, t, isFinal)
	local v = {}
	for i = 1, 8 do
		v[i] = { h[i][1], h[i][2] }
		v[i + 8] = { IV[i][1], IV[i][2] }
	end
	v[13] = xor64(v[13], { t[1], t[2] })
	if isFinal then
		v[15] = xor64(v[15], { 0xFFFFFFFF, 0xFFFFFFFF })
	end

	for r = 0, 11 do
		local s = SIGMA[r % 10 + 1]
		G(v, 1, 5, 9, 13, m[s[1] + 1], m[s[2] + 1])
		G(v, 2, 6, 10, 14, m[s[3] + 1], m[s[4] + 1])
		G(v, 3, 7, 11, 15, m[s[5] + 1], m[s[6] + 1])
		G(v, 4, 8, 12, 16, m[s[7] + 1], m[s[8] + 1])
		G(v, 1, 6, 11, 16, m[s[9] + 1], m[s[10] + 1])
		G(v, 2, 7, 12, 13, m[s[11] + 1], m[s[12] + 1])
		G(v, 3, 8, 9, 14, m[s[13] + 1], m[s[14] + 1])
		G(v, 4, 5, 10, 15, m[s[15] + 1], m[s[16] + 1])
	end

	for i = 1, 8 do
		h[i] = xor64(xor64(h[i], v[i]), v[i + 8])
	end
end

-- Load 8 little-endian bytes starting at position p (1-based) into a word.
local function loadWord(s, p)
	local b1, b2, b3, b4 = string.byte(s, p, p + 3)
	local b5, b6, b7, b8 = string.byte(s, p + 4, p + 7)
	return {
		bor(bor(b1, lshift(b2, 8)), bor(lshift(b3, 16), lshift(b4, 24))),
		bor(bor(b5, lshift(b6, 8)), bor(lshift(b7, 16), lshift(b8, 24))),
	}
end

local function le32(n)
	local b = {}
	for i = 1, 4 do
		b[i] = string.char(n % 256)
		n = math.floor(n / 256)
	end
	return table.concat(b)
end

-- Core driver: hashes `data` with given outlen/key.
local function hash(data, outlen, key)
	local kk = key and #key or 0
	local h = {}
	for i = 1, 8 do
		h[i] = { IV[i][1], IV[i][2] }
	end
	h[1] = { bxor(h[1][1], bxor(0x01010000, bxor(lshift(kk, 8), outlen))), h[1][2] }

	-- Layout: an optional padded 128-byte key block first, then the message
	-- split into 128-byte blocks.  The key block always counts as a full
	-- block for the offset counter t.  An unkeyed empty message still yields
	-- one all-zero block with t = 0.
	local ll = #data
	local keyBlocks = kk > 0 and 1 or 0
	local msgBlocks = ll > 0 and math.ceil(ll / 128) or 0
	local blocks = keyBlocks + msgBlocks
	if blocks < 1 then
		blocks = 1
	end

	local t = { 0, 0 }
	for bi = 1, blocks do
		local blockStr
		local countedBytes
		if bi <= keyBlocks then
			countedBytes = 128
			blockStr = key:sub(1, 128) .. ("\0"):rep(128 - math.min(kk, 128))
		else
			local offset = (bi - keyBlocks - 1) * 128
			local n = ll - offset
			if n > 128 then
				n = 128
			end
			countedBytes = n
			blockStr = data:sub(offset + 1, offset + n) .. ("\0"):rep(128 - n)
		end

		local m = {}
		for w = 0, 15 do
			m[w + 1] = loadWord(blockStr, w * 8 + 1)
		end

		t[1] = t[1] + countedBytes
		if t[1] >= 0x100000000 then
			t[1] = t[1] - 0x100000000
			t[2] = t[2] + 1
		end

		compress(h, m, t, bi == blocks)
	end

	return h
end

local function finalize(h, outlen)
	local parts = {}
	local need = outlen
	for i = 1, 8 do
		if need <= 0 then
			break
		end
		local w = h[i]
		local bytes = {
			string.char(w[1] % 256),
			string.char(math.floor(w[1] / 256) % 256),
			string.char(math.floor(w[1] / 65536) % 256),
			string.char(math.floor(w[1] / 16777216) % 256),
			string.char(w[2] % 256),
			string.char(math.floor(w[2] / 256) % 256),
			string.char(math.floor(w[2] / 65536) % 256),
			string.char(math.floor(w[2] / 16777216) % 256),
		}
		local take = need < 8 and need or 8
		parts[#parts + 1] = table.concat(bytes, "", 1, take)
		need = need - take
	end
	return table.concat(parts)
end

function M.blake2b(msg, outlen, key)
	msg = msg or ""
	key = key or ""
	assert(type(key) == "string" and #key <= 64, "key must be a string of at most 64 bytes")
	assert(type(outlen) == "number" and outlen >= 1 and outlen <= 64, "outlen must be 1..64")
	local h = hash(msg, outlen, key)
	return finalize(h, outlen)
end

function M.blakeLong(outlen, msg)
	msg = msg or ""
	if outlen <= 64 then
		return M.blake2b(le32(outlen) .. msg, outlen, "")
	end
	local v = M.blake2b(le32(outlen) .. msg, 64, "")
	local r = math.ceil(outlen / 32) - 2
	local acc = {}
	for i = 1, r do
		acc[#acc + 1] = v:sub(1, 32)
		if i < r then
			v = M.blake2b(v, 64, "")
		end
	end
	local tail = outlen - 32 * r
	acc[#acc + 1] = M.blake2b(v, tail, "")
	return table.concat(acc)
end

return M
