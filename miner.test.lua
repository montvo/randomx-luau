-- miner.lua — GENEROVANY SOUBOR, needituj primo (viz miner/main.lua + tools/bundle.py)
-- RandomX v1 (rx/0) miner pro Roblox executor pres lokalni WS bridge.

local __mod = function(src, name)
	local f = (loadstring or load)(src, '=' .. name)
	assert(f, 'modul se nenacetl: ' .. name)
	return f()
end

local blake = __mod([==[
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
]==], 'blake')

local aes = __mod([==[
--!strict
-- AES-128 (FIPS-197) single round + RandomX custom functions built on it.
-- Ground truth: rxsrc/src/soft_aes.cpp, rxsrc/src/aes_hash.cpp, spec 3.2-3.4.
--
-- encRound = SubBytes, ShiftRows, MixColumns, XOR key
-- decRound = InvShiftRows, InvSubBytes, InvMixColumns, XOR key
-- (byte-exact equivalent of soft_aesenc/soft_aesdec with the portable
--  rx_set_int_vec_i128 word order, i.e. a plain 16-byte AES state.)
--
-- gen1R  = AesGenerator1R  (spec 3.2)
-- gen4R  = AesGenerator4R  (spec 3.3)
-- hash1R = AesHash1R       (spec 3.4)
--
-- Pure Luau, bit32 + precomputed T-tables.

local bit32 = bit32
local band, bxor, shr, shl, ror = bit32.band, bit32.bxor, bit32.rshift, bit32.lshift, bit32.rrotate
local sbyte, schar = string.byte, string.char

local M = {}

--------------------------------------------------------------------------------
-- GF(2^8) helpers / tables
--------------------------------------------------------------------------------

local function gmul(a: number, b: number): number
	local r = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then
			r = bxor(r, a)
		end
		local t = shl(a, 1)
		if t > 0xff then
			t = bxor(t, 0x11b)
		end
		a = t
		b = shr(b, 1)
	end
	return r
end

local function rotl8(x: number, n: number): number
	return band(bxor(shl(x, n), shr(x, 8 - n)), 0xff)
end

local S: { number } = {}
local IS: { number } = {}

do
	-- multiplicative inverses in GF(2^8)
	local inv: { number } = { [0] = 0 }
	for a = 1, 255 do
		for b = 1, 255 do
			if gmul(a, b) == 1 then
				inv[a] = b
				break
			end
		end
	end
	for x = 0, 255 do
		local y = inv[x] or 0
		S[x] = bxor(y, bxor(bxor(bxor(rotl8(y, 1), rotl8(y, 2)), bxor(rotl8(y, 3), rotl8(y, 4))), 0x63))
	end
	for x = 0, 255 do
		IS[S[x]] = x
	end
end

-- T tables: T1..T4 for encryption, D1..D4 for decryption.
-- T1[x] holds [2s, s, s, 3s] with byte 0 in the low 8 bits; T2..T4 are its
-- 8/16/24-bit rotates. D1[x] holds [0e, 09, 0d, 0b] * InvS(x), D2..D4 rotated.
local T1, T2, T3, T4 = {}, {}, {}, {}
local D1, D2, D3, D4 = {}, {}, {}, {}
for x = 0, 255 do
	local s = S[x]
	local w = gmul(s, 2) + s * 0x100 + s * 0x10000 + gmul(s, 3) * 0x1000000
	T1[x], T2[x], T3[x], T4[x] = w, ror(w, 24), ror(w, 16), ror(w, 8)
	local i = IS[x]
	local d = gmul(i, 14) + gmul(i, 9) * 0x100 + gmul(i, 13) * 0x10000 + gmul(i, 11) * 0x1000000
	D1[x], D2[x], D3[x], D4[x] = d, ror(d, 24), ror(d, 16), ror(d, 8)
end

local function packW(w0: number, w1: number, w2: number, w3: number): string
	return schar(
		band(w0, 0xff), band(shr(w0, 8), 0xff), band(shr(w0, 16), 0xff), band(shr(w0, 24), 0xff),
		band(w1, 0xff), band(shr(w1, 8), 0xff), band(shr(w1, 16), 0xff), band(shr(w1, 24), 0xff),
		band(w2, 0xff), band(shr(w2, 8), 0xff), band(shr(w2, 16), 0xff), band(shr(w2, 24), 0xff),
		band(w3, 0xff), band(shr(w3, 8), 0xff), band(shr(w3, 16), 0xff), band(shr(w3, 24), 0xff)
	)
end

-- 16-byte column at `off` of `s`, round key `kw` (4 words) -> 16 bytes
local function encCol(s: string, off: number, kw: { number }): string
	local b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = sbyte(s, off, off + 15)
	local w0 = bxor(bxor(bxor(T1[b0], T2[b5]), bxor(T3[b10], T4[b15])), kw[1])
	local w1 = bxor(bxor(bxor(T1[b4], T2[b9]), bxor(T3[b14], T4[b3])), kw[2])
	local w2 = bxor(bxor(bxor(T1[b8], T2[b13]), bxor(T3[b2], T4[b7])), kw[3])
	local w3 = bxor(bxor(bxor(T1[b12], T2[b1]), bxor(T3[b6], T4[b11])), kw[4])
	return packW(w0, w1, w2, w3)
end

local function decCol(s: string, off: number, kw: { number }): string
	local b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = sbyte(s, off, off + 15)
	local w0 = bxor(bxor(bxor(D1[b0], D2[b13]), bxor(D3[b10], D4[b7])), kw[1])
	local w1 = bxor(bxor(bxor(D1[b4], D2[b1]), bxor(D3[b14], D4[b11])), kw[2])
	local w2 = bxor(bxor(bxor(D1[b8], D2[b5]), bxor(D3[b2], D4[b15])), kw[3])
	local w3 = bxor(bxor(bxor(D1[b12], D2[b9]), bxor(D3[b6], D4[b3])), kw[4])
	return packW(w0, w1, w2, w3)
end

local function unhex(h: string): string
	local out = table.create(#h // 2)
	for i = 1, #h, 2 do
		local v = tonumber(string.sub(h, i, i + 1), 16) :: number
		table.insert(out, schar(v))
	end
	return table.concat(out)
end

local function keyWords(key: string): { number }
	local k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15 = sbyte(key, 1, 16)
	return {
		k0 + k1 * 0x100 + k2 * 0x10000 + k3 * 0x1000000,
		k4 + k5 * 0x100 + k6 * 0x10000 + k7 * 0x1000000,
		k8 + k9 * 0x100 + k10 * 0x10000 + k11 * 0x1000000,
		k12 + k13 * 0x100 + k14 * 0x10000 + k15 * 0x1000000,
	}
end

local function wordsAt(s: string, off: number): { number }
	local a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p = sbyte(s, off, off + 15)
	return {
		a + b * 0x100 + c * 0x10000 + d * 0x1000000,
		e + f * 0x100 + g * 0x10000 + h * 0x1000000,
		i + j * 0x100 + k * 0x10000 + l * 0x1000000,
		m + n * 0x100 + o * 0x10000 + p * 0x1000000,
	}
end

--------------------------------------------------------------------------------
-- Public round functions
--------------------------------------------------------------------------------

function M.encRound(state: string, key: string): string
	assert(#state == 16 and #key == 16, "encRound needs 16-byte state and key")
	return encCol(state, 1, keyWords(key))
end

function M.decRound(state: string, key: string): string
	assert(#state == 16 and #key == 16, "decRound needs 16-byte state and key")
	return decCol(state, 1, keyWords(key))
end

--------------------------------------------------------------------------------
-- AesGenerator1R (spec 3.2)
--------------------------------------------------------------------------------

local K1R = {
	keyWords(unhex("53a5ac6d096671622b55b5db1749f4b4")),
	keyWords(unhex("07af7c6d0d716a8478d325174edca10d")),
	keyWords(unhex("f162123fc67e949f4f79c0f445e3203e")),
	keyWords(unhex("3581ef6a7c31bab1884c311654911649")),
}

function M.gen1R(seed: string)
	assert(#seed == 64, "gen1R needs a 64-byte seed")
	local o = { state = seed }
	function o:next(): string
		local s = self.state
		local r = decCol(s, 1, K1R[1])
			.. encCol(s, 17, K1R[2])
			.. decCol(s, 33, K1R[3])
			.. encCol(s, 49, K1R[4])
		self.state = r
		return r
	end
	return o
end

--------------------------------------------------------------------------------
-- AesGenerator4R (spec 3.3)
--------------------------------------------------------------------------------

local K4R = {
	keyWords(unhex("ddaa2164db3d83d12b6d542f3fd2e599")),
	keyWords(unhex("50340eb2553f91b6539df706e5cddfa5")),
	keyWords(unhex("04d93e5caf7b5e519f67a40abf021c17")),
	keyWords(unhex("63376285085d8fe7853767cd91d2ded8")),
	keyWords(unhex("736f82b5a6a7d6e36d8b513db4ff9e22")),
	keyWords(unhex("f36b56c7d9b3109c4e4d02e9d2b772b2")),
	keyWords(unhex("e7c973f28ba365f70a66a92ba7ef3bf6")),
	keyWords(unhex("09d67c7ade395891fdd1060c2d76b0c0")),
}

function M.gen4R(seed: string)
	assert(#seed == 64, "gen4R needs a 64-byte seed")
	local o = { state = seed }
	function o:next(): string
		local s = self.state
		local c0 = decCol(s, 1, K4R[1])
		local c1 = encCol(s, 17, K4R[1])
		local c2 = decCol(s, 33, K4R[5])
		local c3 = encCol(s, 49, K4R[5])
		for r = 2, 4 do
			c0 = decCol(c0, 1, K4R[r])
			c1 = encCol(c1, 1, K4R[r])
			c2 = decCol(c2, 1, K4R[r + 4])
			c3 = encCol(c3, 1, K4R[r + 4])
		end
		local out = c0 .. c1 .. c2 .. c3
		self.state = out
		return out
	end
	return o
end

--------------------------------------------------------------------------------
-- AesHash1R (spec 3.4)
--------------------------------------------------------------------------------

local HSTATE = unhex(
	"0d2cb592de56a89f47db82ccad3a98d7"
	.. "6e998d3398b7c7155a129ef55780e7ac"
	.. "1700776ad0c762ae6b507950e47ca0e8"
	.. "0c240a638d82ad070500a1794849997e"
)
local XKEY0 = keyWords(unhex("8983faf69f94248bbf56dc9001028906"))
local XKEY1 = keyWords(unhex("d163b2613ce0f451c64310ee9bf918ed"))

function M.hash1R(buf: string | buffer): string
	local s: string
	if type(buf) == "buffer" then
		local b = buf :: buffer
		s = buffer.readstring(b, 0, buffer.len(b))
	else
		s = buf :: string
	end
	local len = #s
	assert(len % 64 == 0, "hash1R input size must be a multiple of 64")

	local st = HSTATE
	for off = 1, len, 64 do
		local k0 = wordsAt(s, off)
		local k1 = wordsAt(s, off + 16)
		local k2 = wordsAt(s, off + 32)
		local k3 = wordsAt(s, off + 48)
		st = encCol(st, 1, k0) .. decCol(st, 17, k1) .. encCol(st, 33, k2) .. decCol(st, 49, k3)
	end

	for _, xk in ipairs({ XKEY0, XKEY1 }) do
		st = encCol(st, 1, xk) .. decCol(st, 17, xk) .. encCol(st, 33, xk) .. decCol(st, 49, xk)
	end
	return st
end

return M
]==], 'aes')

local argon2 = __mod([==[
-- Argon2d "memory fill" exactly as RandomX uses it (no finalization).
-- lanes=1, m_cost=262144 blocks of 1024 B, t_cost=3, version=0x13, type=0.
-- Pure Luau; 64-bit words are (lo, hi) pairs of 32-bit words held in a buffer.
local band, bor, bxor, lshift, rshift =
	bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local readu32, writeu32 = buffer.readu32, buffer.writeu32
local W = 4294967296

local LANES = 1
local M_COST = 262144
local T_COST = 3
local VERSION = 0x13
local ARGON2_D = 0
local SEG_LEN = 65536
local LANE_LEN = 262144
local BLOCK = 1024
local PROGRESS_STEP = 8
local SALT = "RandomX" -- 8 bytes, no NUL terminator
local SALT_LEN = 8

local R = table.create(256, 0)
local T = table.create(256, 0)


local function fillBlock(mem, prv, ref, cur)
do
  local pl = readu32(mem, prv + 0)
  local ph = readu32(mem, prv + 4)
  local l0 = bxor(pl, readu32(mem, ref + 0))
  local h0 = bxor(ph, readu32(mem, ref + 4))
  R[1] = l0; R[2] = h0
  T[1] = l0; T[2] = h0
  local pl = readu32(mem, prv + 8)
  local ph = readu32(mem, prv + 12)
  local l1 = bxor(pl, readu32(mem, ref + 8))
  local h1 = bxor(ph, readu32(mem, ref + 12))
  R[3] = l1; R[4] = h1
  T[3] = l1; T[4] = h1
  local pl = readu32(mem, prv + 16)
  local ph = readu32(mem, prv + 20)
  local l2 = bxor(pl, readu32(mem, ref + 16))
  local h2 = bxor(ph, readu32(mem, ref + 20))
  R[5] = l2; R[6] = h2
  T[5] = l2; T[6] = h2
  local pl = readu32(mem, prv + 24)
  local ph = readu32(mem, prv + 28)
  local l3 = bxor(pl, readu32(mem, ref + 24))
  local h3 = bxor(ph, readu32(mem, ref + 28))
  R[7] = l3; R[8] = h3
  T[7] = l3; T[8] = h3
  local pl = readu32(mem, prv + 32)
  local ph = readu32(mem, prv + 36)
  local l4 = bxor(pl, readu32(mem, ref + 32))
  local h4 = bxor(ph, readu32(mem, ref + 36))
  R[9] = l4; R[10] = h4
  T[9] = l4; T[10] = h4
  local pl = readu32(mem, prv + 40)
  local ph = readu32(mem, prv + 44)
  local l5 = bxor(pl, readu32(mem, ref + 40))
  local h5 = bxor(ph, readu32(mem, ref + 44))
  R[11] = l5; R[12] = h5
  T[11] = l5; T[12] = h5
  local pl = readu32(mem, prv + 48)
  local ph = readu32(mem, prv + 52)
  local l6 = bxor(pl, readu32(mem, ref + 48))
  local h6 = bxor(ph, readu32(mem, ref + 52))
  R[13] = l6; R[14] = h6
  T[13] = l6; T[14] = h6
  local pl = readu32(mem, prv + 56)
  local ph = readu32(mem, prv + 60)
  local l7 = bxor(pl, readu32(mem, ref + 56))
  local h7 = bxor(ph, readu32(mem, ref + 60))
  R[15] = l7; R[16] = h7
  T[15] = l7; T[16] = h7
  local pl = readu32(mem, prv + 64)
  local ph = readu32(mem, prv + 68)
  local l8 = bxor(pl, readu32(mem, ref + 64))
  local h8 = bxor(ph, readu32(mem, ref + 68))
  R[17] = l8; R[18] = h8
  T[17] = l8; T[18] = h8
  local pl = readu32(mem, prv + 72)
  local ph = readu32(mem, prv + 76)
  local l9 = bxor(pl, readu32(mem, ref + 72))
  local h9 = bxor(ph, readu32(mem, ref + 76))
  R[19] = l9; R[20] = h9
  T[19] = l9; T[20] = h9
  local pl = readu32(mem, prv + 80)
  local ph = readu32(mem, prv + 84)
  local l10 = bxor(pl, readu32(mem, ref + 80))
  local h10 = bxor(ph, readu32(mem, ref + 84))
  R[21] = l10; R[22] = h10
  T[21] = l10; T[22] = h10
  local pl = readu32(mem, prv + 88)
  local ph = readu32(mem, prv + 92)
  local l11 = bxor(pl, readu32(mem, ref + 88))
  local h11 = bxor(ph, readu32(mem, ref + 92))
  R[23] = l11; R[24] = h11
  T[23] = l11; T[24] = h11
  local pl = readu32(mem, prv + 96)
  local ph = readu32(mem, prv + 100)
  local l12 = bxor(pl, readu32(mem, ref + 96))
  local h12 = bxor(ph, readu32(mem, ref + 100))
  R[25] = l12; R[26] = h12
  T[25] = l12; T[26] = h12
  local pl = readu32(mem, prv + 104)
  local ph = readu32(mem, prv + 108)
  local l13 = bxor(pl, readu32(mem, ref + 104))
  local h13 = bxor(ph, readu32(mem, ref + 108))
  R[27] = l13; R[28] = h13
  T[27] = l13; T[28] = h13
  local pl = readu32(mem, prv + 112)
  local ph = readu32(mem, prv + 116)
  local l14 = bxor(pl, readu32(mem, ref + 112))
  local h14 = bxor(ph, readu32(mem, ref + 116))
  R[29] = l14; R[30] = h14
  T[29] = l14; T[30] = h14
  local pl = readu32(mem, prv + 120)
  local ph = readu32(mem, prv + 124)
  local l15 = bxor(pl, readu32(mem, ref + 120))
  local h15 = bxor(ph, readu32(mem, ref + 124))
  R[31] = l15; R[32] = h15
  T[31] = l15; T[32] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[1] = l0; R[2] = h0
  R[3] = l1; R[4] = h1
  R[5] = l2; R[6] = h2
  R[7] = l3; R[8] = h3
  R[9] = l4; R[10] = h4
  R[11] = l5; R[12] = h5
  R[13] = l6; R[14] = h6
  R[15] = l7; R[16] = h7
  R[17] = l8; R[18] = h8
  R[19] = l9; R[20] = h9
  R[21] = l10; R[22] = h10
  R[23] = l11; R[24] = h11
  R[25] = l12; R[26] = h12
  R[27] = l13; R[28] = h13
  R[29] = l14; R[30] = h14
  R[31] = l15; R[32] = h15
end
do
  local pl = readu32(mem, prv + 128)
  local ph = readu32(mem, prv + 132)
  local l0 = bxor(pl, readu32(mem, ref + 128))
  local h0 = bxor(ph, readu32(mem, ref + 132))
  R[33] = l0; R[34] = h0
  T[33] = l0; T[34] = h0
  local pl = readu32(mem, prv + 136)
  local ph = readu32(mem, prv + 140)
  local l1 = bxor(pl, readu32(mem, ref + 136))
  local h1 = bxor(ph, readu32(mem, ref + 140))
  R[35] = l1; R[36] = h1
  T[35] = l1; T[36] = h1
  local pl = readu32(mem, prv + 144)
  local ph = readu32(mem, prv + 148)
  local l2 = bxor(pl, readu32(mem, ref + 144))
  local h2 = bxor(ph, readu32(mem, ref + 148))
  R[37] = l2; R[38] = h2
  T[37] = l2; T[38] = h2
  local pl = readu32(mem, prv + 152)
  local ph = readu32(mem, prv + 156)
  local l3 = bxor(pl, readu32(mem, ref + 152))
  local h3 = bxor(ph, readu32(mem, ref + 156))
  R[39] = l3; R[40] = h3
  T[39] = l3; T[40] = h3
  local pl = readu32(mem, prv + 160)
  local ph = readu32(mem, prv + 164)
  local l4 = bxor(pl, readu32(mem, ref + 160))
  local h4 = bxor(ph, readu32(mem, ref + 164))
  R[41] = l4; R[42] = h4
  T[41] = l4; T[42] = h4
  local pl = readu32(mem, prv + 168)
  local ph = readu32(mem, prv + 172)
  local l5 = bxor(pl, readu32(mem, ref + 168))
  local h5 = bxor(ph, readu32(mem, ref + 172))
  R[43] = l5; R[44] = h5
  T[43] = l5; T[44] = h5
  local pl = readu32(mem, prv + 176)
  local ph = readu32(mem, prv + 180)
  local l6 = bxor(pl, readu32(mem, ref + 176))
  local h6 = bxor(ph, readu32(mem, ref + 180))
  R[45] = l6; R[46] = h6
  T[45] = l6; T[46] = h6
  local pl = readu32(mem, prv + 184)
  local ph = readu32(mem, prv + 188)
  local l7 = bxor(pl, readu32(mem, ref + 184))
  local h7 = bxor(ph, readu32(mem, ref + 188))
  R[47] = l7; R[48] = h7
  T[47] = l7; T[48] = h7
  local pl = readu32(mem, prv + 192)
  local ph = readu32(mem, prv + 196)
  local l8 = bxor(pl, readu32(mem, ref + 192))
  local h8 = bxor(ph, readu32(mem, ref + 196))
  R[49] = l8; R[50] = h8
  T[49] = l8; T[50] = h8
  local pl = readu32(mem, prv + 200)
  local ph = readu32(mem, prv + 204)
  local l9 = bxor(pl, readu32(mem, ref + 200))
  local h9 = bxor(ph, readu32(mem, ref + 204))
  R[51] = l9; R[52] = h9
  T[51] = l9; T[52] = h9
  local pl = readu32(mem, prv + 208)
  local ph = readu32(mem, prv + 212)
  local l10 = bxor(pl, readu32(mem, ref + 208))
  local h10 = bxor(ph, readu32(mem, ref + 212))
  R[53] = l10; R[54] = h10
  T[53] = l10; T[54] = h10
  local pl = readu32(mem, prv + 216)
  local ph = readu32(mem, prv + 220)
  local l11 = bxor(pl, readu32(mem, ref + 216))
  local h11 = bxor(ph, readu32(mem, ref + 220))
  R[55] = l11; R[56] = h11
  T[55] = l11; T[56] = h11
  local pl = readu32(mem, prv + 224)
  local ph = readu32(mem, prv + 228)
  local l12 = bxor(pl, readu32(mem, ref + 224))
  local h12 = bxor(ph, readu32(mem, ref + 228))
  R[57] = l12; R[58] = h12
  T[57] = l12; T[58] = h12
  local pl = readu32(mem, prv + 232)
  local ph = readu32(mem, prv + 236)
  local l13 = bxor(pl, readu32(mem, ref + 232))
  local h13 = bxor(ph, readu32(mem, ref + 236))
  R[59] = l13; R[60] = h13
  T[59] = l13; T[60] = h13
  local pl = readu32(mem, prv + 240)
  local ph = readu32(mem, prv + 244)
  local l14 = bxor(pl, readu32(mem, ref + 240))
  local h14 = bxor(ph, readu32(mem, ref + 244))
  R[61] = l14; R[62] = h14
  T[61] = l14; T[62] = h14
  local pl = readu32(mem, prv + 248)
  local ph = readu32(mem, prv + 252)
  local l15 = bxor(pl, readu32(mem, ref + 248))
  local h15 = bxor(ph, readu32(mem, ref + 252))
  R[63] = l15; R[64] = h15
  T[63] = l15; T[64] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[33] = l0; R[34] = h0
  R[35] = l1; R[36] = h1
  R[37] = l2; R[38] = h2
  R[39] = l3; R[40] = h3
  R[41] = l4; R[42] = h4
  R[43] = l5; R[44] = h5
  R[45] = l6; R[46] = h6
  R[47] = l7; R[48] = h7
  R[49] = l8; R[50] = h8
  R[51] = l9; R[52] = h9
  R[53] = l10; R[54] = h10
  R[55] = l11; R[56] = h11
  R[57] = l12; R[58] = h12
  R[59] = l13; R[60] = h13
  R[61] = l14; R[62] = h14
  R[63] = l15; R[64] = h15
end
do
  local pl = readu32(mem, prv + 256)
  local ph = readu32(mem, prv + 260)
  local l0 = bxor(pl, readu32(mem, ref + 256))
  local h0 = bxor(ph, readu32(mem, ref + 260))
  R[65] = l0; R[66] = h0
  T[65] = l0; T[66] = h0
  local pl = readu32(mem, prv + 264)
  local ph = readu32(mem, prv + 268)
  local l1 = bxor(pl, readu32(mem, ref + 264))
  local h1 = bxor(ph, readu32(mem, ref + 268))
  R[67] = l1; R[68] = h1
  T[67] = l1; T[68] = h1
  local pl = readu32(mem, prv + 272)
  local ph = readu32(mem, prv + 276)
  local l2 = bxor(pl, readu32(mem, ref + 272))
  local h2 = bxor(ph, readu32(mem, ref + 276))
  R[69] = l2; R[70] = h2
  T[69] = l2; T[70] = h2
  local pl = readu32(mem, prv + 280)
  local ph = readu32(mem, prv + 284)
  local l3 = bxor(pl, readu32(mem, ref + 280))
  local h3 = bxor(ph, readu32(mem, ref + 284))
  R[71] = l3; R[72] = h3
  T[71] = l3; T[72] = h3
  local pl = readu32(mem, prv + 288)
  local ph = readu32(mem, prv + 292)
  local l4 = bxor(pl, readu32(mem, ref + 288))
  local h4 = bxor(ph, readu32(mem, ref + 292))
  R[73] = l4; R[74] = h4
  T[73] = l4; T[74] = h4
  local pl = readu32(mem, prv + 296)
  local ph = readu32(mem, prv + 300)
  local l5 = bxor(pl, readu32(mem, ref + 296))
  local h5 = bxor(ph, readu32(mem, ref + 300))
  R[75] = l5; R[76] = h5
  T[75] = l5; T[76] = h5
  local pl = readu32(mem, prv + 304)
  local ph = readu32(mem, prv + 308)
  local l6 = bxor(pl, readu32(mem, ref + 304))
  local h6 = bxor(ph, readu32(mem, ref + 308))
  R[77] = l6; R[78] = h6
  T[77] = l6; T[78] = h6
  local pl = readu32(mem, prv + 312)
  local ph = readu32(mem, prv + 316)
  local l7 = bxor(pl, readu32(mem, ref + 312))
  local h7 = bxor(ph, readu32(mem, ref + 316))
  R[79] = l7; R[80] = h7
  T[79] = l7; T[80] = h7
  local pl = readu32(mem, prv + 320)
  local ph = readu32(mem, prv + 324)
  local l8 = bxor(pl, readu32(mem, ref + 320))
  local h8 = bxor(ph, readu32(mem, ref + 324))
  R[81] = l8; R[82] = h8
  T[81] = l8; T[82] = h8
  local pl = readu32(mem, prv + 328)
  local ph = readu32(mem, prv + 332)
  local l9 = bxor(pl, readu32(mem, ref + 328))
  local h9 = bxor(ph, readu32(mem, ref + 332))
  R[83] = l9; R[84] = h9
  T[83] = l9; T[84] = h9
  local pl = readu32(mem, prv + 336)
  local ph = readu32(mem, prv + 340)
  local l10 = bxor(pl, readu32(mem, ref + 336))
  local h10 = bxor(ph, readu32(mem, ref + 340))
  R[85] = l10; R[86] = h10
  T[85] = l10; T[86] = h10
  local pl = readu32(mem, prv + 344)
  local ph = readu32(mem, prv + 348)
  local l11 = bxor(pl, readu32(mem, ref + 344))
  local h11 = bxor(ph, readu32(mem, ref + 348))
  R[87] = l11; R[88] = h11
  T[87] = l11; T[88] = h11
  local pl = readu32(mem, prv + 352)
  local ph = readu32(mem, prv + 356)
  local l12 = bxor(pl, readu32(mem, ref + 352))
  local h12 = bxor(ph, readu32(mem, ref + 356))
  R[89] = l12; R[90] = h12
  T[89] = l12; T[90] = h12
  local pl = readu32(mem, prv + 360)
  local ph = readu32(mem, prv + 364)
  local l13 = bxor(pl, readu32(mem, ref + 360))
  local h13 = bxor(ph, readu32(mem, ref + 364))
  R[91] = l13; R[92] = h13
  T[91] = l13; T[92] = h13
  local pl = readu32(mem, prv + 368)
  local ph = readu32(mem, prv + 372)
  local l14 = bxor(pl, readu32(mem, ref + 368))
  local h14 = bxor(ph, readu32(mem, ref + 372))
  R[93] = l14; R[94] = h14
  T[93] = l14; T[94] = h14
  local pl = readu32(mem, prv + 376)
  local ph = readu32(mem, prv + 380)
  local l15 = bxor(pl, readu32(mem, ref + 376))
  local h15 = bxor(ph, readu32(mem, ref + 380))
  R[95] = l15; R[96] = h15
  T[95] = l15; T[96] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[65] = l0; R[66] = h0
  R[67] = l1; R[68] = h1
  R[69] = l2; R[70] = h2
  R[71] = l3; R[72] = h3
  R[73] = l4; R[74] = h4
  R[75] = l5; R[76] = h5
  R[77] = l6; R[78] = h6
  R[79] = l7; R[80] = h7
  R[81] = l8; R[82] = h8
  R[83] = l9; R[84] = h9
  R[85] = l10; R[86] = h10
  R[87] = l11; R[88] = h11
  R[89] = l12; R[90] = h12
  R[91] = l13; R[92] = h13
  R[93] = l14; R[94] = h14
  R[95] = l15; R[96] = h15
end
do
  local pl = readu32(mem, prv + 384)
  local ph = readu32(mem, prv + 388)
  local l0 = bxor(pl, readu32(mem, ref + 384))
  local h0 = bxor(ph, readu32(mem, ref + 388))
  R[97] = l0; R[98] = h0
  T[97] = l0; T[98] = h0
  local pl = readu32(mem, prv + 392)
  local ph = readu32(mem, prv + 396)
  local l1 = bxor(pl, readu32(mem, ref + 392))
  local h1 = bxor(ph, readu32(mem, ref + 396))
  R[99] = l1; R[100] = h1
  T[99] = l1; T[100] = h1
  local pl = readu32(mem, prv + 400)
  local ph = readu32(mem, prv + 404)
  local l2 = bxor(pl, readu32(mem, ref + 400))
  local h2 = bxor(ph, readu32(mem, ref + 404))
  R[101] = l2; R[102] = h2
  T[101] = l2; T[102] = h2
  local pl = readu32(mem, prv + 408)
  local ph = readu32(mem, prv + 412)
  local l3 = bxor(pl, readu32(mem, ref + 408))
  local h3 = bxor(ph, readu32(mem, ref + 412))
  R[103] = l3; R[104] = h3
  T[103] = l3; T[104] = h3
  local pl = readu32(mem, prv + 416)
  local ph = readu32(mem, prv + 420)
  local l4 = bxor(pl, readu32(mem, ref + 416))
  local h4 = bxor(ph, readu32(mem, ref + 420))
  R[105] = l4; R[106] = h4
  T[105] = l4; T[106] = h4
  local pl = readu32(mem, prv + 424)
  local ph = readu32(mem, prv + 428)
  local l5 = bxor(pl, readu32(mem, ref + 424))
  local h5 = bxor(ph, readu32(mem, ref + 428))
  R[107] = l5; R[108] = h5
  T[107] = l5; T[108] = h5
  local pl = readu32(mem, prv + 432)
  local ph = readu32(mem, prv + 436)
  local l6 = bxor(pl, readu32(mem, ref + 432))
  local h6 = bxor(ph, readu32(mem, ref + 436))
  R[109] = l6; R[110] = h6
  T[109] = l6; T[110] = h6
  local pl = readu32(mem, prv + 440)
  local ph = readu32(mem, prv + 444)
  local l7 = bxor(pl, readu32(mem, ref + 440))
  local h7 = bxor(ph, readu32(mem, ref + 444))
  R[111] = l7; R[112] = h7
  T[111] = l7; T[112] = h7
  local pl = readu32(mem, prv + 448)
  local ph = readu32(mem, prv + 452)
  local l8 = bxor(pl, readu32(mem, ref + 448))
  local h8 = bxor(ph, readu32(mem, ref + 452))
  R[113] = l8; R[114] = h8
  T[113] = l8; T[114] = h8
  local pl = readu32(mem, prv + 456)
  local ph = readu32(mem, prv + 460)
  local l9 = bxor(pl, readu32(mem, ref + 456))
  local h9 = bxor(ph, readu32(mem, ref + 460))
  R[115] = l9; R[116] = h9
  T[115] = l9; T[116] = h9
  local pl = readu32(mem, prv + 464)
  local ph = readu32(mem, prv + 468)
  local l10 = bxor(pl, readu32(mem, ref + 464))
  local h10 = bxor(ph, readu32(mem, ref + 468))
  R[117] = l10; R[118] = h10
  T[117] = l10; T[118] = h10
  local pl = readu32(mem, prv + 472)
  local ph = readu32(mem, prv + 476)
  local l11 = bxor(pl, readu32(mem, ref + 472))
  local h11 = bxor(ph, readu32(mem, ref + 476))
  R[119] = l11; R[120] = h11
  T[119] = l11; T[120] = h11
  local pl = readu32(mem, prv + 480)
  local ph = readu32(mem, prv + 484)
  local l12 = bxor(pl, readu32(mem, ref + 480))
  local h12 = bxor(ph, readu32(mem, ref + 484))
  R[121] = l12; R[122] = h12
  T[121] = l12; T[122] = h12
  local pl = readu32(mem, prv + 488)
  local ph = readu32(mem, prv + 492)
  local l13 = bxor(pl, readu32(mem, ref + 488))
  local h13 = bxor(ph, readu32(mem, ref + 492))
  R[123] = l13; R[124] = h13
  T[123] = l13; T[124] = h13
  local pl = readu32(mem, prv + 496)
  local ph = readu32(mem, prv + 500)
  local l14 = bxor(pl, readu32(mem, ref + 496))
  local h14 = bxor(ph, readu32(mem, ref + 500))
  R[125] = l14; R[126] = h14
  T[125] = l14; T[126] = h14
  local pl = readu32(mem, prv + 504)
  local ph = readu32(mem, prv + 508)
  local l15 = bxor(pl, readu32(mem, ref + 504))
  local h15 = bxor(ph, readu32(mem, ref + 508))
  R[127] = l15; R[128] = h15
  T[127] = l15; T[128] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[97] = l0; R[98] = h0
  R[99] = l1; R[100] = h1
  R[101] = l2; R[102] = h2
  R[103] = l3; R[104] = h3
  R[105] = l4; R[106] = h4
  R[107] = l5; R[108] = h5
  R[109] = l6; R[110] = h6
  R[111] = l7; R[112] = h7
  R[113] = l8; R[114] = h8
  R[115] = l9; R[116] = h9
  R[117] = l10; R[118] = h10
  R[119] = l11; R[120] = h11
  R[121] = l12; R[122] = h12
  R[123] = l13; R[124] = h13
  R[125] = l14; R[126] = h14
  R[127] = l15; R[128] = h15
end
do
  local pl = readu32(mem, prv + 512)
  local ph = readu32(mem, prv + 516)
  local l0 = bxor(pl, readu32(mem, ref + 512))
  local h0 = bxor(ph, readu32(mem, ref + 516))
  R[129] = l0; R[130] = h0
  T[129] = l0; T[130] = h0
  local pl = readu32(mem, prv + 520)
  local ph = readu32(mem, prv + 524)
  local l1 = bxor(pl, readu32(mem, ref + 520))
  local h1 = bxor(ph, readu32(mem, ref + 524))
  R[131] = l1; R[132] = h1
  T[131] = l1; T[132] = h1
  local pl = readu32(mem, prv + 528)
  local ph = readu32(mem, prv + 532)
  local l2 = bxor(pl, readu32(mem, ref + 528))
  local h2 = bxor(ph, readu32(mem, ref + 532))
  R[133] = l2; R[134] = h2
  T[133] = l2; T[134] = h2
  local pl = readu32(mem, prv + 536)
  local ph = readu32(mem, prv + 540)
  local l3 = bxor(pl, readu32(mem, ref + 536))
  local h3 = bxor(ph, readu32(mem, ref + 540))
  R[135] = l3; R[136] = h3
  T[135] = l3; T[136] = h3
  local pl = readu32(mem, prv + 544)
  local ph = readu32(mem, prv + 548)
  local l4 = bxor(pl, readu32(mem, ref + 544))
  local h4 = bxor(ph, readu32(mem, ref + 548))
  R[137] = l4; R[138] = h4
  T[137] = l4; T[138] = h4
  local pl = readu32(mem, prv + 552)
  local ph = readu32(mem, prv + 556)
  local l5 = bxor(pl, readu32(mem, ref + 552))
  local h5 = bxor(ph, readu32(mem, ref + 556))
  R[139] = l5; R[140] = h5
  T[139] = l5; T[140] = h5
  local pl = readu32(mem, prv + 560)
  local ph = readu32(mem, prv + 564)
  local l6 = bxor(pl, readu32(mem, ref + 560))
  local h6 = bxor(ph, readu32(mem, ref + 564))
  R[141] = l6; R[142] = h6
  T[141] = l6; T[142] = h6
  local pl = readu32(mem, prv + 568)
  local ph = readu32(mem, prv + 572)
  local l7 = bxor(pl, readu32(mem, ref + 568))
  local h7 = bxor(ph, readu32(mem, ref + 572))
  R[143] = l7; R[144] = h7
  T[143] = l7; T[144] = h7
  local pl = readu32(mem, prv + 576)
  local ph = readu32(mem, prv + 580)
  local l8 = bxor(pl, readu32(mem, ref + 576))
  local h8 = bxor(ph, readu32(mem, ref + 580))
  R[145] = l8; R[146] = h8
  T[145] = l8; T[146] = h8
  local pl = readu32(mem, prv + 584)
  local ph = readu32(mem, prv + 588)
  local l9 = bxor(pl, readu32(mem, ref + 584))
  local h9 = bxor(ph, readu32(mem, ref + 588))
  R[147] = l9; R[148] = h9
  T[147] = l9; T[148] = h9
  local pl = readu32(mem, prv + 592)
  local ph = readu32(mem, prv + 596)
  local l10 = bxor(pl, readu32(mem, ref + 592))
  local h10 = bxor(ph, readu32(mem, ref + 596))
  R[149] = l10; R[150] = h10
  T[149] = l10; T[150] = h10
  local pl = readu32(mem, prv + 600)
  local ph = readu32(mem, prv + 604)
  local l11 = bxor(pl, readu32(mem, ref + 600))
  local h11 = bxor(ph, readu32(mem, ref + 604))
  R[151] = l11; R[152] = h11
  T[151] = l11; T[152] = h11
  local pl = readu32(mem, prv + 608)
  local ph = readu32(mem, prv + 612)
  local l12 = bxor(pl, readu32(mem, ref + 608))
  local h12 = bxor(ph, readu32(mem, ref + 612))
  R[153] = l12; R[154] = h12
  T[153] = l12; T[154] = h12
  local pl = readu32(mem, prv + 616)
  local ph = readu32(mem, prv + 620)
  local l13 = bxor(pl, readu32(mem, ref + 616))
  local h13 = bxor(ph, readu32(mem, ref + 620))
  R[155] = l13; R[156] = h13
  T[155] = l13; T[156] = h13
  local pl = readu32(mem, prv + 624)
  local ph = readu32(mem, prv + 628)
  local l14 = bxor(pl, readu32(mem, ref + 624))
  local h14 = bxor(ph, readu32(mem, ref + 628))
  R[157] = l14; R[158] = h14
  T[157] = l14; T[158] = h14
  local pl = readu32(mem, prv + 632)
  local ph = readu32(mem, prv + 636)
  local l15 = bxor(pl, readu32(mem, ref + 632))
  local h15 = bxor(ph, readu32(mem, ref + 636))
  R[159] = l15; R[160] = h15
  T[159] = l15; T[160] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[129] = l0; R[130] = h0
  R[131] = l1; R[132] = h1
  R[133] = l2; R[134] = h2
  R[135] = l3; R[136] = h3
  R[137] = l4; R[138] = h4
  R[139] = l5; R[140] = h5
  R[141] = l6; R[142] = h6
  R[143] = l7; R[144] = h7
  R[145] = l8; R[146] = h8
  R[147] = l9; R[148] = h9
  R[149] = l10; R[150] = h10
  R[151] = l11; R[152] = h11
  R[153] = l12; R[154] = h12
  R[155] = l13; R[156] = h13
  R[157] = l14; R[158] = h14
  R[159] = l15; R[160] = h15
end
do
  local pl = readu32(mem, prv + 640)
  local ph = readu32(mem, prv + 644)
  local l0 = bxor(pl, readu32(mem, ref + 640))
  local h0 = bxor(ph, readu32(mem, ref + 644))
  R[161] = l0; R[162] = h0
  T[161] = l0; T[162] = h0
  local pl = readu32(mem, prv + 648)
  local ph = readu32(mem, prv + 652)
  local l1 = bxor(pl, readu32(mem, ref + 648))
  local h1 = bxor(ph, readu32(mem, ref + 652))
  R[163] = l1; R[164] = h1
  T[163] = l1; T[164] = h1
  local pl = readu32(mem, prv + 656)
  local ph = readu32(mem, prv + 660)
  local l2 = bxor(pl, readu32(mem, ref + 656))
  local h2 = bxor(ph, readu32(mem, ref + 660))
  R[165] = l2; R[166] = h2
  T[165] = l2; T[166] = h2
  local pl = readu32(mem, prv + 664)
  local ph = readu32(mem, prv + 668)
  local l3 = bxor(pl, readu32(mem, ref + 664))
  local h3 = bxor(ph, readu32(mem, ref + 668))
  R[167] = l3; R[168] = h3
  T[167] = l3; T[168] = h3
  local pl = readu32(mem, prv + 672)
  local ph = readu32(mem, prv + 676)
  local l4 = bxor(pl, readu32(mem, ref + 672))
  local h4 = bxor(ph, readu32(mem, ref + 676))
  R[169] = l4; R[170] = h4
  T[169] = l4; T[170] = h4
  local pl = readu32(mem, prv + 680)
  local ph = readu32(mem, prv + 684)
  local l5 = bxor(pl, readu32(mem, ref + 680))
  local h5 = bxor(ph, readu32(mem, ref + 684))
  R[171] = l5; R[172] = h5
  T[171] = l5; T[172] = h5
  local pl = readu32(mem, prv + 688)
  local ph = readu32(mem, prv + 692)
  local l6 = bxor(pl, readu32(mem, ref + 688))
  local h6 = bxor(ph, readu32(mem, ref + 692))
  R[173] = l6; R[174] = h6
  T[173] = l6; T[174] = h6
  local pl = readu32(mem, prv + 696)
  local ph = readu32(mem, prv + 700)
  local l7 = bxor(pl, readu32(mem, ref + 696))
  local h7 = bxor(ph, readu32(mem, ref + 700))
  R[175] = l7; R[176] = h7
  T[175] = l7; T[176] = h7
  local pl = readu32(mem, prv + 704)
  local ph = readu32(mem, prv + 708)
  local l8 = bxor(pl, readu32(mem, ref + 704))
  local h8 = bxor(ph, readu32(mem, ref + 708))
  R[177] = l8; R[178] = h8
  T[177] = l8; T[178] = h8
  local pl = readu32(mem, prv + 712)
  local ph = readu32(mem, prv + 716)
  local l9 = bxor(pl, readu32(mem, ref + 712))
  local h9 = bxor(ph, readu32(mem, ref + 716))
  R[179] = l9; R[180] = h9
  T[179] = l9; T[180] = h9
  local pl = readu32(mem, prv + 720)
  local ph = readu32(mem, prv + 724)
  local l10 = bxor(pl, readu32(mem, ref + 720))
  local h10 = bxor(ph, readu32(mem, ref + 724))
  R[181] = l10; R[182] = h10
  T[181] = l10; T[182] = h10
  local pl = readu32(mem, prv + 728)
  local ph = readu32(mem, prv + 732)
  local l11 = bxor(pl, readu32(mem, ref + 728))
  local h11 = bxor(ph, readu32(mem, ref + 732))
  R[183] = l11; R[184] = h11
  T[183] = l11; T[184] = h11
  local pl = readu32(mem, prv + 736)
  local ph = readu32(mem, prv + 740)
  local l12 = bxor(pl, readu32(mem, ref + 736))
  local h12 = bxor(ph, readu32(mem, ref + 740))
  R[185] = l12; R[186] = h12
  T[185] = l12; T[186] = h12
  local pl = readu32(mem, prv + 744)
  local ph = readu32(mem, prv + 748)
  local l13 = bxor(pl, readu32(mem, ref + 744))
  local h13 = bxor(ph, readu32(mem, ref + 748))
  R[187] = l13; R[188] = h13
  T[187] = l13; T[188] = h13
  local pl = readu32(mem, prv + 752)
  local ph = readu32(mem, prv + 756)
  local l14 = bxor(pl, readu32(mem, ref + 752))
  local h14 = bxor(ph, readu32(mem, ref + 756))
  R[189] = l14; R[190] = h14
  T[189] = l14; T[190] = h14
  local pl = readu32(mem, prv + 760)
  local ph = readu32(mem, prv + 764)
  local l15 = bxor(pl, readu32(mem, ref + 760))
  local h15 = bxor(ph, readu32(mem, ref + 764))
  R[191] = l15; R[192] = h15
  T[191] = l15; T[192] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[161] = l0; R[162] = h0
  R[163] = l1; R[164] = h1
  R[165] = l2; R[166] = h2
  R[167] = l3; R[168] = h3
  R[169] = l4; R[170] = h4
  R[171] = l5; R[172] = h5
  R[173] = l6; R[174] = h6
  R[175] = l7; R[176] = h7
  R[177] = l8; R[178] = h8
  R[179] = l9; R[180] = h9
  R[181] = l10; R[182] = h10
  R[183] = l11; R[184] = h11
  R[185] = l12; R[186] = h12
  R[187] = l13; R[188] = h13
  R[189] = l14; R[190] = h14
  R[191] = l15; R[192] = h15
end
do
  local pl = readu32(mem, prv + 768)
  local ph = readu32(mem, prv + 772)
  local l0 = bxor(pl, readu32(mem, ref + 768))
  local h0 = bxor(ph, readu32(mem, ref + 772))
  R[193] = l0; R[194] = h0
  T[193] = l0; T[194] = h0
  local pl = readu32(mem, prv + 776)
  local ph = readu32(mem, prv + 780)
  local l1 = bxor(pl, readu32(mem, ref + 776))
  local h1 = bxor(ph, readu32(mem, ref + 780))
  R[195] = l1; R[196] = h1
  T[195] = l1; T[196] = h1
  local pl = readu32(mem, prv + 784)
  local ph = readu32(mem, prv + 788)
  local l2 = bxor(pl, readu32(mem, ref + 784))
  local h2 = bxor(ph, readu32(mem, ref + 788))
  R[197] = l2; R[198] = h2
  T[197] = l2; T[198] = h2
  local pl = readu32(mem, prv + 792)
  local ph = readu32(mem, prv + 796)
  local l3 = bxor(pl, readu32(mem, ref + 792))
  local h3 = bxor(ph, readu32(mem, ref + 796))
  R[199] = l3; R[200] = h3
  T[199] = l3; T[200] = h3
  local pl = readu32(mem, prv + 800)
  local ph = readu32(mem, prv + 804)
  local l4 = bxor(pl, readu32(mem, ref + 800))
  local h4 = bxor(ph, readu32(mem, ref + 804))
  R[201] = l4; R[202] = h4
  T[201] = l4; T[202] = h4
  local pl = readu32(mem, prv + 808)
  local ph = readu32(mem, prv + 812)
  local l5 = bxor(pl, readu32(mem, ref + 808))
  local h5 = bxor(ph, readu32(mem, ref + 812))
  R[203] = l5; R[204] = h5
  T[203] = l5; T[204] = h5
  local pl = readu32(mem, prv + 816)
  local ph = readu32(mem, prv + 820)
  local l6 = bxor(pl, readu32(mem, ref + 816))
  local h6 = bxor(ph, readu32(mem, ref + 820))
  R[205] = l6; R[206] = h6
  T[205] = l6; T[206] = h6
  local pl = readu32(mem, prv + 824)
  local ph = readu32(mem, prv + 828)
  local l7 = bxor(pl, readu32(mem, ref + 824))
  local h7 = bxor(ph, readu32(mem, ref + 828))
  R[207] = l7; R[208] = h7
  T[207] = l7; T[208] = h7
  local pl = readu32(mem, prv + 832)
  local ph = readu32(mem, prv + 836)
  local l8 = bxor(pl, readu32(mem, ref + 832))
  local h8 = bxor(ph, readu32(mem, ref + 836))
  R[209] = l8; R[210] = h8
  T[209] = l8; T[210] = h8
  local pl = readu32(mem, prv + 840)
  local ph = readu32(mem, prv + 844)
  local l9 = bxor(pl, readu32(mem, ref + 840))
  local h9 = bxor(ph, readu32(mem, ref + 844))
  R[211] = l9; R[212] = h9
  T[211] = l9; T[212] = h9
  local pl = readu32(mem, prv + 848)
  local ph = readu32(mem, prv + 852)
  local l10 = bxor(pl, readu32(mem, ref + 848))
  local h10 = bxor(ph, readu32(mem, ref + 852))
  R[213] = l10; R[214] = h10
  T[213] = l10; T[214] = h10
  local pl = readu32(mem, prv + 856)
  local ph = readu32(mem, prv + 860)
  local l11 = bxor(pl, readu32(mem, ref + 856))
  local h11 = bxor(ph, readu32(mem, ref + 860))
  R[215] = l11; R[216] = h11
  T[215] = l11; T[216] = h11
  local pl = readu32(mem, prv + 864)
  local ph = readu32(mem, prv + 868)
  local l12 = bxor(pl, readu32(mem, ref + 864))
  local h12 = bxor(ph, readu32(mem, ref + 868))
  R[217] = l12; R[218] = h12
  T[217] = l12; T[218] = h12
  local pl = readu32(mem, prv + 872)
  local ph = readu32(mem, prv + 876)
  local l13 = bxor(pl, readu32(mem, ref + 872))
  local h13 = bxor(ph, readu32(mem, ref + 876))
  R[219] = l13; R[220] = h13
  T[219] = l13; T[220] = h13
  local pl = readu32(mem, prv + 880)
  local ph = readu32(mem, prv + 884)
  local l14 = bxor(pl, readu32(mem, ref + 880))
  local h14 = bxor(ph, readu32(mem, ref + 884))
  R[221] = l14; R[222] = h14
  T[221] = l14; T[222] = h14
  local pl = readu32(mem, prv + 888)
  local ph = readu32(mem, prv + 892)
  local l15 = bxor(pl, readu32(mem, ref + 888))
  local h15 = bxor(ph, readu32(mem, ref + 892))
  R[223] = l15; R[224] = h15
  T[223] = l15; T[224] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[193] = l0; R[194] = h0
  R[195] = l1; R[196] = h1
  R[197] = l2; R[198] = h2
  R[199] = l3; R[200] = h3
  R[201] = l4; R[202] = h4
  R[203] = l5; R[204] = h5
  R[205] = l6; R[206] = h6
  R[207] = l7; R[208] = h7
  R[209] = l8; R[210] = h8
  R[211] = l9; R[212] = h9
  R[213] = l10; R[214] = h10
  R[215] = l11; R[216] = h11
  R[217] = l12; R[218] = h12
  R[219] = l13; R[220] = h13
  R[221] = l14; R[222] = h14
  R[223] = l15; R[224] = h15
end
do
  local pl = readu32(mem, prv + 896)
  local ph = readu32(mem, prv + 900)
  local l0 = bxor(pl, readu32(mem, ref + 896))
  local h0 = bxor(ph, readu32(mem, ref + 900))
  R[225] = l0; R[226] = h0
  T[225] = l0; T[226] = h0
  local pl = readu32(mem, prv + 904)
  local ph = readu32(mem, prv + 908)
  local l1 = bxor(pl, readu32(mem, ref + 904))
  local h1 = bxor(ph, readu32(mem, ref + 908))
  R[227] = l1; R[228] = h1
  T[227] = l1; T[228] = h1
  local pl = readu32(mem, prv + 912)
  local ph = readu32(mem, prv + 916)
  local l2 = bxor(pl, readu32(mem, ref + 912))
  local h2 = bxor(ph, readu32(mem, ref + 916))
  R[229] = l2; R[230] = h2
  T[229] = l2; T[230] = h2
  local pl = readu32(mem, prv + 920)
  local ph = readu32(mem, prv + 924)
  local l3 = bxor(pl, readu32(mem, ref + 920))
  local h3 = bxor(ph, readu32(mem, ref + 924))
  R[231] = l3; R[232] = h3
  T[231] = l3; T[232] = h3
  local pl = readu32(mem, prv + 928)
  local ph = readu32(mem, prv + 932)
  local l4 = bxor(pl, readu32(mem, ref + 928))
  local h4 = bxor(ph, readu32(mem, ref + 932))
  R[233] = l4; R[234] = h4
  T[233] = l4; T[234] = h4
  local pl = readu32(mem, prv + 936)
  local ph = readu32(mem, prv + 940)
  local l5 = bxor(pl, readu32(mem, ref + 936))
  local h5 = bxor(ph, readu32(mem, ref + 940))
  R[235] = l5; R[236] = h5
  T[235] = l5; T[236] = h5
  local pl = readu32(mem, prv + 944)
  local ph = readu32(mem, prv + 948)
  local l6 = bxor(pl, readu32(mem, ref + 944))
  local h6 = bxor(ph, readu32(mem, ref + 948))
  R[237] = l6; R[238] = h6
  T[237] = l6; T[238] = h6
  local pl = readu32(mem, prv + 952)
  local ph = readu32(mem, prv + 956)
  local l7 = bxor(pl, readu32(mem, ref + 952))
  local h7 = bxor(ph, readu32(mem, ref + 956))
  R[239] = l7; R[240] = h7
  T[239] = l7; T[240] = h7
  local pl = readu32(mem, prv + 960)
  local ph = readu32(mem, prv + 964)
  local l8 = bxor(pl, readu32(mem, ref + 960))
  local h8 = bxor(ph, readu32(mem, ref + 964))
  R[241] = l8; R[242] = h8
  T[241] = l8; T[242] = h8
  local pl = readu32(mem, prv + 968)
  local ph = readu32(mem, prv + 972)
  local l9 = bxor(pl, readu32(mem, ref + 968))
  local h9 = bxor(ph, readu32(mem, ref + 972))
  R[243] = l9; R[244] = h9
  T[243] = l9; T[244] = h9
  local pl = readu32(mem, prv + 976)
  local ph = readu32(mem, prv + 980)
  local l10 = bxor(pl, readu32(mem, ref + 976))
  local h10 = bxor(ph, readu32(mem, ref + 980))
  R[245] = l10; R[246] = h10
  T[245] = l10; T[246] = h10
  local pl = readu32(mem, prv + 984)
  local ph = readu32(mem, prv + 988)
  local l11 = bxor(pl, readu32(mem, ref + 984))
  local h11 = bxor(ph, readu32(mem, ref + 988))
  R[247] = l11; R[248] = h11
  T[247] = l11; T[248] = h11
  local pl = readu32(mem, prv + 992)
  local ph = readu32(mem, prv + 996)
  local l12 = bxor(pl, readu32(mem, ref + 992))
  local h12 = bxor(ph, readu32(mem, ref + 996))
  R[249] = l12; R[250] = h12
  T[249] = l12; T[250] = h12
  local pl = readu32(mem, prv + 1000)
  local ph = readu32(mem, prv + 1004)
  local l13 = bxor(pl, readu32(mem, ref + 1000))
  local h13 = bxor(ph, readu32(mem, ref + 1004))
  R[251] = l13; R[252] = h13
  T[251] = l13; T[252] = h13
  local pl = readu32(mem, prv + 1008)
  local ph = readu32(mem, prv + 1012)
  local l14 = bxor(pl, readu32(mem, ref + 1008))
  local h14 = bxor(ph, readu32(mem, ref + 1012))
  R[253] = l14; R[254] = h14
  T[253] = l14; T[254] = h14
  local pl = readu32(mem, prv + 1016)
  local ph = readu32(mem, prv + 1020)
  local l15 = bxor(pl, readu32(mem, ref + 1016))
  local h15 = bxor(ph, readu32(mem, ref + 1020))
  R[255] = l15; R[256] = h15
  T[255] = l15; T[256] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[225] = l0; R[226] = h0
  R[227] = l1; R[228] = h1
  R[229] = l2; R[230] = h2
  R[231] = l3; R[232] = h3
  R[233] = l4; R[234] = h4
  R[235] = l5; R[236] = h5
  R[237] = l6; R[238] = h6
  R[239] = l7; R[240] = h7
  R[241] = l8; R[242] = h8
  R[243] = l9; R[244] = h9
  R[245] = l10; R[246] = h10
  R[247] = l11; R[248] = h11
  R[249] = l12; R[250] = h12
  R[251] = l13; R[252] = h13
  R[253] = l14; R[254] = h14
  R[255] = l15; R[256] = h15
end
do
  local l0, h0 = R[1], R[2]
  local l1, h1 = R[3], R[4]
  local l2, h2 = R[33], R[34]
  local l3, h3 = R[35], R[36]
  local l4, h4 = R[65], R[66]
  local l5, h5 = R[67], R[68]
  local l6, h6 = R[97], R[98]
  local l7, h7 = R[99], R[100]
  local l8, h8 = R[129], R[130]
  local l9, h9 = R[131], R[132]
  local l10, h10 = R[161], R[162]
  local l11, h11 = R[163], R[164]
  local l12, h12 = R[193], R[194]
  local l13, h13 = R[195], R[196]
  local l14, h14 = R[225], R[226]
  local l15, h15 = R[227], R[228]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 0, bxor(T[1], l0))
  writeu32(mem, cur + 4, bxor(T[2], h0))
  writeu32(mem, cur + 8, bxor(T[3], l1))
  writeu32(mem, cur + 12, bxor(T[4], h1))
  writeu32(mem, cur + 128, bxor(T[33], l2))
  writeu32(mem, cur + 132, bxor(T[34], h2))
  writeu32(mem, cur + 136, bxor(T[35], l3))
  writeu32(mem, cur + 140, bxor(T[36], h3))
  writeu32(mem, cur + 256, bxor(T[65], l4))
  writeu32(mem, cur + 260, bxor(T[66], h4))
  writeu32(mem, cur + 264, bxor(T[67], l5))
  writeu32(mem, cur + 268, bxor(T[68], h5))
  writeu32(mem, cur + 384, bxor(T[97], l6))
  writeu32(mem, cur + 388, bxor(T[98], h6))
  writeu32(mem, cur + 392, bxor(T[99], l7))
  writeu32(mem, cur + 396, bxor(T[100], h7))
  writeu32(mem, cur + 512, bxor(T[129], l8))
  writeu32(mem, cur + 516, bxor(T[130], h8))
  writeu32(mem, cur + 520, bxor(T[131], l9))
  writeu32(mem, cur + 524, bxor(T[132], h9))
  writeu32(mem, cur + 640, bxor(T[161], l10))
  writeu32(mem, cur + 644, bxor(T[162], h10))
  writeu32(mem, cur + 648, bxor(T[163], l11))
  writeu32(mem, cur + 652, bxor(T[164], h11))
  writeu32(mem, cur + 768, bxor(T[193], l12))
  writeu32(mem, cur + 772, bxor(T[194], h12))
  writeu32(mem, cur + 776, bxor(T[195], l13))
  writeu32(mem, cur + 780, bxor(T[196], h13))
  writeu32(mem, cur + 896, bxor(T[225], l14))
  writeu32(mem, cur + 900, bxor(T[226], h14))
  writeu32(mem, cur + 904, bxor(T[227], l15))
  writeu32(mem, cur + 908, bxor(T[228], h15))
end
do
  local l0, h0 = R[5], R[6]
  local l1, h1 = R[7], R[8]
  local l2, h2 = R[37], R[38]
  local l3, h3 = R[39], R[40]
  local l4, h4 = R[69], R[70]
  local l5, h5 = R[71], R[72]
  local l6, h6 = R[101], R[102]
  local l7, h7 = R[103], R[104]
  local l8, h8 = R[133], R[134]
  local l9, h9 = R[135], R[136]
  local l10, h10 = R[165], R[166]
  local l11, h11 = R[167], R[168]
  local l12, h12 = R[197], R[198]
  local l13, h13 = R[199], R[200]
  local l14, h14 = R[229], R[230]
  local l15, h15 = R[231], R[232]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 16, bxor(T[5], l0))
  writeu32(mem, cur + 20, bxor(T[6], h0))
  writeu32(mem, cur + 24, bxor(T[7], l1))
  writeu32(mem, cur + 28, bxor(T[8], h1))
  writeu32(mem, cur + 144, bxor(T[37], l2))
  writeu32(mem, cur + 148, bxor(T[38], h2))
  writeu32(mem, cur + 152, bxor(T[39], l3))
  writeu32(mem, cur + 156, bxor(T[40], h3))
  writeu32(mem, cur + 272, bxor(T[69], l4))
  writeu32(mem, cur + 276, bxor(T[70], h4))
  writeu32(mem, cur + 280, bxor(T[71], l5))
  writeu32(mem, cur + 284, bxor(T[72], h5))
  writeu32(mem, cur + 400, bxor(T[101], l6))
  writeu32(mem, cur + 404, bxor(T[102], h6))
  writeu32(mem, cur + 408, bxor(T[103], l7))
  writeu32(mem, cur + 412, bxor(T[104], h7))
  writeu32(mem, cur + 528, bxor(T[133], l8))
  writeu32(mem, cur + 532, bxor(T[134], h8))
  writeu32(mem, cur + 536, bxor(T[135], l9))
  writeu32(mem, cur + 540, bxor(T[136], h9))
  writeu32(mem, cur + 656, bxor(T[165], l10))
  writeu32(mem, cur + 660, bxor(T[166], h10))
  writeu32(mem, cur + 664, bxor(T[167], l11))
  writeu32(mem, cur + 668, bxor(T[168], h11))
  writeu32(mem, cur + 784, bxor(T[197], l12))
  writeu32(mem, cur + 788, bxor(T[198], h12))
  writeu32(mem, cur + 792, bxor(T[199], l13))
  writeu32(mem, cur + 796, bxor(T[200], h13))
  writeu32(mem, cur + 912, bxor(T[229], l14))
  writeu32(mem, cur + 916, bxor(T[230], h14))
  writeu32(mem, cur + 920, bxor(T[231], l15))
  writeu32(mem, cur + 924, bxor(T[232], h15))
end
do
  local l0, h0 = R[9], R[10]
  local l1, h1 = R[11], R[12]
  local l2, h2 = R[41], R[42]
  local l3, h3 = R[43], R[44]
  local l4, h4 = R[73], R[74]
  local l5, h5 = R[75], R[76]
  local l6, h6 = R[105], R[106]
  local l7, h7 = R[107], R[108]
  local l8, h8 = R[137], R[138]
  local l9, h9 = R[139], R[140]
  local l10, h10 = R[169], R[170]
  local l11, h11 = R[171], R[172]
  local l12, h12 = R[201], R[202]
  local l13, h13 = R[203], R[204]
  local l14, h14 = R[233], R[234]
  local l15, h15 = R[235], R[236]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 32, bxor(T[9], l0))
  writeu32(mem, cur + 36, bxor(T[10], h0))
  writeu32(mem, cur + 40, bxor(T[11], l1))
  writeu32(mem, cur + 44, bxor(T[12], h1))
  writeu32(mem, cur + 160, bxor(T[41], l2))
  writeu32(mem, cur + 164, bxor(T[42], h2))
  writeu32(mem, cur + 168, bxor(T[43], l3))
  writeu32(mem, cur + 172, bxor(T[44], h3))
  writeu32(mem, cur + 288, bxor(T[73], l4))
  writeu32(mem, cur + 292, bxor(T[74], h4))
  writeu32(mem, cur + 296, bxor(T[75], l5))
  writeu32(mem, cur + 300, bxor(T[76], h5))
  writeu32(mem, cur + 416, bxor(T[105], l6))
  writeu32(mem, cur + 420, bxor(T[106], h6))
  writeu32(mem, cur + 424, bxor(T[107], l7))
  writeu32(mem, cur + 428, bxor(T[108], h7))
  writeu32(mem, cur + 544, bxor(T[137], l8))
  writeu32(mem, cur + 548, bxor(T[138], h8))
  writeu32(mem, cur + 552, bxor(T[139], l9))
  writeu32(mem, cur + 556, bxor(T[140], h9))
  writeu32(mem, cur + 672, bxor(T[169], l10))
  writeu32(mem, cur + 676, bxor(T[170], h10))
  writeu32(mem, cur + 680, bxor(T[171], l11))
  writeu32(mem, cur + 684, bxor(T[172], h11))
  writeu32(mem, cur + 800, bxor(T[201], l12))
  writeu32(mem, cur + 804, bxor(T[202], h12))
  writeu32(mem, cur + 808, bxor(T[203], l13))
  writeu32(mem, cur + 812, bxor(T[204], h13))
  writeu32(mem, cur + 928, bxor(T[233], l14))
  writeu32(mem, cur + 932, bxor(T[234], h14))
  writeu32(mem, cur + 936, bxor(T[235], l15))
  writeu32(mem, cur + 940, bxor(T[236], h15))
end
do
  local l0, h0 = R[13], R[14]
  local l1, h1 = R[15], R[16]
  local l2, h2 = R[45], R[46]
  local l3, h3 = R[47], R[48]
  local l4, h4 = R[77], R[78]
  local l5, h5 = R[79], R[80]
  local l6, h6 = R[109], R[110]
  local l7, h7 = R[111], R[112]
  local l8, h8 = R[141], R[142]
  local l9, h9 = R[143], R[144]
  local l10, h10 = R[173], R[174]
  local l11, h11 = R[175], R[176]
  local l12, h12 = R[205], R[206]
  local l13, h13 = R[207], R[208]
  local l14, h14 = R[237], R[238]
  local l15, h15 = R[239], R[240]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 48, bxor(T[13], l0))
  writeu32(mem, cur + 52, bxor(T[14], h0))
  writeu32(mem, cur + 56, bxor(T[15], l1))
  writeu32(mem, cur + 60, bxor(T[16], h1))
  writeu32(mem, cur + 176, bxor(T[45], l2))
  writeu32(mem, cur + 180, bxor(T[46], h2))
  writeu32(mem, cur + 184, bxor(T[47], l3))
  writeu32(mem, cur + 188, bxor(T[48], h3))
  writeu32(mem, cur + 304, bxor(T[77], l4))
  writeu32(mem, cur + 308, bxor(T[78], h4))
  writeu32(mem, cur + 312, bxor(T[79], l5))
  writeu32(mem, cur + 316, bxor(T[80], h5))
  writeu32(mem, cur + 432, bxor(T[109], l6))
  writeu32(mem, cur + 436, bxor(T[110], h6))
  writeu32(mem, cur + 440, bxor(T[111], l7))
  writeu32(mem, cur + 444, bxor(T[112], h7))
  writeu32(mem, cur + 560, bxor(T[141], l8))
  writeu32(mem, cur + 564, bxor(T[142], h8))
  writeu32(mem, cur + 568, bxor(T[143], l9))
  writeu32(mem, cur + 572, bxor(T[144], h9))
  writeu32(mem, cur + 688, bxor(T[173], l10))
  writeu32(mem, cur + 692, bxor(T[174], h10))
  writeu32(mem, cur + 696, bxor(T[175], l11))
  writeu32(mem, cur + 700, bxor(T[176], h11))
  writeu32(mem, cur + 816, bxor(T[205], l12))
  writeu32(mem, cur + 820, bxor(T[206], h12))
  writeu32(mem, cur + 824, bxor(T[207], l13))
  writeu32(mem, cur + 828, bxor(T[208], h13))
  writeu32(mem, cur + 944, bxor(T[237], l14))
  writeu32(mem, cur + 948, bxor(T[238], h14))
  writeu32(mem, cur + 952, bxor(T[239], l15))
  writeu32(mem, cur + 956, bxor(T[240], h15))
end
do
  local l0, h0 = R[17], R[18]
  local l1, h1 = R[19], R[20]
  local l2, h2 = R[49], R[50]
  local l3, h3 = R[51], R[52]
  local l4, h4 = R[81], R[82]
  local l5, h5 = R[83], R[84]
  local l6, h6 = R[113], R[114]
  local l7, h7 = R[115], R[116]
  local l8, h8 = R[145], R[146]
  local l9, h9 = R[147], R[148]
  local l10, h10 = R[177], R[178]
  local l11, h11 = R[179], R[180]
  local l12, h12 = R[209], R[210]
  local l13, h13 = R[211], R[212]
  local l14, h14 = R[241], R[242]
  local l15, h15 = R[243], R[244]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 64, bxor(T[17], l0))
  writeu32(mem, cur + 68, bxor(T[18], h0))
  writeu32(mem, cur + 72, bxor(T[19], l1))
  writeu32(mem, cur + 76, bxor(T[20], h1))
  writeu32(mem, cur + 192, bxor(T[49], l2))
  writeu32(mem, cur + 196, bxor(T[50], h2))
  writeu32(mem, cur + 200, bxor(T[51], l3))
  writeu32(mem, cur + 204, bxor(T[52], h3))
  writeu32(mem, cur + 320, bxor(T[81], l4))
  writeu32(mem, cur + 324, bxor(T[82], h4))
  writeu32(mem, cur + 328, bxor(T[83], l5))
  writeu32(mem, cur + 332, bxor(T[84], h5))
  writeu32(mem, cur + 448, bxor(T[113], l6))
  writeu32(mem, cur + 452, bxor(T[114], h6))
  writeu32(mem, cur + 456, bxor(T[115], l7))
  writeu32(mem, cur + 460, bxor(T[116], h7))
  writeu32(mem, cur + 576, bxor(T[145], l8))
  writeu32(mem, cur + 580, bxor(T[146], h8))
  writeu32(mem, cur + 584, bxor(T[147], l9))
  writeu32(mem, cur + 588, bxor(T[148], h9))
  writeu32(mem, cur + 704, bxor(T[177], l10))
  writeu32(mem, cur + 708, bxor(T[178], h10))
  writeu32(mem, cur + 712, bxor(T[179], l11))
  writeu32(mem, cur + 716, bxor(T[180], h11))
  writeu32(mem, cur + 832, bxor(T[209], l12))
  writeu32(mem, cur + 836, bxor(T[210], h12))
  writeu32(mem, cur + 840, bxor(T[211], l13))
  writeu32(mem, cur + 844, bxor(T[212], h13))
  writeu32(mem, cur + 960, bxor(T[241], l14))
  writeu32(mem, cur + 964, bxor(T[242], h14))
  writeu32(mem, cur + 968, bxor(T[243], l15))
  writeu32(mem, cur + 972, bxor(T[244], h15))
end
do
  local l0, h0 = R[21], R[22]
  local l1, h1 = R[23], R[24]
  local l2, h2 = R[53], R[54]
  local l3, h3 = R[55], R[56]
  local l4, h4 = R[85], R[86]
  local l5, h5 = R[87], R[88]
  local l6, h6 = R[117], R[118]
  local l7, h7 = R[119], R[120]
  local l8, h8 = R[149], R[150]
  local l9, h9 = R[151], R[152]
  local l10, h10 = R[181], R[182]
  local l11, h11 = R[183], R[184]
  local l12, h12 = R[213], R[214]
  local l13, h13 = R[215], R[216]
  local l14, h14 = R[245], R[246]
  local l15, h15 = R[247], R[248]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 80, bxor(T[21], l0))
  writeu32(mem, cur + 84, bxor(T[22], h0))
  writeu32(mem, cur + 88, bxor(T[23], l1))
  writeu32(mem, cur + 92, bxor(T[24], h1))
  writeu32(mem, cur + 208, bxor(T[53], l2))
  writeu32(mem, cur + 212, bxor(T[54], h2))
  writeu32(mem, cur + 216, bxor(T[55], l3))
  writeu32(mem, cur + 220, bxor(T[56], h3))
  writeu32(mem, cur + 336, bxor(T[85], l4))
  writeu32(mem, cur + 340, bxor(T[86], h4))
  writeu32(mem, cur + 344, bxor(T[87], l5))
  writeu32(mem, cur + 348, bxor(T[88], h5))
  writeu32(mem, cur + 464, bxor(T[117], l6))
  writeu32(mem, cur + 468, bxor(T[118], h6))
  writeu32(mem, cur + 472, bxor(T[119], l7))
  writeu32(mem, cur + 476, bxor(T[120], h7))
  writeu32(mem, cur + 592, bxor(T[149], l8))
  writeu32(mem, cur + 596, bxor(T[150], h8))
  writeu32(mem, cur + 600, bxor(T[151], l9))
  writeu32(mem, cur + 604, bxor(T[152], h9))
  writeu32(mem, cur + 720, bxor(T[181], l10))
  writeu32(mem, cur + 724, bxor(T[182], h10))
  writeu32(mem, cur + 728, bxor(T[183], l11))
  writeu32(mem, cur + 732, bxor(T[184], h11))
  writeu32(mem, cur + 848, bxor(T[213], l12))
  writeu32(mem, cur + 852, bxor(T[214], h12))
  writeu32(mem, cur + 856, bxor(T[215], l13))
  writeu32(mem, cur + 860, bxor(T[216], h13))
  writeu32(mem, cur + 976, bxor(T[245], l14))
  writeu32(mem, cur + 980, bxor(T[246], h14))
  writeu32(mem, cur + 984, bxor(T[247], l15))
  writeu32(mem, cur + 988, bxor(T[248], h15))
end
do
  local l0, h0 = R[25], R[26]
  local l1, h1 = R[27], R[28]
  local l2, h2 = R[57], R[58]
  local l3, h3 = R[59], R[60]
  local l4, h4 = R[89], R[90]
  local l5, h5 = R[91], R[92]
  local l6, h6 = R[121], R[122]
  local l7, h7 = R[123], R[124]
  local l8, h8 = R[153], R[154]
  local l9, h9 = R[155], R[156]
  local l10, h10 = R[185], R[186]
  local l11, h11 = R[187], R[188]
  local l12, h12 = R[217], R[218]
  local l13, h13 = R[219], R[220]
  local l14, h14 = R[249], R[250]
  local l15, h15 = R[251], R[252]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 96, bxor(T[25], l0))
  writeu32(mem, cur + 100, bxor(T[26], h0))
  writeu32(mem, cur + 104, bxor(T[27], l1))
  writeu32(mem, cur + 108, bxor(T[28], h1))
  writeu32(mem, cur + 224, bxor(T[57], l2))
  writeu32(mem, cur + 228, bxor(T[58], h2))
  writeu32(mem, cur + 232, bxor(T[59], l3))
  writeu32(mem, cur + 236, bxor(T[60], h3))
  writeu32(mem, cur + 352, bxor(T[89], l4))
  writeu32(mem, cur + 356, bxor(T[90], h4))
  writeu32(mem, cur + 360, bxor(T[91], l5))
  writeu32(mem, cur + 364, bxor(T[92], h5))
  writeu32(mem, cur + 480, bxor(T[121], l6))
  writeu32(mem, cur + 484, bxor(T[122], h6))
  writeu32(mem, cur + 488, bxor(T[123], l7))
  writeu32(mem, cur + 492, bxor(T[124], h7))
  writeu32(mem, cur + 608, bxor(T[153], l8))
  writeu32(mem, cur + 612, bxor(T[154], h8))
  writeu32(mem, cur + 616, bxor(T[155], l9))
  writeu32(mem, cur + 620, bxor(T[156], h9))
  writeu32(mem, cur + 736, bxor(T[185], l10))
  writeu32(mem, cur + 740, bxor(T[186], h10))
  writeu32(mem, cur + 744, bxor(T[187], l11))
  writeu32(mem, cur + 748, bxor(T[188], h11))
  writeu32(mem, cur + 864, bxor(T[217], l12))
  writeu32(mem, cur + 868, bxor(T[218], h12))
  writeu32(mem, cur + 872, bxor(T[219], l13))
  writeu32(mem, cur + 876, bxor(T[220], h13))
  writeu32(mem, cur + 992, bxor(T[249], l14))
  writeu32(mem, cur + 996, bxor(T[250], h14))
  writeu32(mem, cur + 1000, bxor(T[251], l15))
  writeu32(mem, cur + 1004, bxor(T[252], h15))
end
do
  local l0, h0 = R[29], R[30]
  local l1, h1 = R[31], R[32]
  local l2, h2 = R[61], R[62]
  local l3, h3 = R[63], R[64]
  local l4, h4 = R[93], R[94]
  local l5, h5 = R[95], R[96]
  local l6, h6 = R[125], R[126]
  local l7, h7 = R[127], R[128]
  local l8, h8 = R[157], R[158]
  local l9, h9 = R[159], R[160]
  local l10, h10 = R[189], R[190]
  local l11, h11 = R[191], R[192]
  local l12, h12 = R[221], R[222]
  local l13, h13 = R[223], R[224]
  local l14, h14 = R[253], R[254]
  local l15, h15 = R[255], R[256]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 112, bxor(T[29], l0))
  writeu32(mem, cur + 116, bxor(T[30], h0))
  writeu32(mem, cur + 120, bxor(T[31], l1))
  writeu32(mem, cur + 124, bxor(T[32], h1))
  writeu32(mem, cur + 240, bxor(T[61], l2))
  writeu32(mem, cur + 244, bxor(T[62], h2))
  writeu32(mem, cur + 248, bxor(T[63], l3))
  writeu32(mem, cur + 252, bxor(T[64], h3))
  writeu32(mem, cur + 368, bxor(T[93], l4))
  writeu32(mem, cur + 372, bxor(T[94], h4))
  writeu32(mem, cur + 376, bxor(T[95], l5))
  writeu32(mem, cur + 380, bxor(T[96], h5))
  writeu32(mem, cur + 496, bxor(T[125], l6))
  writeu32(mem, cur + 500, bxor(T[126], h6))
  writeu32(mem, cur + 504, bxor(T[127], l7))
  writeu32(mem, cur + 508, bxor(T[128], h7))
  writeu32(mem, cur + 624, bxor(T[157], l8))
  writeu32(mem, cur + 628, bxor(T[158], h8))
  writeu32(mem, cur + 632, bxor(T[159], l9))
  writeu32(mem, cur + 636, bxor(T[160], h9))
  writeu32(mem, cur + 752, bxor(T[189], l10))
  writeu32(mem, cur + 756, bxor(T[190], h10))
  writeu32(mem, cur + 760, bxor(T[191], l11))
  writeu32(mem, cur + 764, bxor(T[192], h11))
  writeu32(mem, cur + 880, bxor(T[221], l12))
  writeu32(mem, cur + 884, bxor(T[222], h12))
  writeu32(mem, cur + 888, bxor(T[223], l13))
  writeu32(mem, cur + 892, bxor(T[224], h13))
  writeu32(mem, cur + 1008, bxor(T[253], l14))
  writeu32(mem, cur + 1012, bxor(T[254], h14))
  writeu32(mem, cur + 1016, bxor(T[255], l15))
  writeu32(mem, cur + 1020, bxor(T[256], h15))
end
end

local function fillBlockX(mem, prv, ref, cur)
do
  local pl = readu32(mem, prv + 0)
  local ph = readu32(mem, prv + 4)
  local l0 = bxor(pl, readu32(mem, ref + 0))
  local h0 = bxor(ph, readu32(mem, ref + 4))
  R[1] = l0; R[2] = h0
  T[1] = bxor(l0, readu32(mem, cur + 0))
  T[2] = bxor(h0, readu32(mem, cur + 4))
  local pl = readu32(mem, prv + 8)
  local ph = readu32(mem, prv + 12)
  local l1 = bxor(pl, readu32(mem, ref + 8))
  local h1 = bxor(ph, readu32(mem, ref + 12))
  R[3] = l1; R[4] = h1
  T[3] = bxor(l1, readu32(mem, cur + 8))
  T[4] = bxor(h1, readu32(mem, cur + 12))
  local pl = readu32(mem, prv + 16)
  local ph = readu32(mem, prv + 20)
  local l2 = bxor(pl, readu32(mem, ref + 16))
  local h2 = bxor(ph, readu32(mem, ref + 20))
  R[5] = l2; R[6] = h2
  T[5] = bxor(l2, readu32(mem, cur + 16))
  T[6] = bxor(h2, readu32(mem, cur + 20))
  local pl = readu32(mem, prv + 24)
  local ph = readu32(mem, prv + 28)
  local l3 = bxor(pl, readu32(mem, ref + 24))
  local h3 = bxor(ph, readu32(mem, ref + 28))
  R[7] = l3; R[8] = h3
  T[7] = bxor(l3, readu32(mem, cur + 24))
  T[8] = bxor(h3, readu32(mem, cur + 28))
  local pl = readu32(mem, prv + 32)
  local ph = readu32(mem, prv + 36)
  local l4 = bxor(pl, readu32(mem, ref + 32))
  local h4 = bxor(ph, readu32(mem, ref + 36))
  R[9] = l4; R[10] = h4
  T[9] = bxor(l4, readu32(mem, cur + 32))
  T[10] = bxor(h4, readu32(mem, cur + 36))
  local pl = readu32(mem, prv + 40)
  local ph = readu32(mem, prv + 44)
  local l5 = bxor(pl, readu32(mem, ref + 40))
  local h5 = bxor(ph, readu32(mem, ref + 44))
  R[11] = l5; R[12] = h5
  T[11] = bxor(l5, readu32(mem, cur + 40))
  T[12] = bxor(h5, readu32(mem, cur + 44))
  local pl = readu32(mem, prv + 48)
  local ph = readu32(mem, prv + 52)
  local l6 = bxor(pl, readu32(mem, ref + 48))
  local h6 = bxor(ph, readu32(mem, ref + 52))
  R[13] = l6; R[14] = h6
  T[13] = bxor(l6, readu32(mem, cur + 48))
  T[14] = bxor(h6, readu32(mem, cur + 52))
  local pl = readu32(mem, prv + 56)
  local ph = readu32(mem, prv + 60)
  local l7 = bxor(pl, readu32(mem, ref + 56))
  local h7 = bxor(ph, readu32(mem, ref + 60))
  R[15] = l7; R[16] = h7
  T[15] = bxor(l7, readu32(mem, cur + 56))
  T[16] = bxor(h7, readu32(mem, cur + 60))
  local pl = readu32(mem, prv + 64)
  local ph = readu32(mem, prv + 68)
  local l8 = bxor(pl, readu32(mem, ref + 64))
  local h8 = bxor(ph, readu32(mem, ref + 68))
  R[17] = l8; R[18] = h8
  T[17] = bxor(l8, readu32(mem, cur + 64))
  T[18] = bxor(h8, readu32(mem, cur + 68))
  local pl = readu32(mem, prv + 72)
  local ph = readu32(mem, prv + 76)
  local l9 = bxor(pl, readu32(mem, ref + 72))
  local h9 = bxor(ph, readu32(mem, ref + 76))
  R[19] = l9; R[20] = h9
  T[19] = bxor(l9, readu32(mem, cur + 72))
  T[20] = bxor(h9, readu32(mem, cur + 76))
  local pl = readu32(mem, prv + 80)
  local ph = readu32(mem, prv + 84)
  local l10 = bxor(pl, readu32(mem, ref + 80))
  local h10 = bxor(ph, readu32(mem, ref + 84))
  R[21] = l10; R[22] = h10
  T[21] = bxor(l10, readu32(mem, cur + 80))
  T[22] = bxor(h10, readu32(mem, cur + 84))
  local pl = readu32(mem, prv + 88)
  local ph = readu32(mem, prv + 92)
  local l11 = bxor(pl, readu32(mem, ref + 88))
  local h11 = bxor(ph, readu32(mem, ref + 92))
  R[23] = l11; R[24] = h11
  T[23] = bxor(l11, readu32(mem, cur + 88))
  T[24] = bxor(h11, readu32(mem, cur + 92))
  local pl = readu32(mem, prv + 96)
  local ph = readu32(mem, prv + 100)
  local l12 = bxor(pl, readu32(mem, ref + 96))
  local h12 = bxor(ph, readu32(mem, ref + 100))
  R[25] = l12; R[26] = h12
  T[25] = bxor(l12, readu32(mem, cur + 96))
  T[26] = bxor(h12, readu32(mem, cur + 100))
  local pl = readu32(mem, prv + 104)
  local ph = readu32(mem, prv + 108)
  local l13 = bxor(pl, readu32(mem, ref + 104))
  local h13 = bxor(ph, readu32(mem, ref + 108))
  R[27] = l13; R[28] = h13
  T[27] = bxor(l13, readu32(mem, cur + 104))
  T[28] = bxor(h13, readu32(mem, cur + 108))
  local pl = readu32(mem, prv + 112)
  local ph = readu32(mem, prv + 116)
  local l14 = bxor(pl, readu32(mem, ref + 112))
  local h14 = bxor(ph, readu32(mem, ref + 116))
  R[29] = l14; R[30] = h14
  T[29] = bxor(l14, readu32(mem, cur + 112))
  T[30] = bxor(h14, readu32(mem, cur + 116))
  local pl = readu32(mem, prv + 120)
  local ph = readu32(mem, prv + 124)
  local l15 = bxor(pl, readu32(mem, ref + 120))
  local h15 = bxor(ph, readu32(mem, ref + 124))
  R[31] = l15; R[32] = h15
  T[31] = bxor(l15, readu32(mem, cur + 120))
  T[32] = bxor(h15, readu32(mem, cur + 124))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[1] = l0; R[2] = h0
  R[3] = l1; R[4] = h1
  R[5] = l2; R[6] = h2
  R[7] = l3; R[8] = h3
  R[9] = l4; R[10] = h4
  R[11] = l5; R[12] = h5
  R[13] = l6; R[14] = h6
  R[15] = l7; R[16] = h7
  R[17] = l8; R[18] = h8
  R[19] = l9; R[20] = h9
  R[21] = l10; R[22] = h10
  R[23] = l11; R[24] = h11
  R[25] = l12; R[26] = h12
  R[27] = l13; R[28] = h13
  R[29] = l14; R[30] = h14
  R[31] = l15; R[32] = h15
end
do
  local pl = readu32(mem, prv + 128)
  local ph = readu32(mem, prv + 132)
  local l0 = bxor(pl, readu32(mem, ref + 128))
  local h0 = bxor(ph, readu32(mem, ref + 132))
  R[33] = l0; R[34] = h0
  T[33] = bxor(l0, readu32(mem, cur + 128))
  T[34] = bxor(h0, readu32(mem, cur + 132))
  local pl = readu32(mem, prv + 136)
  local ph = readu32(mem, prv + 140)
  local l1 = bxor(pl, readu32(mem, ref + 136))
  local h1 = bxor(ph, readu32(mem, ref + 140))
  R[35] = l1; R[36] = h1
  T[35] = bxor(l1, readu32(mem, cur + 136))
  T[36] = bxor(h1, readu32(mem, cur + 140))
  local pl = readu32(mem, prv + 144)
  local ph = readu32(mem, prv + 148)
  local l2 = bxor(pl, readu32(mem, ref + 144))
  local h2 = bxor(ph, readu32(mem, ref + 148))
  R[37] = l2; R[38] = h2
  T[37] = bxor(l2, readu32(mem, cur + 144))
  T[38] = bxor(h2, readu32(mem, cur + 148))
  local pl = readu32(mem, prv + 152)
  local ph = readu32(mem, prv + 156)
  local l3 = bxor(pl, readu32(mem, ref + 152))
  local h3 = bxor(ph, readu32(mem, ref + 156))
  R[39] = l3; R[40] = h3
  T[39] = bxor(l3, readu32(mem, cur + 152))
  T[40] = bxor(h3, readu32(mem, cur + 156))
  local pl = readu32(mem, prv + 160)
  local ph = readu32(mem, prv + 164)
  local l4 = bxor(pl, readu32(mem, ref + 160))
  local h4 = bxor(ph, readu32(mem, ref + 164))
  R[41] = l4; R[42] = h4
  T[41] = bxor(l4, readu32(mem, cur + 160))
  T[42] = bxor(h4, readu32(mem, cur + 164))
  local pl = readu32(mem, prv + 168)
  local ph = readu32(mem, prv + 172)
  local l5 = bxor(pl, readu32(mem, ref + 168))
  local h5 = bxor(ph, readu32(mem, ref + 172))
  R[43] = l5; R[44] = h5
  T[43] = bxor(l5, readu32(mem, cur + 168))
  T[44] = bxor(h5, readu32(mem, cur + 172))
  local pl = readu32(mem, prv + 176)
  local ph = readu32(mem, prv + 180)
  local l6 = bxor(pl, readu32(mem, ref + 176))
  local h6 = bxor(ph, readu32(mem, ref + 180))
  R[45] = l6; R[46] = h6
  T[45] = bxor(l6, readu32(mem, cur + 176))
  T[46] = bxor(h6, readu32(mem, cur + 180))
  local pl = readu32(mem, prv + 184)
  local ph = readu32(mem, prv + 188)
  local l7 = bxor(pl, readu32(mem, ref + 184))
  local h7 = bxor(ph, readu32(mem, ref + 188))
  R[47] = l7; R[48] = h7
  T[47] = bxor(l7, readu32(mem, cur + 184))
  T[48] = bxor(h7, readu32(mem, cur + 188))
  local pl = readu32(mem, prv + 192)
  local ph = readu32(mem, prv + 196)
  local l8 = bxor(pl, readu32(mem, ref + 192))
  local h8 = bxor(ph, readu32(mem, ref + 196))
  R[49] = l8; R[50] = h8
  T[49] = bxor(l8, readu32(mem, cur + 192))
  T[50] = bxor(h8, readu32(mem, cur + 196))
  local pl = readu32(mem, prv + 200)
  local ph = readu32(mem, prv + 204)
  local l9 = bxor(pl, readu32(mem, ref + 200))
  local h9 = bxor(ph, readu32(mem, ref + 204))
  R[51] = l9; R[52] = h9
  T[51] = bxor(l9, readu32(mem, cur + 200))
  T[52] = bxor(h9, readu32(mem, cur + 204))
  local pl = readu32(mem, prv + 208)
  local ph = readu32(mem, prv + 212)
  local l10 = bxor(pl, readu32(mem, ref + 208))
  local h10 = bxor(ph, readu32(mem, ref + 212))
  R[53] = l10; R[54] = h10
  T[53] = bxor(l10, readu32(mem, cur + 208))
  T[54] = bxor(h10, readu32(mem, cur + 212))
  local pl = readu32(mem, prv + 216)
  local ph = readu32(mem, prv + 220)
  local l11 = bxor(pl, readu32(mem, ref + 216))
  local h11 = bxor(ph, readu32(mem, ref + 220))
  R[55] = l11; R[56] = h11
  T[55] = bxor(l11, readu32(mem, cur + 216))
  T[56] = bxor(h11, readu32(mem, cur + 220))
  local pl = readu32(mem, prv + 224)
  local ph = readu32(mem, prv + 228)
  local l12 = bxor(pl, readu32(mem, ref + 224))
  local h12 = bxor(ph, readu32(mem, ref + 228))
  R[57] = l12; R[58] = h12
  T[57] = bxor(l12, readu32(mem, cur + 224))
  T[58] = bxor(h12, readu32(mem, cur + 228))
  local pl = readu32(mem, prv + 232)
  local ph = readu32(mem, prv + 236)
  local l13 = bxor(pl, readu32(mem, ref + 232))
  local h13 = bxor(ph, readu32(mem, ref + 236))
  R[59] = l13; R[60] = h13
  T[59] = bxor(l13, readu32(mem, cur + 232))
  T[60] = bxor(h13, readu32(mem, cur + 236))
  local pl = readu32(mem, prv + 240)
  local ph = readu32(mem, prv + 244)
  local l14 = bxor(pl, readu32(mem, ref + 240))
  local h14 = bxor(ph, readu32(mem, ref + 244))
  R[61] = l14; R[62] = h14
  T[61] = bxor(l14, readu32(mem, cur + 240))
  T[62] = bxor(h14, readu32(mem, cur + 244))
  local pl = readu32(mem, prv + 248)
  local ph = readu32(mem, prv + 252)
  local l15 = bxor(pl, readu32(mem, ref + 248))
  local h15 = bxor(ph, readu32(mem, ref + 252))
  R[63] = l15; R[64] = h15
  T[63] = bxor(l15, readu32(mem, cur + 248))
  T[64] = bxor(h15, readu32(mem, cur + 252))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[33] = l0; R[34] = h0
  R[35] = l1; R[36] = h1
  R[37] = l2; R[38] = h2
  R[39] = l3; R[40] = h3
  R[41] = l4; R[42] = h4
  R[43] = l5; R[44] = h5
  R[45] = l6; R[46] = h6
  R[47] = l7; R[48] = h7
  R[49] = l8; R[50] = h8
  R[51] = l9; R[52] = h9
  R[53] = l10; R[54] = h10
  R[55] = l11; R[56] = h11
  R[57] = l12; R[58] = h12
  R[59] = l13; R[60] = h13
  R[61] = l14; R[62] = h14
  R[63] = l15; R[64] = h15
end
do
  local pl = readu32(mem, prv + 256)
  local ph = readu32(mem, prv + 260)
  local l0 = bxor(pl, readu32(mem, ref + 256))
  local h0 = bxor(ph, readu32(mem, ref + 260))
  R[65] = l0; R[66] = h0
  T[65] = bxor(l0, readu32(mem, cur + 256))
  T[66] = bxor(h0, readu32(mem, cur + 260))
  local pl = readu32(mem, prv + 264)
  local ph = readu32(mem, prv + 268)
  local l1 = bxor(pl, readu32(mem, ref + 264))
  local h1 = bxor(ph, readu32(mem, ref + 268))
  R[67] = l1; R[68] = h1
  T[67] = bxor(l1, readu32(mem, cur + 264))
  T[68] = bxor(h1, readu32(mem, cur + 268))
  local pl = readu32(mem, prv + 272)
  local ph = readu32(mem, prv + 276)
  local l2 = bxor(pl, readu32(mem, ref + 272))
  local h2 = bxor(ph, readu32(mem, ref + 276))
  R[69] = l2; R[70] = h2
  T[69] = bxor(l2, readu32(mem, cur + 272))
  T[70] = bxor(h2, readu32(mem, cur + 276))
  local pl = readu32(mem, prv + 280)
  local ph = readu32(mem, prv + 284)
  local l3 = bxor(pl, readu32(mem, ref + 280))
  local h3 = bxor(ph, readu32(mem, ref + 284))
  R[71] = l3; R[72] = h3
  T[71] = bxor(l3, readu32(mem, cur + 280))
  T[72] = bxor(h3, readu32(mem, cur + 284))
  local pl = readu32(mem, prv + 288)
  local ph = readu32(mem, prv + 292)
  local l4 = bxor(pl, readu32(mem, ref + 288))
  local h4 = bxor(ph, readu32(mem, ref + 292))
  R[73] = l4; R[74] = h4
  T[73] = bxor(l4, readu32(mem, cur + 288))
  T[74] = bxor(h4, readu32(mem, cur + 292))
  local pl = readu32(mem, prv + 296)
  local ph = readu32(mem, prv + 300)
  local l5 = bxor(pl, readu32(mem, ref + 296))
  local h5 = bxor(ph, readu32(mem, ref + 300))
  R[75] = l5; R[76] = h5
  T[75] = bxor(l5, readu32(mem, cur + 296))
  T[76] = bxor(h5, readu32(mem, cur + 300))
  local pl = readu32(mem, prv + 304)
  local ph = readu32(mem, prv + 308)
  local l6 = bxor(pl, readu32(mem, ref + 304))
  local h6 = bxor(ph, readu32(mem, ref + 308))
  R[77] = l6; R[78] = h6
  T[77] = bxor(l6, readu32(mem, cur + 304))
  T[78] = bxor(h6, readu32(mem, cur + 308))
  local pl = readu32(mem, prv + 312)
  local ph = readu32(mem, prv + 316)
  local l7 = bxor(pl, readu32(mem, ref + 312))
  local h7 = bxor(ph, readu32(mem, ref + 316))
  R[79] = l7; R[80] = h7
  T[79] = bxor(l7, readu32(mem, cur + 312))
  T[80] = bxor(h7, readu32(mem, cur + 316))
  local pl = readu32(mem, prv + 320)
  local ph = readu32(mem, prv + 324)
  local l8 = bxor(pl, readu32(mem, ref + 320))
  local h8 = bxor(ph, readu32(mem, ref + 324))
  R[81] = l8; R[82] = h8
  T[81] = bxor(l8, readu32(mem, cur + 320))
  T[82] = bxor(h8, readu32(mem, cur + 324))
  local pl = readu32(mem, prv + 328)
  local ph = readu32(mem, prv + 332)
  local l9 = bxor(pl, readu32(mem, ref + 328))
  local h9 = bxor(ph, readu32(mem, ref + 332))
  R[83] = l9; R[84] = h9
  T[83] = bxor(l9, readu32(mem, cur + 328))
  T[84] = bxor(h9, readu32(mem, cur + 332))
  local pl = readu32(mem, prv + 336)
  local ph = readu32(mem, prv + 340)
  local l10 = bxor(pl, readu32(mem, ref + 336))
  local h10 = bxor(ph, readu32(mem, ref + 340))
  R[85] = l10; R[86] = h10
  T[85] = bxor(l10, readu32(mem, cur + 336))
  T[86] = bxor(h10, readu32(mem, cur + 340))
  local pl = readu32(mem, prv + 344)
  local ph = readu32(mem, prv + 348)
  local l11 = bxor(pl, readu32(mem, ref + 344))
  local h11 = bxor(ph, readu32(mem, ref + 348))
  R[87] = l11; R[88] = h11
  T[87] = bxor(l11, readu32(mem, cur + 344))
  T[88] = bxor(h11, readu32(mem, cur + 348))
  local pl = readu32(mem, prv + 352)
  local ph = readu32(mem, prv + 356)
  local l12 = bxor(pl, readu32(mem, ref + 352))
  local h12 = bxor(ph, readu32(mem, ref + 356))
  R[89] = l12; R[90] = h12
  T[89] = bxor(l12, readu32(mem, cur + 352))
  T[90] = bxor(h12, readu32(mem, cur + 356))
  local pl = readu32(mem, prv + 360)
  local ph = readu32(mem, prv + 364)
  local l13 = bxor(pl, readu32(mem, ref + 360))
  local h13 = bxor(ph, readu32(mem, ref + 364))
  R[91] = l13; R[92] = h13
  T[91] = bxor(l13, readu32(mem, cur + 360))
  T[92] = bxor(h13, readu32(mem, cur + 364))
  local pl = readu32(mem, prv + 368)
  local ph = readu32(mem, prv + 372)
  local l14 = bxor(pl, readu32(mem, ref + 368))
  local h14 = bxor(ph, readu32(mem, ref + 372))
  R[93] = l14; R[94] = h14
  T[93] = bxor(l14, readu32(mem, cur + 368))
  T[94] = bxor(h14, readu32(mem, cur + 372))
  local pl = readu32(mem, prv + 376)
  local ph = readu32(mem, prv + 380)
  local l15 = bxor(pl, readu32(mem, ref + 376))
  local h15 = bxor(ph, readu32(mem, ref + 380))
  R[95] = l15; R[96] = h15
  T[95] = bxor(l15, readu32(mem, cur + 376))
  T[96] = bxor(h15, readu32(mem, cur + 380))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[65] = l0; R[66] = h0
  R[67] = l1; R[68] = h1
  R[69] = l2; R[70] = h2
  R[71] = l3; R[72] = h3
  R[73] = l4; R[74] = h4
  R[75] = l5; R[76] = h5
  R[77] = l6; R[78] = h6
  R[79] = l7; R[80] = h7
  R[81] = l8; R[82] = h8
  R[83] = l9; R[84] = h9
  R[85] = l10; R[86] = h10
  R[87] = l11; R[88] = h11
  R[89] = l12; R[90] = h12
  R[91] = l13; R[92] = h13
  R[93] = l14; R[94] = h14
  R[95] = l15; R[96] = h15
end
do
  local pl = readu32(mem, prv + 384)
  local ph = readu32(mem, prv + 388)
  local l0 = bxor(pl, readu32(mem, ref + 384))
  local h0 = bxor(ph, readu32(mem, ref + 388))
  R[97] = l0; R[98] = h0
  T[97] = bxor(l0, readu32(mem, cur + 384))
  T[98] = bxor(h0, readu32(mem, cur + 388))
  local pl = readu32(mem, prv + 392)
  local ph = readu32(mem, prv + 396)
  local l1 = bxor(pl, readu32(mem, ref + 392))
  local h1 = bxor(ph, readu32(mem, ref + 396))
  R[99] = l1; R[100] = h1
  T[99] = bxor(l1, readu32(mem, cur + 392))
  T[100] = bxor(h1, readu32(mem, cur + 396))
  local pl = readu32(mem, prv + 400)
  local ph = readu32(mem, prv + 404)
  local l2 = bxor(pl, readu32(mem, ref + 400))
  local h2 = bxor(ph, readu32(mem, ref + 404))
  R[101] = l2; R[102] = h2
  T[101] = bxor(l2, readu32(mem, cur + 400))
  T[102] = bxor(h2, readu32(mem, cur + 404))
  local pl = readu32(mem, prv + 408)
  local ph = readu32(mem, prv + 412)
  local l3 = bxor(pl, readu32(mem, ref + 408))
  local h3 = bxor(ph, readu32(mem, ref + 412))
  R[103] = l3; R[104] = h3
  T[103] = bxor(l3, readu32(mem, cur + 408))
  T[104] = bxor(h3, readu32(mem, cur + 412))
  local pl = readu32(mem, prv + 416)
  local ph = readu32(mem, prv + 420)
  local l4 = bxor(pl, readu32(mem, ref + 416))
  local h4 = bxor(ph, readu32(mem, ref + 420))
  R[105] = l4; R[106] = h4
  T[105] = bxor(l4, readu32(mem, cur + 416))
  T[106] = bxor(h4, readu32(mem, cur + 420))
  local pl = readu32(mem, prv + 424)
  local ph = readu32(mem, prv + 428)
  local l5 = bxor(pl, readu32(mem, ref + 424))
  local h5 = bxor(ph, readu32(mem, ref + 428))
  R[107] = l5; R[108] = h5
  T[107] = bxor(l5, readu32(mem, cur + 424))
  T[108] = bxor(h5, readu32(mem, cur + 428))
  local pl = readu32(mem, prv + 432)
  local ph = readu32(mem, prv + 436)
  local l6 = bxor(pl, readu32(mem, ref + 432))
  local h6 = bxor(ph, readu32(mem, ref + 436))
  R[109] = l6; R[110] = h6
  T[109] = bxor(l6, readu32(mem, cur + 432))
  T[110] = bxor(h6, readu32(mem, cur + 436))
  local pl = readu32(mem, prv + 440)
  local ph = readu32(mem, prv + 444)
  local l7 = bxor(pl, readu32(mem, ref + 440))
  local h7 = bxor(ph, readu32(mem, ref + 444))
  R[111] = l7; R[112] = h7
  T[111] = bxor(l7, readu32(mem, cur + 440))
  T[112] = bxor(h7, readu32(mem, cur + 444))
  local pl = readu32(mem, prv + 448)
  local ph = readu32(mem, prv + 452)
  local l8 = bxor(pl, readu32(mem, ref + 448))
  local h8 = bxor(ph, readu32(mem, ref + 452))
  R[113] = l8; R[114] = h8
  T[113] = bxor(l8, readu32(mem, cur + 448))
  T[114] = bxor(h8, readu32(mem, cur + 452))
  local pl = readu32(mem, prv + 456)
  local ph = readu32(mem, prv + 460)
  local l9 = bxor(pl, readu32(mem, ref + 456))
  local h9 = bxor(ph, readu32(mem, ref + 460))
  R[115] = l9; R[116] = h9
  T[115] = bxor(l9, readu32(mem, cur + 456))
  T[116] = bxor(h9, readu32(mem, cur + 460))
  local pl = readu32(mem, prv + 464)
  local ph = readu32(mem, prv + 468)
  local l10 = bxor(pl, readu32(mem, ref + 464))
  local h10 = bxor(ph, readu32(mem, ref + 468))
  R[117] = l10; R[118] = h10
  T[117] = bxor(l10, readu32(mem, cur + 464))
  T[118] = bxor(h10, readu32(mem, cur + 468))
  local pl = readu32(mem, prv + 472)
  local ph = readu32(mem, prv + 476)
  local l11 = bxor(pl, readu32(mem, ref + 472))
  local h11 = bxor(ph, readu32(mem, ref + 476))
  R[119] = l11; R[120] = h11
  T[119] = bxor(l11, readu32(mem, cur + 472))
  T[120] = bxor(h11, readu32(mem, cur + 476))
  local pl = readu32(mem, prv + 480)
  local ph = readu32(mem, prv + 484)
  local l12 = bxor(pl, readu32(mem, ref + 480))
  local h12 = bxor(ph, readu32(mem, ref + 484))
  R[121] = l12; R[122] = h12
  T[121] = bxor(l12, readu32(mem, cur + 480))
  T[122] = bxor(h12, readu32(mem, cur + 484))
  local pl = readu32(mem, prv + 488)
  local ph = readu32(mem, prv + 492)
  local l13 = bxor(pl, readu32(mem, ref + 488))
  local h13 = bxor(ph, readu32(mem, ref + 492))
  R[123] = l13; R[124] = h13
  T[123] = bxor(l13, readu32(mem, cur + 488))
  T[124] = bxor(h13, readu32(mem, cur + 492))
  local pl = readu32(mem, prv + 496)
  local ph = readu32(mem, prv + 500)
  local l14 = bxor(pl, readu32(mem, ref + 496))
  local h14 = bxor(ph, readu32(mem, ref + 500))
  R[125] = l14; R[126] = h14
  T[125] = bxor(l14, readu32(mem, cur + 496))
  T[126] = bxor(h14, readu32(mem, cur + 500))
  local pl = readu32(mem, prv + 504)
  local ph = readu32(mem, prv + 508)
  local l15 = bxor(pl, readu32(mem, ref + 504))
  local h15 = bxor(ph, readu32(mem, ref + 508))
  R[127] = l15; R[128] = h15
  T[127] = bxor(l15, readu32(mem, cur + 504))
  T[128] = bxor(h15, readu32(mem, cur + 508))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[97] = l0; R[98] = h0
  R[99] = l1; R[100] = h1
  R[101] = l2; R[102] = h2
  R[103] = l3; R[104] = h3
  R[105] = l4; R[106] = h4
  R[107] = l5; R[108] = h5
  R[109] = l6; R[110] = h6
  R[111] = l7; R[112] = h7
  R[113] = l8; R[114] = h8
  R[115] = l9; R[116] = h9
  R[117] = l10; R[118] = h10
  R[119] = l11; R[120] = h11
  R[121] = l12; R[122] = h12
  R[123] = l13; R[124] = h13
  R[125] = l14; R[126] = h14
  R[127] = l15; R[128] = h15
end
do
  local pl = readu32(mem, prv + 512)
  local ph = readu32(mem, prv + 516)
  local l0 = bxor(pl, readu32(mem, ref + 512))
  local h0 = bxor(ph, readu32(mem, ref + 516))
  R[129] = l0; R[130] = h0
  T[129] = bxor(l0, readu32(mem, cur + 512))
  T[130] = bxor(h0, readu32(mem, cur + 516))
  local pl = readu32(mem, prv + 520)
  local ph = readu32(mem, prv + 524)
  local l1 = bxor(pl, readu32(mem, ref + 520))
  local h1 = bxor(ph, readu32(mem, ref + 524))
  R[131] = l1; R[132] = h1
  T[131] = bxor(l1, readu32(mem, cur + 520))
  T[132] = bxor(h1, readu32(mem, cur + 524))
  local pl = readu32(mem, prv + 528)
  local ph = readu32(mem, prv + 532)
  local l2 = bxor(pl, readu32(mem, ref + 528))
  local h2 = bxor(ph, readu32(mem, ref + 532))
  R[133] = l2; R[134] = h2
  T[133] = bxor(l2, readu32(mem, cur + 528))
  T[134] = bxor(h2, readu32(mem, cur + 532))
  local pl = readu32(mem, prv + 536)
  local ph = readu32(mem, prv + 540)
  local l3 = bxor(pl, readu32(mem, ref + 536))
  local h3 = bxor(ph, readu32(mem, ref + 540))
  R[135] = l3; R[136] = h3
  T[135] = bxor(l3, readu32(mem, cur + 536))
  T[136] = bxor(h3, readu32(mem, cur + 540))
  local pl = readu32(mem, prv + 544)
  local ph = readu32(mem, prv + 548)
  local l4 = bxor(pl, readu32(mem, ref + 544))
  local h4 = bxor(ph, readu32(mem, ref + 548))
  R[137] = l4; R[138] = h4
  T[137] = bxor(l4, readu32(mem, cur + 544))
  T[138] = bxor(h4, readu32(mem, cur + 548))
  local pl = readu32(mem, prv + 552)
  local ph = readu32(mem, prv + 556)
  local l5 = bxor(pl, readu32(mem, ref + 552))
  local h5 = bxor(ph, readu32(mem, ref + 556))
  R[139] = l5; R[140] = h5
  T[139] = bxor(l5, readu32(mem, cur + 552))
  T[140] = bxor(h5, readu32(mem, cur + 556))
  local pl = readu32(mem, prv + 560)
  local ph = readu32(mem, prv + 564)
  local l6 = bxor(pl, readu32(mem, ref + 560))
  local h6 = bxor(ph, readu32(mem, ref + 564))
  R[141] = l6; R[142] = h6
  T[141] = bxor(l6, readu32(mem, cur + 560))
  T[142] = bxor(h6, readu32(mem, cur + 564))
  local pl = readu32(mem, prv + 568)
  local ph = readu32(mem, prv + 572)
  local l7 = bxor(pl, readu32(mem, ref + 568))
  local h7 = bxor(ph, readu32(mem, ref + 572))
  R[143] = l7; R[144] = h7
  T[143] = bxor(l7, readu32(mem, cur + 568))
  T[144] = bxor(h7, readu32(mem, cur + 572))
  local pl = readu32(mem, prv + 576)
  local ph = readu32(mem, prv + 580)
  local l8 = bxor(pl, readu32(mem, ref + 576))
  local h8 = bxor(ph, readu32(mem, ref + 580))
  R[145] = l8; R[146] = h8
  T[145] = bxor(l8, readu32(mem, cur + 576))
  T[146] = bxor(h8, readu32(mem, cur + 580))
  local pl = readu32(mem, prv + 584)
  local ph = readu32(mem, prv + 588)
  local l9 = bxor(pl, readu32(mem, ref + 584))
  local h9 = bxor(ph, readu32(mem, ref + 588))
  R[147] = l9; R[148] = h9
  T[147] = bxor(l9, readu32(mem, cur + 584))
  T[148] = bxor(h9, readu32(mem, cur + 588))
  local pl = readu32(mem, prv + 592)
  local ph = readu32(mem, prv + 596)
  local l10 = bxor(pl, readu32(mem, ref + 592))
  local h10 = bxor(ph, readu32(mem, ref + 596))
  R[149] = l10; R[150] = h10
  T[149] = bxor(l10, readu32(mem, cur + 592))
  T[150] = bxor(h10, readu32(mem, cur + 596))
  local pl = readu32(mem, prv + 600)
  local ph = readu32(mem, prv + 604)
  local l11 = bxor(pl, readu32(mem, ref + 600))
  local h11 = bxor(ph, readu32(mem, ref + 604))
  R[151] = l11; R[152] = h11
  T[151] = bxor(l11, readu32(mem, cur + 600))
  T[152] = bxor(h11, readu32(mem, cur + 604))
  local pl = readu32(mem, prv + 608)
  local ph = readu32(mem, prv + 612)
  local l12 = bxor(pl, readu32(mem, ref + 608))
  local h12 = bxor(ph, readu32(mem, ref + 612))
  R[153] = l12; R[154] = h12
  T[153] = bxor(l12, readu32(mem, cur + 608))
  T[154] = bxor(h12, readu32(mem, cur + 612))
  local pl = readu32(mem, prv + 616)
  local ph = readu32(mem, prv + 620)
  local l13 = bxor(pl, readu32(mem, ref + 616))
  local h13 = bxor(ph, readu32(mem, ref + 620))
  R[155] = l13; R[156] = h13
  T[155] = bxor(l13, readu32(mem, cur + 616))
  T[156] = bxor(h13, readu32(mem, cur + 620))
  local pl = readu32(mem, prv + 624)
  local ph = readu32(mem, prv + 628)
  local l14 = bxor(pl, readu32(mem, ref + 624))
  local h14 = bxor(ph, readu32(mem, ref + 628))
  R[157] = l14; R[158] = h14
  T[157] = bxor(l14, readu32(mem, cur + 624))
  T[158] = bxor(h14, readu32(mem, cur + 628))
  local pl = readu32(mem, prv + 632)
  local ph = readu32(mem, prv + 636)
  local l15 = bxor(pl, readu32(mem, ref + 632))
  local h15 = bxor(ph, readu32(mem, ref + 636))
  R[159] = l15; R[160] = h15
  T[159] = bxor(l15, readu32(mem, cur + 632))
  T[160] = bxor(h15, readu32(mem, cur + 636))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[129] = l0; R[130] = h0
  R[131] = l1; R[132] = h1
  R[133] = l2; R[134] = h2
  R[135] = l3; R[136] = h3
  R[137] = l4; R[138] = h4
  R[139] = l5; R[140] = h5
  R[141] = l6; R[142] = h6
  R[143] = l7; R[144] = h7
  R[145] = l8; R[146] = h8
  R[147] = l9; R[148] = h9
  R[149] = l10; R[150] = h10
  R[151] = l11; R[152] = h11
  R[153] = l12; R[154] = h12
  R[155] = l13; R[156] = h13
  R[157] = l14; R[158] = h14
  R[159] = l15; R[160] = h15
end
do
  local pl = readu32(mem, prv + 640)
  local ph = readu32(mem, prv + 644)
  local l0 = bxor(pl, readu32(mem, ref + 640))
  local h0 = bxor(ph, readu32(mem, ref + 644))
  R[161] = l0; R[162] = h0
  T[161] = bxor(l0, readu32(mem, cur + 640))
  T[162] = bxor(h0, readu32(mem, cur + 644))
  local pl = readu32(mem, prv + 648)
  local ph = readu32(mem, prv + 652)
  local l1 = bxor(pl, readu32(mem, ref + 648))
  local h1 = bxor(ph, readu32(mem, ref + 652))
  R[163] = l1; R[164] = h1
  T[163] = bxor(l1, readu32(mem, cur + 648))
  T[164] = bxor(h1, readu32(mem, cur + 652))
  local pl = readu32(mem, prv + 656)
  local ph = readu32(mem, prv + 660)
  local l2 = bxor(pl, readu32(mem, ref + 656))
  local h2 = bxor(ph, readu32(mem, ref + 660))
  R[165] = l2; R[166] = h2
  T[165] = bxor(l2, readu32(mem, cur + 656))
  T[166] = bxor(h2, readu32(mem, cur + 660))
  local pl = readu32(mem, prv + 664)
  local ph = readu32(mem, prv + 668)
  local l3 = bxor(pl, readu32(mem, ref + 664))
  local h3 = bxor(ph, readu32(mem, ref + 668))
  R[167] = l3; R[168] = h3
  T[167] = bxor(l3, readu32(mem, cur + 664))
  T[168] = bxor(h3, readu32(mem, cur + 668))
  local pl = readu32(mem, prv + 672)
  local ph = readu32(mem, prv + 676)
  local l4 = bxor(pl, readu32(mem, ref + 672))
  local h4 = bxor(ph, readu32(mem, ref + 676))
  R[169] = l4; R[170] = h4
  T[169] = bxor(l4, readu32(mem, cur + 672))
  T[170] = bxor(h4, readu32(mem, cur + 676))
  local pl = readu32(mem, prv + 680)
  local ph = readu32(mem, prv + 684)
  local l5 = bxor(pl, readu32(mem, ref + 680))
  local h5 = bxor(ph, readu32(mem, ref + 684))
  R[171] = l5; R[172] = h5
  T[171] = bxor(l5, readu32(mem, cur + 680))
  T[172] = bxor(h5, readu32(mem, cur + 684))
  local pl = readu32(mem, prv + 688)
  local ph = readu32(mem, prv + 692)
  local l6 = bxor(pl, readu32(mem, ref + 688))
  local h6 = bxor(ph, readu32(mem, ref + 692))
  R[173] = l6; R[174] = h6
  T[173] = bxor(l6, readu32(mem, cur + 688))
  T[174] = bxor(h6, readu32(mem, cur + 692))
  local pl = readu32(mem, prv + 696)
  local ph = readu32(mem, prv + 700)
  local l7 = bxor(pl, readu32(mem, ref + 696))
  local h7 = bxor(ph, readu32(mem, ref + 700))
  R[175] = l7; R[176] = h7
  T[175] = bxor(l7, readu32(mem, cur + 696))
  T[176] = bxor(h7, readu32(mem, cur + 700))
  local pl = readu32(mem, prv + 704)
  local ph = readu32(mem, prv + 708)
  local l8 = bxor(pl, readu32(mem, ref + 704))
  local h8 = bxor(ph, readu32(mem, ref + 708))
  R[177] = l8; R[178] = h8
  T[177] = bxor(l8, readu32(mem, cur + 704))
  T[178] = bxor(h8, readu32(mem, cur + 708))
  local pl = readu32(mem, prv + 712)
  local ph = readu32(mem, prv + 716)
  local l9 = bxor(pl, readu32(mem, ref + 712))
  local h9 = bxor(ph, readu32(mem, ref + 716))
  R[179] = l9; R[180] = h9
  T[179] = bxor(l9, readu32(mem, cur + 712))
  T[180] = bxor(h9, readu32(mem, cur + 716))
  local pl = readu32(mem, prv + 720)
  local ph = readu32(mem, prv + 724)
  local l10 = bxor(pl, readu32(mem, ref + 720))
  local h10 = bxor(ph, readu32(mem, ref + 724))
  R[181] = l10; R[182] = h10
  T[181] = bxor(l10, readu32(mem, cur + 720))
  T[182] = bxor(h10, readu32(mem, cur + 724))
  local pl = readu32(mem, prv + 728)
  local ph = readu32(mem, prv + 732)
  local l11 = bxor(pl, readu32(mem, ref + 728))
  local h11 = bxor(ph, readu32(mem, ref + 732))
  R[183] = l11; R[184] = h11
  T[183] = bxor(l11, readu32(mem, cur + 728))
  T[184] = bxor(h11, readu32(mem, cur + 732))
  local pl = readu32(mem, prv + 736)
  local ph = readu32(mem, prv + 740)
  local l12 = bxor(pl, readu32(mem, ref + 736))
  local h12 = bxor(ph, readu32(mem, ref + 740))
  R[185] = l12; R[186] = h12
  T[185] = bxor(l12, readu32(mem, cur + 736))
  T[186] = bxor(h12, readu32(mem, cur + 740))
  local pl = readu32(mem, prv + 744)
  local ph = readu32(mem, prv + 748)
  local l13 = bxor(pl, readu32(mem, ref + 744))
  local h13 = bxor(ph, readu32(mem, ref + 748))
  R[187] = l13; R[188] = h13
  T[187] = bxor(l13, readu32(mem, cur + 744))
  T[188] = bxor(h13, readu32(mem, cur + 748))
  local pl = readu32(mem, prv + 752)
  local ph = readu32(mem, prv + 756)
  local l14 = bxor(pl, readu32(mem, ref + 752))
  local h14 = bxor(ph, readu32(mem, ref + 756))
  R[189] = l14; R[190] = h14
  T[189] = bxor(l14, readu32(mem, cur + 752))
  T[190] = bxor(h14, readu32(mem, cur + 756))
  local pl = readu32(mem, prv + 760)
  local ph = readu32(mem, prv + 764)
  local l15 = bxor(pl, readu32(mem, ref + 760))
  local h15 = bxor(ph, readu32(mem, ref + 764))
  R[191] = l15; R[192] = h15
  T[191] = bxor(l15, readu32(mem, cur + 760))
  T[192] = bxor(h15, readu32(mem, cur + 764))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[161] = l0; R[162] = h0
  R[163] = l1; R[164] = h1
  R[165] = l2; R[166] = h2
  R[167] = l3; R[168] = h3
  R[169] = l4; R[170] = h4
  R[171] = l5; R[172] = h5
  R[173] = l6; R[174] = h6
  R[175] = l7; R[176] = h7
  R[177] = l8; R[178] = h8
  R[179] = l9; R[180] = h9
  R[181] = l10; R[182] = h10
  R[183] = l11; R[184] = h11
  R[185] = l12; R[186] = h12
  R[187] = l13; R[188] = h13
  R[189] = l14; R[190] = h14
  R[191] = l15; R[192] = h15
end
do
  local pl = readu32(mem, prv + 768)
  local ph = readu32(mem, prv + 772)
  local l0 = bxor(pl, readu32(mem, ref + 768))
  local h0 = bxor(ph, readu32(mem, ref + 772))
  R[193] = l0; R[194] = h0
  T[193] = bxor(l0, readu32(mem, cur + 768))
  T[194] = bxor(h0, readu32(mem, cur + 772))
  local pl = readu32(mem, prv + 776)
  local ph = readu32(mem, prv + 780)
  local l1 = bxor(pl, readu32(mem, ref + 776))
  local h1 = bxor(ph, readu32(mem, ref + 780))
  R[195] = l1; R[196] = h1
  T[195] = bxor(l1, readu32(mem, cur + 776))
  T[196] = bxor(h1, readu32(mem, cur + 780))
  local pl = readu32(mem, prv + 784)
  local ph = readu32(mem, prv + 788)
  local l2 = bxor(pl, readu32(mem, ref + 784))
  local h2 = bxor(ph, readu32(mem, ref + 788))
  R[197] = l2; R[198] = h2
  T[197] = bxor(l2, readu32(mem, cur + 784))
  T[198] = bxor(h2, readu32(mem, cur + 788))
  local pl = readu32(mem, prv + 792)
  local ph = readu32(mem, prv + 796)
  local l3 = bxor(pl, readu32(mem, ref + 792))
  local h3 = bxor(ph, readu32(mem, ref + 796))
  R[199] = l3; R[200] = h3
  T[199] = bxor(l3, readu32(mem, cur + 792))
  T[200] = bxor(h3, readu32(mem, cur + 796))
  local pl = readu32(mem, prv + 800)
  local ph = readu32(mem, prv + 804)
  local l4 = bxor(pl, readu32(mem, ref + 800))
  local h4 = bxor(ph, readu32(mem, ref + 804))
  R[201] = l4; R[202] = h4
  T[201] = bxor(l4, readu32(mem, cur + 800))
  T[202] = bxor(h4, readu32(mem, cur + 804))
  local pl = readu32(mem, prv + 808)
  local ph = readu32(mem, prv + 812)
  local l5 = bxor(pl, readu32(mem, ref + 808))
  local h5 = bxor(ph, readu32(mem, ref + 812))
  R[203] = l5; R[204] = h5
  T[203] = bxor(l5, readu32(mem, cur + 808))
  T[204] = bxor(h5, readu32(mem, cur + 812))
  local pl = readu32(mem, prv + 816)
  local ph = readu32(mem, prv + 820)
  local l6 = bxor(pl, readu32(mem, ref + 816))
  local h6 = bxor(ph, readu32(mem, ref + 820))
  R[205] = l6; R[206] = h6
  T[205] = bxor(l6, readu32(mem, cur + 816))
  T[206] = bxor(h6, readu32(mem, cur + 820))
  local pl = readu32(mem, prv + 824)
  local ph = readu32(mem, prv + 828)
  local l7 = bxor(pl, readu32(mem, ref + 824))
  local h7 = bxor(ph, readu32(mem, ref + 828))
  R[207] = l7; R[208] = h7
  T[207] = bxor(l7, readu32(mem, cur + 824))
  T[208] = bxor(h7, readu32(mem, cur + 828))
  local pl = readu32(mem, prv + 832)
  local ph = readu32(mem, prv + 836)
  local l8 = bxor(pl, readu32(mem, ref + 832))
  local h8 = bxor(ph, readu32(mem, ref + 836))
  R[209] = l8; R[210] = h8
  T[209] = bxor(l8, readu32(mem, cur + 832))
  T[210] = bxor(h8, readu32(mem, cur + 836))
  local pl = readu32(mem, prv + 840)
  local ph = readu32(mem, prv + 844)
  local l9 = bxor(pl, readu32(mem, ref + 840))
  local h9 = bxor(ph, readu32(mem, ref + 844))
  R[211] = l9; R[212] = h9
  T[211] = bxor(l9, readu32(mem, cur + 840))
  T[212] = bxor(h9, readu32(mem, cur + 844))
  local pl = readu32(mem, prv + 848)
  local ph = readu32(mem, prv + 852)
  local l10 = bxor(pl, readu32(mem, ref + 848))
  local h10 = bxor(ph, readu32(mem, ref + 852))
  R[213] = l10; R[214] = h10
  T[213] = bxor(l10, readu32(mem, cur + 848))
  T[214] = bxor(h10, readu32(mem, cur + 852))
  local pl = readu32(mem, prv + 856)
  local ph = readu32(mem, prv + 860)
  local l11 = bxor(pl, readu32(mem, ref + 856))
  local h11 = bxor(ph, readu32(mem, ref + 860))
  R[215] = l11; R[216] = h11
  T[215] = bxor(l11, readu32(mem, cur + 856))
  T[216] = bxor(h11, readu32(mem, cur + 860))
  local pl = readu32(mem, prv + 864)
  local ph = readu32(mem, prv + 868)
  local l12 = bxor(pl, readu32(mem, ref + 864))
  local h12 = bxor(ph, readu32(mem, ref + 868))
  R[217] = l12; R[218] = h12
  T[217] = bxor(l12, readu32(mem, cur + 864))
  T[218] = bxor(h12, readu32(mem, cur + 868))
  local pl = readu32(mem, prv + 872)
  local ph = readu32(mem, prv + 876)
  local l13 = bxor(pl, readu32(mem, ref + 872))
  local h13 = bxor(ph, readu32(mem, ref + 876))
  R[219] = l13; R[220] = h13
  T[219] = bxor(l13, readu32(mem, cur + 872))
  T[220] = bxor(h13, readu32(mem, cur + 876))
  local pl = readu32(mem, prv + 880)
  local ph = readu32(mem, prv + 884)
  local l14 = bxor(pl, readu32(mem, ref + 880))
  local h14 = bxor(ph, readu32(mem, ref + 884))
  R[221] = l14; R[222] = h14
  T[221] = bxor(l14, readu32(mem, cur + 880))
  T[222] = bxor(h14, readu32(mem, cur + 884))
  local pl = readu32(mem, prv + 888)
  local ph = readu32(mem, prv + 892)
  local l15 = bxor(pl, readu32(mem, ref + 888))
  local h15 = bxor(ph, readu32(mem, ref + 892))
  R[223] = l15; R[224] = h15
  T[223] = bxor(l15, readu32(mem, cur + 888))
  T[224] = bxor(h15, readu32(mem, cur + 892))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[193] = l0; R[194] = h0
  R[195] = l1; R[196] = h1
  R[197] = l2; R[198] = h2
  R[199] = l3; R[200] = h3
  R[201] = l4; R[202] = h4
  R[203] = l5; R[204] = h5
  R[205] = l6; R[206] = h6
  R[207] = l7; R[208] = h7
  R[209] = l8; R[210] = h8
  R[211] = l9; R[212] = h9
  R[213] = l10; R[214] = h10
  R[215] = l11; R[216] = h11
  R[217] = l12; R[218] = h12
  R[219] = l13; R[220] = h13
  R[221] = l14; R[222] = h14
  R[223] = l15; R[224] = h15
end
do
  local pl = readu32(mem, prv + 896)
  local ph = readu32(mem, prv + 900)
  local l0 = bxor(pl, readu32(mem, ref + 896))
  local h0 = bxor(ph, readu32(mem, ref + 900))
  R[225] = l0; R[226] = h0
  T[225] = bxor(l0, readu32(mem, cur + 896))
  T[226] = bxor(h0, readu32(mem, cur + 900))
  local pl = readu32(mem, prv + 904)
  local ph = readu32(mem, prv + 908)
  local l1 = bxor(pl, readu32(mem, ref + 904))
  local h1 = bxor(ph, readu32(mem, ref + 908))
  R[227] = l1; R[228] = h1
  T[227] = bxor(l1, readu32(mem, cur + 904))
  T[228] = bxor(h1, readu32(mem, cur + 908))
  local pl = readu32(mem, prv + 912)
  local ph = readu32(mem, prv + 916)
  local l2 = bxor(pl, readu32(mem, ref + 912))
  local h2 = bxor(ph, readu32(mem, ref + 916))
  R[229] = l2; R[230] = h2
  T[229] = bxor(l2, readu32(mem, cur + 912))
  T[230] = bxor(h2, readu32(mem, cur + 916))
  local pl = readu32(mem, prv + 920)
  local ph = readu32(mem, prv + 924)
  local l3 = bxor(pl, readu32(mem, ref + 920))
  local h3 = bxor(ph, readu32(mem, ref + 924))
  R[231] = l3; R[232] = h3
  T[231] = bxor(l3, readu32(mem, cur + 920))
  T[232] = bxor(h3, readu32(mem, cur + 924))
  local pl = readu32(mem, prv + 928)
  local ph = readu32(mem, prv + 932)
  local l4 = bxor(pl, readu32(mem, ref + 928))
  local h4 = bxor(ph, readu32(mem, ref + 932))
  R[233] = l4; R[234] = h4
  T[233] = bxor(l4, readu32(mem, cur + 928))
  T[234] = bxor(h4, readu32(mem, cur + 932))
  local pl = readu32(mem, prv + 936)
  local ph = readu32(mem, prv + 940)
  local l5 = bxor(pl, readu32(mem, ref + 936))
  local h5 = bxor(ph, readu32(mem, ref + 940))
  R[235] = l5; R[236] = h5
  T[235] = bxor(l5, readu32(mem, cur + 936))
  T[236] = bxor(h5, readu32(mem, cur + 940))
  local pl = readu32(mem, prv + 944)
  local ph = readu32(mem, prv + 948)
  local l6 = bxor(pl, readu32(mem, ref + 944))
  local h6 = bxor(ph, readu32(mem, ref + 948))
  R[237] = l6; R[238] = h6
  T[237] = bxor(l6, readu32(mem, cur + 944))
  T[238] = bxor(h6, readu32(mem, cur + 948))
  local pl = readu32(mem, prv + 952)
  local ph = readu32(mem, prv + 956)
  local l7 = bxor(pl, readu32(mem, ref + 952))
  local h7 = bxor(ph, readu32(mem, ref + 956))
  R[239] = l7; R[240] = h7
  T[239] = bxor(l7, readu32(mem, cur + 952))
  T[240] = bxor(h7, readu32(mem, cur + 956))
  local pl = readu32(mem, prv + 960)
  local ph = readu32(mem, prv + 964)
  local l8 = bxor(pl, readu32(mem, ref + 960))
  local h8 = bxor(ph, readu32(mem, ref + 964))
  R[241] = l8; R[242] = h8
  T[241] = bxor(l8, readu32(mem, cur + 960))
  T[242] = bxor(h8, readu32(mem, cur + 964))
  local pl = readu32(mem, prv + 968)
  local ph = readu32(mem, prv + 972)
  local l9 = bxor(pl, readu32(mem, ref + 968))
  local h9 = bxor(ph, readu32(mem, ref + 972))
  R[243] = l9; R[244] = h9
  T[243] = bxor(l9, readu32(mem, cur + 968))
  T[244] = bxor(h9, readu32(mem, cur + 972))
  local pl = readu32(mem, prv + 976)
  local ph = readu32(mem, prv + 980)
  local l10 = bxor(pl, readu32(mem, ref + 976))
  local h10 = bxor(ph, readu32(mem, ref + 980))
  R[245] = l10; R[246] = h10
  T[245] = bxor(l10, readu32(mem, cur + 976))
  T[246] = bxor(h10, readu32(mem, cur + 980))
  local pl = readu32(mem, prv + 984)
  local ph = readu32(mem, prv + 988)
  local l11 = bxor(pl, readu32(mem, ref + 984))
  local h11 = bxor(ph, readu32(mem, ref + 988))
  R[247] = l11; R[248] = h11
  T[247] = bxor(l11, readu32(mem, cur + 984))
  T[248] = bxor(h11, readu32(mem, cur + 988))
  local pl = readu32(mem, prv + 992)
  local ph = readu32(mem, prv + 996)
  local l12 = bxor(pl, readu32(mem, ref + 992))
  local h12 = bxor(ph, readu32(mem, ref + 996))
  R[249] = l12; R[250] = h12
  T[249] = bxor(l12, readu32(mem, cur + 992))
  T[250] = bxor(h12, readu32(mem, cur + 996))
  local pl = readu32(mem, prv + 1000)
  local ph = readu32(mem, prv + 1004)
  local l13 = bxor(pl, readu32(mem, ref + 1000))
  local h13 = bxor(ph, readu32(mem, ref + 1004))
  R[251] = l13; R[252] = h13
  T[251] = bxor(l13, readu32(mem, cur + 1000))
  T[252] = bxor(h13, readu32(mem, cur + 1004))
  local pl = readu32(mem, prv + 1008)
  local ph = readu32(mem, prv + 1012)
  local l14 = bxor(pl, readu32(mem, ref + 1008))
  local h14 = bxor(ph, readu32(mem, ref + 1012))
  R[253] = l14; R[254] = h14
  T[253] = bxor(l14, readu32(mem, cur + 1008))
  T[254] = bxor(h14, readu32(mem, cur + 1012))
  local pl = readu32(mem, prv + 1016)
  local ph = readu32(mem, prv + 1020)
  local l15 = bxor(pl, readu32(mem, ref + 1016))
  local h15 = bxor(ph, readu32(mem, ref + 1020))
  R[255] = l15; R[256] = h15
  T[255] = bxor(l15, readu32(mem, cur + 1016))
  T[256] = bxor(h15, readu32(mem, cur + 1020))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[225] = l0; R[226] = h0
  R[227] = l1; R[228] = h1
  R[229] = l2; R[230] = h2
  R[231] = l3; R[232] = h3
  R[233] = l4; R[234] = h4
  R[235] = l5; R[236] = h5
  R[237] = l6; R[238] = h6
  R[239] = l7; R[240] = h7
  R[241] = l8; R[242] = h8
  R[243] = l9; R[244] = h9
  R[245] = l10; R[246] = h10
  R[247] = l11; R[248] = h11
  R[249] = l12; R[250] = h12
  R[251] = l13; R[252] = h13
  R[253] = l14; R[254] = h14
  R[255] = l15; R[256] = h15
end
do
  local l0, h0 = R[1], R[2]
  local l1, h1 = R[3], R[4]
  local l2, h2 = R[33], R[34]
  local l3, h3 = R[35], R[36]
  local l4, h4 = R[65], R[66]
  local l5, h5 = R[67], R[68]
  local l6, h6 = R[97], R[98]
  local l7, h7 = R[99], R[100]
  local l8, h8 = R[129], R[130]
  local l9, h9 = R[131], R[132]
  local l10, h10 = R[161], R[162]
  local l11, h11 = R[163], R[164]
  local l12, h12 = R[193], R[194]
  local l13, h13 = R[195], R[196]
  local l14, h14 = R[225], R[226]
  local l15, h15 = R[227], R[228]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 0, bxor(T[1], l0))
  writeu32(mem, cur + 4, bxor(T[2], h0))
  writeu32(mem, cur + 8, bxor(T[3], l1))
  writeu32(mem, cur + 12, bxor(T[4], h1))
  writeu32(mem, cur + 128, bxor(T[33], l2))
  writeu32(mem, cur + 132, bxor(T[34], h2))
  writeu32(mem, cur + 136, bxor(T[35], l3))
  writeu32(mem, cur + 140, bxor(T[36], h3))
  writeu32(mem, cur + 256, bxor(T[65], l4))
  writeu32(mem, cur + 260, bxor(T[66], h4))
  writeu32(mem, cur + 264, bxor(T[67], l5))
  writeu32(mem, cur + 268, bxor(T[68], h5))
  writeu32(mem, cur + 384, bxor(T[97], l6))
  writeu32(mem, cur + 388, bxor(T[98], h6))
  writeu32(mem, cur + 392, bxor(T[99], l7))
  writeu32(mem, cur + 396, bxor(T[100], h7))
  writeu32(mem, cur + 512, bxor(T[129], l8))
  writeu32(mem, cur + 516, bxor(T[130], h8))
  writeu32(mem, cur + 520, bxor(T[131], l9))
  writeu32(mem, cur + 524, bxor(T[132], h9))
  writeu32(mem, cur + 640, bxor(T[161], l10))
  writeu32(mem, cur + 644, bxor(T[162], h10))
  writeu32(mem, cur + 648, bxor(T[163], l11))
  writeu32(mem, cur + 652, bxor(T[164], h11))
  writeu32(mem, cur + 768, bxor(T[193], l12))
  writeu32(mem, cur + 772, bxor(T[194], h12))
  writeu32(mem, cur + 776, bxor(T[195], l13))
  writeu32(mem, cur + 780, bxor(T[196], h13))
  writeu32(mem, cur + 896, bxor(T[225], l14))
  writeu32(mem, cur + 900, bxor(T[226], h14))
  writeu32(mem, cur + 904, bxor(T[227], l15))
  writeu32(mem, cur + 908, bxor(T[228], h15))
end
do
  local l0, h0 = R[5], R[6]
  local l1, h1 = R[7], R[8]
  local l2, h2 = R[37], R[38]
  local l3, h3 = R[39], R[40]
  local l4, h4 = R[69], R[70]
  local l5, h5 = R[71], R[72]
  local l6, h6 = R[101], R[102]
  local l7, h7 = R[103], R[104]
  local l8, h8 = R[133], R[134]
  local l9, h9 = R[135], R[136]
  local l10, h10 = R[165], R[166]
  local l11, h11 = R[167], R[168]
  local l12, h12 = R[197], R[198]
  local l13, h13 = R[199], R[200]
  local l14, h14 = R[229], R[230]
  local l15, h15 = R[231], R[232]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 16, bxor(T[5], l0))
  writeu32(mem, cur + 20, bxor(T[6], h0))
  writeu32(mem, cur + 24, bxor(T[7], l1))
  writeu32(mem, cur + 28, bxor(T[8], h1))
  writeu32(mem, cur + 144, bxor(T[37], l2))
  writeu32(mem, cur + 148, bxor(T[38], h2))
  writeu32(mem, cur + 152, bxor(T[39], l3))
  writeu32(mem, cur + 156, bxor(T[40], h3))
  writeu32(mem, cur + 272, bxor(T[69], l4))
  writeu32(mem, cur + 276, bxor(T[70], h4))
  writeu32(mem, cur + 280, bxor(T[71], l5))
  writeu32(mem, cur + 284, bxor(T[72], h5))
  writeu32(mem, cur + 400, bxor(T[101], l6))
  writeu32(mem, cur + 404, bxor(T[102], h6))
  writeu32(mem, cur + 408, bxor(T[103], l7))
  writeu32(mem, cur + 412, bxor(T[104], h7))
  writeu32(mem, cur + 528, bxor(T[133], l8))
  writeu32(mem, cur + 532, bxor(T[134], h8))
  writeu32(mem, cur + 536, bxor(T[135], l9))
  writeu32(mem, cur + 540, bxor(T[136], h9))
  writeu32(mem, cur + 656, bxor(T[165], l10))
  writeu32(mem, cur + 660, bxor(T[166], h10))
  writeu32(mem, cur + 664, bxor(T[167], l11))
  writeu32(mem, cur + 668, bxor(T[168], h11))
  writeu32(mem, cur + 784, bxor(T[197], l12))
  writeu32(mem, cur + 788, bxor(T[198], h12))
  writeu32(mem, cur + 792, bxor(T[199], l13))
  writeu32(mem, cur + 796, bxor(T[200], h13))
  writeu32(mem, cur + 912, bxor(T[229], l14))
  writeu32(mem, cur + 916, bxor(T[230], h14))
  writeu32(mem, cur + 920, bxor(T[231], l15))
  writeu32(mem, cur + 924, bxor(T[232], h15))
end
do
  local l0, h0 = R[9], R[10]
  local l1, h1 = R[11], R[12]
  local l2, h2 = R[41], R[42]
  local l3, h3 = R[43], R[44]
  local l4, h4 = R[73], R[74]
  local l5, h5 = R[75], R[76]
  local l6, h6 = R[105], R[106]
  local l7, h7 = R[107], R[108]
  local l8, h8 = R[137], R[138]
  local l9, h9 = R[139], R[140]
  local l10, h10 = R[169], R[170]
  local l11, h11 = R[171], R[172]
  local l12, h12 = R[201], R[202]
  local l13, h13 = R[203], R[204]
  local l14, h14 = R[233], R[234]
  local l15, h15 = R[235], R[236]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 32, bxor(T[9], l0))
  writeu32(mem, cur + 36, bxor(T[10], h0))
  writeu32(mem, cur + 40, bxor(T[11], l1))
  writeu32(mem, cur + 44, bxor(T[12], h1))
  writeu32(mem, cur + 160, bxor(T[41], l2))
  writeu32(mem, cur + 164, bxor(T[42], h2))
  writeu32(mem, cur + 168, bxor(T[43], l3))
  writeu32(mem, cur + 172, bxor(T[44], h3))
  writeu32(mem, cur + 288, bxor(T[73], l4))
  writeu32(mem, cur + 292, bxor(T[74], h4))
  writeu32(mem, cur + 296, bxor(T[75], l5))
  writeu32(mem, cur + 300, bxor(T[76], h5))
  writeu32(mem, cur + 416, bxor(T[105], l6))
  writeu32(mem, cur + 420, bxor(T[106], h6))
  writeu32(mem, cur + 424, bxor(T[107], l7))
  writeu32(mem, cur + 428, bxor(T[108], h7))
  writeu32(mem, cur + 544, bxor(T[137], l8))
  writeu32(mem, cur + 548, bxor(T[138], h8))
  writeu32(mem, cur + 552, bxor(T[139], l9))
  writeu32(mem, cur + 556, bxor(T[140], h9))
  writeu32(mem, cur + 672, bxor(T[169], l10))
  writeu32(mem, cur + 676, bxor(T[170], h10))
  writeu32(mem, cur + 680, bxor(T[171], l11))
  writeu32(mem, cur + 684, bxor(T[172], h11))
  writeu32(mem, cur + 800, bxor(T[201], l12))
  writeu32(mem, cur + 804, bxor(T[202], h12))
  writeu32(mem, cur + 808, bxor(T[203], l13))
  writeu32(mem, cur + 812, bxor(T[204], h13))
  writeu32(mem, cur + 928, bxor(T[233], l14))
  writeu32(mem, cur + 932, bxor(T[234], h14))
  writeu32(mem, cur + 936, bxor(T[235], l15))
  writeu32(mem, cur + 940, bxor(T[236], h15))
end
do
  local l0, h0 = R[13], R[14]
  local l1, h1 = R[15], R[16]
  local l2, h2 = R[45], R[46]
  local l3, h3 = R[47], R[48]
  local l4, h4 = R[77], R[78]
  local l5, h5 = R[79], R[80]
  local l6, h6 = R[109], R[110]
  local l7, h7 = R[111], R[112]
  local l8, h8 = R[141], R[142]
  local l9, h9 = R[143], R[144]
  local l10, h10 = R[173], R[174]
  local l11, h11 = R[175], R[176]
  local l12, h12 = R[205], R[206]
  local l13, h13 = R[207], R[208]
  local l14, h14 = R[237], R[238]
  local l15, h15 = R[239], R[240]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 48, bxor(T[13], l0))
  writeu32(mem, cur + 52, bxor(T[14], h0))
  writeu32(mem, cur + 56, bxor(T[15], l1))
  writeu32(mem, cur + 60, bxor(T[16], h1))
  writeu32(mem, cur + 176, bxor(T[45], l2))
  writeu32(mem, cur + 180, bxor(T[46], h2))
  writeu32(mem, cur + 184, bxor(T[47], l3))
  writeu32(mem, cur + 188, bxor(T[48], h3))
  writeu32(mem, cur + 304, bxor(T[77], l4))
  writeu32(mem, cur + 308, bxor(T[78], h4))
  writeu32(mem, cur + 312, bxor(T[79], l5))
  writeu32(mem, cur + 316, bxor(T[80], h5))
  writeu32(mem, cur + 432, bxor(T[109], l6))
  writeu32(mem, cur + 436, bxor(T[110], h6))
  writeu32(mem, cur + 440, bxor(T[111], l7))
  writeu32(mem, cur + 444, bxor(T[112], h7))
  writeu32(mem, cur + 560, bxor(T[141], l8))
  writeu32(mem, cur + 564, bxor(T[142], h8))
  writeu32(mem, cur + 568, bxor(T[143], l9))
  writeu32(mem, cur + 572, bxor(T[144], h9))
  writeu32(mem, cur + 688, bxor(T[173], l10))
  writeu32(mem, cur + 692, bxor(T[174], h10))
  writeu32(mem, cur + 696, bxor(T[175], l11))
  writeu32(mem, cur + 700, bxor(T[176], h11))
  writeu32(mem, cur + 816, bxor(T[205], l12))
  writeu32(mem, cur + 820, bxor(T[206], h12))
  writeu32(mem, cur + 824, bxor(T[207], l13))
  writeu32(mem, cur + 828, bxor(T[208], h13))
  writeu32(mem, cur + 944, bxor(T[237], l14))
  writeu32(mem, cur + 948, bxor(T[238], h14))
  writeu32(mem, cur + 952, bxor(T[239], l15))
  writeu32(mem, cur + 956, bxor(T[240], h15))
end
do
  local l0, h0 = R[17], R[18]
  local l1, h1 = R[19], R[20]
  local l2, h2 = R[49], R[50]
  local l3, h3 = R[51], R[52]
  local l4, h4 = R[81], R[82]
  local l5, h5 = R[83], R[84]
  local l6, h6 = R[113], R[114]
  local l7, h7 = R[115], R[116]
  local l8, h8 = R[145], R[146]
  local l9, h9 = R[147], R[148]
  local l10, h10 = R[177], R[178]
  local l11, h11 = R[179], R[180]
  local l12, h12 = R[209], R[210]
  local l13, h13 = R[211], R[212]
  local l14, h14 = R[241], R[242]
  local l15, h15 = R[243], R[244]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 64, bxor(T[17], l0))
  writeu32(mem, cur + 68, bxor(T[18], h0))
  writeu32(mem, cur + 72, bxor(T[19], l1))
  writeu32(mem, cur + 76, bxor(T[20], h1))
  writeu32(mem, cur + 192, bxor(T[49], l2))
  writeu32(mem, cur + 196, bxor(T[50], h2))
  writeu32(mem, cur + 200, bxor(T[51], l3))
  writeu32(mem, cur + 204, bxor(T[52], h3))
  writeu32(mem, cur + 320, bxor(T[81], l4))
  writeu32(mem, cur + 324, bxor(T[82], h4))
  writeu32(mem, cur + 328, bxor(T[83], l5))
  writeu32(mem, cur + 332, bxor(T[84], h5))
  writeu32(mem, cur + 448, bxor(T[113], l6))
  writeu32(mem, cur + 452, bxor(T[114], h6))
  writeu32(mem, cur + 456, bxor(T[115], l7))
  writeu32(mem, cur + 460, bxor(T[116], h7))
  writeu32(mem, cur + 576, bxor(T[145], l8))
  writeu32(mem, cur + 580, bxor(T[146], h8))
  writeu32(mem, cur + 584, bxor(T[147], l9))
  writeu32(mem, cur + 588, bxor(T[148], h9))
  writeu32(mem, cur + 704, bxor(T[177], l10))
  writeu32(mem, cur + 708, bxor(T[178], h10))
  writeu32(mem, cur + 712, bxor(T[179], l11))
  writeu32(mem, cur + 716, bxor(T[180], h11))
  writeu32(mem, cur + 832, bxor(T[209], l12))
  writeu32(mem, cur + 836, bxor(T[210], h12))
  writeu32(mem, cur + 840, bxor(T[211], l13))
  writeu32(mem, cur + 844, bxor(T[212], h13))
  writeu32(mem, cur + 960, bxor(T[241], l14))
  writeu32(mem, cur + 964, bxor(T[242], h14))
  writeu32(mem, cur + 968, bxor(T[243], l15))
  writeu32(mem, cur + 972, bxor(T[244], h15))
end
do
  local l0, h0 = R[21], R[22]
  local l1, h1 = R[23], R[24]
  local l2, h2 = R[53], R[54]
  local l3, h3 = R[55], R[56]
  local l4, h4 = R[85], R[86]
  local l5, h5 = R[87], R[88]
  local l6, h6 = R[117], R[118]
  local l7, h7 = R[119], R[120]
  local l8, h8 = R[149], R[150]
  local l9, h9 = R[151], R[152]
  local l10, h10 = R[181], R[182]
  local l11, h11 = R[183], R[184]
  local l12, h12 = R[213], R[214]
  local l13, h13 = R[215], R[216]
  local l14, h14 = R[245], R[246]
  local l15, h15 = R[247], R[248]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 80, bxor(T[21], l0))
  writeu32(mem, cur + 84, bxor(T[22], h0))
  writeu32(mem, cur + 88, bxor(T[23], l1))
  writeu32(mem, cur + 92, bxor(T[24], h1))
  writeu32(mem, cur + 208, bxor(T[53], l2))
  writeu32(mem, cur + 212, bxor(T[54], h2))
  writeu32(mem, cur + 216, bxor(T[55], l3))
  writeu32(mem, cur + 220, bxor(T[56], h3))
  writeu32(mem, cur + 336, bxor(T[85], l4))
  writeu32(mem, cur + 340, bxor(T[86], h4))
  writeu32(mem, cur + 344, bxor(T[87], l5))
  writeu32(mem, cur + 348, bxor(T[88], h5))
  writeu32(mem, cur + 464, bxor(T[117], l6))
  writeu32(mem, cur + 468, bxor(T[118], h6))
  writeu32(mem, cur + 472, bxor(T[119], l7))
  writeu32(mem, cur + 476, bxor(T[120], h7))
  writeu32(mem, cur + 592, bxor(T[149], l8))
  writeu32(mem, cur + 596, bxor(T[150], h8))
  writeu32(mem, cur + 600, bxor(T[151], l9))
  writeu32(mem, cur + 604, bxor(T[152], h9))
  writeu32(mem, cur + 720, bxor(T[181], l10))
  writeu32(mem, cur + 724, bxor(T[182], h10))
  writeu32(mem, cur + 728, bxor(T[183], l11))
  writeu32(mem, cur + 732, bxor(T[184], h11))
  writeu32(mem, cur + 848, bxor(T[213], l12))
  writeu32(mem, cur + 852, bxor(T[214], h12))
  writeu32(mem, cur + 856, bxor(T[215], l13))
  writeu32(mem, cur + 860, bxor(T[216], h13))
  writeu32(mem, cur + 976, bxor(T[245], l14))
  writeu32(mem, cur + 980, bxor(T[246], h14))
  writeu32(mem, cur + 984, bxor(T[247], l15))
  writeu32(mem, cur + 988, bxor(T[248], h15))
end
do
  local l0, h0 = R[25], R[26]
  local l1, h1 = R[27], R[28]
  local l2, h2 = R[57], R[58]
  local l3, h3 = R[59], R[60]
  local l4, h4 = R[89], R[90]
  local l5, h5 = R[91], R[92]
  local l6, h6 = R[121], R[122]
  local l7, h7 = R[123], R[124]
  local l8, h8 = R[153], R[154]
  local l9, h9 = R[155], R[156]
  local l10, h10 = R[185], R[186]
  local l11, h11 = R[187], R[188]
  local l12, h12 = R[217], R[218]
  local l13, h13 = R[219], R[220]
  local l14, h14 = R[249], R[250]
  local l15, h15 = R[251], R[252]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 96, bxor(T[25], l0))
  writeu32(mem, cur + 100, bxor(T[26], h0))
  writeu32(mem, cur + 104, bxor(T[27], l1))
  writeu32(mem, cur + 108, bxor(T[28], h1))
  writeu32(mem, cur + 224, bxor(T[57], l2))
  writeu32(mem, cur + 228, bxor(T[58], h2))
  writeu32(mem, cur + 232, bxor(T[59], l3))
  writeu32(mem, cur + 236, bxor(T[60], h3))
  writeu32(mem, cur + 352, bxor(T[89], l4))
  writeu32(mem, cur + 356, bxor(T[90], h4))
  writeu32(mem, cur + 360, bxor(T[91], l5))
  writeu32(mem, cur + 364, bxor(T[92], h5))
  writeu32(mem, cur + 480, bxor(T[121], l6))
  writeu32(mem, cur + 484, bxor(T[122], h6))
  writeu32(mem, cur + 488, bxor(T[123], l7))
  writeu32(mem, cur + 492, bxor(T[124], h7))
  writeu32(mem, cur + 608, bxor(T[153], l8))
  writeu32(mem, cur + 612, bxor(T[154], h8))
  writeu32(mem, cur + 616, bxor(T[155], l9))
  writeu32(mem, cur + 620, bxor(T[156], h9))
  writeu32(mem, cur + 736, bxor(T[185], l10))
  writeu32(mem, cur + 740, bxor(T[186], h10))
  writeu32(mem, cur + 744, bxor(T[187], l11))
  writeu32(mem, cur + 748, bxor(T[188], h11))
  writeu32(mem, cur + 864, bxor(T[217], l12))
  writeu32(mem, cur + 868, bxor(T[218], h12))
  writeu32(mem, cur + 872, bxor(T[219], l13))
  writeu32(mem, cur + 876, bxor(T[220], h13))
  writeu32(mem, cur + 992, bxor(T[249], l14))
  writeu32(mem, cur + 996, bxor(T[250], h14))
  writeu32(mem, cur + 1000, bxor(T[251], l15))
  writeu32(mem, cur + 1004, bxor(T[252], h15))
end
do
  local l0, h0 = R[29], R[30]
  local l1, h1 = R[31], R[32]
  local l2, h2 = R[61], R[62]
  local l3, h3 = R[63], R[64]
  local l4, h4 = R[93], R[94]
  local l5, h5 = R[95], R[96]
  local l6, h6 = R[125], R[126]
  local l7, h7 = R[127], R[128]
  local l8, h8 = R[157], R[158]
  local l9, h9 = R[159], R[160]
  local l10, h10 = R[189], R[190]
  local l11, h11 = R[191], R[192]
  local l12, h12 = R[221], R[222]
  local l13, h13 = R[223], R[224]
  local l14, h14 = R[253], R[254]
  local l15, h15 = R[255], R[256]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 112, bxor(T[29], l0))
  writeu32(mem, cur + 116, bxor(T[30], h0))
  writeu32(mem, cur + 120, bxor(T[31], l1))
  writeu32(mem, cur + 124, bxor(T[32], h1))
  writeu32(mem, cur + 240, bxor(T[61], l2))
  writeu32(mem, cur + 244, bxor(T[62], h2))
  writeu32(mem, cur + 248, bxor(T[63], l3))
  writeu32(mem, cur + 252, bxor(T[64], h3))
  writeu32(mem, cur + 368, bxor(T[93], l4))
  writeu32(mem, cur + 372, bxor(T[94], h4))
  writeu32(mem, cur + 376, bxor(T[95], l5))
  writeu32(mem, cur + 380, bxor(T[96], h5))
  writeu32(mem, cur + 496, bxor(T[125], l6))
  writeu32(mem, cur + 500, bxor(T[126], h6))
  writeu32(mem, cur + 504, bxor(T[127], l7))
  writeu32(mem, cur + 508, bxor(T[128], h7))
  writeu32(mem, cur + 624, bxor(T[157], l8))
  writeu32(mem, cur + 628, bxor(T[158], h8))
  writeu32(mem, cur + 632, bxor(T[159], l9))
  writeu32(mem, cur + 636, bxor(T[160], h9))
  writeu32(mem, cur + 752, bxor(T[189], l10))
  writeu32(mem, cur + 756, bxor(T[190], h10))
  writeu32(mem, cur + 760, bxor(T[191], l11))
  writeu32(mem, cur + 764, bxor(T[192], h11))
  writeu32(mem, cur + 880, bxor(T[221], l12))
  writeu32(mem, cur + 884, bxor(T[222], h12))
  writeu32(mem, cur + 888, bxor(T[223], l13))
  writeu32(mem, cur + 892, bxor(T[224], h13))
  writeu32(mem, cur + 1008, bxor(T[253], l14))
  writeu32(mem, cur + 1012, bxor(T[254], h14))
  writeu32(mem, cur + 1016, bxor(T[255], l15))
  writeu32(mem, cur + 1020, bxor(T[256], h15))
end
end

local function le32(n)
	local b = {}
	for i = 1, 4 do
		b[i] = string.char(n % 256)
		n = (n - n % 256) / 256
	end
	return table.concat(b)
end

-- reference_area_size base for a segment (index-1 is added per block)
local M = {}

function M.initCache(blake, key, m_cost, t_cost, onProgress)
	assert(type(key) == "string", "key must be a string")
	m_cost = m_cost or M_COST
	t_cost = t_cost or T_COST
	local seg_len = m_cost // 4
	local lane_len = seg_len * 4
	local mem = buffer.create(m_cost * BLOCK)

	-- H0 = Blake2b-512(lanes, outlen, m_cost, t_cost, version, type,
	--                     pwdlen, pwd, saltlen, salt, secretlen, adlen)
	local h0 = blake.blake2b(
		le32(LANES) .. le32(0) .. le32(m_cost) .. le32(t_cost) .. le32(VERSION) ..
		le32(ARGON2_D) .. le32(#key) .. key .. le32(SALT_LEN) .. SALT ..
		le32(0) .. le32(0),
		64)
	local blockhash = h0 .. le32(0) .. le32(0)

	local tmp = buffer.fromstring(blake.blakeLong(BLOCK, blockhash))
	buffer.copy(mem, 0, tmp, 0, BLOCK)
	blockhash = h0 .. le32(1) .. le32(0)
	tmp = buffer.fromstring(blake.blakeLong(BLOCK, blockhash))
	buffer.copy(mem, BLOCK, tmp, 0, BLOCK)

	for pass = 0, t_cost - 1 do
		for slice = 0, 3 do
			local starting_index = (pass == 0 and slice == 0) and 2 or 0
			-- index_alpha: same_lane is always true, pass/slice only pick a base
			local ras_base = (pass == 0) and slice * seg_len or (lane_len - seg_len)
			local start_pos = (pass ~= 0 and slice ~= 3) and (slice + 1) * seg_len or 0
			local with_xor = pass > 0
			local fill = with_xor and fillBlockX or fillBlock

			local curr = slice * seg_len + starting_index
			local prev
			if curr % lane_len == 0 then
				prev = curr + lane_len - 1
			else
				prev = curr - 1
			end

			for i = starting_index, seg_len - 1 do
				-- casto, aby caller mohl plynule yieldovat (rozhoduje si sam podle casu)
				if onProgress and i % PROGRESS_STEP == 0 then onProgress() end
				if curr % lane_len == 1 then
					prev = curr - 1
				end
				local prevOff = prev * BLOCK
				-- pseudo_rand = first qword of the previous block
				local pr = readu32(mem, prevOff)
				-- relative_position = (u64)pr * pr >> 32  (high 32 bits)
				local p0 = pr % 65536
				local p1 = (pr - p0) / 65536
				local cross = p0 * p1 * 2
				local q = cross % 65536
				local lo = q * 65536 + p0 * p0
				local rp = ((cross - q) / 65536 + p1 * p1 + (lo - lo % W) / W) % W
				-- 1.2.4 map to 0..<reference_area_size-1>
				local ras = ras_base + i - 1
				local m = ras * rp
				rp = ras - 1 - (m - m % W) / W
				-- 1.2.6 absolute position, always lane 0
				local ref = (start_pos + rp) % lane_len
				fill(mem, prevOff, ref * BLOCK, curr * BLOCK)
				curr += 1
				prev += 1
			end
		end
	end
	return mem
end

return M
]==], 'argon2')

local ss = __mod([==[
--!strict
-- SuperscalarHash: program generator + interpreter (pure Luau).
-- Faithful port of rxsrc/src/superscalar.cpp (+ superscalar.hpp,
-- superscalar_program.hpp, blake2_generator.cpp, common.hpp, reciprocal.c).
--
-- Instruction wire format (8 bytes, matches randomx::Instruction):
--   opcode(8) dst(8) src(8) mod(8) imm32(32 LE)
--
-- 64-bit values are pairs of 32-bit halfwords {lo, hi} throughout.

local bit32 = bit32
local band, bor, bxor, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local btest = bit32.btest

local M = {}

local MASK32 = 0xFFFFFFFF

--------------------------------------------------------------------------------
-- Constants (common.hpp / superscalar.hpp)
--------------------------------------------------------------------------------

local RANDOMX_SUPERSCALAR_LATENCY = 170
local SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2
local CYCLE_MAP_SIZE = RANDOMX_SUPERSCALAR_LATENCY + 4
local LOOK_FORWARD_CYCLES = 4
local MAX_THROWAWAY_COUNT = 256
local RegisterNeedsDisplacement = 5 -- x86 r13
local RegistersCount = 8

-- SuperscalarInstructionType
local OP_ISUB_R = 0
local OP_IXOR_R = 1
local OP_IADD_RS = 2
local OP_IMUL_R = 3
local OP_IROR_C = 4
local OP_IADD_C7 = 5
local OP_IXOR_C7 = 6
local OP_IADD_C8 = 7
local OP_IXOR_C8 = 8
local OP_IADD_C9 = 9
local OP_IXOR_C9 = 10
local OP_IMULH_R = 11
local OP_ISMULH_R = 12
local OP_IMUL_RCP = 13
local OP_INVALID = -1

-- ExecutionPort
local PORT_NULL = 0
local PORT_P0 = 1
local PORT_P1 = 2
local PORT_P5 = 4
local PORT_P01 = 3
local PORT_P05 = 5
local PORT_P015 = 7

--------------------------------------------------------------------------------
-- 64-bit helpers (halfword pairs)
--------------------------------------------------------------------------------

local function isZeroOrPowerOf2(x: number): boolean
	return band(x, x - 1) == 0
end

-- shift a 64-bit value left by n (0..63); returns lo, hi (mod 2^32)
local function shl64(lo: number, hi: number, n: number): (number, number)
	if n == 0 then
		return lo, hi
	elseif n == 32 then
		return 0, lo
	elseif n > 32 then
		return lshift(lo, n - 32), bor(lshift(hi, n - 32), rshift(lo, 64 - n))
	end
	return band(lshift(lo, n), MASK32), bor(lshift(hi, n), rshift(lo, 32 - n))
end

local function add64(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo = alo + blo
	local carry = 0
	if lo > MASK32 then
		lo = lo - 0x100000000
		carry = 1
	end
	local hi = ahi + bhi + carry
	if hi > MASK32 then
		hi = hi - 0x100000000
	end
	return lo, hi
end

local function sub64(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo = alo - blo
	local borrow = 0
	if lo < 0 then
		lo = lo + 0x100000000
		borrow = 1
	end
	local hi = ahi - bhi - borrow
	if hi < 0 then
		hi = hi + 0x100000000
	end
	return lo, hi
end

-- full 64x64 -> 128 multiply, 16-bit limbs; returns c0..c7 (limb 0 = LSB)
local function mul128(alo: number, ahi: number, blo: number, bhi: number): (number, number, number, number, number, number, number, number)
	local a0 = band(alo, 0xFFFF)
	local a1 = rshift(alo, 16)
	local a2 = band(ahi, 0xFFFF)
	local a3 = rshift(ahi, 16)
	local b0 = band(blo, 0xFFFF)
	local b1 = rshift(blo, 16)
	local b2 = band(bhi, 0xFFFF)
	local b3 = rshift(bhi, 16)

	local t = a0 * b0
	local c0 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b1 + a1 * b0
	local c1 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b2 + a1 * b1 + a2 * b0
	local c2 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
	local c3 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a1 * b3 + a2 * b2 + a3 * b1
	local c4 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a2 * b3 + a3 * b2
	local c5 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a3 * b3
	local c6 = band(t, 0xFFFF)
	local c7 = math.floor(t / 65536)
	return c0, c1, c2, c3, c4, c5, c6, c7
end

local function mul64lo(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local c0, c1, c2, c3 = mul128(alo, ahi, blo, bhi)
	return c0 + c1 * 65536, c2 + c3 * 65536
end

local function mul64hi(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local _, _, _, _, c4, c5, c6, c7 = mul128(alo, ahi, blo, bhi)
	return c4 + c5 * 65536, c6 + c7 * 65536
end

-- signed 64x64 -> high 64 bits (two's complement)
local function smul64hi(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo, hi = mul64hi(alo, ahi, blo, bhi)
	if ahi >= 0x80000000 then -- a < 0: high -= b
		lo, hi = sub64(lo, hi, blo, bhi)
	end
	if bhi >= 0x80000000 then -- b < 0: high -= a
		lo, hi = sub64(lo, hi, alo, ahi)
	end
	return lo, hi
end

-- rotr of a 64-bit value by n (0..63)
local function rotr64(lo: number, hi: number, n: number): (number, number)
	if n == 0 then
		return lo, hi
	elseif n >= 32 then
		lo, hi = hi, lo
		n = n - 32
		if n == 0 then
			return lo, hi
		end
	end
	return bor(rshift(lo, n), lshift(hi, 32 - n)), bor(rshift(hi, n), lshift(lo, 32 - n))
end

-- 64-bit unsigned div/mod by 32-bit divisor (bitwise long division)
local function divmod64by32(hi: number, lo: number, d: number): (number, number, number)
	local qhi, qlo, rem = 0, 0, 0
	for i = 63, 0, -1 do
		local bitv
		if i >= 32 then
			bitv = band(rshift(hi, i - 32), 1)
		else
			bitv = band(rshift(lo, i), 1)
		end
		rem = rem * 2 + bitv
		if rem >= d then
			rem = rem - d
			if i >= 32 then
				qhi = bor(qhi, lshift(1, i - 32))
			else
				qlo = bor(qlo, lshift(1, i))
			end
		end
	end
	return qhi, qlo, rem
end

local function bitLength(x: number): number
	local n = 0
	while x > 0 do
		n = n + 1
		x = math.floor(x / 2)
	end
	return n
end

-- reciprocal.c: 2**x / divisor for the highest x keeping rcp < 2**64
function M.reciprocal(divisor: number): (number, number)
	local shift = bitLength(divisor) -- 64 - __builtin_clzll(divisor)
	local qhi, qlo, r = divmod64by32(0x80000000, 0, divisor) -- q = 2^63 / d, r = 2^63 % d
	local qs_lo, qs_hi = shl64(qlo, qhi, shift)
	local rs_lo, rs_hi = shl64(r, 0, shift)
	local dhi, dlo = divmod64by32(rs_hi, rs_lo, divisor)
	return add64(qs_lo, qs_hi, dlo, dhi)
end

--------------------------------------------------------------------------------
-- Blake2Generator (blake2_generator.cpp)
--------------------------------------------------------------------------------

local maxSeedSize = 60

local Gen = {}
Gen.__index = Gen

function M.newGen(blake, key: string)
	local data = key:sub(1, maxSeedSize)
	data = data .. string.rep("\0", 64 - #data) -- nonce (0) occupies bytes 60..63
	data = blake.blake2b(data, 64) -- dataIndex starts at sizeof(data)
	return setmetatable({ blake = blake, data = data, dataIndex = 0 }, Gen)
end

function Gen.checkData(self, bytesNeeded: number)
	if self.dataIndex + bytesNeeded > 64 then
		self.data = self.blake.blake2b(self.data, 64)
		self.dataIndex = 0
	end
end

function Gen.getByte(self): number
	self:checkData(1)
	self.dataIndex = self.dataIndex + 1
	return string.byte(self.data, self.dataIndex)
end

function Gen.getUInt32(self): number
	self:checkData(4)
	local i = self.dataIndex
	self.dataIndex = i + 4
	local a, b, c, d = string.byte(self.data, i + 1, i + 4)
	return a + b * 256 + c * 65536 + d * 16777216
end

--------------------------------------------------------------------------------
-- MacroOps
--------------------------------------------------------------------------------

type MacroOp = {
	size: number,
	latency: number,
	uop1: number,
	uop2: number,
	dependent: boolean,
}

local function mop(size: number, latency: number, uop1: number, uop2: number?, dependent: boolean?): MacroOp
	return { size = size, latency = latency, uop1 = uop1, uop2 = uop2 or PORT_NULL, dependent = dependent or false }
end

local function isSimple(m: MacroOp): boolean
	return m.uop2 == PORT_NULL
end

local function isEliminated(m: MacroOp): boolean
	return m.uop1 == PORT_NULL
end

local Add_rr = mop(3, 1, PORT_P015)
local Sub_rr = mop(3, 1, PORT_P015)
local Xor_rr = mop(3, 1, PORT_P015)
local Imul_r = mop(3, 4, PORT_P1, PORT_P5)
local Mul_r = mop(3, 4, PORT_P1, PORT_P5)
local Mov_rr = mop(3, 0, PORT_NULL)

local Lea_sib = mop(4, 1, PORT_P01)
local Imul_rr = mop(4, 3, PORT_P1)
local Ror_ri = mop(4, 1, PORT_P05)

local Add_ri = mop(7, 1, PORT_P015)
local Xor_ri = mop(7, 1, PORT_P015)

local Mov_ri64 = mop(10, 1, PORT_P015)

local function dependentOp(parent: MacroOp): MacroOp
	return mop(parent.size, parent.latency, parent.uop1, parent.uop2, true)
end

--------------------------------------------------------------------------------
-- SuperscalarInstructionInfo
--------------------------------------------------------------------------------

type InstrInfo = {
	name: string,
	type: number,
	ops: { MacroOp },
	latency: number,
	resultOp: number,
	dstOp: number,
	srcOp: number,
	isSimple: boolean,
}

local function makeInfo(name: string, t: number, op: MacroOp, srcOp: number): InstrInfo
	return {
		name = name,
		type = t,
		ops = { op },
		latency = op.latency,
		resultOp = 0,
		dstOp = 0,
		srcOp = srcOp,
		isSimple = true,
	}
end

local function makeMultiInfo(name: string, t: number, ops: { MacroOp }, resultOp: number, dstOp: number, srcOp: number): InstrInfo
	local latency = 0
	for i = 1, #ops do
		latency = latency + ops[i].latency
	end
	return {
		name = name,
		type = t,
		ops = ops,
		latency = latency,
		resultOp = resultOp,
		dstOp = dstOp,
		srcOp = srcOp,
		isSimple = false,
	}
end

local INFO_ISUB_R = makeInfo("ISUB_R", OP_ISUB_R, Sub_rr, 0)
local INFO_IXOR_R = makeInfo("IXOR_R", OP_IXOR_R, Xor_rr, 0)
local INFO_IADD_RS = makeInfo("IADD_RS", OP_IADD_RS, Lea_sib, 0)
local INFO_IMUL_R = makeInfo("IMUL_R", OP_IMUL_R, Imul_rr, 0)
local INFO_IROR_C = makeInfo("IROR_C", OP_IROR_C, Ror_ri, -1)
local INFO_IADD_C7 = makeInfo("IADD_C7", OP_IADD_C7, Add_ri, -1)
local INFO_IXOR_C7 = makeInfo("IXOR_C7", OP_IXOR_C7, Xor_ri, -1)
local INFO_IADD_C8 = makeInfo("IADD_C8", OP_IADD_C8, Add_ri, -1)
local INFO_IXOR_C8 = makeInfo("IXOR_C8", OP_IXOR_C8, Xor_ri, -1)
local INFO_IADD_C9 = makeInfo("IADD_C9", OP_IADD_C9, Add_ri, -1)
local INFO_IXOR_C9 = makeInfo("IXOR_C9", OP_IXOR_C9, Xor_ri, -1)
local INFO_IMULH_R = makeMultiInfo("IMULH_R", OP_IMULH_R, { Mov_rr, Mul_r, Mov_rr }, 1, 0, 1)
local INFO_ISMULH_R = makeMultiInfo("ISMULH_R", OP_ISMULH_R, { Mov_rr, Imul_r, Mov_rr }, 1, 0, 1)
local INFO_IMUL_RCP = makeMultiInfo("IMUL_RCP", OP_IMUL_RCP, { Mov_ri64, dependentOp(Imul_rr) }, 1, 1, -1)
local INFO_NOP: InstrInfo = {
	name = "NOP",
	type = OP_INVALID,
	ops = {},
	latency = 0,
	resultOp = 0,
	dstOp = 0,
	srcOp = -1,
	isSimple = false,
}

local function isMultiplication(t: number): boolean
	return t == OP_IMUL_R or t == OP_IMULH_R or t == OP_ISMULH_R or t == OP_IMUL_RCP
end

--------------------------------------------------------------------------------
-- DecoderBuffers
--------------------------------------------------------------------------------

type DecoderBuffer = {
	name: string,
	index: number,
	counts: { number },
	size: number,
}

local DecoderBufferDefault: DecoderBuffer = { name = "default", index = -1, counts = {}, size = 0 }

local decodeBuffer484: DecoderBuffer = { name = "4,8,4", index = 0, counts = { 4, 8, 4 }, size = 3 }
local decodeBuffer7333: DecoderBuffer = { name = "7,3,3,3", index = 1, counts = { 7, 3, 3, 3 }, size = 4 }
local decodeBuffer3733: DecoderBuffer = { name = "3,7,3,3", index = 2, counts = { 3, 7, 3, 3 }, size = 4 }
local decodeBuffer493: DecoderBuffer = { name = "4,9,3", index = 3, counts = { 4, 9, 3 }, size = 3 }
local decodeBuffer4444: DecoderBuffer = { name = "4,4,4,4", index = 4, counts = { 4, 4, 4, 4 }, size = 4 }
local decodeBuffer3310: DecoderBuffer = { name = "3,3,10", index = 5, counts = { 3, 3, 10 }, size = 3 }

local decodeBuffers = { decodeBuffer484, decodeBuffer7333, decodeBuffer3733, decodeBuffer493 }

local function fetchNext(instrType: number, cycle: number, mulCount: number, gen: Gen): DecoderBuffer
	-- IMULH/ISMULH must be followed by a 3-3-10 fetch configuration.
	if instrType == OP_IMULH_R or instrType == OP_ISMULH_R then
		return decodeBuffer3310
	end
	-- Saturate the multiplication port when multiplications are scarce.
	if mulCount < cycle + 1 then
		return decodeBuffer4444
	end
	-- IMUL_RCP needs a 4-byte multiplication slot first.
	if instrType == OP_IMUL_RCP then
		return band(gen:getByte(), 1) ~= 0 and decodeBuffer484 or decodeBuffer493
	end
	-- Default: random fetch configuration.
	return decodeBuffers[band(gen:getByte(), 3) + 1]
end

--------------------------------------------------------------------------------
-- Slots
--------------------------------------------------------------------------------

local slot_3 = { INFO_ISUB_R, INFO_IXOR_R }
local slot_3L = { INFO_ISUB_R, INFO_IXOR_R, INFO_IMULH_R, INFO_ISMULH_R }
local slot_4 = { INFO_IROR_C, INFO_IADD_RS }
local slot_7 = { INFO_IXOR_C7, INFO_IADD_C7 }
local slot_8 = { INFO_IXOR_C8, INFO_IADD_C8 }
local slot_9 = { INFO_IXOR_C9, INFO_IADD_C9 }
local slot_10 = INFO_IMUL_RCP

--------------------------------------------------------------------------------
-- SuperscalarInstruction
--------------------------------------------------------------------------------

type Instr = {
	info: InstrInfo,
	src: number,
	dst: number,
	mod: number,
	imm32: number,
	opGroup: number,
	opGroupPar: number,
	canReuse: boolean,
	groupParIsSource: boolean,
}

local function newInstr(info: InstrInfo): Instr
	return {
		info = info,
		src = -1,
		dst = -1,
		mod = 0,
		imm32 = 0,
		opGroup = OP_INVALID,
		opGroupPar = -1,
		canReuse = false,
		groupParIsSource = false,
	}
end

local function nullInstr(): Instr
	return newInstr(INFO_NOP)
end

type EncodedInstr = { op: number, dst: number, src: number, mod: number, imm: number }

-- translation to a RandomX instruction
local function toInstr(ins: Instr): EncodedInstr
	return {
		op = ins.info.type,
		dst = ins.dst,
		src = ins.src >= 0 and ins.src or ins.dst,
		mod = ins.mod,
		imm = ins.imm32,
	}
end

local function create(ins: Instr, info: InstrInfo, gen: Gen)
	ins.info = info
	ins.src = -1
	ins.dst = -1
	ins.canReuse = false
	ins.groupParIsSource = false
	local t = info.type
	if t == OP_ISUB_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IADD_RS
		ins.groupParIsSource = true
	elseif t == OP_IXOR_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IXOR_R
		ins.groupParIsSource = true
	elseif t == OP_IADD_RS then
		ins.mod = gen:getByte()
		ins.imm32 = 0
		ins.opGroup = OP_IADD_RS
		ins.groupParIsSource = true
	elseif t == OP_IMUL_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IMUL_R
		ins.groupParIsSource = true
	elseif t == OP_IROR_C then
		ins.mod = 0
		repeat
			ins.imm32 = band(gen:getByte(), 63)
		until ins.imm32 ~= 0
		ins.opGroup = OP_IROR_C
		ins.opGroupPar = -1
	elseif t == OP_IADD_C7 or t == OP_IADD_C8 or t == OP_IADD_C9 then
		ins.mod = 0
		ins.imm32 = gen:getUInt32()
		ins.opGroup = OP_IADD_C7
		ins.opGroupPar = -1
	elseif t == OP_IXOR_C7 or t == OP_IXOR_C8 or t == OP_IXOR_C9 then
		ins.mod = 0
		ins.imm32 = gen:getUInt32()
		ins.opGroup = OP_IXOR_C7
		ins.opGroupPar = -1
	elseif t == OP_IMULH_R then
		ins.canReuse = true
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IMULH_R
		ins.opGroupPar = gen:getUInt32()
	elseif t == OP_ISMULH_R then
		ins.canReuse = true
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_ISMULH_R
		ins.opGroupPar = gen:getUInt32()
	elseif t == OP_IMUL_RCP then
		ins.mod = 0
		repeat
			ins.imm32 = gen:getUInt32()
		until not isZeroOrPowerOf2(ins.imm32)
		ins.opGroup = OP_IMUL_RCP
		ins.opGroupPar = -1
	end
end

local function createForSlot(ins: Instr, gen: Gen, slotSize: number, fetchType: number, isLast: boolean)
	if slotSize == 3 then
		if isLast then
			create(ins, slot_3L[band(gen:getByte(), 3) + 1], gen)
		else
			create(ins, slot_3[band(gen:getByte(), 1) + 1], gen)
		end
	elseif slotSize == 4 then
		if fetchType == 4 and not isLast then
			create(ins, INFO_IMUL_R, gen)
		else
			create(ins, slot_4[band(gen:getByte(), 1) + 1], gen)
		end
	elseif slotSize == 7 then
		create(ins, slot_7[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 8 then
		create(ins, slot_8[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 9 then
		create(ins, slot_9[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 10 then
		create(ins, slot_10, gen)
	else
		error("invalid slot size " .. tostring(slotSize))
	end
end

type RegInfo = { latency: number, lastOpGroup: number, lastOpPar: number, value: number }

local function selectRegister(available: { number }, gen: Gen): number
	if #available == 0 then
		return -1
	end
	local index = 1
	if #available > 1 then
		index = math.fmod(gen:getUInt32(), #available) + 1
	end
	return available[index]
end

local function selectDestination(ins: Instr, cycle: number, allowChainedMul: boolean, registers: { RegInfo }, gen: Gen): boolean
	local available = {}
	local t = ins.info.type
	for i = 0, RegistersCount - 1 do
		local ri = registers[i + 1]
		if
			ri.latency <= cycle
			and (ins.canReuse or i ~= ins.src)
			and (allowChainedMul or ins.opGroup ~= OP_IMUL_R or ri.lastOpGroup ~= OP_IMUL_R)
			and (ri.lastOpGroup ~= ins.opGroup or ri.lastOpPar ~= ins.opGroupPar)
			and (t ~= OP_IADD_RS or i ~= RegisterNeedsDisplacement)
		then
			available[#available + 1] = i
		end
	end
	local reg = selectRegister(available, gen)
	if reg < 0 then
		return false
	end
	ins.dst = reg
	return true
end

local function selectSource(ins: Instr, cycle: number, registers: { RegInfo }, gen: Gen): boolean
	local available = {}
	for i = 0, RegistersCount - 1 do
		if registers[i + 1].latency <= cycle then
			available[#available + 1] = i
		end
	end
	-- r5 cannot be the destination of IADD_RS, so prefer it as the source
	if #available == 2 and ins.info.type == OP_IADD_RS then
		if available[1] == RegisterNeedsDisplacement or available[2] == RegisterNeedsDisplacement then
			ins.opGroupPar = RegisterNeedsDisplacement
			ins.src = RegisterNeedsDisplacement
			return true
		end
	end
	local reg = selectRegister(available, gen)
	if reg < 0 then
		return false
	end
	ins.src = reg
	if ins.groupParIsSource then
		ins.opGroupPar = reg
	end
	return true
end

--------------------------------------------------------------------------------
-- Scheduling
--------------------------------------------------------------------------------

type Bools = { boolean }
type PortBusy = { Bools }

local function scheduleUop(uop: number, portBusy: PortBusy, cycle: number, commit: boolean): number
	while cycle < CYCLE_MAP_SIZE do
		local idx = cycle + 1
		if band(uop, PORT_P5) ~= 0 and not portBusy[3][idx] then
			if commit then
				portBusy[3][idx] = true
			end
			return cycle
		end
		if band(uop, PORT_P0) ~= 0 and not portBusy[1][idx] then
			if commit then
				portBusy[1][idx] = true
			end
			return cycle
		end
		if band(uop, PORT_P1) ~= 0 and not portBusy[2][idx] then
			if commit then
				portBusy[2][idx] = true
			end
			return cycle
		end
		cycle = cycle + 1
	end
	return -1
end

local function scheduleMop(m: MacroOp, portBusy: PortBusy, cycle: number, depCycle: number, commit: boolean): number
	-- explicit dependency chain (IMUL_RCP) pushes the start cycle out
	if m.dependent and depCycle > cycle then
		cycle = depCycle
	end
	-- eliminated macro-ops (moves) need no execution unit
	if isEliminated(m) then
		return cycle
	elseif isSimple(m) then
		return scheduleUop(m.uop1, portBusy, cycle, commit)
	else
		-- 2 uOPs must retire in the same cycle
		while cycle < CYCLE_MAP_SIZE do
			local cycle1 = scheduleUop(m.uop1, portBusy, cycle, false)
			local cycle2 = scheduleUop(m.uop2, portBusy, cycle, false)
			if cycle1 >= 0 and cycle1 == cycle2 then
				if commit then
					scheduleUop(m.uop1, portBusy, cycle1, true)
					scheduleUop(m.uop2, portBusy, cycle2, true)
				end
				return cycle1
			end
			cycle = cycle + 1
		end
		return -1
	end
end

--------------------------------------------------------------------------------
-- generateSuperscalar
--------------------------------------------------------------------------------

function M.generate(gen: Gen)
	local portBusy: PortBusy = { {}, {}, {} }
	for i = 1, CYCLE_MAP_SIZE do
		portBusy[1][i] = false
		portBusy[2][i] = false
		portBusy[3][i] = false
	end
	local registers: { RegInfo } = {}
	for i = 1, RegistersCount do
		registers[i] = { latency = 0, lastOpGroup = OP_INVALID, lastOpPar = -1, value = 0 }
	end

	local decodeBuffer = DecoderBufferDefault
	local currentInstruction = nullInstr()
	local macroOpIndex = 0
	local codeSize = 0
	local macroOpCount = 0
	local cycle = 0
	local depCycle = 0
	local retireCycle = 0
	local portsSaturated = false
	local programSize = 0
	local mulCount = 0
	local decodeCycle = 0
	local throwAwayCount = 0
	local program: { EncodedInstr } = {}

	local decodeCycleStop = false
	while decodeCycle < RANDOMX_SUPERSCALAR_LATENCY and not portsSaturated and programSize < SuperscalarMaxSize do
		decodeBuffer = fetchNext(currentInstruction.info.type, decodeCycle, mulCount, gen)

		local bufferIndex = 0
		while bufferIndex < decodeBuffer.size do
			local topCycle = cycle

			-- all macro-ops of the current RandomX instruction issued: pick a new instruction
			if macroOpIndex >= #currentInstruction.info.ops then
				if portsSaturated or programSize >= SuperscalarMaxSize then
					break
				end
				local counts = decodeBuffer.counts
				createForSlot(currentInstruction, gen, counts[bufferIndex + 1], decodeBuffer.index, decodeBuffer.size == bufferIndex + 1)
				macroOpIndex = 0
			end

			local info = currentInstruction.info
			local m = info.ops[macroOpIndex + 1]

			-- earliest cycle this macro-op can be scheduled
			local scheduleCycle = scheduleMop(m, portBusy, cycle, depCycle, false)
			if scheduleCycle < 0 then
				portsSaturated = true
				break
			end

			local threwAway = false

			if macroOpIndex == info.srcOp then
				local forward = 0
				while forward < LOOK_FORWARD_CYCLES and not selectSource(currentInstruction, scheduleCycle, registers, gen) do
					forward = forward + 1
					scheduleCycle = scheduleCycle + 1
					cycle = cycle + 1
				end
				if forward == LOOK_FORWARD_CYCLES then
					if throwAwayCount < MAX_THROWAWAY_COUNT then
						throwAwayCount = throwAwayCount + 1
						macroOpIndex = #info.ops
						threwAway = true
					else
						currentInstruction = nullInstr()
						break
					end
				end
			end

			if not threwAway and macroOpIndex == info.dstOp then
				local forward = 0
				while forward < LOOK_FORWARD_CYCLES and not selectDestination(currentInstruction, scheduleCycle, throwAwayCount > 0, registers, gen) do
					forward = forward + 1
					scheduleCycle = scheduleCycle + 1
					cycle = cycle + 1
				end
				if forward == LOOK_FORWARD_CYCLES then
					if throwAwayCount < MAX_THROWAWAY_COUNT then
						throwAwayCount = throwAwayCount + 1
						macroOpIndex = #info.ops
						threwAway = true
					else
						currentInstruction = nullInstr()
						break
					end
				end
			end

			if threwAway then
				continue
			end

			throwAwayCount = 0

			-- re-schedule with the actual operand availability
			scheduleCycle = scheduleMop(m, portBusy, scheduleCycle, scheduleCycle, true)
			if scheduleCycle < 0 then
				portsSaturated = true
				break
			end

			depCycle = scheduleCycle + m.latency

			if macroOpIndex == info.resultOp then
				local dst = currentInstruction.dst
				local ri = registers[dst + 1]
				retireCycle = depCycle
				ri.latency = retireCycle
				ri.lastOpGroup = currentInstruction.opGroup
				ri.lastOpPar = currentInstruction.opGroupPar
			end

			codeSize = codeSize + m.size
			bufferIndex = bufferIndex + 1
			macroOpIndex = macroOpIndex + 1
			macroOpCount = macroOpCount + 1

			if scheduleCycle >= RANDOMX_SUPERSCALAR_LATENCY then
				portsSaturated = true
			end
			cycle = topCycle

			if macroOpIndex >= #info.ops then
				programSize = programSize + 1
				program[programSize] = toInstr(currentInstruction)
				if isMultiplication(info.type) then
					mulCount = mulCount + 1
				end
			end
		end
		cycle = cycle + 1
		decodeCycle = decodeCycle + 1
	end
	if decodeCycleStop then
		decodeCycle = decodeCycle
	end

	local ipc = macroOpCount / retireCycle

	-- ASIC latency: 1 cycle per operation, unlimited parallelization
	local asicLatencies = { 0, 0, 0, 0, 0, 0, 0, 0 }
	for i = 1, programSize do
		local instr = program[i]
		local latDst = asicLatencies[instr.dst + 1] + 1
		local latSrc = instr.dst ~= instr.src and asicLatencies[instr.src + 1] + 1 or 0
		asicLatencies[instr.dst + 1] = math.max(latDst, latSrc)
	end

	-- address register is the register with the highest ASIC latency
	local asicLatencyMax = 0
	local addressReg = 0
	local cpuLatencies = {}
	for i = 0, RegistersCount - 1 do
		if asicLatencies[i + 1] > asicLatencyMax then
			asicLatencyMax = asicLatencies[i + 1]
			addressReg = i
		end
		cpuLatencies[i + 1] = registers[i + 1].latency
	end

	return {
		size = programSize,
		addrReg = addressReg,
		ins = program,
		asicLatencies = asicLatencies,
		cpuLatencies = cpuLatencies,
		cpuLatency = retireCycle,
		asicLatency = asicLatencyMax,
		codeSize = codeSize,
		macroOps = macroOpCount,
		decodeCycles = decodeCycle,
		ipc = ipc,
		mulCount = mulCount,
	}
end

--------------------------------------------------------------------------------
-- Encoding / interpretation
--------------------------------------------------------------------------------

function M.encode(prog): string
	local parts = {}
	local ins = prog.ins
	for i = 1, prog.size do
		local v = ins[i]
		local imm = v.imm % 0x100000000
		parts[#parts + 1] = string.char(
			band(v.op, 0xFF),
			band(v.dst, 0xFF),
			band(v.src, 0xFF),
			band(v.mod, 0xFF),
			imm % 256,
			math.floor(imm / 256) % 256,
			math.floor(imm / 65536) % 256,
			math.floor(imm / 16777216) % 256
		)
	end
	return table.concat(parts)
end

-- rlo/rhi: 1..8 registers. Each register may be either a {lo, hi} pair stored in
-- rlo[i], or rlo[i]/rhi[i] holding the low/high halfword directly.
function M.execute(prog, rlo, rhi)
	local paired = type(rlo[1]) == "table"
	local lo, hi = {}, {}
	for i = 1, RegistersCount do
		if paired then
			local v = rlo[i]
			lo[i] = (v and v[1]) or 0
			hi[i] = (v and v[2]) or 0
		else
			lo[i] = rlo[i] or 0
			hi[i] = (rhi and rhi[i]) or 0
		end
	end

	local ins = prog.ins
	for j = 1, prog.size do
		local instr = ins[j]
		local dst = instr.dst + 1
		local src = instr.src + 1
		local op = instr.op
		if op == OP_ISUB_R then
			lo[dst], hi[dst] = sub64(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IXOR_R then
			lo[dst] = bxor(lo[dst], lo[src])
			hi[dst] = bxor(hi[dst], hi[src])
		elseif op == OP_IADD_RS then
			local sh = rshift(instr.mod, 2) % 4
			local slo, shi = shl64(lo[src], hi[src], sh)
			lo[dst], hi[dst] = add64(lo[dst], hi[dst], slo, shi)
		elseif op == OP_IMUL_R then
			lo[dst], hi[dst] = mul64lo(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IROR_C then
			lo[dst], hi[dst] = rotr64(lo[dst], hi[dst], instr.imm % 64)
		elseif op == OP_IADD_C7 or op == OP_IADD_C8 or op == OP_IADD_C9 then
			local imm = instr.imm
			if imm >= 0x80000000 then
				imm = imm - 0x100000000
			end
			if imm >= 0 then
				lo[dst], hi[dst] = add64(lo[dst], hi[dst], imm, 0)
			else
				lo[dst], hi[dst] = sub64(lo[dst], hi[dst], -imm, 0)
			end
		elseif op == OP_IXOR_C7 or op == OP_IXOR_C8 or op == OP_IXOR_C9 then
			local imm = instr.imm
			if imm >= 0x80000000 then -- sign extend
				imm = imm - 0x100000000
			end
			lo[dst] = bxor(lo[dst], imm % 0x100000000)
			hi[dst] = bxor(hi[dst], imm < 0 and MASK32 or 0)
		elseif op == OP_IMULH_R then
			lo[dst], hi[dst] = mul64hi(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_ISMULH_R then
			lo[dst], hi[dst] = smul64hi(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IMUL_RCP then
			local rcpLo, rcpHi = M.reciprocal(instr.imm)
			lo[dst], hi[dst] = mul64lo(lo[dst], hi[dst], rcpLo, rcpHi)
		else
			error("invalid opcode " .. tostring(op))
		end
	end

	for i = 1, RegistersCount do
		if paired then
			local v = rlo[i]
			if v then
				v[1] = lo[i]
				v[2] = hi[i]
			else
				rlo[i] = { lo[i], hi[i] }
			end
		else
			rlo[i] = lo[i]
			rhi[i] = hi[i]
		end
	end
end

return M
]==], 'ss')

local rx = __mod([==[
-- RandomX v1 (rx/0) light-mode hash, pure Luau.
-- Debug/ladiní hacky: traceSp, traceReg, traceRF, traceFE, tracePC, traceBlob,
-- _chains/_iters, slicePcs + slice (yield kazdych N instrukci, pro executor).
local M = {}

-- yield hook pro executor: zavola se po kazdem `slicePcs` instrukci a vraci
-- delku dalsiho useku (caller si tak ridi plynulost podle realneho casu)
M.slice = function() end

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

-- Bez vetveni: `//` je podlahove deleni (0 nebo 1, resp. -1) a `%` uz vyjde
-- nezaporne, takze odpadá i podminka u vyssiho limbuse.
local function ad64(alo, ahi, blo, bhi)
	local lo = alo + blo
	local hi = ahi + bhi + lo // W
	return lo % W, hi % W
end
local function sb64(alo, ahi, blo, bhi)
	local lo = alo - blo
	local hi = ahi - bhi + lo // W
	return lo % W, hi % W
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

-- Jen spodních 64 bitů (vyšší členy se do nich nepropíšou, řetěz končí po
-- limbusi 2). Limby po 22 bitech: tři se vejdou do 53bitove mantisy presne,
-- takze staci 6 násobení místo 16.
local B22 = 4194304
local function mul64lo(alo, ahi, blo, bhi)
	local a0 = alo % B22 local a1 = alo // B22 + (ahi % 4096) * 1024 local a2 = ahi // 4096
	local b0 = blo % B22 local b1 = blo // B22 + (bhi % 4096) * 1024 local b2 = bhi // 4096
	local t = a0 * b0
	local o0 = t % B22
	t = a0 * b1 + a1 * b0 + (t - o0) / B22
	local o1 = t % B22
	t = a0 * b2 + a1 * b1 + a2 * b0 + (t - o1) / B22
	local l = o0 + o1 * B22
	return l % W, (l // W + (t % B22 % 1048576) * 4096) % W
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

-- Superscalar program je prima cara bez vetveni: prelozi se do jedne Luau
-- funkce, takze v tele neni zadny dispatch podle op a zadne cteni ins[j].
-- Konstanty, posuny i reciprokni hodnoty jsou predpocitane v kodu. Kdyz
-- loadstring neni (nebo kompilace selze), runSuperscalar vezme interpreter.
local function compileProg(prog)
	if M.noCompile then return nil end
	local ok, ls = pcall(function() return loadstring end)
	if not ok then return nil end
	local ls2 = loadstring or ls
	if type(ls2) ~= "function" then return nil end
	local lines = {}
	-- ad64/sb64 rozbalene na miste; operandy jsou bud "rlo[i]"/"rhi[i]", nebo cisla
	local function emit63(sign, d, aLo, aHi, bLo, bHi)
		local lo, hi = "q1", "q2"
		if sign == "-" then
			lines[#lines + 1] = string.format("%s = %s - %s", lo, aLo, bLo)
			lines[#lines + 1] = string.format("%s = %s - %s + %s // 4294967296", hi, aHi, bHi, lo)
		else
			lines[#lines + 1] = string.format("%s = %s + %s", lo, aLo, bLo)
			lines[#lines + 1] = string.format("%s = %s + %s + %s // 4294967296", hi, aHi, bHi, lo)
		end
		lines[#lines + 1] = string.format("rlo[%d] = %s %% 4294967296", d, lo)
		lines[#lines + 1] = string.format("rhi[%d] = %s %% 4294967296", d, hi)
	end
	-- mul64lo rozbaleny na miste (3 limby po 22 bitech, jen spodních 64 bitů)
	local function emitMul(d, aLo, aHi, bLo, bHi)
		local a0, a1, a2, b0, b1, b2, t, o = "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8"
		local L = lines
		L[#L + 1] = string.format("%s = %s %% 4194304", a0, aLo)
		L[#L + 1] = string.format("%s = %s // 4194304 + (%s %% 4096) * 1024", a1, aLo, aHi)
		L[#L + 1] = string.format("%s = %s // 4096", a2, aHi)
		L[#L + 1] = string.format("%s = %s %% 4194304", b0, bLo)
		L[#L + 1] = string.format("%s = %s // 4194304 + (%s %% 4096) * 1024", b1, bLo, bHi)
		L[#L + 1] = string.format("%s = %s // 4096", b2, bHi)
		L[#L + 1] = string.format("%s = %s * %s", t, a0, b0)
		L[#L + 1] = string.format("%s = %s %% 4194304", o, t)
		L[#L + 1] = string.format("rlo[%d] = %s", d, o)
		L[#L + 1] = string.format("%s = %s * %s + %s * %s + (%s - %s) / 4194304", t, a0, b1, a1, b0, t, o)
		L[#L + 1] = string.format("%s = %s %% 4194304", o, t)
		L[#L + 1] = string.format("rlo[%d] = rlo[%d] + %s * 4194304", d, d, o)
		L[#L + 1] = string.format("%s = %s * %s + %s * %s + %s * %s + (%s - %s) / 4194304", t, a0, b2, a1, b1, a2, b0, t, o)
		L[#L + 1] = string.format("rhi[%d] = (rlo[%d] // 4294967296 + (%s %% 4194304 %% 1048576) * 4096) %% 4294967296", d, d, t)
		L[#L + 1] = string.format("rlo[%d] = rlo[%d] %% 4294967296", d, d)
	end
	local ins = prog.ins
	for j = 1, prog.size do
		local i2 = ins[j]
		local op, d, s = i2.op, i2.dst + 1, i2.src + 1
		if op == 0 then
			emit63("-", d, string.format("rlo[%d]", d), string.format("rhi[%d]", d), string.format("rlo[%d]", s), string.format("rhi[%d]", s))
		elseif op == 1 then
			lines[#lines + 1] = string.format("rlo[%d] = bxor(rlo[%d], rlo[%d]) rhi[%d] = bxor(rhi[%d], rhi[%d])", d, d, s, d, d, s)
		elseif op == 2 then
			local n = rshift(i2.mod, 2) % 4
			if n == 0 then
				emit63("+", d, string.format("rlo[%d]", d), string.format("rhi[%d]", d), string.format("rlo[%d]", s), string.format("rhi[%d]", s))
			else
				emit63("+", d, string.format("rlo[%d]", d), string.format("rhi[%d]", d),
					string.format("lshift(rlo[%d], %d)", s, n), string.format("bor(lshift(rhi[%d], %d), rshift(rlo[%d], %d))", s, n, s, 32 - n))
			end
		elseif op == 3 then
			emitMul(d, string.format("rlo[%d]", d), string.format("rhi[%d]", d), string.format("rlo[%d]", s), string.format("rhi[%d]", s))
		elseif op == 4 then
			local n = i2.imm % 64
			if n == 0 then
				lines[#lines + 1] = ""
			elseif n >= 32 then
				n = n - 32
				-- prohozeni a pak uz jen n-rotace
				lines[#lines + 1] = string.format("rlo[%d], rhi[%d] = rhi[%d], rlo[%d] rlo[%d], rhi[%d] = bor(rshift(rlo[%d], %d), lshift(rhi[%d], %d)), bor(rshift(rhi[%d], %d), lshift(rlo[%d], %d))",
					d, d, d, d, d, d, d, n, d, 32 - n, d, n, d, 32 - n)
			else
				lines[#lines + 1] = string.format("rlo[%d], rhi[%d] = bor(rshift(rlo[%d], %d), lshift(rhi[%d], %d)), bor(rshift(rhi[%d], %d), lshift(rlo[%d], %d))",
					d, d, d, n, d, 32 - n, d, n, d, 32 - n)
			end
		elseif op == 5 or op == 7 or op == 9 then
			local alo, ahi = signExt(i2.imm)
			emit63("+", d, string.format("rlo[%d]", d), string.format("rhi[%d]", d), tostring(alo), tostring(ahi))
		elseif op == 6 or op == 8 or op == 10 then
			local alo, ahi = signExt(i2.imm)
			lines[#lines + 1] = string.format("rlo[%d] = bxor(rlo[%d], %d) rhi[%d] = bxor(rhi[%d], %d)", d, d, alo, d, d, ahi)
		elseif op == 11 then
			lines[#lines + 1] = string.format("rlo[%d], rhi[%d] = mul64hi(rlo[%d], rhi[%d], rlo[%d], rhi[%d])", d, d, d, d, s, s)
		elseif op == 12 then
			lines[#lines + 1] = string.format("rlo[%d], rhi[%d] = smulh(rlo[%d], rhi[%d], rlo[%d], rhi[%d])", d, d, d, d, s, s)
		elseif op == 13 then
			local xlo, xhi = reciprocal(i2.imm)
			emitMul(d, string.format("rlo[%d]", d), string.format("rhi[%d]", d), tostring(xlo), tostring(xhi))
		else
			return nil -- nezname op -> interpreter
		end
	end
	local src = "local sb64, ad64, mul64lo, mul64hi, smulh, lshift, rshift, bor, bxor = ...\n" ..
		"return function(rlo, rhi)\nlocal q1, q2, q3, q4, q5, q6, q7, q8\n" .. table.concat(lines, "\n") .. "\nend"
	local chunk = ls2(src)
	if type(chunk) ~= "function" then return nil end
	local okc, fn = pcall(chunk, sb64, ad64, mul64lo, mul64hi, smulh, lshift, rshift, bor, bxor)
	if not okc or type(fn) ~= "function" then return nil end
	prog.src = src
	return fn
end

local function runSuperscalar(prog, rlo, rhi)
	local fn = prog.fn
	if fn == nil then
		fn = compileProg(prog) or false
		prog.fn = fn
	end
	if fn then return fn(rlo, rhi) end
	-- mul64lo rozbaleny na miste (jen spodnich 64 bitu, zadny call)
	local function emitMul(d, aLo, aHi, bLo, bHi)
		local a0, a1, a2, a3, b0, b1, b2, b3, t, o = "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
		local L = lines
		L[#L + 1] = string.format("%s = %s %% 65536", a0, aLo)
		L[#L + 1] = string.format("%s = (%s - %s) / 65536", a1, aLo, a0)
		L[#L + 1] = string.format("%s = %s %% 65536", a2, aHi)
		L[#L + 1] = string.format("%s = (%s - %s) / 65536", a3, aHi, a2)
		L[#L + 1] = string.format("%s = %s %% 65536", b0, bLo)
		L[#L + 1] = string.format("%s = (%s - %s) / 65536", b1, bLo, b0)
		L[#L + 1] = string.format("%s = %s %% 65536", b2, bHi)
		L[#L + 1] = string.format("%s = (%s - %s) / 65536", b3, bHi, b2)
		L[#L + 1] = string.format("%s = %s * %s", t, a0, b0)
		L[#L + 1] = string.format("%s = %s %% 65536", o, t)
		L[#L + 1] = string.format("rlo[%d] = %s", d, o)
		L[#L + 1] = string.format("%s = %s * %s + %s * %s + (%s - %s) / 65536", t, a0, b1, a1, b0, t, o)
		L[#L + 1] = string.format("%s = %s %% 65536", o, t)
		L[#L + 1] = string.format("rlo[%d] = rlo[%d] + %s * 65536", d, d, o)
		L[#L + 1] = string.format("%s = %s * %s + %s * %s + %s * %s + (%s - %s) / 65536", t, a0, b2, a1, b1, a2, b0, t, o)
		L[#L + 1] = string.format("%s = %s %% 65536", o, t)
		L[#L + 1] = string.format("rhi[%d] = %s", d, o)
		L[#L + 1] = string.format("%s = %s * %s + %s * %s + %s * %s + %s * %s + (%s - %s) / 65536", t, a0, b3, a1, b2, a2, b1, a3, b0, t, o)
		L[#L + 1] = string.format("%s = %s %% 65536", o, t)
		L[#L + 1] = string.format("rhi[%d] = rhi[%d] + %s * 65536", d, d, o)
	end
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
	local slicePcs = M.slicePcs or 0
	local sliceLeft = slicePcs
	while pc <= ProgramSize do
		if slicePcs > 0 then
			sliceLeft = sliceLeft - 1
			if sliceLeft <= 0 then
				local nxt = M.slice()
				if type(nxt) == "number" and nxt > 0 then slicePcs = nxt end
				sliceLeft = slicePcs
			end
		end
		local k = K[pc]
		local d = D[pc]
		local s = S[pc]
		local mod = MU[pc]
		
		-- Vetve jsou serazene podle frekvence (decodeWords na nahodnych seedech),
		-- aby se bezne instrukce dostaly k sosnu po par comparech.
		if k == 24 then
			elo[d] = fprod(elo[d], alo[s]) ehi[d] = fprod(ehi[d], ahi[s])
		elseif k == 27 then
			local q1 = rlo[d] + ILO[pc]
			local q2 = rhi[d] + IHI[pc] + q1 // W
			rlo[d], rhi[d] = q1 % W, q2 % W
			if M.debug then M.debug(string.format('cb d=%d ilo=%08x pc=%d tgt=%d', d, ILO[pc], pc, TGT[pc])) end
			if band(rlo[d], lshift(ConditionMask, rshift(mod, 4) + ConditionOffset)) == 0 then pc = TGT[pc] end
		elseif k == 29 then
			local addr = band(rlo[d] + ILO[pc], MASK[pc])
			buffer.writeu32(scratch, addr, rlo[s])
			buffer.writeu32(scratch, addr + 4, rhi[s])
		elseif k == 3 then
			local alo, ahi, blo, bhi
			if s ~= d then alo, ahi, blo, bhi = rlo[d], rhi[d], rlo[s], rhi[s]
			else alo, ahi, blo, bhi = rlo[d], rhi[d], ILO[pc], IHI[pc] end
			local q1 = alo - blo
			local q2 = ahi - bhi + q1 // W
			rlo[d], rhi[d] = q1 % W, q2 % W
		elseif k == 21 then
			flo[d] = fsub(flo[d], alo[s]) fhi[d] = fsub(fhi[d], ahi[s])
		elseif k == 1 then
			local slo, shi = shl64(rlo[s], rhi[s], rshift(mod, 2) % 4)
			if d == 6 then
				local t1 = slo + ILO[pc]
				shi = shi + IHI[pc] + t1 // W
				slo = t1 % W
			end
			local q1 = rlo[d] + slo
			local q2 = rhi[d] + shi + q1 // W
			rlo[d], rhi[d] = q1 % W, q2 % W
		elseif k == 19 then
			flo[d] = fadd(flo[d], alo[s]) fhi[d] = fadd(fhi[d], ahi[s])
		elseif k == 5 then
			if s ~= d then rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], rlo[s], rhi[s])
			else rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], ILO[pc], IHI[pc]) end
		elseif k == 13 then
			if s ~= d then rlo[d] = bxor(rlo[d], rlo[s]) rhi[d] = bxor(rhi[d], rhi[s])
			else rlo[d] = bxor(rlo[d], ILO[pc]) rhi[d] = bxor(rhi[d], IHI[pc]) end
		elseif k == 15 then
			if s ~= d then rlo[d], rhi[d] = rotr64(rlo[d], rhi[d], rlo[s] % 64)
			else rlo[d], rhi[d] = rotr64(rlo[d], rhi[d], words[pc][5] % 64) end
		elseif k == 11 then
			local xlo, xhi = reciprocal(words[pc][5])
			rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], xlo, xhi)
		elseif k == 4 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			local q1 = rlo[d] - mlo
			local q2 = rhi[d] - mhi + q1 // W
			rlo[d], rhi[d] = q1 % W, q2 % W
		elseif k == 2 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			local q1 = rlo[d] + mlo
			local q2 = rhi[d] + mhi + q1 // W
			rlo[d], rhi[d] = q1 % W, q2 % W
		elseif k == 23 then
			local lo, hi = f2b(flo[d]) flo[d] = b2f(lo, bxor(hi, 0x80F00000))
			lo, hi = f2b(fhi[d]) fhi[d] = b2f(lo, bxor(hi, 0x80F00000))
		elseif k == 26 then
			if M.debug then M.debug(string.format("fsqrt pc=%d fprc=%d x0=%d x1=%d", pc, fprc, elo[d], ehi[d])) end
			if M.traceE2 then local a1, a2 = f2b(elo[d]) local b1, b2 = f2b(ehi[d]) print(string.format("FS in pc=%d %08x,%08x %08x,%08x", pc, a1, a2, b1, b2)) end
			elo[d] = fsqrt(elo[d]) ehi[d] = fsqrt(ehi[d])
			if M.traceE2 then local a1, a2 = f2b(elo[d]) local b1, b2 = f2b(ehi[d]) print(string.format("FS out pc=%d %08x,%08x %08x,%08x", pc, a1, a2, b1, b2)) end
		elseif k == 20 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			if M.debug then M.debug(string.format("faddm pc=%d d=%d addr=%x p0=%d p1=%d", pc, d, addr, flo[d], fhi[d])) end
			flo[d] = fadd(flo[d], buffer.readi32(scratch, addr))
			fhi[d] = fadd(fhi[d], buffer.readi32(scratch, addr + 4))
			if M.debug then M.debug(string.format("after d=%d lo=%d hi=%d", d, flo[d], fhi[d])) end
		elseif k == 22 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			flo[d] = fsub(flo[d], buffer.readi32(scratch, addr))
			fhi[d] = fsub(fhi[d], buffer.readi32(scratch, addr + 4))
		elseif k == 14 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			rlo[d] = bxor(rlo[d], mlo) rhi[d] = bxor(rhi[d], mhi)
		elseif k == 17 then
			if s ~= d then rlo[d], rhi[d], rlo[s], rhi[s] = rlo[s], rhi[s], rlo[d], rhi[d] end
		elseif k == 6 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			rlo[d], rhi[d] = mul64lo(rlo[d], rhi[d], mlo, mhi)
		elseif k == 25 then
			local addr = band(rlo[s] + ILO[pc], MASK[pc])
			local m1, m2 = eMask[1][1], eMask[1][2]
			local x1, x2 = f2b(buffer.readi32(scratch, addr))
			local d1 = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			m1, m2 = eMask[2][1], eMask[2][2]
			x1, x2 = f2b(buffer.readi32(scratch, addr + 4))
			local d2 = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			elo[d] = fdiv(elo[d], d1) ehi[d] = fdiv(ehi[d], d2)
		elseif k == 18 then
			if d < 4 then flo[d + 1], fhi[d + 1] = fhi[d + 1], flo[d + 1] else elo[d - 3], ehi[d - 3] = ehi[d - 3], elo[d - 3] end
		elseif k == 7 then rlo[d], rhi[d] = mul64hi(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif k == 9 then rlo[d], rhi[d] = smulh(rlo[d], rhi[d], rlo[s], rhi[s])
		elseif k == 12 then rlo[d], rhi[d] = neg64(rlo[d], rhi[d])
		elseif k == 16 then
			if s ~= d then rlo[d], rhi[d] = rotl64(rlo[d], rhi[d], rlo[s] % 64)
			else rlo[d], rhi[d] = rotl64(rlo[d], rhi[d], words[pc][5] % 64) end
		elseif k == 10 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			rlo[d], rhi[d] = smulh(rlo[d], rhi[d], mlo, mhi)
		elseif k == 8 then
			local addr = band((ZEROBASE[pc] and 0 or rlo[s]) + ILO[pc], MASK[pc])
			local mlo, mhi = buffer.readu32(scratch, addr), buffer.readu32(scratch, addr + 4)
			rlo[d], rhi[d] = mul64hi(rlo[d], rhi[d], mlo, mhi)
		elseif k == 28 then
			local r1 = rotr64(rlo[s], rhi[s], words[pc][5] % 64)
			fprc = band(r1, 3)
		end
		if hook then hook(pc) end
		pc = pc + 1
	end

end
M._mullo = mul64lo
M._recip = reciprocal
M._clearRcp = function() rcpCache = {} end
M._exec = execProgram
M._runsuper = runSuperscalar
M.datasetItem = datasetItem
M.decodeWords = decodeWords

function M.hash(blake, aes, ss, cache, key, input)
	local scratch = buffer.create(ScratchpadSize)
	local seed = blake.blake2b(input, 64)
	local gen1 = aes.gen1R(seed)
	local spStep = M.slicePcs or 0
	if spStep > 0 then spStep = math.max(256, spStep * 4) end
	for i = 0, ScratchpadSize / 64 - 1 do
		if spStep > 0 and i % spStep == 0 then M.slice() end
		buffer.writestring(scratch, i * 64, gen1:next())
	end
	if M.traceFill then print("FILL:" .. (blake.blake2b(buffer.readstring(scratch, 0, ScratchpadSize), 8):gsub('.', function(c) return string.format('%02x', string.byte(c)) end))) end
	-- referencni randomx_calculate_hash() vola resetRoundingMode() jednou na hash
	-- (pred smyckou chainu); bez toho by se fprc prenasi mezi hashi
	fprc = 0
	local gen4 = aes.gen4R(gen1.state)

	if M.traceBlob then print("GEN1STATE:" .. (gen1.state:gsub('.', function(c) return string.format('%02x', string.byte(c)) end)):sub(1, 16) .. " SEED:" .. (seed:gsub('.', function(c) return string.format('%02x', string.byte(c)) end)):sub(1, 16)) end
	local sgen = ss.newGen(blake, key)
	local progs = {}
	for i = 1, 8 do
		progs[i] = ss.generate(sgen)
		if M.slicePcs and M.slicePcs > 0 then M.slice() end
	end

	local rlo, rhi, flo, fhi, elo, ehi, alo, ahi = {}, {}, {}, {}, {}, {}, {}, {}
	local words, tgt = {}, {}

	for chain = 1, (M._chains or ProgramCount) do
		-- referencni execute() ma nreg.r zero-inicializovane pri kazdem chainu
		for i = 1, 8 do rlo[i] = 0 rhi[i] = 0 end
		local parts = {}
		for i = 1, 34 do parts[i] = gen4:next() end
		local blob = buffer.fromstring(table.concat(parts))
		if M.traceBlob then print("BLOB:" .. (blake.blake2b(buffer.readstring(blob, 0, buffer.len(blob)), 8):gsub('.', function(c) return string.format('%02x', string.byte(c)) end))) end
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
		if M.slicePcs and M.slicePcs > 0 and chain ~= 1 then M.slice() end
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
				if M.traceE and ic <= 1 then print(string.format("E it%d i%d o2=%x raw=%08x,%08x mask=%08x,%08x -> %08x,%08x", ic, i, o2, x1, x2, m1, m2, bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))) end
				m1, m2 = eMask[2][1], eMask[2][2]
				x1, x2 = f2b(buffer.readi32(scratch, o2 + 4))
				ehi[i] = b2f(bor(x1, m1), bor(band(x2, 0xFFFFFF), m2))
			end

				if M.traceFE then
					local fb = {}
					for i = 1, 4 do local a1, a2 = f2b(flo[i]) local b1, b2 = f2b(fhi[i]) fb[i] = string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
					print("DBGFE f:" .. table.concat(fb))
					local eb = {}
					for i = 1, 4 do local a1, a2 = f2b(elo[i]) local b1, b2 = f2b(ehi[i]) eb[i] = string.format("%08x%08x%08x%08x", a1, a2, b1, b2) end
					print("DBGFE e:" .. table.concat(eb))
					print("DBGFN " .. tostring(flo[1]) .. " direct=" .. tostring(buffer.readi32(scratch, spAddr1)))
				end
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
]==], 'rx')


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
	cacheUrl = nil, -- HTTP zaklad pro sdilenou cache (nil = odvozeno z bridge)
	uploadCache = true, -- po postaveni cache ji nabidnout ostatnim
	http = nil, -- HTTP klient (testy); defaultne request/http_request ze executoru
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

------------------------------------------------------------------------ sdilena cache

-- Argon2 cache je cista funkce seedu, takze ji nema smysl pocitat v kazdem
-- klientu: 30 klientu by delalo 30x stejnou praci. Prvni ji nahraje na bridge,
-- ostatni stahnout. Je to 83 % prace klienta, takze bez toho pri nizkem duty
-- klient nestiha ani postavit cache na dalsi blok.
local function httpBase()
	local u = CONFIG.cacheUrl or CONFIG.bridge
	if type(u) ~= "string" then return nil end
	local base = u:gsub("^ws://", "http://"):gsub("^wss://", "https://")
	if not base:find("^https?://") then return nil end
	return (base:gsub("/+$", ""))
end

local function httpReq(method, url, body)
	if CONFIG.http then return CONFIG.http(method, url, body) end
	local req = rawget(_G, "request") or rawget(_G, "http_request")
		or (type(syn) == "table" and syn.request) or nil
	if type(req) ~= "function" then return nil end
	local opts = { Url = url, Method = method, Headers = { ["Content-Type"] = "application/octet-stream" } }
	if body then opts.Body = body end
	local ok, res = pcall(req, opts)
	if not ok or type(res) ~= "table" then return nil end
	local code = tonumber(res.StatusCode or res.status)
	local out = res.Body or res.body
	if not code or code < 200 or code > 299 or type(out) ~= "string" then return nil end
	return out
end

-- vraci seznam chybejicich dilu, nebo nil kdyz bridge nema/nerekne
local function bridgeMeta(base, key)
	local body = httpReq("GET", base .. "/cache/" .. key .. "/meta")
	if not body then return nil end
	local ok, m = pcall(decode, body)
	if not ok or type(m) ~= "table" or type(m.have) ~= "table" then return nil end
	if m.complete == true then return {} end
	local missing = {}
	local have = {}
	for _, i in ipairs(m.have) do have[tonumber(i)] = true end
	for i = 0, CACHE_PARTS - 1 do
		if not have[i] then missing[#missing + 1] = i end
	end
	return missing
end

local function fetchBridge(seed)
	local base = httpBase()
	if not base then return nil end
	local key = hex(seed):sub(1, 16)
	local missing = bridgeMeta(base, key)
	if missing == nil then return nil end -- bridge cache endpoint nema
	if #missing > 0 then
		log(string.format("cache na bridge nekompletni (%d/%d dilu)", CACHE_PARTS - #missing, CACHE_PARTS))
		return nil
	end
	local wall0 = wall()
	local okc, buf = pcall(buffer.create, CACHE_BYTES)
	if not okc then return nil end
	for i = 0, CACHE_PARTS - 1 do
		local okr, data = pcall(httpReq, "GET", base .. "/cache/" .. key .. "/" .. i)
		if not okr or type(data) ~= "string" or #data ~= CACHE_CHUNK then return nil end
		buffer.copy(buf, i * CACHE_CHUNK, buffer.fromstring(data), 0, #data)
		data = nil
		pcall(FS.gc, "collect")
		sliceDue()
	end
	log(string.format("cache stazena z bridge za %.1f s", wall() - wall0))
	return buf
end

-- nabidnuti cache ostatnim; bezi na pozadi, aby se hned tezilo
local function pushBridge(seed, buf)
	if CONFIG.uploadCache == false then return end
	local base = httpBase()
	if not base then return end
	local key = hex(seed):sub(1, 16)
	local missing = bridgeMeta(base, key)
	if missing == nil or #missing == 0 then return end
	local tmp = buffer.create(CACHE_CHUNK)
	local okAll = true
	for _, i in ipairs(missing) do
		buffer.copy(tmp, 0, buf, i * CACHE_CHUNK, CACHE_CHUNK)
		if not httpReq("PUT", base .. "/cache/" .. key .. "/" .. i, buffer.tostring(tmp)) then
			okAll = false
			break
		end
		pcall(FS.gc, "collect")
	end
	if okAll then log("cache nabidnuta ostatnim (" .. key:sub(1, 8) .. ")") end
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

local function detach(fn)
	if type(task) == "table" and type(task.spawn) == "function" then return task.spawn(fn) end
	return fn()
end

local function getCache(seed)
	if cacheKey == seed then return cache end
	-- 1) sdilena cache z bridge (nejrychlejsi, nativni HTTP nezere Luau CPU)
	local fromBridge = fetchBridge(seed)
	if fromBridge then
		cache, cacheKey = fromBridge, seed
		local keep = cache -- hodnota, ne upvalue (cache se pri dalsim seedu prebije)
		detach(function() saveCache(seed, keep) end) -- at je i na disku, kdyz bridge spadne
		return cache
	end
	-- 2) vlastni disk
	local fromDisk = loadCache(seed)
	if fromDisk then
		cache, cacheKey = fromDisk, seed
		local keep = cache
		detach(function() pushBridge(seed, keep) end) -- doplnit bridge pro ostatni
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
	local keep = cache
	detach(function() pushBridge(seed, keep) end) -- ostatni klienti uz nemusi pocitat
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
